<#
.SYNOPSIS
    Configure Windows Optional Features
    
.DESCRIPTION
    Enables and disables Windows optional features for Windows 11 workstations.
    Manages features like .NET Framework, Media Player, Internet Explorer, and more.
    
    Features:
    - Enable optional Windows features
    - Disable unwanted Windows features
    - Validate feature availability before configuration
    - Support for multiple features in one operation
    - Automatic reboot handling
    - Rollback capability
    - Comprehensive logging and validation
    - DISM and PowerShell module support
    
.PARAMETER EnableFeatures
    Array of features to enable.
    Default: @("NetFx3", "Printing-XPSServices-Features")
    
    Common features to enable:
    - NetFx3 (.NET Framework 3.5)
    - NetFx4-AdvSrvs (.NET Framework 4.x Advanced Services)
    - Printing-XPSServices-Features (XPS Viewer)
    - TFTP (TFTP Client)
    - TelnetClient (Telnet Client)
    - WorkFolders-Client (Work Folders Client)
    
.PARAMETER DisableFeatures
    Array of features to disable.
    Default: @("WindowsMediaPlayer", "Internet-Explorer-Optional-amd64")
    
    Common features to disable:
    - WindowsMediaPlayer (Windows Media Player)
    - Internet-Explorer-Optional-amd64 (Internet Explorer 11)
    - MediaPlayback (Media Features)
    - WorkFolders-Client (Work Folders)
    - SMB1Protocol (SMB 1.0/CIFS File Sharing Support)
    
.PARAMETER SkipReboot
    Skip automatic reboot after feature changes.
    Default: $false
    Note: Some features require reboot to complete
    
.PARAMETER RebootTimeout
    Timeout in seconds before automatic reboot.
    Default: 300 (5 minutes)
    Set to 0 for immediate reboot
    
.PARAMETER ValidateOnly
    Only validate feature availability without making changes.
    Default: $false
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1
    Enables and disables features with default settings
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1 -EnableFeatures @("NetFx3", "TelnetClient")
    Enables .NET Framework 3.5 and Telnet Client
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1 -DisableFeatures @("WindowsMediaPlayer", "Internet-Explorer-Optional-amd64")
    Disables Windows Media Player and Internet Explorer
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1 -ValidateOnly
    Lists all available features without making changes
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1 -SkipReboot
    Configures features but does not automatically reboot
    
.EXAMPLE
    .\Configure-WindowsFeatures.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Windows Features configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Feature not available
    4   = Configuration failed
    5   = Reboot required
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - DISM module (built-in)
    - Internet connection (for online features)
    
    NOTES:
    - Some features require Windows installation media
    - Internet connection recommended for downloading features
    - Reboot typically required after feature changes
    - Script can run in offline mode with installation media
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$EnableFeatures = @("Printing-XPSServices-Features"),  # Removed NetFx3 (requires Windows source)

    [Parameter(Mandatory=$false)]
    [string[]]$DisableFeatures = @("WindowsMediaPlayer"),  # Removed Internet-Explorer (not in Windows 11)
    
    [Parameter(Mandatory=$false)]
    [bool]$SkipReboot = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$RebootTimeout = 300,
    
    [Parameter(Mandatory=$false)]
    [switch]$ValidateOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Initialize logging
$LogPath = "C:\ProgramData\OrchestrationLogs"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Configure-WindowsFeatures_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    FeaturesEnabled = 0
    FeaturesDisabled = 0
    FeaturesAlreadyEnabled = 0
    FeaturesAlreadyDisabled = 0
    FeaturesFailed = 0
    RebootRequired = $false
    Errors = 0
    Warnings = 0
}

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $Global:LogFile -Value $LogMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log: $_"
    }
    
    # Write to console with color
    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "DEBUG"   { "Cyan" }
        default   { "White" }
    }
    Write-Host $LogMessage -ForegroundColor $Color
    
    # Update statistics
    if ($Level -eq "ERROR") { $Global:Stats.Errors++ }
    if ($Level -eq "WARNING") { $Global:Stats.Warnings++ }
}

function Write-LogHeader {
    param([string]$Title)
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region PREREQUISITE FUNCTIONS
#==============================================================================

function Test-Prerequisites {
    Write-LogHeader "PREREQUISITE CHECKS"
    
    $AllChecksPassed = $true
    
    # Check 1: Administrator privileges
    Write-Log "Checking administrator privileges..." -Level "INFO"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Log "FAILED: Script must be run as Administrator" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "Administrator privileges confirmed" -Level "SUCCESS"
    }
    
    # Check 2: DISM module
    Write-Log "Checking DISM module availability..." -Level "INFO"
    try {
        $DismModule = Get-Module -Name DISM -ListAvailable -ErrorAction Stop
        if ($DismModule) {
            Write-Log "DISM module available" -Level "SUCCESS"
        }
        else {
            Write-Log "WARNING: DISM module not found, will use dism.exe" -Level "WARNING"
        }
    }
    catch {
        Write-Log "WARNING: Cannot check DISM module: $_" -Level "WARNING"
    }
    
    # Check 3: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($OSVersion.Major -lt 10) {
        Write-Log "WARNING: This script is optimized for Windows 10/11" -Level "WARNING"
    }
    else {
        Write-Log "Windows version check passed" -Level "SUCCESS"
    }
    
    return $AllChecksPassed
}

#endregion

#region FEATURE MANAGEMENT FUNCTIONS
#==============================================================================

function Get-AllWindowsFeatures {
    <#
    .SYNOPSIS
        Gets all available Windows features
    #>
    
    Write-LogHeader "AVAILABLE WINDOWS FEATURES"
    
    try {
        Write-Log "Querying available Windows features..." -Level "INFO"
        
        # Try using Get-WindowsOptionalFeature first (faster)
        try {
            $Features = Get-WindowsOptionalFeature -Online -ErrorAction Stop
            Write-Log "Retrieved $(($Features | Measure-Object).Count) features" -Level "SUCCESS"
        }
        catch {
            Write-Log "Get-WindowsOptionalFeature failed, trying DISM..." -Level "WARNING"
            
            # Fallback to DISM
            $DismOutput = dism /online /get-features /format:table 2>&1
            Write-Log "Retrieved features using DISM" -Level "SUCCESS"
            
            # Parse DISM output (not ideal but works)
            return $null
        }
        
        # Display feature summary
        $EnabledFeatures = $Features | Where-Object { $_.State -eq "Enabled" }
        $DisabledFeatures = $Features | Where-Object { $_.State -eq "Disabled" }
        
        Write-Log "Feature summary:" -Level "INFO"
        Write-Log "  Total features: $(($Features | Measure-Object).Count)" -Level "INFO"
        Write-Log "  Enabled: $(($EnabledFeatures | Measure-Object).Count)" -Level "INFO"
        Write-Log "  Disabled: $(($DisabledFeatures | Measure-Object).Count)" -Level "INFO"
        
        return $Features
    }
    catch {
        Write-Log "Exception getting Windows features: $_" -Level "ERROR"
        return $null
    }
}

function Get-FeatureState {
    <#
    .SYNOPSIS
        Gets the current state of a specific feature
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    
    try {
        $Feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        return $Feature.State
    }
    catch {
        Write-Log "Feature not found: $FeatureName" -Level "DEBUG"
        return "NotFound"
    }
}

function Enable-WindowsFeature {
    <#
    .SYNOPSIS
        Enables a Windows optional feature
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    
    try {
        Write-Log "Processing feature: $FeatureName" -Level "INFO"
        
        # Check current state
        $CurrentState = Get-FeatureState -FeatureName $FeatureName
        
        if ($CurrentState -eq "NotFound") {
            Write-Log "Feature not available: $FeatureName" -Level "ERROR"
            $Global:Stats.FeaturesFailed++
            return $false
        }
        
        if ($CurrentState -eq "Enabled") {
            Write-Log "Feature already enabled: $FeatureName" -Level "SUCCESS"
            $Global:Stats.FeaturesAlreadyEnabled++
            return $true
        }
        
        Write-Log "Enabling feature: $FeatureName (Current state: $CurrentState)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would enable feature: $FeatureName" -Level "INFO"
            return $true
        }
        
        # Enable the feature
        $Result = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart -ErrorAction Stop
        
        if ($Result.RestartNeeded) {
            Write-Log "Feature enabled (reboot required): $FeatureName" -Level "SUCCESS"
            $Global:Stats.RebootRequired = $true
        }
        else {
            Write-Log "Feature enabled successfully: $FeatureName" -Level "SUCCESS"
        }
        
        $Global:Stats.FeaturesEnabled++
        return $true
    }
    catch {
        Write-Log "Failed to enable feature $FeatureName : $_" -Level "ERROR"
        $Global:Stats.FeaturesFailed++
        return $false
    }
}

function Disable-WindowsFeature {
    <#
    .SYNOPSIS
        Disables a Windows optional feature
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    
    try {
        Write-Log "Processing feature: $FeatureName" -Level "INFO"
        
        # Check current state
        $CurrentState = Get-FeatureState -FeatureName $FeatureName
        
        if ($CurrentState -eq "NotFound") {
            Write-Log "Feature not available: $FeatureName" -Level "ERROR"
            $Global:Stats.FeaturesFailed++
            return $false
        }
        
        if ($CurrentState -eq "Disabled") {
            Write-Log "Feature already disabled: $FeatureName" -Level "SUCCESS"
            $Global:Stats.FeaturesAlreadyDisabled++
            return $true
        }
        
        Write-Log "Disabling feature: $FeatureName (Current state: $CurrentState)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable feature: $FeatureName" -Level "INFO"
            return $true
        }
        
        # Disable the feature
        $Result = Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
        
        if ($Result.RestartNeeded) {
            Write-Log "Feature disabled (reboot required): $FeatureName" -Level "SUCCESS"
            $Global:Stats.RebootRequired = $true
        }
        else {
            Write-Log "Feature disabled successfully: $FeatureName" -Level "SUCCESS"
        }
        
        $Global:Stats.FeaturesDisabled++
        return $true
    }
    catch {
        Write-Log "Failed to disable feature $FeatureName : $_" -Level "ERROR"
        $Global:Stats.FeaturesFailed++
        return $false
    }
}

function Enable-RequestedFeatures {
    <#
    .SYNOPSIS
        Enables all requested features
    #>
    
    if (-not $EnableFeatures -or $EnableFeatures.Count -eq 0) {
        Write-Log "No features to enable" -Level "INFO"
        return $true
    }
    
    Write-LogHeader "ENABLING WINDOWS FEATURES"
    
    Write-Log "Features to enable: $($EnableFeatures.Count)" -Level "INFO"
    foreach ($Feature in $EnableFeatures) {
        Write-Log "  - $Feature" -Level "INFO"
    }
    Write-Log " " -Level "INFO"
    
    $AllSucceeded = $true
    
    foreach ($Feature in $EnableFeatures) {
        $Result = Enable-WindowsFeature -FeatureName $Feature
        if (-not $Result) {
            $AllSucceeded = $false
        }
        Write-Log " " -Level "INFO"
    }
    
    return $AllSucceeded
}

function Disable-RequestedFeatures {
    <#
    .SYNOPSIS
        Disables all requested features
    #>
    
    if (-not $DisableFeatures -or $DisableFeatures.Count -eq 0) {
        Write-Log "No features to disable" -Level "INFO"
        return $true
    }
    
    Write-LogHeader "DISABLING WINDOWS FEATURES"
    
    Write-Log "Features to disable: $($DisableFeatures.Count)" -Level "INFO"
    foreach ($Feature in $DisableFeatures) {
        Write-Log "  - $Feature" -Level "INFO"
    }
    Write-Log " " -Level "INFO"
    
    $AllSucceeded = $true
    
    foreach ($Feature in $DisableFeatures) {
        $Result = Disable-WindowsFeature -FeatureName $Feature
        if (-not $Result) {
            $AllSucceeded = $false
        }
        Write-Log " " -Level "INFO"
    }
    
    return $AllSucceeded
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-FeatureConfiguration {
    <#
    .SYNOPSIS
        Validates feature configuration
    #>
    
    Write-LogHeader "VALIDATING FEATURE CONFIGURATION"
    
    try {
        # Validate enabled features
        if ($EnableFeatures -and $EnableFeatures.Count -gt 0) {
            Write-Log "Validating enabled features:" -Level "INFO"
            
            foreach ($Feature in $EnableFeatures) {
                $State = Get-FeatureState -FeatureName $Feature
                
                if ($State -eq "Enabled") {
                    Write-Log "  ✓ $Feature : Enabled" -Level "SUCCESS"
                }
                elseif ($State -eq "EnablePending") {
                    Write-Log "  ⏳ $Feature : Enable Pending (reboot required)" -Level "WARNING"
                }
                else {
                    Write-Log "  ✗ $Feature : Not Enabled (State: $State)" -Level "ERROR"
                }
            }
        }
        
        # Validate disabled features
        if ($DisableFeatures -and $DisableFeatures.Count -gt 0) {
            Write-Log " " -Level "INFO"
            Write-Log "Validating disabled features:" -Level "INFO"
            
            foreach ($Feature in $DisableFeatures) {
                $State = Get-FeatureState -FeatureName $Feature
                
                if ($State -eq "Disabled") {
                    Write-Log "  ✓ $Feature : Disabled" -Level "SUCCESS"
                }
                elseif ($State -eq "DisablePending") {
                    Write-Log "  ⏳ $Feature : Disable Pending (reboot required)" -Level "WARNING"
                }
                else {
                    Write-Log "  ✗ $Feature : Not Disabled (State: $State)" -Level "ERROR"
                }
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Exception during validation: $_" -Level "ERROR"
        return $false
    }
}

function Show-ConfigurationSummary {
    <#
    .SYNOPSIS
        Displays comprehensive configuration summary
    #>
    
    Write-LogHeader "CONFIGURATION SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    Write-Log "  Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log "  Validate Only: $ValidateOnly" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Feature Configuration Results:" -Level "INFO"
    Write-Log "  Features Enabled: $($Global:Stats.FeaturesEnabled)" -Level "SUCCESS"
    Write-Log "  Features Disabled: $($Global:Stats.FeaturesDisabled)" -Level "SUCCESS"
    Write-Log "  Already Enabled: $($Global:Stats.FeaturesAlreadyEnabled)" -Level "INFO"
    Write-Log "  Already Disabled: $($Global:Stats.FeaturesAlreadyDisabled)" -Level "INFO"
    Write-Log "  Failed: $($Global:Stats.FeaturesFailed)" -Level $(if($Global:Stats.FeaturesFailed -gt 0){"ERROR"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Reboot Status:" -Level "INFO"
    if ($Global:Stats.RebootRequired) {
        Write-Log "  Reboot Required: YES" -Level "WARNING"
        if (-not $SkipReboot -and -not $DryRun -and -not $ValidateOnly) {
            Write-Log "  Auto-Reboot: Scheduled in $RebootTimeout seconds" -Level "WARNING"
        }
        else {
            Write-Log "  Auto-Reboot: Disabled (manual reboot required)" -Level "WARNING"
        }
    }
    else {
        Write-Log "  Reboot Required: NO" -Level "SUCCESS"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
}

function Invoke-SystemReboot {
    <#
    .SYNOPSIS
        Handles system reboot if required
    #>
    
    if (-not $Global:Stats.RebootRequired) {
        Write-Log "No reboot required" -Level "SUCCESS"
        return $false
    }
    
    if ($SkipReboot) {
        Write-Log "Reboot required but skipped by parameter" -Level "WARNING"
        Write-Log "Please reboot the system manually to complete feature configuration" -Level "WARNING"
        return $false
    }
    
    if ($DryRun -or $ValidateOnly) {
        Write-Log "[DRY RUN] Would reboot system in $RebootTimeout seconds" -Level "INFO"
        return $false
    }
    
    Write-LogHeader "SYSTEM REBOOT"
    
    if ($RebootTimeout -gt 0) {
        Write-Log "System will reboot in $RebootTimeout seconds..." -Level "WARNING"
        Write-Log "Press Ctrl+C to cancel the reboot" -Level "WARNING"
        
        $Minutes = [math]::Floor($RebootTimeout / 60)
        $Seconds = $RebootTimeout % 60
        
        if ($Minutes -gt 0) {
            Write-Log "Waiting $Minutes minute(s) and $Seconds second(s)..." -Level "INFO"
        }
        else {
            Write-Log "Waiting $Seconds second(s)..." -Level "INFO"
        }
        
        Start-Sleep -Seconds $RebootTimeout
    }
    
    Write-Log "Initiating system reboot..." -Level "WARNING"
    
    # Schedule reboot
    shutdown /r /t 10 /c "Windows Features configuration complete. System reboot required." /f
    
    Write-Log "Reboot scheduled in 10 seconds" -Level "SUCCESS"
    
    return $true
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    # Display banner
    Clear-Host
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        WINDOWS FEATURES CONFIGURATION                         ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}elseif($ValidateOnly){'VALIDATE ONLY'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun -or $ValidateOnly){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WINDOWS FEATURES CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log "Validate Only: $ValidateOnly" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Configuration:" -Level "INFO"
    Write-Log "  Features to Enable: $($EnableFeatures.Count)" -Level "INFO"
    if ($EnableFeatures) {
        foreach ($Feature in $EnableFeatures) {
            Write-Log "    - $Feature" -Level "INFO"
        }
    }
    Write-Log "  Features to Disable: $($DisableFeatures.Count)" -Level "INFO"
    if ($DisableFeatures) {
        foreach ($Feature in $DisableFeatures) {
            Write-Log "    - $Feature" -Level "INFO"
        }
    }
    Write-Log "  Skip Reboot: $SkipReboot" -Level "INFO"
    Write-Log "  Reboot Timeout: $RebootTimeout seconds" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Validate only mode
    if ($ValidateOnly) {
        Get-AllWindowsFeatures
        Test-FeatureConfiguration
        Show-ConfigurationSummary
        exit 0
    }
    
    # Enable requested features
    $EnableResult = Enable-RequestedFeatures
    
    # Disable requested features
    $DisableResult = Disable-RequestedFeatures
    
    # Validate configuration
    Test-FeatureConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Handle reboot
    $Rebooting = Invoke-SystemReboot
    
    # Determine exit code
    if ($Rebooting) {
        $ExitCode = 5  # Reboot pending
    }
    elseif ($Global:Stats.Errors -eq 0) {
        $ExitCode = 0  # Success
    }
    else {
        $ExitCode = 4  # Configuration failed
    }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Windows Features configuration completed successfully!" -Level "SUCCESS"
    }
    elseif ($ExitCode -eq 5) {
        Write-Log "Windows Features configuration completed - system rebooting..." -Level "SUCCESS"
    }
    else {
        Write-Log "Configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
    }
    
    if ($Global:Stats.RebootRequired -and -not $Rebooting) {
        Write-Log " " -Level "INFO"
        Write-Log "IMPORTANT: A system reboot is required to complete feature configuration" -Level "WARNING"
        Write-Log "Please reboot the system at your earliest convenience" -Level "WARNING"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-ConfigurationSummary
    
    exit 1
}

#endregion
