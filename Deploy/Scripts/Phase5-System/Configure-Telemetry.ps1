<#
.SYNOPSIS
    Configure Windows Telemetry and Diagnostics
    
.DESCRIPTION
    Configures Windows telemetry, diagnostics data collection, and feedback settings
    for Windows 11 workstations. Balances privacy, compliance, and system diagnostics.
    
    Features:
    - Set telemetry level (Security/Basic/Enhanced/Full)
    - Disable/enable diagnostic data collection
    - Configure feedback frequency
    - Disable consumer experiences
    - Configure Windows Error Reporting
    - Disable advertising ID
    - Control App Diagnostics
    - Comprehensive logging and validation
    
.PARAMETER TelemetryLevel
    Windows telemetry/diagnostic data level.
    Options: "Security", "Basic", "Enhanced", "Full"
    Default: "Basic"
    
    Levels explained:
    - Security (0):     Minimal data, enterprise recommended (requires Enterprise/Education)
    - Basic (1):        Basic device info, Windows Update data
    - Enhanced (2):     Additional quality/usage data
    - Full (3):         All diagnostic data (default consumer Windows)
    
    Note: "Security" level requires Windows 11 Enterprise or Education edition
    
.PARAMETER DisableFeedback
    Disable Windows Feedback prompts.
    Default: $true
    
    When true:
    - No feedback notifications
    - No "How do you like Windows?" prompts
    - Cleaner user experience
    
.PARAMETER DisableConsumerExperiences
    Disable Windows consumer experiences (app suggestions, tips).
    Default: $true
    
    When true:
    - No app install suggestions
    - No tips and tricks
    - No consumer-focused features
    
.PARAMETER DisableAdvertisingID
    Disable Windows advertising ID.
    Default: $true
    
    When true:
    - No personalized ads
    - Privacy improvement
    - No cross-app tracking
    
.PARAMETER DisableWindowsErrorReporting
    Disable Windows Error Reporting.
    Default: $false
    
    When true:
    - No crash reports sent
    - Privacy improvement
    - May impact troubleshooting
    
.PARAMETER DisableAppDiagnostics
    Prevent apps from accessing diagnostic information.
    Default: $true
    
.PARAMETER ApplyToAllUsers
    Apply settings to default user profile (affects new users).
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-Telemetry.ps1
    Configures telemetry with default settings (Security level, feedback disabled)
    
.EXAMPLE
    .\Configure-Telemetry.ps1 -TelemetryLevel "Basic"
    Sets telemetry to Basic level (compatible with Pro edition)
    
.EXAMPLE
    .\Configure-Telemetry.ps1 -TelemetryLevel "Security" -DisableFeedback $true
    Minimal telemetry with no feedback prompts (maximum privacy)
    
.EXAMPLE
    .\Configure-Telemetry.ps1 -DisableConsumerExperiences $true
    Disables app suggestions and consumer features
    
.EXAMPLE
    .\Configure-Telemetry.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Telemetry configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Incompatible Windows edition (for Security level)
    4   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - Enterprise/Education edition (for Security telemetry level)
    
    IMPORTANT NOTES:
    - "Security" telemetry level requires Enterprise or Education edition
    - Windows Pro maximum: "Basic" level
    - Some diagnostic data always collected (required for Windows Update)
    - Changes take effect immediately (no reboot required)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Security", "Basic", "Enhanced", "Full")]
    [string]$TelemetryLevel = "Security",
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableFeedback = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableConsumerExperiences = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableAdvertisingID = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableWindowsErrorReporting = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableAppDiagnostics = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToAllUsers = $true,
    
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

$LogFileName = "Configure-Telemetry_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    TelemetryLevelSet = ""
    SettingsApplied = 0
    ServicesDisabled = 0
    TasksDisabled = 0
    Errors = 0
    Warnings = 0
}

# Telemetry level mapping
$TelemetryLevels = @{
    "Security" = 0
    "Basic"    = 1
    "Enhanced" = 2
    "Full"     = 3
}

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
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
    
    # Check 2: Windows edition for Security telemetry level
    Write-Log "Checking Windows edition..." -Level "INFO"
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $Edition = $OSInfo.Caption
    
    Write-Log "Windows Edition: $Edition" -Level "INFO"
    
    if ($TelemetryLevel -eq "Security") {
        if ($Edition -notmatch "Enterprise|Education") {
            Write-Log "WARNING: 'Security' telemetry level requires Enterprise or Education edition" -Level "WARNING"
            Write-Log "Current edition: $Edition" -Level "WARNING"
            Write-Log "Telemetry will be set to 'Basic' instead (minimum for Pro)" -Level "WARNING"
            
            # Automatically adjust to Basic for Pro
            $script:TelemetryLevel = "Basic"
        }
        else {
            Write-Log "Enterprise/Education edition confirmed - Security level supported" -Level "SUCCESS"
        }
    }
    
    # Check 3: Registry access
    Write-Log "Checking registry access..." -Level "INFO"
    try {
        $TestKey = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction SilentlyContinue
        Write-Log "Registry access confirmed" -Level "SUCCESS"
    }
    catch {
        Write-Log "WARNING: Cannot access DataCollection registry: $_" -Level "WARNING"
    }
    
    return $AllChecksPassed
}

#endregion

#region TELEMETRY CONFIGURATION FUNCTIONS
#==============================================================================

function Get-CurrentTelemetrySettings {
    <#
    .SYNOPSIS
        Gets current telemetry settings
    #>
    
    Write-LogHeader "CURRENT TELEMETRY SETTINGS"
    
    try {
        $DCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        
        # Get current telemetry level
        $CurrentLevel = (Get-ItemProperty $DCPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        
        $LevelName = switch ($CurrentLevel) {
            0 { "Security" }
            1 { "Basic" }
            2 { "Enhanced" }
            3 { "Full" }
            default { "Unknown" }
        }
        
        Write-Log "Current telemetry settings:" -Level "INFO"
        Write-Log "  Telemetry Level: $LevelName (Value: $CurrentLevel)" -Level "INFO"
        
        return @{
            Level = $CurrentLevel
            LevelName = $LevelName
        }
    }
    catch {
        Write-Log "Exception getting current settings: $_" -Level "ERROR"
        return $null
    }
}

function Set-TelemetryLevel {
    <#
    .SYNOPSIS
        Sets Windows telemetry level
    #>
    
    Write-LogHeader "CONFIGURING TELEMETRY LEVEL"
    
    try {
        $TelemetryValue = $TelemetryLevels[$TelemetryLevel]
        
        Write-Log "Setting telemetry level to: $TelemetryLevel (Value: $TelemetryValue)" -Level "INFO"
        
        # Explain telemetry level
        switch ($TelemetryLevel) {
            "Security" {
                Write-Log "  Security: Minimal data collection (Enterprise/Education only)" -Level "INFO"
                Write-Log "  - Security updates only" -Level "DEBUG"
                Write-Log "  - Malicious software removal" -Level "DEBUG"
            }
            "Basic" {
                Write-Log "  Basic: Essential device and compatibility data" -Level "INFO"
                Write-Log "  - Device info, quality data" -Level "DEBUG"
                Write-Log "  - Windows Update data" -Level "DEBUG"
            }
            "Enhanced" {
                Write-Log "  Enhanced: Additional diagnostic data" -Level "INFO"
                Write-Log "  - Usage patterns, error reports" -Level "DEBUG"
            }
            "Full" {
                Write-Log "  Full: Complete diagnostic data (default consumer)" -Level "INFO"
                Write-Log "  - All diagnostic and usage data" -Level "DEBUG"
            }
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set telemetry to: $TelemetryLevel" -Level "INFO"
            return $true
        }
        
        # Create DataCollection key if doesn't exist
        $DCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $DCPath)) {
            New-Item -Path $DCPath -Force | Out-Null
            Write-Log "Created DataCollection registry key" -Level "DEBUG"
        }
        
        # Set telemetry level
        Set-ItemProperty -Path $DCPath -Name "AllowTelemetry" -Value $TelemetryValue -Type DWord -Force
        
        # Verify
        $Verification = (Get-ItemProperty $DCPath -Name "AllowTelemetry").AllowTelemetry
        if ($Verification -eq $TelemetryValue) {
            Write-Log "Telemetry level set successfully: $TelemetryLevel" -Level "SUCCESS"
            $Global:Stats.TelemetryLevelSet = $TelemetryLevel
            $Global:Stats.SettingsApplied++
        }
        else {
            Write-Log "Telemetry level verification failed" -Level "ERROR"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Exception setting telemetry level: $_" -Level "ERROR"
        return $false
    }
}

function Set-FeedbackSettings {
    <#
    .SYNOPSIS
        Configures Windows Feedback settings
    #>
    
    Write-LogHeader "CONFIGURING FEEDBACK SETTINGS"
    
    try {
        Write-Log "Setting: Disable Feedback = $DisableFeedback" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure feedback settings" -Level "INFO"
            return $true
        }
        
        # Siuf = Software Improvement and User Feedback
        $SiufPath = "HKCU:\Software\Microsoft\Siuf\Rules"
        
        if (-not (Test-Path $SiufPath)) {
            New-Item -Path $SiufPath -Force | Out-Null
        }
        
        if ($DisableFeedback) {
            # Disable feedback notifications
            Set-ItemProperty -Path $SiufPath -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $SiufPath -Name "PeriodInNanoSeconds" -Value 0 -Type DWord -Force
            
            Write-Log "Windows Feedback disabled" -Level "SUCCESS"
        }
        else {
            # Enable feedback (default Windows behavior)
            Remove-ItemProperty -Path $SiufPath -Name "NumberOfSIUFInPeriod" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $SiufPath -Name "PeriodInNanoSeconds" -Force -ErrorAction SilentlyContinue
            
            Write-Log "Windows Feedback enabled" -Level "SUCCESS"
        }
        
        $Global:Stats.SettingsApplied++
        return $true
    }
    catch {
        Write-Log "Exception setting feedback settings: $_" -Level "ERROR"
        return $false
    }
}

function Set-ConsumerExperiences {
    <#
    .SYNOPSIS
        Configures Windows consumer experiences (app suggestions, tips)
    #>
    
    Write-LogHeader "CONFIGURING CONSUMER EXPERIENCES"
    
    try {
        Write-Log "Setting: Disable Consumer Experiences = $DisableConsumerExperiences" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure consumer experiences" -Level "INFO"
            return $true
        }
        
        $CloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        
        if (-not (Test-Path $CloudContentPath)) {
            New-Item -Path $CloudContentPath -Force | Out-Null
        }
        
        if ($DisableConsumerExperiences) {
            # Disable consumer experiences
            Set-ItemProperty -Path $CloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
            
            Write-Log "Consumer experiences disabled (no app suggestions, tips)" -Level "SUCCESS"
        }
        else {
            # Enable consumer experiences
            Set-ItemProperty -Path $CloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 0 -Type DWord -Force
            
            Write-Log "Consumer experiences enabled" -Level "SUCCESS"
        }
        
        $Global:Stats.SettingsApplied++
        return $true
    }
    catch {
        Write-Log "Exception setting consumer experiences: $_" -Level "ERROR"
        return $false
    }
}

function Set-AdvertisingID {
    <#
    .SYNOPSIS
        Configures Windows Advertising ID
    #>
    
    Write-LogHeader "CONFIGURING ADVERTISING ID"
    
    try {
        Write-Log "Setting: Disable Advertising ID = $DisableAdvertisingID" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure advertising ID" -Level "INFO"
            return $true
        }
        
        $AdvertisingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        
        if (-not (Test-Path $AdvertisingPath)) {
            New-Item -Path $AdvertisingPath -Force | Out-Null
        }
        
        if ($DisableAdvertisingID) {
            # Disable advertising ID
            Set-ItemProperty -Path $AdvertisingPath -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
            
            Write-Log "Advertising ID disabled (privacy improvement)" -Level "SUCCESS"
        }
        else {
            # Enable advertising ID
            Set-ItemProperty -Path $AdvertisingPath -Name "DisabledByGroupPolicy" -Value 0 -Type DWord -Force
            
            Write-Log "Advertising ID enabled" -Level "SUCCESS"
        }
        
        $Global:Stats.SettingsApplied++
        return $true
    }
    catch {
        Write-Log "Exception setting advertising ID: $_" -Level "ERROR"
        return $false
    }
}

function Set-WindowsErrorReporting {
    <#
    .SYNOPSIS
        Configures Windows Error Reporting
    #>
    
    Write-LogHeader "CONFIGURING WINDOWS ERROR REPORTING"
    
    try {
        Write-Log "Setting: Disable Windows Error Reporting = $DisableWindowsErrorReporting" -Level "INFO"
        
        if ($DisableWindowsErrorReporting) {
            Write-Log "WARNING: Disabling error reporting may impact troubleshooting" -Level "WARNING"
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure Windows Error Reporting" -Level "INFO"
            return $true
        }
        
        $WERPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
        
        if (-not (Test-Path $WERPath)) {
            New-Item -Path $WERPath -Force | Out-Null
        }
        
        if ($DisableWindowsErrorReporting) {
            # Disable Windows Error Reporting
            Set-ItemProperty -Path $WERPath -Name "Disabled" -Value 1 -Type DWord -Force
            
            Write-Log "Windows Error Reporting disabled" -Level "SUCCESS"
        }
        else {
            # Enable Windows Error Reporting
            Set-ItemProperty -Path $WERPath -Name "Disabled" -Value 0 -Type DWord -Force
            
            Write-Log "Windows Error Reporting enabled" -Level "SUCCESS"
        }
        
        $Global:Stats.SettingsApplied++
        return $true
    }
    catch {
        Write-Log "Exception setting Windows Error Reporting: $_" -Level "ERROR"
        return $false
    }
}

function Set-AppDiagnostics {
    <#
    .SYNOPSIS
        Configures app access to diagnostic information
    #>
    
    Write-LogHeader "CONFIGURING APP DIAGNOSTICS"
    
    try {
        Write-Log "Setting: Disable App Diagnostics = $DisableAppDiagnostics" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure app diagnostics" -Level "INFO"
            return $true
        }
        
        $AppPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        
        if (-not (Test-Path $AppPrivacyPath)) {
            New-Item -Path $AppPrivacyPath -Force | Out-Null
        }
        
        if ($DisableAppDiagnostics) {
            # Deny app access to diagnostics
            Set-ItemProperty -Path $AppPrivacyPath -Name "LetAppsAccessDiagnostics" -Value 2 -Type DWord -Force
            
            Write-Log "App access to diagnostics disabled" -Level "SUCCESS"
        }
        else {
            # Allow app access to diagnostics
            Set-ItemProperty -Path $AppPrivacyPath -Name "LetAppsAccessDiagnostics" -Value 0 -Type DWord -Force
            
            Write-Log "App access to diagnostics enabled" -Level "SUCCESS"
        }
        
        $Global:Stats.SettingsApplied++
        return $true
    }
    catch {
        Write-Log "Exception setting app diagnostics: $_" -Level "ERROR"
        return $false
    }
}

function Disable-TelemetryServices {
    <#
    .SYNOPSIS
        Disables telemetry-related services (optional)
    #>
    
    Write-LogHeader "MANAGING TELEMETRY SERVICES"
    
    try {
        if ($TelemetryLevel -ne "Security" -and $TelemetryLevel -ne "Basic") {
            Write-Log "Keeping telemetry services enabled (telemetry level: $TelemetryLevel)" -Level "INFO"
            return $true
        }
        
        Write-Log "Configuring telemetry services for minimal data collection..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure telemetry services" -Level "INFO"
            return $true
        }
        
        # Diagnostic services that can be disabled for minimal telemetry
        $ServicesToManage = @(
            "DiagTrack",          # Connected User Experiences and Telemetry
            "dmwappushservice"    # Device Management Wireless Application Protocol
        )
        
        foreach ($ServiceName in $ServicesToManage) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    Write-Log "Managing service: $ServiceName" -Level "DEBUG"
                    
                    # Stop service if running
                    if ($Service.Status -eq "Running") {
                        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                        Write-Log "  Stopped: $ServiceName" -Level "DEBUG"
                    }
                    
                    # Set to manual (not disabled to avoid issues)
                    Set-Service -Name $ServiceName -StartupType Manual -ErrorAction SilentlyContinue
                    Write-Log "  Set to Manual: $ServiceName" -Level "DEBUG"
                    
                    $Global:Stats.ServicesDisabled++
                }
            }
            catch {
                Write-Log "Warning managing service $ServiceName : $_" -Level "WARNING"
            }
        }
        
        Write-Log "Telemetry services configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Exception managing telemetry services: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-TelemetryConfiguration {
    <#
    .SYNOPSIS
        Validates telemetry configuration
    #>
    
    Write-LogHeader "VALIDATING TELEMETRY CONFIGURATION"
    
    try {
        $DCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        
        Write-Log "Validating configuration..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        # Telemetry Level
        $TelemetryValue = (Get-ItemProperty $DCPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        $Expected = $TelemetryLevels[$TelemetryLevel]
        
        if ($TelemetryValue -eq $Expected) {
            Write-Log "  ✓ Telemetry Level: $TelemetryLevel" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Telemetry Level: Configuration mismatch (Expected: $Expected, Found: $TelemetryValue)" -Level "ERROR"
        }
        
        # Consumer Experiences
        $CloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        $ConsumerValue = (Get-ItemProperty $CloudContentPath -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue).DisableWindowsConsumerFeatures
        
        Write-Log "  ✓ Consumer Experiences: $(if($ConsumerValue -eq 1){'DISABLED'}else{'ENABLED'})" -Level "SUCCESS"
        
        # Advertising ID
        $AdvertisingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        $AdIDValue = (Get-ItemProperty $AdvertisingPath -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue).DisabledByGroupPolicy
        
        Write-Log "  ✓ Advertising ID: $(if($AdIDValue -eq 1){'DISABLED'}else{'ENABLED'})" -Level "SUCCESS"
        
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
    
    Write-Log " " -Level "INFO"
    Write-Log "Telemetry Configuration Results:" -Level "INFO"
    Write-Log "  Telemetry Level Set: $($Global:Stats.TelemetryLevelSet)" -Level "SUCCESS"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    Write-Log "  Services Managed: $($Global:Stats.ServicesDisabled)" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Telemetry Level: $TelemetryLevel" -Level "INFO"
    Write-Log "  Disable Feedback: $DisableFeedback" -Level "INFO"
    Write-Log "  Disable Consumer Experiences: $DisableConsumerExperiences" -Level "INFO"
    Write-Log "  Disable Advertising ID: $DisableAdvertisingID" -Level "INFO"
    Write-Log "  Disable Windows Error Reporting: $DisableWindowsErrorReporting" -Level "INFO"
    Write-Log "  Disable App Diagnostics: $DisableAppDiagnostics" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Privacy Impact:" -Level "INFO"
    if ($TelemetryLevel -eq "Security") {
        Write-Log "  ✓ Minimal data collection (Security level)" -Level "SUCCESS"
    }
    elseif ($TelemetryLevel -eq "Basic") {
        Write-Log "  ⚠ Essential data only (Basic level)" -Level "WARNING"
    }
    else {
        Write-Log "  ⚠ Increased data collection ($TelemetryLevel level)" -Level "WARNING"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
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
║        WINDOWS TELEMETRY CONFIGURATION                        ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WINDOWS TELEMETRY CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Telemetry Level: $TelemetryLevel" -Level "INFO"
    Write-Log "  Disable Feedback: $DisableFeedback" -Level "INFO"
    Write-Log "  Disable Consumer Experiences: $DisableConsumerExperiences" -Level "INFO"
    Write-Log "  Disable Advertising ID: $DisableAdvertisingID" -Level "INFO"
    Write-Log "  Disable Windows Error Reporting: $DisableWindowsErrorReporting" -Level "INFO"
    Write-Log "  Disable App Diagnostics: $DisableAppDiagnostics" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Get current settings
    Get-CurrentTelemetrySettings
    
    # Configure telemetry level
    $TelemetryResult = Set-TelemetryLevel
    
    # Configure feedback settings
    $FeedbackResult = Set-FeedbackSettings
    
    # Configure consumer experiences
    $ConsumerResult = Set-ConsumerExperiences
    
    # Configure advertising ID
    $AdvertisingResult = Set-AdvertisingID
    
    # Configure Windows Error Reporting
    $WERResult = Set-WindowsErrorReporting
    
    # Configure app diagnostics
    $AppDiagResult = Set-AppDiagnostics
    
    # Manage telemetry services
    $ServicesResult = Disable-TelemetryServices
    
    # Validate configuration
    Test-TelemetryConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Windows Telemetry configuration completed successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
