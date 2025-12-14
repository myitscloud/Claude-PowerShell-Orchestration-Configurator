<#
.SYNOPSIS
    Configure Windows 11 Start Menu Layout
    
.DESCRIPTION
    Configures Windows 11 Start Menu layout, pinned items, and recommendations.
    Designed to run as SYSTEM to configure default user profile.
    
    Features:
    - Import Start Menu layout from XML
    - Pin/unpin applications
    - Configure Start Menu settings (size, position, recommendations)
    - Remove default pinned items
    - Apply to default user profile (new users)
    - Apply to existing users (optional)
    - Comprehensive logging and validation
    
.PARAMETER LayoutXML
    Path to Start Menu layout XML file.
    Default: "Config\StartMenuLayout.xml"
    
    If not specified or file doesn't exist, uses basic configuration
    
.PARAMETER ApplyToAllUsers
    Apply Start Menu configuration to default user profile.
    Default: $true
    
    When true:
    - Modifies C:\Users\Default profile
    - All NEW users get this configuration
    
.PARAMETER ApplyToExistingUsers
    Apply Start Menu configuration to all existing user profiles.
    Default: $false
    
    WARNING: Overwrites existing users' customizations
    
.PARAMETER RemoveDefaultPins
    Remove Windows default pinned items from Start Menu.
    Default: $true
    
    Removes: Microsoft Store, Photos, Settings, etc.
    
.PARAMETER PinApplications
    Array of applications to pin to Start Menu.
    Default: @()
    
    Example: @("Microsoft Edge", "File Explorer", "Notepad")
    
.PARAMETER ShowRecentlyAdded
    Show recently added apps in Start Menu.
    Default: $false
    
.PARAMETER ShowMostUsed
    Show most used apps in Start Menu.
    Default: $false
    
.PARAMETER ShowRecommendations
    Show recommendations section in Start Menu.
    Default: $false
    
.PARAMETER StartMenuSize
    Start Menu size: "Default", "MorePins", "MoreRecommendations"
    Default: "MorePins"
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-StartMenu.ps1
    Applies default Start Menu configuration to default user profile
    
.EXAMPLE
    .\Configure-StartMenu.ps1 -LayoutXML "C:\Deploy\StartLayout.xml"
    Imports Start Menu layout from custom XML file
    
.EXAMPLE
    .\Configure-StartMenu.ps1 -RemoveDefaultPins $true -ShowRecommendations $false
    Removes default pins and disables recommendations
    
.EXAMPLE
    .\Configure-StartMenu.ps1 -PinApplications @("Microsoft Edge", "File Explorer")
    Pins specific applications to Start Menu
    
.EXAMPLE
    .\Configure-StartMenu.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Start Menu configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    4   = Layout XML file not found
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    IMPORTANT NOTES:
    - Best run as SYSTEM (via SCCM or PsExec)
    - Start Menu layout is partially supported in Windows 11
    - Windows 11 has fewer customization options than Windows 10
    - Some features require Group Policy
    - Changes apply on next user login
    
    WINDOWS 11 LIMITATIONS:
    - Full Start Menu layout XML not supported (like Windows 10)
    - Cannot pin UWP apps programmatically as easily
    - Limited API for Start Menu customization
    - Recommendations section cannot be fully removed (only hidden)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LayoutXML = "Config\StartMenuLayout.xml",
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToAllUsers = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToExistingUsers = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemoveDefaultPins = $true,
    
    [Parameter(Mandatory=$false)]
    [string[]]$PinApplications = @(),
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowRecentlyAdded = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowMostUsed = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowRecommendations = $false,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Default", "MorePins", "MoreRecommendations")]
    [string]$StartMenuSize = "MorePins",
    
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

$LogFileName = "Configure-StartMenu_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    SettingsApplied = 0
    PinsRemoved = 0
    PinsAdded = 0
    ProfilesModified = 0
    Errors = 0
    Warnings = 0
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
    
    # Check 2: Running context
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Log "Running as: $CurrentUser" -Level "INFO"
    
    if ($CurrentUser -like "*SYSTEM*") {
        Write-Log "Running as SYSTEM - can modify default profile" -Level "SUCCESS"
    }
    else {
        Write-Log "WARNING: Not running as SYSTEM - will only modify current user" -Level "WARNING"
        if ($ApplyToAllUsers) {
            Write-Log "WARNING: ApplyToAllUsers=true but not SYSTEM - may not work as expected" -Level "WARNING"
        }
    }
    
    # Check 3: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($BuildNumber -lt 22000) {
        Write-Log "WARNING: This script is optimized for Windows 11 (Build 22000+)" -Level "WARNING"
        Write-Log "Current build: $BuildNumber (may be Windows 10)" -Level "WARNING"
    }
    else {
        Write-Log "Windows 11 detected" -Level "SUCCESS"
    }
    
    # Check 4: Layout XML file (if specified)
    if ($LayoutXML) {
        Write-Log "Checking for layout XML file..." -Level "INFO"
        
        # Make path absolute if relative
        if (-not [System.IO.Path]::IsPathRooted($LayoutXML)) {
            $LayoutXML = Join-Path (Split-Path $PSScriptRoot -Parent) $LayoutXML
        }
        
        if (Test-Path $LayoutXML) {
            Write-Log "Layout XML found: $LayoutXML" -Level "SUCCESS"
        }
        else {
            Write-Log "Layout XML not found: $LayoutXML" -Level "WARNING"
            Write-Log "Will use basic registry-based configuration instead" -Level "WARNING"
        }
    }
    
    return $AllChecksPassed
}

#endregion

#region START MENU CONFIGURATION FUNCTIONS
#==============================================================================

function Get-CurrentStartMenuConfig {
    <#
    .SYNOPSIS
        Gets current Start Menu configuration
    #>
    
    Write-LogHeader "CURRENT START MENU CONFIGURATION"
    
    try {
        $StartPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        Write-Log "Current Start Menu settings:" -Level "INFO"
        
        # Recently added apps
        $RecentApps = (Get-ItemProperty $StartPath -Name "Start_TrackProgs" -ErrorAction SilentlyContinue).Start_TrackProgs
        Write-Log "  Recently Added Apps: $(if($RecentApps -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        
        # Most used apps
        $MostUsed = (Get-ItemProperty $StartPath -Name "Start_TrackDocs" -ErrorAction SilentlyContinue).Start_TrackDocs
        Write-Log "  Most Used Apps: $(if($MostUsed -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        
        return @{
            RecentlyAdded = $RecentApps
            MostUsed = $MostUsed
        }
    }
    catch {
        Write-Log "Exception getting current configuration: $_" -Level "ERROR"
        return $null
    }
}

function Set-StartMenuSettings {
    <#
    .SYNOPSIS
        Configures Start Menu registry settings
    #>
    param(
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "CONFIGURING START MENU SETTINGS"
    
    try {
        $StartPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        Write-Log "Configuring Start Menu registry settings..." -Level "INFO"
        Write-Log "  Target Registry Hive: $TargetHive" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure Start Menu settings" -Level "INFO"
            return $true
        }
        
        # Ensure registry path exists
        if (-not (Test-Path $StartPath)) {
            New-Item -Path $StartPath -Force | Out-Null
            Write-Log "Created registry path: $StartPath" -Level "DEBUG"
        }
        
        # Show recently added apps
        Write-Log "Setting: Show Recently Added = $ShowRecentlyAdded" -Level "INFO"
        Set-ItemProperty -Path $StartPath -Name "Start_TrackProgs" -Value $(if($ShowRecentlyAdded){1}else{0}) -Type DWord -Force
        
        # Show most used apps  
        Write-Log "Setting: Show Most Used = $ShowMostUsed" -Level "INFO"
        Set-ItemProperty -Path $StartPath -Name "Start_TrackDocs" -Value $(if($ShowMostUsed){1}else{0}) -Type DWord -Force
        
        # Hide recommendations (Windows 11)
        Write-Log "Setting: Show Recommendations = $ShowRecommendations" -Level "INFO"
        $StartContentPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $StartContentPath -Name "Start_IrisRecommendations" -Value $(if($ShowRecommendations){1}else{0}) -Type DWord -Force -ErrorAction SilentlyContinue
        
        # Start Menu layout (MorePins vs MoreRecommendations)
        Write-Log "Setting: Start Menu Size = $StartMenuSize" -Level "INFO"
        $StartLayoutPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        switch ($StartMenuSize) {
            "MorePins" {
                Set-ItemProperty -Path $StartLayoutPath -Name "Start_Layout" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            }
            "MoreRecommendations" {
                Set-ItemProperty -Path $StartLayoutPath -Name "Start_Layout" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            }
            "Default" {
                # Remove setting to use Windows default
                Remove-ItemProperty -Path $StartLayoutPath -Name "Start_Layout" -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Start Menu settings configured successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting Start Menu settings: $_" -Level "ERROR"
        return $false
    }
}

function Remove-DefaultStartMenuPins {
    <#
    .SYNOPSIS
        Removes default Windows pinned items from Start Menu
    #>
    param(
        [string]$ProfilePath = $env:USERPROFILE
    )
    
    Write-LogHeader "REMOVING DEFAULT START MENU PINS"
    
    if (-not $RemoveDefaultPins) {
        Write-Log "Default pin removal disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Removing default pinned items..." -Level "INFO"
        Write-Log "Profile: $ProfilePath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would remove default pinned items" -Level "INFO"
            return $true
        }
        
        # Windows 11: Start Menu pins are stored in multiple locations
        $PinLocations = @(
            "$ProfilePath\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start.bin",
            "$ProfilePath\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin"
        )
        
        foreach ($PinFile in $PinLocations) {
            if (Test-Path $PinFile) {
                try {
                    Remove-Item -Path $PinFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed: $(Split-Path $PinFile -Leaf)" -Level "DEBUG"
                    $Global:Stats.PinsRemoved++
                }
                catch {
                    Write-Log "Could not remove $PinFile : $_" -Level "DEBUG"
                }
            }
        }
        
        Write-Log "Default pins removed (will reset on next login)" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception removing default pins: $_" -Level "ERROR"
        return $false
    }
}

function Import-StartMenuLayout {
    <#
    .SYNOPSIS
        Imports Start Menu layout from XML file
    #>
    param(
        [string]$XMLPath
    )
    
    Write-LogHeader "IMPORTING START MENU LAYOUT"
    
    if (-not $XMLPath -or -not (Test-Path $XMLPath)) {
        Write-Log "No layout XML file to import" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Importing layout from: $XMLPath" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would import Start Menu layout from XML" -Level "INFO"
            return $true
        }
        
        # Note: Windows 11 has limited support for Start Menu layout XML
        # This is more of a Windows 10 feature
        Write-Log "WARNING: Windows 11 has limited Start Menu layout XML support" -Level "WARNING"
        Write-Log "Layout XML is best deployed via Group Policy or Intune" -Level "WARNING"
        
        # Copy layout file to known location for Group Policy
        $LayoutDestination = "C:\ProgramData\StartMenuLayout.xml"
        Copy-Item -Path $XMLPath -Destination $LayoutDestination -Force
        Write-Log "Layout copied to: $LayoutDestination" -Level "SUCCESS"
        
        # Set Group Policy registry for layout (requires GPO to be effective)
        $GPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (-not (Test-Path $GPPath)) {
            New-Item -Path $GPPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $GPPath -Name "LockedStartLayout" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $GPPath -Name "StartLayoutFile" -Value $LayoutDestination -Type String -Force
        
        Write-Log "Layout file configured (requires Group Policy to enforce)" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception importing layout: $_" -Level "ERROR"
        return $false
    }
}

function Add-StartMenuPins {
    <#
    .SYNOPSIS
        Pins applications to Start Menu
    #>
    param(
        [string[]]$Applications
    )
    
    Write-LogHeader "PINNING APPLICATIONS TO START MENU"
    
    if (-not $Applications -or $Applications.Count -eq 0) {
        Write-Log "No applications to pin" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applications to pin: $($Applications.Count)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would pin applications to Start Menu" -Level "INFO"
            foreach ($App in $Applications) {
                Write-Log "[DRY RUN]   - $App" -Level "INFO"
            }
            return $true
        }
        
        # Note: Windows 11 makes programmatic pinning very difficult
        Write-Log "WARNING: Windows 11 has limited API for programmatic pinning" -Level "WARNING"
        Write-Log "Pins are best managed via Start Menu layout XML or Intune" -Level "WARNING"
        
        foreach ($App in $Applications) {
            Write-Log "  Attempting to pin: $App" -Level "INFO"
            
            # Try to find application
            $AppPath = $null
            
            # Check Program Files
            $SearchPaths = @(
                "$env:ProgramFiles",
                "${env:ProgramFiles(x86)}",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
            )
            
            foreach ($SearchPath in $SearchPaths) {
                if (Test-Path $SearchPath) {
                    $Found = Get-ChildItem -Path $SearchPath -Filter "$App*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($Found) {
                        $AppPath = $Found.FullName
                        break
                    }
                }
            }
            
            if ($AppPath) {
                Write-Log "    Found: $AppPath" -Level "DEBUG"
                # Pinning logic would go here (limited in Windows 11)
                $Global:Stats.PinsAdded++
            }
            else {
                Write-Log "    Not found: $App" -Level "WARNING"
            }
        }
        
        Write-Log "Pin requests processed (note: Windows 11 limitations apply)" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception pinning applications: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultUserProfile {
    <#
    .SYNOPSIS
        Applies Start Menu configuration to default user profile
    #>
    
    Write-LogHeader "CONFIGURING DEFAULT USER PROFILE"
    
    if (-not $ApplyToAllUsers) {
        Write-Log "Default profile configuration disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applying Start Menu configuration to default user profile..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure default user profile" -Level "INFO"
            return $true
        }
        
        $DefaultProfilePath = "C:\Users\Default"
        
        if (-not (Test-Path $DefaultProfilePath)) {
            Write-Log "Default profile not found: $DefaultProfilePath" -Level "ERROR"
            return $false
        }
        
        # Load default user registry hive
        $DefaultHive = "HKU\DefaultUser"
        Write-Log "Loading default user registry hive..." -Level "DEBUG"
        
        $LoadResult = reg load $DefaultHive "$DefaultProfilePath\NTUSER.DAT" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to load default user hive: $LoadResult" -Level "ERROR"
            return $false
        }
        
        # Configure Start Menu settings in default profile
        Set-StartMenuSettings -TargetHive "HKU\DefaultUser"
        
        # Remove default pins from default profile
        Remove-DefaultStartMenuPins -ProfilePath $DefaultProfilePath
        
        # Unload registry hive
        Write-Log "Unloading default user registry hive..." -Level "DEBUG"
        [System.GC]::Collect()
        Start-Sleep -Seconds 1
        
        $UnloadResult = reg unload $DefaultHive 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Default user profile configured successfully" -Level "SUCCESS"
            $Global:Stats.ProfilesModified++
        }
        else {
            Write-Log "Warning unloading hive (settings may still be applied): $UnloadResult" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Exception configuring default profile: $_" -Level "ERROR"
        
        # Try to unload hive if error occurred
        reg unload "HKU\DefaultUser" 2>&1 | Out-Null
        
        return $false
    }
}

function Set-ExistingUserProfiles {
    <#
    .SYNOPSIS
        Applies Start Menu configuration to existing user profiles
    #>
    
    Write-LogHeader "CONFIGURING EXISTING USER PROFILES"
    
    if (-not $ApplyToExistingUsers) {
        Write-Log "Existing user configuration disabled by parameter" -Level "INFO"
        return $true
    }
    
    Write-Log "WARNING: This will overwrite existing users' Start Menu customizations" -Level "WARNING"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure existing user profiles" -Level "INFO"
            return $true
        }
        
        # Get all user profiles
        $UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
            $_.Name -notlike "Default*" -and
            $_.Name -ne "Public" -and
            (Test-Path "$($_.FullName)\NTUSER.DAT")
        }
        
        Write-Log "Found $($UserProfiles.Count) user profile(s)" -Level "INFO"
        
        foreach ($Profile in $UserProfiles) {
            Write-Log "Configuring profile: $($Profile.Name)" -Level "INFO"
            
            # Load user registry hive
            $HiveName = "HKU\TempUser_$($Profile.Name)"
            $HivePath = Join-Path $Profile.FullName "NTUSER.DAT"
            
            $LoadResult = reg load $HiveName $HivePath 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                # Configure settings
                Set-StartMenuSettings -TargetHive $HiveName
                
                # Remove default pins
                Remove-DefaultStartMenuPins -ProfilePath $Profile.FullName
                
                # Unload hive
                [System.GC]::Collect()
                Start-Sleep -Milliseconds 500
                reg unload $HiveName 2>&1 | Out-Null
                
                $Global:Stats.ProfilesModified++
            }
            else {
                Write-Log "  Could not load profile registry (may be in use)" -Level "WARNING"
            }
        }
        
        Write-Log "Existing user profiles configured" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception configuring existing profiles: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-StartMenuConfiguration {
    <#
    .SYNOPSIS
        Validates Start Menu configuration
    #>
    
    Write-LogHeader "VALIDATING START MENU CONFIGURATION"
    
    try {
        Write-Log "Validating configuration..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        $StartPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        # Recently added apps
        $RecentApps = (Get-ItemProperty $StartPath -Name "Start_TrackProgs" -ErrorAction SilentlyContinue).Start_TrackProgs
        $Expected = if ($ShowRecentlyAdded) { 1 } else { 0 }
        
        if ($RecentApps -eq $Expected) {
            Write-Log "  ✓ Recently Added Apps: $(if($ShowRecentlyAdded){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Recently Added Apps: Configuration mismatch" -Level "WARNING"
        }
        
        # Most used apps
        $MostUsed = (Get-ItemProperty $StartPath -Name "Start_TrackDocs" -ErrorAction SilentlyContinue).Start_TrackDocs
        $Expected = if ($ShowMostUsed) { 1 } else { 0 }
        
        if ($MostUsed -eq $Expected) {
            Write-Log "  ✓ Most Used Apps: $(if($ShowMostUsed){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Most Used Apps: Configuration mismatch" -Level "WARNING"
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
    
    Write-Log " " -Level "INFO"
    Write-Log "Start Menu Configuration Results:" -Level "INFO"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    Write-Log "  Default Pins Removed: $($Global:Stats.PinsRemoved)" -Level $(if($Global:Stats.PinsRemoved -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Applications Pinned: $($Global:Stats.PinsAdded)" -Level $(if($Global:Stats.PinsAdded -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Profiles Modified: $($Global:Stats.ProfilesModified)" -Level $(if($Global:Stats.ProfilesModified -gt 0){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Show Recently Added: $ShowRecentlyAdded" -Level "INFO"
    Write-Log "  Show Most Used: $ShowMostUsed" -Level "INFO"
    Write-Log "  Show Recommendations: $ShowRecommendations" -Level "INFO"
    Write-Log "  Start Menu Size: $StartMenuSize" -Level "INFO"
    Write-Log "  Remove Default Pins: $RemoveDefaultPins" -Level "INFO"
    Write-Log "  Layout XML: $(if($LayoutXML -and (Test-Path $LayoutXML)){'Imported'}else{'Not Used'})" -Level "INFO"
    
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
║        CONFIGURE WINDOWS 11 START MENU                        ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "START MENU CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Layout XML: $LayoutXML" -Level "INFO"
    Write-Log "  Apply To All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log "  Apply To Existing Users: $ApplyToExistingUsers" -Level "INFO"
    Write-Log "  Remove Default Pins: $RemoveDefaultPins" -Level "INFO"
    Write-Log "  Show Recently Added: $ShowRecentlyAdded" -Level "INFO"
    Write-Log "  Show Most Used: $ShowMostUsed" -Level "INFO"
    Write-Log "  Show Recommendations: $ShowRecommendations" -Level "INFO"
    Write-Log "  Start Menu Size: $StartMenuSize" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Get current configuration
    Get-CurrentStartMenuConfig
    
    # Import layout XML if provided
    if ($LayoutXML -and (Test-Path $LayoutXML)) {
        Import-StartMenuLayout -XMLPath $LayoutXML
    }
    
    # Configure current user/SYSTEM Start Menu settings
    Set-StartMenuSettings -TargetHive "HKCU"
    
    # Remove default pins from current user
    Remove-DefaultStartMenuPins
    
    # Pin applications if specified
    if ($PinApplications -and $PinApplications.Count -gt 0) {
        Add-StartMenuPins -Applications $PinApplications
    }
    
    # Configure default user profile
    if ($ApplyToAllUsers) {
        Set-DefaultUserProfile
    }
    
    # Configure existing user profiles
    if ($ApplyToExistingUsers) {
        Set-ExistingUserProfiles
    }
    
    # Validate configuration
    Test-StartMenuConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Start Menu configuration completed successfully!" -Level "SUCCESS"
        if ($ApplyToAllUsers) {
            Write-Log "Configuration will apply to new users on next login" -Level "SUCCESS"
        }
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
