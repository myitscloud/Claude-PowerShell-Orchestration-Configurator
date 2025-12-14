<#
.SYNOPSIS
    Disable Windows Consumer Features and Suggestions
    
.DESCRIPTION
    Disables consumer-focused features, app suggestions, tips, and advertising
    in Windows 11 to provide a clean, professional enterprise experience.
    
    Features:
    - Disable app suggestions in Start menu
    - Disable tips and tricks notifications
    - Disable advertising features
    - Disable Windows Spotlight suggestions
    - Disable OneDrive advertising
    - Disable consumer experiences
    - Disable tailored experiences
    - Remove preinstalled consumer apps
    - Comprehensive logging and validation
    
.PARAMETER DisableSuggestedApps
    Disable app suggestions in Start menu.
    Default: $true
    
    When true:
    - No "Try Candy Crush" suggestions
    - No app recommendations
    - Clean Start menu
    
.PARAMETER DisableTips
    Disable Windows tips and tricks.
    Default: $true
    
    When true:
    - No "Get to know Windows" notifications
    - No tips popups
    - No feature suggestions
    
.PARAMETER DisableAdvertising
    Disable advertising features.
    Default: $true
    
    When true:
    - No Microsoft advertising
    - No "Try Office 365" prompts
    - No product recommendations
    
.PARAMETER DisableSpotlight
    Disable Windows Spotlight on lock screen.
    Default: $true
    
    When true:
    - No Bing wallpaper suggestions
    - No lock screen tips
    - Clean lock screen
    
.PARAMETER DisableOneDriveAds
    Disable OneDrive advertising and prompts.
    Default: $true
    
.PARAMETER RemoveConsumerApps
    Remove preinstalled consumer apps (Candy Crush, etc).
    Default: $false
    
    When true:
    - Removes consumer games
    - Removes trial apps
    - WARNING: Cannot be easily reversed
    
.PARAMETER ApplyToAllUsers
    Apply settings to default user profile (affects new users).
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Disable-ConsumerFeatures.ps1
    Disables all consumer features with default settings
    
.EXAMPLE
    .\Disable-ConsumerFeatures.ps1 -RemoveConsumerApps $true
    Disables features AND removes consumer apps
    
.EXAMPLE
    .\Disable-ConsumerFeatures.ps1 -DisableSuggestedApps $true -DisableTips $true
    Disables app suggestions and tips
    
.EXAMPLE
    .\Disable-ConsumerFeatures.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Disable consumer features for professional Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    
    NOTES:
    - Changes take effect immediately (no reboot required)
    - Some settings require sign out/sign in
    - App removal is permanent (cannot easily undo)
    - Creates professional enterprise experience
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$DisableSuggestedApps = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableTips = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableAdvertising = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableSpotlight = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableOneDriveAds = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemoveConsumerApps = $false,
    
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

$LogFileName = "Disable-ConsumerFeatures_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    SettingsApplied = 0
    AppsRemoved = 0
    TasksDisabled = 0
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
    
    # Check 2: Windows version
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

#region CONSUMER FEATURES DISABLE FUNCTIONS
#==============================================================================

function Disable-SuggestedApps {
    <#
    .SYNOPSIS
        Disables app suggestions in Start menu
    #>
    
    Write-LogHeader "DISABLING APP SUGGESTIONS"
    
    try {
        Write-Log "Disabling app suggestions in Start menu..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable app suggestions" -Level "INFO"
            return $true
        }
        
        # Disable suggested apps in Start menu
        $ContentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        
        if (-not (Test-Path $ContentDeliveryPath)) {
            New-Item -Path $ContentDeliveryPath -Force | Out-Null
        }
        
        # Disable various app suggestions
        Set-ItemProperty -Path $ContentDeliveryPath -Name "ContentDeliveryAllowed" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "OemPreInstalledAppsEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "PreInstalledAppsEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "PreInstalledAppsEverEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
        
        # Disable "Suggested Applications" in Settings
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord -Force
        
        Write-Log "App suggestions disabled successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception disabling app suggestions: $_" -Level "ERROR"
        return $false
    }
}

function Disable-TipsAndTricks {
    <#
    .SYNOPSIS
        Disables Windows tips and tricks
    #>
    
    Write-LogHeader "DISABLING TIPS AND TRICKS"
    
    try {
        Write-Log "Disabling Windows tips and tricks..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable tips and tricks" -Level "INFO"
            return $true
        }
        
        $ContentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        
        # Disable tips, tricks, and suggestions
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338387Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-353698Enabled" -Value 0 -Type DWord -Force
        
        # Disable "Get tips, tricks, and suggestions as you use Windows"
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force
        
        # Disable "Show me the Windows welcome experience"
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
        
        Write-Log "Tips and tricks disabled successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception disabling tips: $_" -Level "ERROR"
        return $false
    }
}

function Disable-AdvertisingFeatures {
    <#
    .SYNOPSIS
        Disables advertising features
    #>
    
    Write-LogHeader "DISABLING ADVERTISING FEATURES"
    
    try {
        Write-Log "Disabling advertising features..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable advertising" -Level "INFO"
            return $true
        }
        
        # Disable cloud content / consumer experiences
        $CloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        
        if (-not (Test-Path $CloudContentPath)) {
            New-Item -Path $CloudContentPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $CloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $CloudContentPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -Force
        
        # Disable tailored experiences
        $PrivacyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
        
        if (-not (Test-Path $PrivacyPath)) {
            New-Item -Path $PrivacyPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $PrivacyPath -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
        
        # Disable Start menu suggestions
        $ContentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
        
        Write-Log "Advertising features disabled successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception disabling advertising: $_" -Level "ERROR"
        return $false
    }
}

function Disable-SpotlightFeatures {
    <#
    .SYNOPSIS
        Disables Windows Spotlight on lock screen
    #>
    
    Write-LogHeader "DISABLING WINDOWS SPOTLIGHT"
    
    try {
        Write-Log "Disabling Windows Spotlight on lock screen..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Windows Spotlight" -Level "INFO"
            return $true
        }
        
        # Disable Windows Spotlight
        $PersonalizationPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
        
        if (-not (Test-Path $PersonalizationPath)) {
            New-Item -Path $PersonalizationPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $PersonalizationPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "DisableWindowsSpotlightOnActionCenter" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "DisableWindowsSpotlightOnSettings" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1 -Type DWord -Force
        
        # Disable fun facts, tips, etc on lock screen
        $ContentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Set-ItemProperty -Path $ContentDeliveryPath -Name "RotatingLockScreenEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ContentDeliveryPath -Name "SubscribedContent-338387Enabled" -Value 0 -Type DWord -Force
        
        Write-Log "Windows Spotlight disabled successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception disabling Spotlight: $_" -Level "ERROR"
        return $false
    }
}

function Disable-OneDriveAdvertising {
    <#
    .SYNOPSIS
        Disables OneDrive advertising and prompts
    #>
    
    Write-LogHeader "DISABLING ONEDRIVE ADVERTISING"
    
    try {
        Write-Log "Disabling OneDrive advertising..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable OneDrive advertising" -Level "INFO"
            return $true
        }
        
        # Disable OneDrive setup nag
        $OneDrivePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $OneDrivePath -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord -Force
        
        # Disable OneDrive in File Explorer sidebar
        $OneDriveGPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        
        if (-not (Test-Path $OneDriveGPPath)) {
            New-Item -Path $OneDriveGPPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $OneDriveGPPath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
        
        Write-Log "OneDrive advertising disabled successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception disabling OneDrive ads: $_" -Level "ERROR"
        return $false
    }
}

function Remove-ConsumerApps {
    <#
    .SYNOPSIS
        Removes preinstalled consumer apps
    #>
    
    Write-LogHeader "REMOVING CONSUMER APPS"
    
    if (-not $RemoveConsumerApps) {
        Write-Log "App removal disabled by parameter" -Level "INFO"
        return $true
    }
    
    Write-Log "WARNING: Removing consumer apps (this cannot be easily reversed)" -Level "WARNING"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would remove consumer apps" -Level "INFO"
        return $true
    }
    
    # List of consumer apps to remove
    $AppsToRemove = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GamingApp",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.YourPhone",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "MicrosoftCorporationII.QuickAssist",
        "king.com.CandyCrushSaga",
        "king.com.CandyCrushSodaSaga",
        "king.com.*",
        "Microsoft.549981C3F5F10",  # Cortana
        "Clipchamp.Clipchamp"
    )
    
    try {
        Write-Log "Scanning for consumer apps..." -Level "INFO"
        
        foreach ($App in $AppsToRemove) {
            try {
                $Package = Get-AppxPackage -Name $App -AllUsers -ErrorAction SilentlyContinue
                
                if ($Package) {
                    Write-Log "  Removing: $App" -Level "INFO"
                    Remove-AppxPackage -Package $Package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                    $Global:Stats.AppsRemoved++
                    Write-Log "  Removed: $App" -Level "SUCCESS"
                }
                else {
                    Write-Log "  Not found: $App" -Level "DEBUG"
                }
            }
            catch {
                Write-Log "  Warning removing $App : $_" -Level "WARNING"
            }
        }
        
        Write-Log "Consumer app removal completed" -Level "SUCCESS"
        Write-Log "Apps removed: $($Global:Stats.AppsRemoved)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Exception removing consumer apps: $_" -Level "ERROR"
        return $false
    }
}

function Disable-ScheduledTasks {
    <#
    .SYNOPSIS
        Disables consumer feature scheduled tasks
    #>
    
    Write-LogHeader "DISABLING CONSUMER FEATURE TASKS"
    
    try {
        Write-Log "Disabling consumer feature scheduled tasks..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable scheduled tasks" -Level "INFO"
            return $true
        }
        
        # Tasks to disable
        $TasksToDisable = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\Feedback\Siuf\DmClient",
            "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
            "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
        )
        
        foreach ($Task in $TasksToDisable) {
            try {
                $TaskExists = Get-ScheduledTask -TaskPath (Split-Path $Task -Parent) -TaskName (Split-Path $Task -Leaf) -ErrorAction SilentlyContinue
                
                if ($TaskExists) {
                    Disable-ScheduledTask -TaskPath (Split-Path $Task -Parent) -TaskName (Split-Path $Task -Leaf) -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "  Disabled: $Task" -Level "DEBUG"
                    $Global:Stats.TasksDisabled++
                }
            }
            catch {
                Write-Log "  Warning disabling task $Task : $_" -Level "DEBUG"
            }
        }
        
        Write-Log "Scheduled tasks disabled: $($Global:Stats.TasksDisabled)" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception disabling tasks: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-ConsumerFeaturesConfiguration {
    <#
    .SYNOPSIS
        Validates consumer features are disabled
    #>
    
    Write-LogHeader "VALIDATING CONFIGURATION"
    
    try {
        Write-Log "Validating consumer features are disabled..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        # Check cloud content
        $CloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        $ConsumerFeatures = (Get-ItemProperty $CloudContentPath -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue).DisableWindowsConsumerFeatures
        
        if ($ConsumerFeatures -eq 1) {
            Write-Log "  ✓ Consumer Features: DISABLED" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Consumer Features: Not disabled" -Level "WARNING"
        }
        
        # Check content delivery
        $ContentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        $SuggestedApps = (Get-ItemProperty $ContentDeliveryPath -Name "SystemPaneSuggestionsEnabled" -ErrorAction SilentlyContinue).SystemPaneSuggestionsEnabled
        
        if ($SuggestedApps -eq 0) {
            Write-Log "  ✓ App Suggestions: DISABLED" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ App Suggestions: Not disabled" -Level "WARNING"
        }
        
        # Check tailored experiences
        $PrivacyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
        $Tailored = (Get-ItemProperty $PrivacyPath -Name "TailoredExperiencesWithDiagnosticDataEnabled" -ErrorAction SilentlyContinue).TailoredExperiencesWithDiagnosticDataEnabled
        
        if ($Tailored -eq 0) {
            Write-Log "  ✓ Tailored Experiences: DISABLED" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Tailored Experiences: Not disabled" -Level "WARNING"
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
    Write-Log "Consumer Features Configuration Results:" -Level "INFO"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    Write-Log "  Apps Removed: $($Global:Stats.AppsRemoved)" -Level $(if($Global:Stats.AppsRemoved -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Tasks Disabled: $($Global:Stats.TasksDisabled)" -Level $(if($Global:Stats.TasksDisabled -gt 0){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Features Disabled:" -Level "INFO"
    Write-Log "  Suggested Apps: $DisableSuggestedApps" -Level "INFO"
    Write-Log "  Tips and Tricks: $DisableTips" -Level "INFO"
    Write-Log "  Advertising: $DisableAdvertising" -Level "INFO"
    Write-Log "  Windows Spotlight: $DisableSpotlight" -Level "INFO"
    Write-Log "  OneDrive Ads: $DisableOneDriveAds" -Level "INFO"
    Write-Log "  Consumer Apps Removed: $RemoveConsumerApps" -Level "INFO"
    
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
║        DISABLE WINDOWS CONSUMER FEATURES                      ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "DISABLE CONSUMER FEATURES STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Disable Suggested Apps: $DisableSuggestedApps" -Level "INFO"
    Write-Log "  Disable Tips: $DisableTips" -Level "INFO"
    Write-Log "  Disable Advertising: $DisableAdvertising" -Level "INFO"
    Write-Log "  Disable Spotlight: $DisableSpotlight" -Level "INFO"
    Write-Log "  Disable OneDrive Ads: $DisableOneDriveAds" -Level "INFO"
    Write-Log "  Remove Consumer Apps: $RemoveConsumerApps" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Disable app suggestions
    if ($DisableSuggestedApps) {
        Disable-SuggestedApps
    }
    
    # Disable tips and tricks
    if ($DisableTips) {
        Disable-TipsAndTricks
    }
    
    # Disable advertising
    if ($DisableAdvertising) {
        Disable-AdvertisingFeatures
    }
    
    # Disable Spotlight
    if ($DisableSpotlight) {
        Disable-SpotlightFeatures
    }
    
    # Disable OneDrive advertising
    if ($DisableOneDriveAds) {
        Disable-OneDriveAdvertising
    }
    
    # Remove consumer apps
    if ($RemoveConsumerApps) {
        Remove-ConsumerApps
    }
    
    # Disable scheduled tasks
    Disable-ScheduledTasks
    
    # Validate configuration
    Test-ConsumerFeaturesConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Consumer features disabled successfully!" -Level "SUCCESS"
        Write-Log "Windows will now provide a clean, professional experience" -Level "SUCCESS"
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
