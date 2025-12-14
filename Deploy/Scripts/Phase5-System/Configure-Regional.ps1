<#
.SYNOPSIS
    Configure Regional and Language Settings
    
.DESCRIPTION
    Configures regional settings, language preferences, and keyboard layouts for
    Windows 11 workstations. Ensures consistent locale settings across enterprise.
    
    Features:
    - Set system locale (Windows system language)
    - Set user locale (regional format settings)
    - Configure keyboard layouts (input methods)
    - Set UI language preferences
    - Configure date/time formats
    - Set currency and number formats
    - Configure default language for new users
    - Support for multilingual environments
    - Comprehensive logging and validation
    
.PARAMETER SystemLocale
    System locale (Windows system language).
    Default: "en-US"
    
    Common values:
    - en-US (English - United States)
    - en-GB (English - United Kingdom)
    - es-ES (Spanish - Spain)
    - fr-FR (French - France)
    - de-DE (German - Germany)
    
.PARAMETER UserLocale
    User locale (regional format settings: date, time, currency, numbers).
    Default: "en-US"
    
    This controls:
    - Date format (MM/DD/YYYY vs DD/MM/YYYY)
    - Time format (12-hour vs 24-hour)
    - Currency symbol ($, €, £, ¥)
    - Number format (decimal separator, thousands separator)
    - First day of week (Sunday vs Monday)
    
.PARAMETER KeyboardLayout
    Keyboard layout(s) to configure.
    Format: "LanguageID:KeyboardLayoutID"
    Default: "0409:00000409" (US English keyboard)
    
    Common layouts:
    - 0409:00000409 (US English)
    - 0809:00000809 (UK English)
    - 040c:0000040c (French)
    - 0407:00000407 (German)
    - 0c0a:0000080a (Spanish)
    
.PARAMETER UILanguage
    Windows display language (UI language).
    Default: "en-US"
    
    Note: Language pack must be installed for non-English languages.
    
.PARAMETER GeoLocation
    Geographic location ID.
    Default: 244 (United States)
    
    Common IDs:
    - 244 = United States
    - 242 = United Kingdom
    - 217 = Spain
    - 84 = France
    - 94 = Germany
    
.PARAMETER TimeFormat
    Time format preference.
    Options: "12-Hour", "24-Hour", "Default"
    Default: "Default" (uses locale default)
    
.PARAMETER DateFormat
    Date format preference.
    Options: "MDY" (MM/DD/YYYY), "DMY" (DD/MM/YYYY), "YMD" (YYYY/MM/DD), "Default"
    Default: "Default" (uses locale default)
    
.PARAMETER FirstDayOfWeek
    First day of week preference.
    Options: "Sunday", "Monday", "Default"
    Default: "Default" (uses locale default)
    
.PARAMETER ApplyToNewUsers
    Apply settings to default user profile (affects all new users).
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-Regional.ps1
    Configures regional settings with default US English settings
    
.EXAMPLE
    .\Configure-Regional.ps1 -SystemLocale "en-GB" -UserLocale "en-GB"
    Configures for United Kingdom (date format: DD/MM/YYYY, currency: £)
    
.EXAMPLE
    .\Configure-Regional.ps1 -TimeFormat "24-Hour" -FirstDayOfWeek "Monday"
    Uses 24-hour time format and Monday as first day of week
    
.EXAMPLE
    .\Configure-Regional.ps1 -KeyboardLayout "0409:00000409" -UILanguage "en-US"
    Configures US English keyboard and UI language
    
.EXAMPLE
    .\Configure-Regional.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Regional settings configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Invalid locale
    4   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - PowerShell 5.1 or later
    
    NOTES:
    - Settings apply to current user and system (if SYSTEM account)
    - ApplyToNewUsers parameter affects default user profile
    - UI language requires language pack installation
    - Some changes may require sign out/sign in
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SystemLocale = "en-US",
    
    [Parameter(Mandatory=$false)]
    [string]$UserLocale = "en-US",
    
    [Parameter(Mandatory=$false)]
    [string]$KeyboardLayout = "0409:00000409",
    
    [Parameter(Mandatory=$false)]
    [string]$UILanguage = "en-US",
    
    [Parameter(Mandatory=$false)]
    [int]$GeoLocation = 244,  # United States
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("12-Hour", "24-Hour", "Default")]
    [string]$TimeFormat = "Default",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("MDY", "DMY", "YMD", "Default")]
    [string]$DateFormat = "Default",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Sunday", "Monday", "Default")]
    [string]$FirstDayOfWeek = "Default",
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToNewUsers = $true,
    
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

$LogFileName = "Configure-Regional_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    SystemLocaleSet = ""
    UserLocaleSet = ""
    KeyboardLayoutsConfigured = 0
    SettingsApplied = 0
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
    
    # Check 2: Validate locale parameters
    Write-Log "Validating locale parameters..." -Level "INFO"
    
    $ValidSystemLocale = Test-LocaleValid -Locale $SystemLocale
    if (-not $ValidSystemLocale) {
        Write-Log "ERROR: Invalid system locale: $SystemLocale" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "System locale valid: $SystemLocale" -Level "SUCCESS"
    }
    
    $ValidUserLocale = Test-LocaleValid -Locale $UserLocale
    if (-not $ValidUserLocale) {
        Write-Log "ERROR: Invalid user locale: $UserLocale" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "User locale valid: $UserLocale" -Level "SUCCESS"
    }
    
    # Check 3: Validate keyboard layout format
    Write-Log "Validating keyboard layout..." -Level "INFO"
    if ($KeyboardLayout -match "^[0-9a-fA-F]{4}:[0-9a-fA-F]{8}$") {
        Write-Log "Keyboard layout format valid: $KeyboardLayout" -Level "SUCCESS"
    }
    else {
        Write-Log "WARNING: Keyboard layout format may be incorrect: $KeyboardLayout" -Level "WARNING"
    }
    
    return $AllChecksPassed
}

function Test-LocaleValid {
    param([string]$Locale)
    
    try {
        $Culture = [System.Globalization.CultureInfo]::GetCultureInfo($Locale)
        return $true
    }
    catch {
        return $false
    }
}

#endregion

#region REGIONAL SETTINGS FUNCTIONS
#==============================================================================

function Get-CurrentRegionalSettings {
    <#
    .SYNOPSIS
        Gets current regional settings
    #>
    
    Write-LogHeader "CURRENT REGIONAL SETTINGS"
    
    try {
        # Get system locale
        $SystemLocaleReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "InstallLanguage" -ErrorAction SilentlyContinue
        
        # Get user locale
        $CurrentCulture = Get-Culture
        
        # Get keyboard layouts
        $KeyboardLayouts = Get-WinUserLanguageList
        
        Write-Log "Current regional settings:" -Level "INFO"
        Write-Log "  System Locale: $($SystemLocaleReg.InstallLanguage)" -Level "INFO"
        Write-Log "  User Locale: $($CurrentCulture.Name)" -Level "INFO"
        Write-Log "  Display Name: $($CurrentCulture.DisplayName)" -Level "INFO"
        Write-Log "  Date Format: $($CurrentCulture.DateTimeFormat.ShortDatePattern)" -Level "INFO"
        Write-Log "  Time Format: $($CurrentCulture.DateTimeFormat.ShortTimePattern)" -Level "INFO"
        Write-Log "  Currency: $($CurrentCulture.NumberFormat.CurrencySymbol)" -Level "INFO"
        Write-Log "  First Day of Week: $($CurrentCulture.DateTimeFormat.FirstDayOfWeek)" -Level "INFO"
        
        Write-Log " " -Level "INFO"
        Write-Log "Current keyboard layouts:" -Level "INFO"
        foreach ($Layout in $KeyboardLayouts) {
            Write-Log "  $($Layout.LanguageTag) - $($Layout.InputMethodTips[0])" -Level "INFO"
        }
        
        return @{
            SystemLocale = $SystemLocaleReg.InstallLanguage
            UserLocale = $CurrentCulture.Name
            Culture = $CurrentCulture
            KeyboardLayouts = $KeyboardLayouts
        }
    }
    catch {
        Write-Log "Exception getting current settings: $_" -Level "ERROR"
        return $null
    }
}

function Set-SystemLocaleConfiguration {
    <#
    .SYNOPSIS
        Sets system locale (Windows system language)
    #>
    
    Write-LogHeader "CONFIGURING SYSTEM LOCALE"
    
    try {
        Write-Log "Setting system locale to: $SystemLocale" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set system locale to: $SystemLocale" -Level "INFO"
            return $true
        }
        
        # Set system locale using PowerShell
        Set-WinSystemLocale -SystemLocale $SystemLocale -ErrorAction Stop
        
        Write-Log "System locale set successfully: $SystemLocale" -Level "SUCCESS"
        $Global:Stats.SystemLocaleSet = $SystemLocale
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting system locale: $_" -Level "ERROR"
        return $false
    }
}

function Set-UserLocaleConfiguration {
    <#
    .SYNOPSIS
        Sets user locale (regional format settings)
    #>
    
    Write-LogHeader "CONFIGURING USER LOCALE"
    
    try {
        Write-Log "Setting user locale to: $UserLocale" -Level "INFO"
        
        # Get culture info
        $Culture = [System.Globalization.CultureInfo]::GetCultureInfo($UserLocale)
        
        Write-Log "User locale details:" -Level "INFO"
        Write-Log "  Display Name: $($Culture.DisplayName)" -Level "INFO"
        Write-Log "  English Name: $($Culture.EnglishName)" -Level "INFO"
        Write-Log "  Date Format: $($Culture.DateTimeFormat.ShortDatePattern)" -Level "INFO"
        Write-Log "  Time Format: $($Culture.DateTimeFormat.ShortTimePattern)" -Level "INFO"
        Write-Log "  Currency: $($Culture.NumberFormat.CurrencySymbol)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set user locale to: $UserLocale" -Level "INFO"
            return $true
        }
        
        # Set culture for current user
        Set-Culture -CultureInfo $UserLocale -ErrorAction Stop
        
        Write-Log "User locale set successfully: $UserLocale" -Level "SUCCESS"
        $Global:Stats.UserLocaleSet = $UserLocale
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting user locale: $_" -Level "ERROR"
        return $false
    }
}

function Set-KeyboardLayoutConfiguration {
    <#
    .SYNOPSIS
        Configures keyboard layouts
    #>
    
    Write-LogHeader "CONFIGURING KEYBOARD LAYOUT"
    
    try {
        Write-Log "Configuring keyboard layout: $KeyboardLayout" -Level "INFO"
        
        # Parse keyboard layout string
        $Parts = $KeyboardLayout -split ":"
        if ($Parts.Count -ne 2) {
            Write-Log "ERROR: Invalid keyboard layout format: $KeyboardLayout" -Level "ERROR"
            return $false
        }
        
        $LanguageTag = Get-LanguageTagFromLCID -LCID $Parts[0]
        Write-Log "Language tag: $LanguageTag" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure keyboard layout: $KeyboardLayout" -Level "INFO"
            return $true
        }
        
        # Get current language list
        $LanguageList = Get-WinUserLanguageList
        
        # Check if language already exists
        $ExistingLanguage = $LanguageList | Where-Object { $_.LanguageTag -eq $LanguageTag }
        
        if ($ExistingLanguage) {
            Write-Log "Language already configured: $LanguageTag" -Level "SUCCESS"
        }
        else {
            # Add new language
            Write-Log "Adding language: $LanguageTag" -Level "INFO"
            $NewLanguage = New-WinUserLanguageList -Language $LanguageTag
            
            # Set as primary language
            Set-WinUserLanguageList -LanguageList $NewLanguage -Force -ErrorAction Stop
            
            Write-Log "Language added: $LanguageTag" -Level "SUCCESS"
        }
        
        $Global:Stats.KeyboardLayoutsConfigured++
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception configuring keyboard layout: $_" -Level "ERROR"
        return $false
    }
}

function Get-LanguageTagFromLCID {
    param([string]$LCID)
    
    # Common LCID to language tag mappings
    $Mappings = @{
        "0409" = "en-US"
        "0809" = "en-GB"
        "0c09" = "en-AU"
        "040c" = "fr-FR"
        "0407" = "de-DE"
        "0c0a" = "es-ES"
        "0410" = "it-IT"
        "0411" = "ja-JP"
        "0412" = "ko-KR"
        "0804" = "zh-CN"
        "0404" = "zh-TW"
    }
    
    if ($Mappings.ContainsKey($LCID)) {
        return $Mappings[$LCID]
    }
    
    # If not in mapping, try to use the LCID directly as UserLocale
    return $UserLocale
}

function Set-GeographicLocation {
    <#
    .SYNOPSIS
        Sets geographic location
    #>
    
    Write-LogHeader "CONFIGURING GEOGRAPHIC LOCATION"
    
    try {
        Write-Log "Setting geographic location ID: $GeoLocation" -Level "INFO"
        
        # Get location name
        $LocationName = Get-LocationName -GeoID $GeoLocation
        Write-Log "Location: $LocationName" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set geographic location to: $GeoLocation ($LocationName)" -Level "INFO"
            return $true
        }
        
        # Set home location
        Set-WinHomeLocation -GeoId $GeoLocation -ErrorAction Stop
        
        Write-Log "Geographic location set successfully: $LocationName" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting geographic location: $_" -Level "ERROR"
        return $false
    }
}

function Get-LocationName {
    param([int]$GeoID)
    
    $Locations = @{
        244 = "United States"
        242 = "United Kingdom"
        39  = "Canada"
        217 = "Spain"
        84  = "France"
        94  = "Germany"
        118 = "Italy"
        122 = "Japan"
        137 = "Korea"
        45  = "China"
    }
    
    if ($Locations.ContainsKey($GeoID)) {
        return $Locations[$GeoID]
    }
    
    return "Unknown (ID: $GeoID)"
}

function Set-DateTimeFormats {
    <#
    .SYNOPSIS
        Configures custom date/time formats
    #>
    
    Write-LogHeader "CONFIGURING DATE/TIME FORMATS"
    
    try {
        if ($TimeFormat -eq "Default" -and $DateFormat -eq "Default" -and $FirstDayOfWeek -eq "Default") {
            Write-Log "Using default formats from locale" -Level "INFO"
            return $true
        }
        
        # Get current culture
        $Culture = Get-Culture
        
        # Time format
        if ($TimeFormat -ne "Default") {
            Write-Log "Setting time format: $TimeFormat" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set time format to: $TimeFormat" -Level "INFO"
            }
            else {
                $TimePattern = if ($TimeFormat -eq "12-Hour") { "h:mm:ss tt" } else { "HH:mm:ss" }
                
                # Set via registry for current user
                Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sTimeFormat" -Value $TimePattern
                Write-Log "Time format set: $TimePattern" -Level "SUCCESS"
                $Global:Stats.SettingsApplied++
            }
        }
        
        # Date format
        if ($DateFormat -ne "Default") {
            Write-Log "Setting date format: $DateFormat" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set date format to: $DateFormat" -Level "INFO"
            }
            else {
                $DatePattern = switch ($DateFormat) {
                    "MDY" { "M/d/yyyy" }
                    "DMY" { "d/M/yyyy" }
                    "YMD" { "yyyy/M/d" }
                }
                
                Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Value $DatePattern
                Write-Log "Date format set: $DatePattern" -Level "SUCCESS"
                $Global:Stats.SettingsApplied++
            }
        }
        
        # First day of week
        if ($FirstDayOfWeek -ne "Default") {
            Write-Log "Setting first day of week: $FirstDayOfWeek" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set first day of week to: $FirstDayOfWeek" -Level "INFO"
            }
            else {
                $DayValue = if ($FirstDayOfWeek -eq "Monday") { "0" } else { "6" }
                
                Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "iFirstDayOfWeek" -Value $DayValue
                Write-Log "First day of week set: $FirstDayOfWeek" -Level "SUCCESS"
                $Global:Stats.SettingsApplied++
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Exception setting date/time formats: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultUserProfile {
    <#
    .SYNOPSIS
        Applies settings to default user profile (affects new users)
    #>
    
    Write-LogHeader "APPLYING TO DEFAULT USER PROFILE"
    
    if (-not $ApplyToNewUsers) {
        Write-Log "Skipping default user profile (parameter disabled)" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applying settings to default user profile..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would apply settings to default user profile" -Level "INFO"
            return $true
        }
        
        # Load default user registry hive
        $DefaultUserPath = "C:\Users\Default\NTUSER.DAT"
        
        if (-not (Test-Path $DefaultUserPath)) {
            Write-Log "Default user profile not found" -Level "WARNING"
            return $false
        }
        
        # Load hive
        Write-Log "Loading default user registry hive..." -Level "DEBUG"
        $Result = reg load "HKU\DefaultUser" $DefaultUserPath 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to load default user hive: $Result" -Level "ERROR"
            return $false
        }
        
        # Copy current user settings to default user
        Write-Log "Copying regional settings to default user..." -Level "INFO"
        
        # Copy International settings
        Copy-Item -Path "HKCU:\Control Panel\International" `
                  -Destination "HKU:\DefaultUser\Control Panel\International" `
                  -Recurse -Force -ErrorAction SilentlyContinue
        
        # Unload hive
        Write-Log "Unloading default user registry hive..." -Level "DEBUG"
        [gc]::Collect()
        Start-Sleep -Seconds 1
        $Result = reg unload "HKU\DefaultUser" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Settings applied to default user profile" -Level "SUCCESS"
            $Global:Stats.SettingsApplied++
        }
        else {
            Write-Log "Warning unloading hive (settings may still be applied): $Result" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Exception applying to default user profile: $_" -Level "ERROR"
        
        # Try to unload hive if error occurred
        reg unload "HKU\DefaultUser" 2>&1 | Out-Null
        
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-RegionalConfiguration {
    <#
    .SYNOPSIS
        Validates regional configuration
    #>
    
    Write-LogHeader "VALIDATING REGIONAL CONFIGURATION"
    
    try {
        # Get current settings
        $Culture = Get-Culture
        $SystemLocaleReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "InstallLanguage" -ErrorAction SilentlyContinue
        
        Write-Log "Current regional settings:" -Level "INFO"
        Write-Log "  User Locale: $($Culture.Name)" -Level "SUCCESS"
        Write-Log "  Display Name: $($Culture.DisplayName)" -Level "INFO"
        Write-Log "  Date Format: $($Culture.DateTimeFormat.ShortDatePattern)" -Level "INFO"
        Write-Log "  Time Format: $($Culture.DateTimeFormat.ShortTimePattern)" -Level "INFO"
        Write-Log "  Currency Symbol: $($Culture.NumberFormat.CurrencySymbol)" -Level "INFO"
        Write-Log "  Decimal Separator: $($Culture.NumberFormat.NumberDecimalSeparator)" -Level "INFO"
        Write-Log "  Thousands Separator: $($Culture.NumberFormat.NumberGroupSeparator)" -Level "INFO"
        Write-Log "  First Day of Week: $($Culture.DateTimeFormat.FirstDayOfWeek)" -Level "INFO"
        
        # Get keyboard layouts
        $KeyboardLayouts = Get-WinUserLanguageList
        Write-Log " " -Level "INFO"
        Write-Log "Keyboard layouts configured:" -Level "INFO"
        foreach ($Layout in $KeyboardLayouts) {
            Write-Log "  ✓ $($Layout.LanguageTag)" -Level "SUCCESS"
        }
        
        # Get geographic location
        $HomeLocation = Get-WinHomeLocation
        Write-Log " " -Level "INFO"
        Write-Log "Geographic Location: GeoID $($HomeLocation.GeoId)" -Level "INFO"
        
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
    Write-Log "Regional Configuration Results:" -Level "INFO"
    Write-Log "  System Locale: $($Global:Stats.SystemLocaleSet)" -Level $(if($Global:Stats.SystemLocaleSet){"SUCCESS"}else{"INFO"})
    Write-Log "  User Locale: $($Global:Stats.UserLocaleSet)" -Level $(if($Global:Stats.UserLocaleSet){"SUCCESS"}else{"INFO"})
    Write-Log "  Keyboard Layouts: $($Global:Stats.KeyboardLayoutsConfigured)" -Level "SUCCESS"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
    
    if ($Global:Stats.SettingsApplied -gt 0) {
        Write-Log " " -Level "INFO"
        Write-Log "NOTE: Some changes may require sign out/sign in to take full effect" -Level "WARNING"
    }
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
║        REGIONAL & LANGUAGE SETTINGS                           ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "REGIONAL SETTINGS CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  System Locale: $SystemLocale" -Level "INFO"
    Write-Log "  User Locale: $UserLocale" -Level "INFO"
    Write-Log "  Keyboard Layout: $KeyboardLayout" -Level "INFO"
    Write-Log "  Geographic Location: $GeoLocation" -Level "INFO"
    if ($TimeFormat -ne "Default") { Write-Log "  Time Format: $TimeFormat" -Level "INFO" }
    if ($DateFormat -ne "Default") { Write-Log "  Date Format: $DateFormat" -Level "INFO" }
    if ($FirstDayOfWeek -ne "Default") { Write-Log "  First Day of Week: $FirstDayOfWeek" -Level "INFO" }
    Write-Log "  Apply to New Users: $ApplyToNewUsers" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Get current settings
    Get-CurrentRegionalSettings
    
    # Configure system locale
    $SystemLocaleResult = Set-SystemLocaleConfiguration
    
    # Configure user locale
    $UserLocaleResult = Set-UserLocaleConfiguration
    
    # Configure keyboard layout
    $KeyboardResult = Set-KeyboardLayoutConfiguration
    
    # Configure geographic location
    $GeoResult = Set-GeographicLocation
    
    # Configure custom date/time formats
    $FormatResult = Set-DateTimeFormats
    
    # Apply to default user profile
    if ($ApplyToNewUsers) {
        $DefaultUserResult = Set-DefaultUserProfile
    }
    
    # Validate configuration
    Test-RegionalConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Regional settings configuration completed successfully!" -Level "SUCCESS"
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
