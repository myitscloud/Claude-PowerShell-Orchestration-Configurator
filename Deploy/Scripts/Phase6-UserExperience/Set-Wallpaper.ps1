<#
.SYNOPSIS
    Set Corporate Desktop Wallpaper and Lock Screen
    
.DESCRIPTION
    Configures corporate desktop wallpaper and lock screen image for Windows 11.
    Copies images to local cache and applies to all users.
    
    Features:
    - Set desktop wallpaper
    - Set lock screen image
    - Copy images to local cache (persistent)
    - Apply to default user profile (new users)
    - Apply to existing users (optional)
    - Support for multiple image formats (jpg, png, bmp)
    - Disable Windows Spotlight on lock screen
    - Remove personalization options (optional)
    - Comprehensive logging and validation
    
.PARAMETER WallpaperPath
    Path to corporate wallpaper image.
    Can be network path or local path.
    
    Supported formats: .jpg, .jpeg, .png, .bmp
    Recommended resolution: 1920x1080 or higher
    
.PARAMETER LockScreenPath
    Path to lock screen image.
    Can be network path or local path.
    
    If not specified, uses same as Wallpaper
    
.PARAMETER LocalCachePath
    Local path to cache images (persistent storage).
    Default: C:\ProgramData\CompanyAssets\Wallpapers
    
.PARAMETER ApplyToAllUsers
    Apply to default user profile (new users).
    Default: $true
    
.PARAMETER ApplyToExistingUsers
    Apply to all existing user profiles immediately.
    Default: $false
    
    WARNING: Changes all users' wallpapers
    
.PARAMETER DisableWindowsSpotlight
    Disable Windows Spotlight on lock screen.
    Default: $true
    
    Prevents Bing wallpaper rotation on lock screen
    
.PARAMETER RemovePersonalization
    Remove user ability to change wallpaper.
    Default: $false
    
    WARNING: Users cannot change wallpaper if enabled
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Set-Wallpaper.ps1
    Sets wallpaper from orchestration config
    
.EXAMPLE
    .\Set-Wallpaper.ps1 -WallpaperPath "C:\Images\Corporate.jpg"
    Sets specific wallpaper image
    
.EXAMPLE
    .\Set-Wallpaper.ps1 -WallpaperPath "\\Server\Assets\Wallpaper.jpg" -LockScreenPath "\\Server\Assets\LockScreen.jpg"
    Sets both wallpaper and lock screen from network share
    
.EXAMPLE
    .\Set-Wallpaper.ps1 -ApplyToExistingUsers $true
    Applies to all existing users immediately
    
.EXAMPLE
    .\Set-Wallpaper.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Corporate wallpaper configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    4   = Image file not found
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    - Source image files accessible
    
    IMPORTANT NOTES:
    - Images copied to local cache for persistence
    - Best run as SYSTEM (via SCCM or PsExec)
    - Changes may require sign out/sign in
    - Lock screen changes require restart for full effect
    
    RECOMMENDED IMAGE SPECS:
    - Format: JPG or PNG
    - Resolution: 1920x1080 (minimum), 4K for high-DPI
    - File size: <5MB
    - Aspect ratio: 16:9 (standard) or 16:10 (widescreen)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$WallpaperPath = "\\FileServer\Deployment\Assets\Wallpaper.jpg",
    
    [Parameter(Mandatory=$false)]
    [string]$LockScreenPath = "\\FileServer\Deployment\Assets\LockScreen.jpg",
    
    [Parameter(Mandatory=$false)]
    [string]$LocalCachePath = "C:\ProgramData\CompanyAssets\Wallpapers",
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToAllUsers = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToExistingUsers = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableWindowsSpotlight = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemovePersonalization = $false,
    
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

$LogFileName = "Set-Wallpaper_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    ImagesCached = 0
    WallpapersSet = 0
    LockScreensSet = 0
    ProfilesModified = 0
    Errors = 0
    Warnings = 0
}

# Cached image paths
$Global:CachedWallpaper = ""
$Global:CachedLockScreen = ""

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
    
    # Check 2: Running context
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Log "Running as: $CurrentUser" -Level "INFO"
    
    # Check 3: Wallpaper image
    Write-Log "Checking wallpaper image..." -Level "INFO"
    
    if (Test-Path $WallpaperPath) {
        $WallpaperFile = Get-Item $WallpaperPath
        Write-Log "Wallpaper found: $WallpaperPath" -Level "SUCCESS"
        Write-Log "  Size: $([math]::Round($WallpaperFile.Length / 1MB, 2)) MB" -Level "DEBUG"
        Write-Log "  Extension: $($WallpaperFile.Extension)" -Level "DEBUG"
        
        # Validate format
        $ValidFormats = @(".jpg", ".jpeg", ".png", ".bmp")
        if ($ValidFormats -notcontains $WallpaperFile.Extension.ToLower()) {
            Write-Log "WARNING: Wallpaper format may not be supported: $($WallpaperFile.Extension)" -Level "WARNING"
        }
    }
    else {
        Write-Log "ERROR: Wallpaper not found: $WallpaperPath" -Level "ERROR"
        $AllChecksPassed = $false
    }
    
    # Check 4: Lock screen image
    if ($LockScreenPath -and ($LockScreenPath -ne $WallpaperPath)) {
        Write-Log "Checking lock screen image..." -Level "INFO"
        
        if (Test-Path $LockScreenPath) {
            $LockScreenFile = Get-Item $LockScreenPath
            Write-Log "Lock screen found: $LockScreenPath" -Level "SUCCESS"
            Write-Log "  Size: $([math]::Round($LockScreenFile.Length / 1MB, 2)) MB" -Level "DEBUG"
        }
        else {
            Write-Log "WARNING: Lock screen not found: $LockScreenPath" -Level "WARNING"
            Write-Log "Will use wallpaper image for lock screen" -Level "INFO"
            $Script:LockScreenPath = $WallpaperPath
        }
    }
    else {
        Write-Log "Using wallpaper for lock screen" -Level "INFO"
        $Script:LockScreenPath = $WallpaperPath
    }
    
    return $AllChecksPassed
}

#endregion

#region IMAGE CACHING FUNCTIONS
#==============================================================================

function Copy-ImagesToCache {
    <#
    .SYNOPSIS
        Copies images to local cache for persistence
    #>
    
    Write-LogHeader "CACHING IMAGES LOCALLY"
    
    try {
        Write-Log "Copying images to local cache..." -Level "INFO"
        Write-Log "Cache path: $LocalCachePath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would copy images to cache" -Level "INFO"
            $Global:CachedWallpaper = Join-Path $LocalCachePath "Wallpaper.jpg"
            $Global:CachedLockScreen = Join-Path $LocalCachePath "LockScreen.jpg"
            return $true
        }
        
        # Create cache directory
        if (-not (Test-Path $LocalCachePath)) {
            Write-Log "Creating cache directory..." -Level "INFO"
            New-Item -Path $LocalCachePath -ItemType Directory -Force | Out-Null
        }
        
        # Copy wallpaper
        Write-Log "Copying wallpaper..." -Level "INFO"
        $WallpaperFile = Get-Item $WallpaperPath
        $CachedWallpaperPath = Join-Path $LocalCachePath "Wallpaper$($WallpaperFile.Extension)"
        
        Copy-Item -Path $WallpaperPath -Destination $CachedWallpaperPath -Force
        Write-Log "  Cached: $CachedWallpaperPath" -Level "SUCCESS"
        $Global:CachedWallpaper = $CachedWallpaperPath
        $Global:Stats.ImagesCached++
        
        # Copy lock screen
        Write-Log "Copying lock screen..." -Level "INFO"
        $LockScreenFile = Get-Item $LockScreenPath
        $CachedLockScreenPath = Join-Path $LocalCachePath "LockScreen$($LockScreenFile.Extension)"
        
        Copy-Item -Path $LockScreenPath -Destination $CachedLockScreenPath -Force
        Write-Log "  Cached: $CachedLockScreenPath" -Level "SUCCESS"
        $Global:CachedLockScreen = $CachedLockScreenPath
        $Global:Stats.ImagesCached++
        
        Write-Log "Images cached successfully" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception caching images: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region WALLPAPER CONFIGURATION FUNCTIONS
#==============================================================================

function Set-DesktopWallpaper {
    <#
    .SYNOPSIS
        Sets desktop wallpaper via registry
    #>
    param(
        [string]$ImagePath,
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "SETTING DESKTOP WALLPAPER"
    
    try {
        Write-Log "Setting desktop wallpaper..." -Level "INFO"
        Write-Log "Image: $ImagePath" -Level "DEBUG"
        Write-Log "Target hive: $TargetHive" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set wallpaper to: $ImagePath" -Level "INFO"
            return $true
        }
        
        # Registry path for wallpaper
        $WallpaperRegPath = "$TargetHive`:\Control Panel\Desktop"
        
        if (-not (Test-Path $WallpaperRegPath)) {
            New-Item -Path $WallpaperRegPath -Force | Out-Null
        }
        
        # Set wallpaper path
        Set-ItemProperty -Path $WallpaperRegPath -Name "Wallpaper" -Value $ImagePath -Force
        
        # Set wallpaper style (Fill = 10, Fit = 6, Stretch = 2, Tile = 0, Center = 1)
        Set-ItemProperty -Path $WallpaperRegPath -Name "WallpaperStyle" -Value "10" -Force  # Fill
        Set-ItemProperty -Path $WallpaperRegPath -Name "TileWallpaper" -Value "0" -Force
        
        Write-Log "Wallpaper registry settings applied" -Level "SUCCESS"
        $Global:Stats.WallpapersSet++
        
        # Refresh desktop (only works for current user)
        if ($TargetHive -eq "HKCU") {
            try {
                $UpdatePerUserSystemParameters = @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
                Add-Type -TypeDefinition $UpdatePerUserSystemParameters -ErrorAction SilentlyContinue
                [Wallpaper]::SystemParametersInfo(0x0014, 0, $ImagePath, 0x01 -bor 0x02) | Out-Null
                Write-Log "Desktop refreshed" -Level "DEBUG"
            }
            catch {
                Write-Log "Could not refresh desktop (not critical): $_" -Level "DEBUG"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Exception setting wallpaper: $_" -Level "ERROR"
        return $false
    }
}

function Set-LockScreenImage {
    <#
    .SYNOPSIS
        Sets lock screen image via registry
    #>
    param(
        [string]$ImagePath,
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "SETTING LOCK SCREEN IMAGE"
    
    try {
        Write-Log "Setting lock screen image..." -Level "INFO"
        Write-Log "Image: $ImagePath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set lock screen to: $ImagePath" -Level "INFO"
            return $true
        }
        
        # Registry paths for lock screen
        $PersonalizationPath = "$TargetHive`:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        
        if (-not (Test-Path $PersonalizationPath)) {
            New-Item -Path $PersonalizationPath -Force | Out-Null
        }
        
        # Set lock screen image
        Set-ItemProperty -Path $PersonalizationPath -Name "LockScreenImagePath" -Value $ImagePath -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "LockScreenImageUrl" -Value $ImagePath -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "LockScreenImageStatus" -Value 1 -Force -Type DWord
        
        Write-Log "Lock screen registry settings applied" -Level "SUCCESS"
        $Global:Stats.LockScreensSet++
        
        return $true
    }
    catch {
        Write-Log "Exception setting lock screen: $_" -Level "ERROR"
        return $false
    }
}

function Disable-WindowsSpotlight {
    <#
    .SYNOPSIS
        Disables Windows Spotlight on lock screen
    #>
    param([string]$TargetHive = "HKCU")
    
    Write-LogHeader "DISABLING WINDOWS SPOTLIGHT"
    
    if (-not $DisableWindowsSpotlight) {
        Write-Log "Windows Spotlight disable not requested" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Disabling Windows Spotlight on lock screen..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Windows Spotlight" -Level "INFO"
            return $true
        }
        
        # Disable Windows Spotlight
        $CloudContentPath = "$TargetHive`:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        
        if (-not (Test-Path $CloudContentPath)) {
            New-Item -Path $CloudContentPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $CloudContentPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
        
        # Additional lock screen settings
        $PersonalizationPath = "$TargetHive`:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        if (-not (Test-Path $PersonalizationPath)) {
            New-Item -Path $PersonalizationPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $PersonalizationPath -Name "NoLockScreen" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $PersonalizationPath -Name "LockScreenImage" -Value $Global:CachedLockScreen -Force
        
        Write-Log "Windows Spotlight disabled" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception disabling Spotlight: $_" -Level "ERROR"
        return $false
    }
}

function Disable-WallpaperPersonalization {
    <#
    .SYNOPSIS
        Removes user ability to change wallpaper
    #>
    param([string]$TargetHive = "HKCU")
    
    Write-LogHeader "REMOVING WALLPAPER PERSONALIZATION"
    
    if (-not $RemovePersonalization) {
        Write-Log "Personalization removal not requested" -Level "INFO"
        return $true
    }
    
    Write-Log "WARNING: Users will not be able to change wallpaper" -Level "WARNING"
    
    try {
        Write-Log "Removing wallpaper personalization..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would remove personalization" -Level "INFO"
            return $true
        }
        
        # Remove personalization via Group Policy
        $ActiveDesktopPath = "$TargetHive`:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
        
        if (-not (Test-Path $ActiveDesktopPath)) {
            New-Item -Path $ActiveDesktopPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $ActiveDesktopPath -Name "NoChangingWallPaper" -Value 1 -Type DWord -Force
        
        Write-Log "Wallpaper personalization removed" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception removing personalization: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultUserProfile {
    <#
    .SYNOPSIS
        Applies wallpaper configuration to default user profile
    #>
    
    Write-LogHeader "CONFIGURING DEFAULT USER PROFILE"
    
    if (-not $ApplyToAllUsers) {
        Write-Log "Default profile configuration disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applying wallpaper to default user profile..." -Level "INFO"
        
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
        
        # Set wallpaper and lock screen
        Set-DesktopWallpaper -ImagePath $Global:CachedWallpaper -TargetHive "HKU\DefaultUser"
        Set-LockScreenImage -ImagePath $Global:CachedLockScreen -TargetHive "HKU\DefaultUser"
        
        if ($DisableWindowsSpotlight) {
            Disable-WindowsSpotlight -TargetHive "HKU\DefaultUser"
        }
        
        if ($RemovePersonalization) {
            Disable-WallpaperPersonalization -TargetHive "HKU\DefaultUser"
        }
        
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
        Applies wallpaper to all existing user profiles
    #>
    
    Write-LogHeader "CONFIGURING EXISTING USER PROFILES"
    
    if (-not $ApplyToExistingUsers) {
        Write-Log "Existing user configuration disabled by parameter" -Level "INFO"
        return $true
    }
    
    Write-Log "WARNING: This will change wallpaper for all existing users" -Level "WARNING"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure existing users" -Level "INFO"
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
            Write-Log "Processing profile: $($Profile.Name)" -Level "INFO"
            
            # Load user hive
            $UserHive = "HKU\TempUser_$($Profile.Name)"
            $HivePath = Join-Path $Profile.FullName "NTUSER.DAT"
            
            $LoadResult = reg load $UserHive $HivePath 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                # Set wallpaper
                Set-DesktopWallpaper -ImagePath $Global:CachedWallpaper -TargetHive $UserHive
                Set-LockScreenImage -ImagePath $Global:CachedLockScreen -TargetHive $UserHive
                
                if ($DisableWindowsSpotlight) {
                    Disable-WindowsSpotlight -TargetHive $UserHive
                }
                
                if ($RemovePersonalization) {
                    Disable-WallpaperPersonalization -TargetHive $UserHive
                }
                
                # Unload hive
                [System.GC]::Collect()
                Start-Sleep -Milliseconds 500
                reg unload $UserHive 2>&1 | Out-Null
                
                $Global:Stats.ProfilesModified++
            }
            else {
                Write-Log "  Could not load hive (user may be logged in): $($Profile.Name)" -Level "WARNING"
            }
        }
        
        Write-Log "Existing user profiles configured" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception configuring existing users: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-WallpaperConfiguration {
    <#
    .SYNOPSIS
        Validates wallpaper configuration
    #>
    
    Write-LogHeader "VALIDATING WALLPAPER CONFIGURATION"
    
    try {
        Write-Log "Validating configuration..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        # Check cached images
        Write-Log "Checking cached images..." -Level "INFO"
        
        if (Test-Path $Global:CachedWallpaper) {
            Write-Log "  ✓ Wallpaper cached: $Global:CachedWallpaper" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Wallpaper not cached" -Level "WARNING"
        }
        
        if (Test-Path $Global:CachedLockScreen) {
            Write-Log "  ✓ Lock screen cached: $Global:CachedLockScreen" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Lock screen not cached" -Level "WARNING"
        }
        
        # Check current user wallpaper
        $CurrentWallpaper = Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -ErrorAction SilentlyContinue
        
        if ($CurrentWallpaper) {
            Write-Log "Current user wallpaper: $($CurrentWallpaper.Wallpaper)" -Level "INFO"
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
    Write-Log "Wallpaper Configuration Results:" -Level "INFO"
    Write-Log "  Images Cached: $($Global:Stats.ImagesCached)" -Level "SUCCESS"
    Write-Log "  Wallpapers Set: $($Global:Stats.WallpapersSet)" -Level "SUCCESS"
    Write-Log "  Lock Screens Set: $($Global:Stats.LockScreensSet)" -Level "SUCCESS"
    Write-Log "  Profiles Modified: $($Global:Stats.ProfilesModified)" -Level "SUCCESS"
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Wallpaper Source: $WallpaperPath" -Level "INFO"
    Write-Log "  Lock Screen Source: $LockScreenPath" -Level "INFO"
    Write-Log "  Cached Wallpaper: $Global:CachedWallpaper" -Level "INFO"
    Write-Log "  Cached Lock Screen: $Global:CachedLockScreen" -Level "INFO"
    Write-Log "  Disable Spotlight: $DisableWindowsSpotlight" -Level "INFO"
    Write-Log "  Remove Personalization: $RemovePersonalization" -Level "INFO"
    
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
║        SET CORPORATE WALLPAPER                                ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WALLPAPER CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Wallpaper Path: $WallpaperPath" -Level "INFO"
    Write-Log "  Lock Screen Path: $LockScreenPath" -Level "INFO"
    Write-Log "  Local Cache: $LocalCachePath" -Level "INFO"
    Write-Log "  Apply To All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log "  Apply To Existing Users: $ApplyToExistingUsers" -Level "INFO"
    Write-Log "  Disable Spotlight: $DisableWindowsSpotlight" -Level "INFO"
    Write-Log "  Remove Personalization: $RemovePersonalization" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Cache images locally
    Copy-ImagesToCache
    
    # Set wallpaper for current context
    Set-DesktopWallpaper -ImagePath $Global:CachedWallpaper
    Set-LockScreenImage -ImagePath $Global:CachedLockScreen
    
    if ($DisableWindowsSpotlight) {
        Disable-WindowsSpotlight
    }
    
    if ($RemovePersonalization) {
        Disable-WallpaperPersonalization
    }
    
    # Configure default user profile
    if ($ApplyToAllUsers) {
        Set-DefaultUserProfile
    }
    
    # Configure existing users
    if ($ApplyToExistingUsers) {
        Set-ExistingUserProfiles
    }
    
    # Validate configuration
    Test-WallpaperConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Wallpaper configuration completed successfully!" -Level "SUCCESS"
        Write-Log "Changes will be visible on next login" -Level "SUCCESS"
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
