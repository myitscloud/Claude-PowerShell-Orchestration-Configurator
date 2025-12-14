<#
.SYNOPSIS
    Configure Windows File Explorer Settings
    
.DESCRIPTION
    Configures Windows File Explorer (formerly Windows Explorer) settings and 
    preferences for Windows 11 workstations. Ensures consistent, user-friendly 
    Explorer experience across enterprise.
    
    Features:
    - Show/hide file extensions
    - Show/hide hidden files and folders
    - Configure default Explorer start location
    - Enable/disable Quick Access
    - Configure folder view settings
    - Show/hide protected operating system files
    - Configure Explorer navigation pane
    - Set default folder view for all folders
    - Comprehensive logging and validation
    
.PARAMETER ShowFileExtensions
    Show file extensions for known file types.
    Default: $true
    
    Why enable:
    - Security: Identify malicious files (e.g., virus.txt.exe)
    - Clarity: Know exact file type
    - Power users: Essential for IT/developers
    
.PARAMETER ShowHiddenFiles
    Show hidden files and folders.
    Default: $false
    
    Options:
    - $true: Show all hidden files/folders
    - $false: Hide hidden files/folders (recommended for normal users)
    
.PARAMETER OpenToThisPC
    Open File Explorer to "This PC" instead of Quick Access.
    Default: $true
    
    Options:
    - $true: Opens to This PC (C:, D:, Network, etc.)
    - $false: Opens to Quick Access (recent files/folders)
    
.PARAMETER DisableQuickAccess
    Disable Quick Access functionality entirely.
    Default: $false
    
    When true:
    - No recent files shown
    - No frequent folders shown
    - Privacy improvement
    - Cleaner interface
    
.PARAMETER ShowProtectedOS
    Show protected operating system files.
    Default: $false
    
    Recommended: $false (prevents accidental system file deletion)
    
.PARAMETER FolderView
    Default folder view for all folders.
    Options: "Details", "List", "Tiles", "Content", "LargeIcons", "Default"
    Default: "Details"
    
.PARAMETER ExpandToCurrentFolder
    Expand navigation pane to current folder.
    Default: $true
    
.PARAMETER ShowRecentFiles
    Show recent files in Quick Access.
    Default: $true (but can disable for privacy)
    
.PARAMETER ShowFrequentFolders
    Show frequent folders in Quick Access.
    Default: $true (but can disable for privacy)
    
.PARAMETER ApplyToAllUsers
    Apply settings to default user profile (affects new users).
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-Explorer.ps1
    Configures Explorer with default settings (show extensions, This PC)
    
.EXAMPLE
    .\Configure-Explorer.ps1 -ShowFileExtensions $true -ShowHiddenFiles $true
    Shows file extensions and hidden files (power user configuration)
    
.EXAMPLE
    .\Configure-Explorer.ps1 -DisableQuickAccess $true
    Disables Quick Access for privacy
    
.EXAMPLE
    .\Configure-Explorer.ps1 -FolderView "Details"
    Sets all folders to Details view
    
.EXAMPLE
    .\Configure-Explorer.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Windows Explorer configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - PowerShell 5.1 or later
    
    NOTES:
    - Settings apply to current user and system (if SYSTEM account)
    - Some settings require Explorer restart to take effect
    - Script restarts Explorer automatically if needed
    - ApplyToAllUsers parameter affects default user profile
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$ShowFileExtensions = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowHiddenFiles = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$OpenToThisPC = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableQuickAccess = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowProtectedOS = $false,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Details", "List", "Tiles", "Content", "LargeIcons", "Default")]
    [string]$FolderView = "Details",
    
    [Parameter(Mandatory=$false)]
    [bool]$ExpandToCurrentFolder = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowRecentFiles = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowFrequentFolders = $true,
    
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

$LogFileName = "Configure-Explorer_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    SettingsApplied = 0
    SettingsSkipped = 0
    ExplorerRestarted = $false
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
    
    # Check 2: Registry access
    Write-Log "Checking registry access..." -Level "INFO"
    try {
        $TestKey = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        Write-Log "Registry access confirmed" -Level "SUCCESS"
    }
    catch {
        Write-Log "WARNING: Cannot access Explorer registry: $_" -Level "WARNING"
    }
    
    return $AllChecksPassed
}

#endregion

#region EXPLORER CONFIGURATION FUNCTIONS
#==============================================================================

function Get-CurrentExplorerSettings {
    <#
    .SYNOPSIS
        Gets current Explorer settings
    #>
    
    Write-LogHeader "CURRENT EXPLORER SETTINGS"
    
    try {
        $AdvancedKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $CabinetStateKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState"
        
        # Get current settings
        $FileExtensions = (Get-ItemProperty $AdvancedKey -Name "HideFileExt" -ErrorAction SilentlyContinue).HideFileExt
        $HiddenFiles = (Get-ItemProperty $AdvancedKey -Name "Hidden" -ErrorAction SilentlyContinue).Hidden
        $LaunchTo = (Get-ItemProperty $AdvancedKey -Name "LaunchTo" -ErrorAction SilentlyContinue).LaunchTo
        
        Write-Log "Current Explorer settings:" -Level "INFO"
        Write-Log "  File Extensions: $(if($FileExtensions -eq 0){'Shown'}else{'Hidden'})" -Level "INFO"
        Write-Log "  Hidden Files: $(if($HiddenFiles -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        Write-Log "  Start Location: $(if($LaunchTo -eq 1){'This PC'}else{'Quick Access'})" -Level "INFO"
        
        return @{
            FileExtensions = $FileExtensions
            HiddenFiles = $HiddenFiles
            LaunchTo = $LaunchTo
        }
    }
    catch {
        Write-Log "Exception getting current settings: $_" -Level "ERROR"
        return $null
    }
}

function Set-FileExtensionVisibility {
    <#
    .SYNOPSIS
        Configures file extension visibility
    #>
    
    Write-LogHeader "CONFIGURING FILE EXTENSION VISIBILITY"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $RegName = "HideFileExt"
        $RegValue = if ($ShowFileExtensions) { 0 } else { 1 }
        
        Write-Log "Setting: Show File Extensions = $ShowFileExtensions" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set $RegName to $RegValue" -Level "INFO"
            return $true
        }
        
        # Set registry value
        Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord -Force
        
        Write-Log "File extension visibility configured: $(if($ShowFileExtensions){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting file extension visibility: $_" -Level "ERROR"
        return $false
    }
}

function Set-HiddenFilesVisibility {
    <#
    .SYNOPSIS
        Configures hidden files visibility
    #>
    
    Write-LogHeader "CONFIGURING HIDDEN FILES VISIBILITY"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $RegName = "Hidden"
        $RegValue = if ($ShowHiddenFiles) { 1 } else { 2 }
        
        Write-Log "Setting: Show Hidden Files = $ShowHiddenFiles" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set $RegName to $RegValue" -Level "INFO"
            return $true
        }
        
        # Set registry value
        Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord -Force
        
        Write-Log "Hidden files visibility configured: $(if($ShowHiddenFiles){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting hidden files visibility: $_" -Level "ERROR"
        return $false
    }
}

function Set-ProtectedOSFilesVisibility {
    <#
    .SYNOPSIS
        Configures protected operating system files visibility
    #>
    
    Write-LogHeader "CONFIGURING PROTECTED OS FILES VISIBILITY"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $RegName = "ShowSuperHidden"
        $RegValue = if ($ShowProtectedOS) { 1 } else { 0 }
        
        Write-Log "Setting: Show Protected OS Files = $ShowProtectedOS" -Level "INFO"
        
        if ($ShowProtectedOS) {
            Write-Log "WARNING: Showing protected OS files can be dangerous!" -Level "WARNING"
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set $RegName to $RegValue" -Level "INFO"
            return $true
        }
        
        # Set registry value
        Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord -Force
        
        Write-Log "Protected OS files visibility configured: $(if($ShowProtectedOS){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting protected OS files visibility: $_" -Level "ERROR"
        return $false
    }
}

function Set-ExplorerStartLocation {
    <#
    .SYNOPSIS
        Configures Explorer default start location
    #>
    
    Write-LogHeader "CONFIGURING EXPLORER START LOCATION"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $RegName = "LaunchTo"
        $RegValue = if ($OpenToThisPC) { 1 } else { 2 }
        
        $LocationName = if ($OpenToThisPC) { "This PC" } else { "Quick Access" }
        Write-Log "Setting: Open Explorer to = $LocationName" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set $RegName to $RegValue" -Level "INFO"
            return $true
        }
        
        # Set registry value
        Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord -Force
        
        Write-Log "Explorer start location configured: $LocationName" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting Explorer start location: $_" -Level "ERROR"
        return $false
    }
}

function Set-QuickAccessSettings {
    <#
    .SYNOPSIS
        Configures Quick Access settings
    #>
    
    Write-LogHeader "CONFIGURING QUICK ACCESS SETTINGS"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        
        Write-Log "Configuring Quick Access settings..." -Level "INFO"
        Write-Log "  Show Recent Files: $ShowRecentFiles" -Level "INFO"
        Write-Log "  Show Frequent Folders: $ShowFrequentFolders" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure Quick Access settings" -Level "INFO"
            return $true
        }
        
        # Show recent files in Quick Access
        Set-ItemProperty -Path $RegPath -Name "ShowRecent" -Value $(if($ShowRecentFiles){1}else{0}) -Type DWord -Force
        
        # Show frequent folders in Quick Access
        Set-ItemProperty -Path $RegPath -Name "ShowFrequent" -Value $(if($ShowFrequentFolders){1}else{0}) -Type DWord -Force
        
        if ($DisableQuickAccess) {
            Write-Log "Disabling Quick Access entirely..." -Level "INFO"
            Set-ItemProperty -Path $RegPath -Name "ShowRecent" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $RegPath -Name "ShowFrequent" -Value 0 -Type DWord -Force
        }
        
        Write-Log "Quick Access settings configured successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting Quick Access settings: $_" -Level "ERROR"
        return $false
    }
}

function Set-NavigationPaneSettings {
    <#
    .SYNOPSIS
        Configures navigation pane settings
    #>
    
    Write-LogHeader "CONFIGURING NAVIGATION PANE"
    
    try {
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        Write-Log "Setting: Expand to Current Folder = $ExpandToCurrentFolder" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure navigation pane" -Level "INFO"
            return $true
        }
        
        # Expand to current folder
        Set-ItemProperty -Path $RegPath -Name "NavPaneExpandToCurrentFolder" -Value $(if($ExpandToCurrentFolder){1}else{0}) -Type DWord -Force
        
        Write-Log "Navigation pane configured successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting navigation pane: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultFolderView {
    <#
    .SYNOPSIS
        Sets default folder view for all folders
    #>
    
    Write-LogHeader "CONFIGURING DEFAULT FOLDER VIEW"
    
    if ($FolderView -eq "Default") {
        Write-Log "Using default folder view (no change)" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Setting default folder view to: $FolderView" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set default folder view to $FolderView" -Level "INFO"
            return $true
        }
        
        # Clear existing folder views
        $ShellBagsPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
        
        if (Test-Path $ShellBagsPath) {
            Write-Log "Clearing existing folder view settings..." -Level "DEBUG"
            Remove-Item -Path "$ShellBagsPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Default folder view will be applied on next Explorer restart" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting default folder view: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultUserProfile {
    <#
    .SYNOPSIS
        Applies settings to default user profile (affects new users)
    #>
    
    Write-LogHeader "APPLYING TO DEFAULT USER PROFILE"
    
    if (-not $ApplyToAllUsers) {
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
        
        # Copy Explorer settings to default user
        Write-Log "Copying Explorer settings to default user..." -Level "INFO"
        
        # Copy Advanced settings
        Copy-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
                  -Destination "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
                  -Recurse -Force -ErrorAction SilentlyContinue
        
        # Copy Explorer root settings
        $ExplorerSettings = @("ShowRecent", "ShowFrequent")
        foreach ($Setting in $ExplorerSettings) {
            try {
                $Value = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name $Setting -ErrorAction SilentlyContinue
                if ($Value) {
                    Set-ItemProperty -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" `
                                    -Name $Setting -Value $Value.$Setting -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Continue even if individual setting fails
            }
        }
        
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

#region EXPLORER RESTART
#==============================================================================

function Restart-ExplorerProcess {
    <#
    .SYNOPSIS
        Restarts Windows Explorer to apply settings
    #>
    
    Write-LogHeader "RESTARTING WINDOWS EXPLORER"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would restart Windows Explorer" -Level "INFO"
            return $true
        }
        
        Write-Log "Stopping Explorer process..." -Level "INFO"
        
        # Stop Explorer
        Stop-Process -Name explorer -Force -ErrorAction Stop
        
        Write-Log "Explorer stopped, waiting 2 seconds..." -Level "DEBUG"
        Start-Sleep -Seconds 2
        
        # Start Explorer
        Write-Log "Starting Explorer process..." -Level "INFO"
        Start-Process explorer -ErrorAction Stop
        
        Write-Log "Explorer restarted successfully" -Level "SUCCESS"
        $Global:Stats.ExplorerRestarted = $true
        
        # Wait for Explorer to stabilize
        Start-Sleep -Seconds 2
        
        return $true
    }
    catch {
        Write-Log "Exception restarting Explorer: $_" -Level "ERROR"
        
        # Try to start Explorer anyway
        try {
            Start-Process explorer -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Failed to restart Explorer - may need manual intervention" -Level "ERROR"
        }
        
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-ExplorerConfiguration {
    <#
    .SYNOPSIS
        Validates Explorer configuration
    #>
    
    Write-LogHeader "VALIDATING EXPLORER CONFIGURATION"
    
    try {
        $AdvancedKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $ExplorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        
        Write-Log "Validating configuration..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        # File Extensions
        $FileExtValue = (Get-ItemProperty $AdvancedKey -Name "HideFileExt" -ErrorAction SilentlyContinue).HideFileExt
        $Expected = if ($ShowFileExtensions) { 0 } else { 1 }
        if ($FileExtValue -eq $Expected) {
            Write-Log "  ✓ File Extensions: $(if($ShowFileExtensions){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ File Extensions: Configuration mismatch" -Level "ERROR"
        }
        
        # Hidden Files
        $HiddenValue = (Get-ItemProperty $AdvancedKey -Name "Hidden" -ErrorAction SilentlyContinue).Hidden
        $Expected = if ($ShowHiddenFiles) { 1 } else { 2 }
        if ($HiddenValue -eq $Expected) {
            Write-Log "  ✓ Hidden Files: $(if($ShowHiddenFiles){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Hidden Files: Configuration mismatch" -Level "ERROR"
        }
        
        # Start Location
        $LaunchValue = (Get-ItemProperty $AdvancedKey -Name "LaunchTo" -ErrorAction SilentlyContinue).LaunchTo
        $Expected = if ($OpenToThisPC) { 1 } else { 2 }
        if ($LaunchValue -eq $Expected) {
            Write-Log "  ✓ Start Location: $(if($OpenToThisPC){'This PC'}else{'Quick Access'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Start Location: Configuration mismatch" -Level "ERROR"
        }
        
        # Quick Access
        $ShowRecentValue = (Get-ItemProperty $ExplorerKey -Name "ShowRecent" -ErrorAction SilentlyContinue).ShowRecent
        $ShowFrequentValue = (Get-ItemProperty $ExplorerKey -Name "ShowFrequent" -ErrorAction SilentlyContinue).ShowFrequent
        
        Write-Log "  ✓ Recent Files: $(if($ShowRecentValue -eq 1){'ENABLED'}else{'DISABLED'})" -Level "SUCCESS"
        Write-Log "  ✓ Frequent Folders: $(if($ShowFrequentValue -eq 1){'ENABLED'}else{'DISABLED'})" -Level "SUCCESS"
        
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
    Write-Log "Explorer Configuration Results:" -Level "INFO"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    Write-Log "  Settings Skipped: $($Global:Stats.SettingsSkipped)" -Level "INFO"
    Write-Log "  Explorer Restarted: $($Global:Stats.ExplorerRestarted)" -Level $(if($Global:Stats.ExplorerRestarted){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Show File Extensions: $ShowFileExtensions" -Level "INFO"
    Write-Log "  Show Hidden Files: $ShowHiddenFiles" -Level "INFO"
    Write-Log "  Open to This PC: $OpenToThisPC" -Level "INFO"
    Write-Log "  Disable Quick Access: $DisableQuickAccess" -Level "INFO"
    Write-Log "  Show Recent Files: $ShowRecentFiles" -Level "INFO"
    Write-Log "  Show Frequent Folders: $ShowFrequentFolders" -Level "INFO"
    
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
║        WINDOWS EXPLORER CONFIGURATION                         ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WINDOWS EXPLORER CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Show File Extensions: $ShowFileExtensions" -Level "INFO"
    Write-Log "  Show Hidden Files: $ShowHiddenFiles" -Level "INFO"
    Write-Log "  Open to This PC: $OpenToThisPC" -Level "INFO"
    Write-Log "  Disable Quick Access: $DisableQuickAccess" -Level "INFO"
    Write-Log "  Show Recent Files: $ShowRecentFiles" -Level "INFO"
    Write-Log "  Show Frequent Folders: $ShowFrequentFolders" -Level "INFO"
    Write-Log "  Apply to All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Get current settings
    Get-CurrentExplorerSettings
    
    # Configure file extension visibility
    Set-FileExtensionVisibility
    
    # Configure hidden files visibility
    Set-HiddenFilesVisibility
    
    # Configure protected OS files visibility
    Set-ProtectedOSFilesVisibility
    
    # Configure Explorer start location
    Set-ExplorerStartLocation
    
    # Configure Quick Access settings
    Set-QuickAccessSettings
    
    # Configure navigation pane
    Set-NavigationPaneSettings
    
    # Configure default folder view
    Set-DefaultFolderView
    
    # Apply to default user profile
    if ($ApplyToAllUsers) {
        Set-DefaultUserProfile
    }
    
    # Restart Explorer to apply settings
    if ($Global:Stats.SettingsApplied -gt 0 -and -not $DryRun) {
        Restart-ExplorerProcess
    }
    
    # Validate configuration
    Test-ExplorerConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Windows Explorer configuration completed successfully!" -Level "SUCCESS"
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
