<#
.SYNOPSIS
    Configure Windows 11 Taskbar Settings
    
.DESCRIPTION
    Configures Windows 11 Taskbar alignment, icons, widgets, and pinned applications.
    Designed to run as SYSTEM to configure default user profile.
    
    Features:
    - Set taskbar alignment (Left or Center)
    - Show/hide Task View button
    - Show/hide Widgets
    - Show/hide Chat (Teams)
    - Show/hide Search
    - Configure system tray icons
    - Pin/unpin applications
    - Remove default pinned apps
    - Apply to default user profile (new users)
    - Comprehensive logging and validation
    
.PARAMETER TaskbarAlignment
    Taskbar icon alignment: "Left" or "Center"
    Default: "Left"
    
    Left (0):   Traditional Windows look (like Windows 10)
    Center (1): New Windows 11 default (macOS-like)
    
.PARAMETER ShowTaskView
    Show Task View button on taskbar.
    Default: $false
    
.PARAMETER ShowWidgets
    Show Widgets button on taskbar.
    Default: $false
    
.PARAMETER ShowChat
    Show Chat (Microsoft Teams) button on taskbar.
    Default: $false
    
.PARAMETER ShowSearch
    Show Search button/box on taskbar.
    Default: $true
    
    Options: Hidden, Icon, Box
    
.PARAMETER HideSystemTrayIcons
    Hide system tray icons (network, volume, etc).
    Default: $false
    
.PARAMETER PinnedApps
    Array of applications to pin to taskbar.
    Default: @()
    
    Example: @("Edge", "Explorer", "Outlook", "Teams")
    
.PARAMETER RemoveDefaultPins
    Remove Windows default pinned applications.
    Default: $true
    
.PARAMETER ApplyToAllUsers
    Apply configuration to default user profile.
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-Taskbar.ps1
    Applies default taskbar configuration
    
.EXAMPLE
    .\Configure-Taskbar.ps1 -TaskbarAlignment "Left" -ShowWidgets $false
    Sets taskbar to left alignment and hides widgets
    
.EXAMPLE
    .\Configure-Taskbar.ps1 -ShowTaskView $false -ShowChat $false
    Hides Task View and Chat buttons
    
.EXAMPLE
    .\Configure-Taskbar.ps1 -PinnedApps @("Edge", "Explorer", "Teams")
    Pins specific applications to taskbar
    
.EXAMPLE
    .\Configure-Taskbar.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Taskbar configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    IMPORTANT NOTES:
    - Best run as SYSTEM (via SCCM or PsExec)
    - Changes apply on next user login
    - Some settings require sign out/sign in
    - Pinning apps programmatically is difficult in Windows 11
    
    WINDOWS 11 TASKBAR NOTES:
    - Taskbar cannot be moved (always bottom)
    - Limited customization compared to Windows 10
    - Cannot resize taskbar
    - Cannot show labels for all apps
    - Programmatic pinning is challenging
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Left", "Center")]
    [string]$TaskbarAlignment = "Left",
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowTaskView = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowWidgets = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowChat = $false,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Hidden", "Icon", "Box")]
    [string]$ShowSearch = "Icon",
    
    [Parameter(Mandatory=$false)]
    [bool]$HideSystemTrayIcons = $false,
    
    [Parameter(Mandatory=$false)]
    [string[]]$PinnedApps = @(),
    
    [Parameter(Mandatory=$false)]
    [bool]$RemoveDefaultPins = $true,
    
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

$LogFileName = "Configure-Taskbar_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
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
    
    if ($CurrentUser -like "*SYSTEM*") {
        Write-Log "Running as SYSTEM - can modify default profile" -Level "SUCCESS"
    }
    else {
        Write-Log "WARNING: Not running as SYSTEM - will only modify current user" -Level "WARNING"
    }
    
    # Check 3: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($BuildNumber -lt 22000) {
        Write-Log "WARNING: This script is optimized for Windows 11 (Build 22000+)" -Level "WARNING"
    }
    else {
        Write-Log "Windows 11 detected" -Level "SUCCESS"
    }
    
    return $AllChecksPassed
}

#endregion

#region TASKBAR CONFIGURATION FUNCTIONS
#==============================================================================

function Get-CurrentTaskbarConfig {
    <#
    .SYNOPSIS
        Gets current taskbar configuration
    #>
    
    Write-LogHeader "CURRENT TASKBAR CONFIGURATION"
    
    try {
        $TaskbarPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $SearchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        
        Write-Log "Current Taskbar settings:" -Level "INFO"
        
        # Taskbar alignment
        $Alignment = (Get-ItemProperty $TaskbarPath -Name "TaskbarAl" -ErrorAction SilentlyContinue).TaskbarAl
        Write-Log "  Alignment: $(if($Alignment -eq 0){'Left'}else{'Center'})" -Level "INFO"
        
        # Task View button
        $TaskView = (Get-ItemProperty $TaskbarPath -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue).ShowTaskViewButton
        Write-Log "  Task View: $(if($TaskView -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        
        # Widgets button
        $Widgets = (Get-ItemProperty $TaskbarPath -Name "TaskbarDa" -ErrorAction SilentlyContinue).TaskbarDa
        Write-Log "  Widgets: $(if($Widgets -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        
        # Chat button
        $Chat = (Get-ItemProperty $TaskbarPath -Name "TaskbarMn" -ErrorAction SilentlyContinue).TaskbarMn
        Write-Log "  Chat: $(if($Chat -eq 1){'Shown'}else{'Hidden'})" -Level "INFO"
        
        # Search
        $Search = (Get-ItemProperty $SearchPath -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue).SearchboxTaskbarMode
        Write-Log "  Search: $(switch($Search){0{'Hidden'}1{'Icon'}2{'Box'}default{'Unknown'}})" -Level "INFO"
        
        return @{
            Alignment = $Alignment
            TaskView = $TaskView
            Widgets = $Widgets
            Chat = $Chat
            Search = $Search
        }
    }
    catch {
        Write-Log "Exception getting current configuration: $_" -Level "ERROR"
        return $null
    }
}

function Set-TaskbarAlignment {
    <#
    .SYNOPSIS
        Sets taskbar icon alignment
    #>
    param(
        [string]$Alignment = "Left",
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "SETTING TASKBAR ALIGNMENT"
    
    try {
        Write-Log "Setting taskbar alignment to: $Alignment" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set alignment to $Alignment" -Level "INFO"
            return $true
        }
        
        $TaskbarPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        if (-not (Test-Path $TaskbarPath)) {
            New-Item -Path $TaskbarPath -Force | Out-Null
        }
        
        # 0 = Left (Windows 10 style)
        # 1 = Center (Windows 11 default)
        $Value = if ($Alignment -eq "Left") { 0 } else { 1 }
        
        Set-ItemProperty -Path $TaskbarPath -Name "TaskbarAl" -Value $Value -PropertyType DWord -Force
        
        Write-Log "Taskbar alignment set to $Alignment" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception setting taskbar alignment: $_" -Level "ERROR"
        return $false
    }
}

function Set-TaskbarButtons {
    <#
    .SYNOPSIS
        Configures taskbar buttons (Task View, Widgets, Chat, Search)
    #>
    param(
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "CONFIGURING TASKBAR BUTTONS"
    
    try {
        Write-Log "Configuring taskbar buttons..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure taskbar buttons" -Level "INFO"
            return $true
        }
        
        $TaskbarPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $SearchPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Search"
        
        if (-not (Test-Path $TaskbarPath)) {
            New-Item -Path $TaskbarPath -Force | Out-Null
        }
        
        if (-not (Test-Path $SearchPath)) {
            New-Item -Path $SearchPath -Force | Out-Null
        }
        
        # Task View button
        Write-Log "  Task View: $ShowTaskView" -Level "INFO"
        Set-ItemProperty -Path $TaskbarPath -Name "ShowTaskViewButton" -Value $(if($ShowTaskView){1}else{0}) -PropertyType DWord -Force
        
        # Widgets button (Windows 11)
        Write-Log "  Widgets: $ShowWidgets" -Level "INFO"
        Set-ItemProperty -Path $TaskbarPath -Name "TaskbarDa" -Value $(if($ShowWidgets){1}else{0}) -PropertyType DWord -Force
        
        # Chat button (Microsoft Teams)
        Write-Log "  Chat: $ShowChat" -Level "INFO"
        Set-ItemProperty -Path $TaskbarPath -Name "TaskbarMn" -Value $(if($ShowChat){1}else{0}) -PropertyType DWord -Force
        
        # Search box/icon
        Write-Log "  Search: $ShowSearch" -Level "INFO"
        $SearchValue = switch ($ShowSearch) {
            "Hidden" { 0 }
            "Icon"   { 1 }
            "Box"    { 2 }
            default  { 1 }
        }
        Set-ItemProperty -Path $SearchPath -Name "SearchboxTaskbarMode" -Value $SearchValue -PropertyType DWord -Force
        
        Write-Log "Taskbar buttons configured successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception configuring taskbar buttons: $_" -Level "ERROR"
        return $false
    }
}

function Set-SystemTraySettings {
    <#
    .SYNOPSIS
        Configures system tray icon visibility
    #>
    param(
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "CONFIGURING SYSTEM TRAY"
    
    try {
        Write-Log "Configuring system tray settings..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure system tray" -Level "INFO"
            return $true
        }
        
        $TrayPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        
        if ($HideSystemTrayIcons) {
            Write-Log "  Hiding system tray icons" -Level "INFO"
            Set-ItemProperty -Path $TrayPath -Name "EnableAutoTray" -Value 1 -PropertyType DWord -Force
        }
        else {
            Write-Log "  Showing system tray icons" -Level "INFO"
            Set-ItemProperty -Path $TrayPath -Name "EnableAutoTray" -Value 0 -PropertyType DWord -Force
        }
        
        Write-Log "System tray configured successfully" -Level "SUCCESS"
        $Global:Stats.SettingsApplied++
        
        return $true
    }
    catch {
        Write-Log "Exception configuring system tray: $_" -Level "ERROR"
        return $false
    }
}

function Remove-DefaultTaskbarPins {
    <#
    .SYNOPSIS
        Removes default pinned applications from taskbar
    #>
    param(
        [string]$ProfilePath = $env:USERPROFILE
    )
    
    Write-LogHeader "REMOVING DEFAULT TASKBAR PINS"
    
    if (-not $RemoveDefaultPins) {
        Write-Log "Default pin removal disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Removing default pinned applications..." -Level "INFO"
        Write-Log "Profile: $ProfilePath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would remove default pinned applications" -Level "INFO"
            return $true
        }
        
        # Windows 11 taskbar pins stored in registry
        $PinsPath = "$ProfilePath\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        
        if (Test-Path $PinsPath) {
            Write-Log "Removing taskbar pins from: $PinsPath" -Level "DEBUG"
            
            # Get all shortcuts in taskbar folder
            $Pins = Get-ChildItem -Path $PinsPath -Filter "*.lnk" -ErrorAction SilentlyContinue
            
            foreach ($Pin in $Pins) {
                try {
                    Remove-Item -Path $Pin.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "  Removed: $($Pin.Name)" -Level "DEBUG"
                    $Global:Stats.PinsRemoved++
                }
                catch {
                    Write-Log "  Could not remove $($Pin.Name): $_" -Level "DEBUG"
                }
            }
        }
        
        Write-Log "Default taskbar pins removed: $($Global:Stats.PinsRemoved)" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception removing default pins: $_" -Level "ERROR"
        return $false
    }
}

function Add-TaskbarPins {
    <#
    .SYNOPSIS
        Pins applications to taskbar
    #>
    param(
        [string[]]$Applications,
        [string]$ProfilePath = $env:USERPROFILE
    )
    
    Write-LogHeader "PINNING APPLICATIONS TO TASKBAR"
    
    if (-not $Applications -or $Applications.Count -eq 0) {
        Write-Log "No applications to pin" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applications to pin: $($Applications.Count)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would pin applications to taskbar" -Level "INFO"
            foreach ($App in $Applications) {
                Write-Log "[DRY RUN]   - $App" -Level "INFO"
            }
            return $true
        }
        
        # Note: Windows 11 makes programmatic taskbar pinning very difficult
        Write-Log "WARNING: Windows 11 has limited API for programmatic taskbar pinning" -Level "WARNING"
        Write-Log "Pins may need to be set via Group Policy or manually by users" -Level "WARNING"
        
        $PinsPath = "$ProfilePath\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        
        if (-not (Test-Path $PinsPath)) {
            New-Item -Path $PinsPath -ItemType Directory -Force | Out-Null
        }
        
        foreach ($App in $Applications) {
            Write-Log "  Attempting to pin: $App" -Level "INFO"
            
            # Map friendly names to actual applications
            $AppPath = switch ($App) {
                "Edge"     { "$env:ProgramFiles\Microsoft\Office\root\Office16\MSEDGE.EXE" }
                "Explorer" { "$env:SystemRoot\explorer.exe" }
                "Outlook"  { "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE" }
                "Teams"    { "$env:LOCALAPPDATA\Microsoft\Teams\Update.exe --processStart `"Teams.exe`"" }
                "Chrome"   { "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" }
                "Word"     { "$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE" }
                "Excel"    { "$env:ProgramFiles\Microsoft Office\root\Office16\EXCEL.EXE" }
                default    { $null }
            }
            
            if ($AppPath -and (Test-Path $AppPath.Split(" ")[0])) {
                Write-Log "    Found: $AppPath" -Level "DEBUG"
                
                # Create shortcut in taskbar pins folder
                $ShortcutPath = Join-Path $PinsPath "$App.lnk"
                $WshShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
                $Shortcut.TargetPath = $AppPath.Split(" ")[0]
                $Shortcut.Save()
                
                $Global:Stats.PinsAdded++
                Write-Log "    Pinned: $App" -Level "SUCCESS"
            }
            else {
                Write-Log "    Not found: $App" -Level "WARNING"
            }
        }
        
        Write-Log "Taskbar pinning completed (note: Windows 11 limitations apply)" -Level "SUCCESS"
        
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
        Applies taskbar configuration to default user profile
    #>
    
    Write-LogHeader "CONFIGURING DEFAULT USER PROFILE"
    
    if (-not $ApplyToAllUsers) {
        Write-Log "Default profile configuration disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Applying taskbar configuration to default user profile..." -Level "INFO"
        
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
        
        # Configure taskbar settings in default profile
        Set-TaskbarAlignment -Alignment $TaskbarAlignment -TargetHive "HKU\DefaultUser"
        Set-TaskbarButtons -TargetHive "HKU\DefaultUser"
        Set-SystemTraySettings -TargetHive "HKU\DefaultUser"
        
        # Remove default pins
        Remove-DefaultTaskbarPins -ProfilePath $DefaultProfilePath
        
        # Pin applications
        if ($PinnedApps -and $PinnedApps.Count -gt 0) {
            Add-TaskbarPins -Applications $PinnedApps -ProfilePath $DefaultProfilePath
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

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-TaskbarConfiguration {
    <#
    .SYNOPSIS
        Validates taskbar configuration
    #>
    
    Write-LogHeader "VALIDATING TASKBAR CONFIGURATION"
    
    try {
        Write-Log "Validating configuration..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        $TaskbarPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $SearchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        
        # Taskbar alignment
        $Alignment = (Get-ItemProperty $TaskbarPath -Name "TaskbarAl" -ErrorAction SilentlyContinue).TaskbarAl
        $Expected = if ($TaskbarAlignment -eq "Left") { 0 } else { 1 }
        
        if ($Alignment -eq $Expected) {
            Write-Log "  ✓ Taskbar Alignment: $(if($Expected -eq 0){'LEFT'}else{'CENTER'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Taskbar Alignment: Configuration mismatch" -Level "WARNING"
        }
        
        # Task View
        $TaskView = (Get-ItemProperty $TaskbarPath -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue).ShowTaskViewButton
        $Expected = if ($ShowTaskView) { 1 } else { 0 }
        
        if ($TaskView -eq $Expected) {
            Write-Log "  ✓ Task View: $(if($ShowTaskView){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Task View: Configuration mismatch" -Level "WARNING"
        }
        
        # Widgets
        $Widgets = (Get-ItemProperty $TaskbarPath -Name "TaskbarDa" -ErrorAction SilentlyContinue).TaskbarDa
        $Expected = if ($ShowWidgets) { 1 } else { 0 }
        
        if ($Widgets -eq $Expected) {
            Write-Log "  ✓ Widgets: $(if($ShowWidgets){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Widgets: Configuration mismatch" -Level "WARNING"
        }
        
        # Chat
        $Chat = (Get-ItemProperty $TaskbarPath -Name "TaskbarMn" -ErrorAction SilentlyContinue).TaskbarMn
        $Expected = if ($ShowChat) { 1 } else { 0 }
        
        if ($Chat -eq $Expected) {
            Write-Log "  ✓ Chat: $(if($ShowChat){'SHOWN'}else{'HIDDEN'})" -Level "SUCCESS"
        }
        else {
            Write-Log "  ✗ Chat: Configuration mismatch" -Level "WARNING"
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
    Write-Log "Taskbar Configuration Results:" -Level "INFO"
    Write-Log "  Settings Applied: $($Global:Stats.SettingsApplied)" -Level "SUCCESS"
    Write-Log "  Default Pins Removed: $($Global:Stats.PinsRemoved)" -Level $(if($Global:Stats.PinsRemoved -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Applications Pinned: $($Global:Stats.PinsAdded)" -Level $(if($Global:Stats.PinsAdded -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Profiles Modified: $($Global:Stats.ProfilesModified)" -Level $(if($Global:Stats.ProfilesModified -gt 0){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Taskbar Alignment: $TaskbarAlignment" -Level "INFO"
    Write-Log "  Task View Button: $ShowTaskView" -Level "INFO"
    Write-Log "  Widgets Button: $ShowWidgets" -Level "INFO"
    Write-Log "  Chat Button: $ShowChat" -Level "INFO"
    Write-Log "  Search: $ShowSearch" -Level "INFO"
    Write-Log "  Remove Default Pins: $RemoveDefaultPins" -Level "INFO"
    Write-Log "  Pinned Apps: $(if($PinnedApps.Count -gt 0){$PinnedApps -join ', '}else{'None'})" -Level "INFO"
    
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
║        CONFIGURE WINDOWS 11 TASKBAR                           ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "TASKBAR CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Taskbar Alignment: $TaskbarAlignment" -Level "INFO"
    Write-Log "  Show Task View: $ShowTaskView" -Level "INFO"
    Write-Log "  Show Widgets: $ShowWidgets" -Level "INFO"
    Write-Log "  Show Chat: $ShowChat" -Level "INFO"
    Write-Log "  Show Search: $ShowSearch" -Level "INFO"
    Write-Log "  Remove Default Pins: $RemoveDefaultPins" -Level "INFO"
    Write-Log "  Pinned Apps: $(if($PinnedApps.Count -gt 0){$PinnedApps -join ', '}else{'None'})" -Level "INFO"
    Write-Log "  Apply To All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Get current configuration
    Get-CurrentTaskbarConfig
    
    # Configure current user/SYSTEM taskbar
    Set-TaskbarAlignment -Alignment $TaskbarAlignment -TargetHive "HKCU"
    Set-TaskbarButtons -TargetHive "HKCU"
    Set-SystemTraySettings -TargetHive "HKCU"
    
    # Remove default pins
    Remove-DefaultTaskbarPins
    
    # Pin applications
    if ($PinnedApps -and $PinnedApps.Count -gt 0) {
        Add-TaskbarPins -Applications $PinnedApps
    }
    
    # Configure default user profile
    if ($ApplyToAllUsers) {
        Set-DefaultUserProfile
    }
    
    # Validate configuration
    Test-TaskbarConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Taskbar configuration completed successfully!" -Level "SUCCESS"
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
