<#
.SYNOPSIS
    Create Desktop Shortcuts for Applications and URLs
    
.DESCRIPTION
    Creates desktop shortcuts for applications, URLs, folders, and network locations.
    Can create shortcuts on Public Desktop (all users) or individual user profiles.
    
    Features:
    - Create application shortcuts
    - Create URL shortcuts (web links)
    - Create folder shortcuts
    - Create network share shortcuts
    - Place on Public Desktop (all users)
    - Place on Default User Desktop (new users)
    - Place on existing user desktops (optional)
    - Custom icons
    - Custom descriptions
    - Comprehensive logging and validation
    
.PARAMETER PublicDesktop
    Create shortcuts on Public Desktop (visible to all users).
    Default: $true
    
    When true: Shortcuts appear on ALL users' desktops
    When false: Only create in default user profile
    
.PARAMETER Shortcuts
    Array of shortcut definitions.
    
    Each shortcut is a hashtable with properties:
    - Name: Shortcut name (without .lnk extension)
    - Target: Application path, URL, or folder path
    - Icon: (Optional) Custom icon path
    - Description: (Optional) Shortcut description
    - Arguments: (Optional) Command-line arguments
    - WorkingDirectory: (Optional) Working directory
    
    Example:
    @{Name="Company Portal"; Target="https://portal.company.com"}
    @{Name="IT Help Desk"; Target="https://helpdesk.company.com"}
    @{Name="File Server"; Target="\\server\share"}
    @{Name="Calculator"; Target="C:\Windows\System32\calc.exe"}
    
.PARAMETER ApplyToAllUsers
    Apply to default user profile (new users get shortcuts).
    Default: $true
    
.PARAMETER ApplyToExistingUsers
    Create shortcuts for all existing user profiles.
    Default: $false
    
    WARNING: Places shortcuts on existing users' desktops
    
.PARAMETER OverwriteExisting
    Overwrite existing shortcuts with same name.
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without creating shortcuts. Default: $false
    
.EXAMPLE
    .\Create-Shortcuts.ps1
    Creates shortcuts from orchestration config
    
.EXAMPLE
    .\Create-Shortcuts.ps1 -PublicDesktop $true
    Creates shortcuts on Public Desktop (all users see them)
    
.EXAMPLE
    $shortcuts = @(
        @{Name="Company Portal"; Target="https://portal.company.com"}
        @{Name="IT Help Desk"; Target="https://helpdesk.company.com"}
    )
    .\Create-Shortcuts.ps1 -Shortcuts $shortcuts
    Creates custom shortcuts
    
.EXAMPLE
    .\Create-Shortcuts.ps1 -ApplyToExistingUsers $true
    Creates shortcuts for all existing users
    
.EXAMPLE
    .\Create-Shortcuts.ps1 -DryRun
    Shows what would be created without actually creating
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Desktop shortcuts creation for Windows 11 workstations
    
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
    - Public Desktop shortcuts visible to ALL users
    - Default profile shortcuts apply to NEW users only
    - Best run as SYSTEM (via SCCM or PsExec)
    - URL shortcuts use .url format (not .lnk)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$PublicDesktop = $true,
    
    [Parameter(Mandatory=$false)]
    [array]$Shortcuts = @(
        @{Name="IT Help Desk"; Target="https://helpdesk.company.com"},
        @{Name="Company Portal"; Target="https://portal.company.com"}
    ),
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToAllUsers = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToExistingUsers = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$OverwriteExisting = $true,
    
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

$LogFileName = "Create-Shortcuts_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    ShortcutsCreated = 0
    ShortcutsSkipped = 0
    ShortcutsUpdated = 0
    ProfilesProcessed = 0
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
        Write-Log "Running as SYSTEM - can modify all profiles" -Level "SUCCESS"
    }
    else {
        Write-Log "WARNING: Not running as SYSTEM - limited profile access" -Level "WARNING"
    }
    
    # Check 3: Shortcut definitions
    Write-Log "Validating shortcut definitions..." -Level "INFO"
    
    if (-not $Shortcuts -or $Shortcuts.Count -eq 0) {
        Write-Log "WARNING: No shortcuts defined" -Level "WARNING"
    }
    else {
        Write-Log "Shortcuts to create: $($Shortcuts.Count)" -Level "SUCCESS"
        
        foreach ($Shortcut in $Shortcuts) {
            if (-not $Shortcut.Name) {
                Write-Log "ERROR: Shortcut missing Name property" -Level "ERROR"
                $AllChecksPassed = $false
            }
            if (-not $Shortcut.Target) {
                Write-Log "ERROR: Shortcut missing Target property" -Level "ERROR"
                $AllChecksPassed = $false
            }
        }
    }
    
    return $AllChecksPassed
}

#endregion

#region SHORTCUT CREATION FUNCTIONS
#==============================================================================

function Get-ShortcutType {
    <#
    .SYNOPSIS
        Determines shortcut type based on target
    #>
    param([string]$Target)
    
    if ($Target -match "^https?://") {
        return "URL"
    }
    elseif ($Target -match "^\\\\") {
        return "NetworkShare"
    }
    elseif (Test-Path $Target -PathType Container) {
        return "Folder"
    }
    elseif (Test-Path $Target -PathType Leaf) {
        return "Application"
    }
    elseif ($Target -match "\.(exe|com|bat|cmd|ps1)$") {
        return "Application"
    }
    else {
        return "Unknown"
    }
}

function New-ApplicationShortcut {
    <#
    .SYNOPSIS
        Creates application shortcut (.lnk)
    #>
    param(
        [string]$Name,
        [string]$Target,
        [string]$DestinationPath,
        [string]$Icon = "",
        [string]$Description = "",
        [string]$Arguments = "",
        [string]$WorkingDirectory = ""
    )
    
    try {
        $ShortcutPath = Join-Path $DestinationPath "$Name.lnk"
        
        # Check if already exists
        if ((Test-Path $ShortcutPath) -and -not $OverwriteExisting) {
            Write-Log "  Skipped (already exists): $Name" -Level "DEBUG"
            $Global:Stats.ShortcutsSkipped++
            return $true
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create: $ShortcutPath" -Level "INFO"
            return $true
        }
        
        # Create shortcut using COM object
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $Target
        
        if ($Arguments) {
            $Shortcut.Arguments = $Arguments
        }
        
        if ($WorkingDirectory) {
            $Shortcut.WorkingDirectory = $WorkingDirectory
        }
        elseif (Test-Path $Target) {
            $Shortcut.WorkingDirectory = Split-Path $Target -Parent
        }
        
        if ($Icon) {
            $Shortcut.IconLocation = $Icon
        }
        
        if ($Description) {
            $Shortcut.Description = $Description
        }
        
        $Shortcut.Save()
        
        # Release COM object
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
        
        Write-Log "  Created: $Name" -Level "SUCCESS"
        $Global:Stats.ShortcutsCreated++
        
        return $true
    }
    catch {
        Write-Log "  Failed to create $Name : $_" -Level "ERROR"
        return $false
    }
}

function New-URLShortcut {
    <#
    .SYNOPSIS
        Creates URL shortcut (.url)
    #>
    param(
        [string]$Name,
        [string]$Target,
        [string]$DestinationPath,
        [string]$Icon = ""
    )
    
    try {
        $ShortcutPath = Join-Path $DestinationPath "$Name.url"
        
        # Check if already exists
        if ((Test-Path $ShortcutPath) -and -not $OverwriteExisting) {
            Write-Log "  Skipped (already exists): $Name" -Level "DEBUG"
            $Global:Stats.ShortcutsSkipped++
            return $true
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create: $ShortcutPath" -Level "INFO"
            return $true
        }
        
        # Create .url file content
        $URLContent = @"
[InternetShortcut]
URL=$Target
"@
        
        if ($Icon) {
            $URLContent += "`r`nIconFile=$Icon"
            $URLContent += "`r`nIconIndex=0"
        }
        
        # Write .url file
        Set-Content -Path $ShortcutPath -Value $URLContent -Force
        
        Write-Log "  Created: $Name" -Level "SUCCESS"
        $Global:Stats.ShortcutsCreated++
        
        return $true
    }
    catch {
        Write-Log "  Failed to create $Name : $_" -Level "ERROR"
        return $false
    }
}

function New-DesktopShortcut {
    <#
    .SYNOPSIS
        Creates a desktop shortcut based on target type
    #>
    param(
        [hashtable]$ShortcutDefinition,
        [string]$DestinationPath
    )
    
    try {
        $Name = $ShortcutDefinition.Name
        $Target = $ShortcutDefinition.Target
        $Icon = $ShortcutDefinition.Icon
        $Description = $ShortcutDefinition.Description
        $Arguments = $ShortcutDefinition.Arguments
        $WorkingDirectory = $ShortcutDefinition.WorkingDirectory
        
        Write-Log "Creating: $Name" -Level "INFO"
        Write-Log "  Target: $Target" -Level "DEBUG"
        Write-Log "  Destination: $DestinationPath" -Level "DEBUG"
        
        # Determine shortcut type
        $Type = Get-ShortcutType -Target $Target
        Write-Log "  Type: $Type" -Level "DEBUG"
        
        # Create appropriate shortcut type
        switch ($Type) {
            "URL" {
                New-URLShortcut -Name $Name -Target $Target -DestinationPath $DestinationPath -Icon $Icon
            }
            "Application" {
                New-ApplicationShortcut -Name $Name -Target $Target -DestinationPath $DestinationPath -Icon $Icon -Description $Description -Arguments $Arguments -WorkingDirectory $WorkingDirectory
            }
            "Folder" {
                New-ApplicationShortcut -Name $Name -Target $Target -DestinationPath $DestinationPath -Icon $Icon -Description $Description
            }
            "NetworkShare" {
                New-ApplicationShortcut -Name $Name -Target $Target -DestinationPath $DestinationPath -Icon $Icon -Description $Description
            }
            default {
                Write-Log "  Unknown target type: $Target" -Level "WARNING"
                # Try to create as application shortcut anyway
                New-ApplicationShortcut -Name $Name -Target $Target -DestinationPath $DestinationPath -Icon $Icon -Description $Description -Arguments $Arguments
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Exception creating shortcut $($ShortcutDefinition.Name): $_" -Level "ERROR"
        return $false
    }
}

function New-PublicDesktopShortcuts {
    <#
    .SYNOPSIS
        Creates shortcuts on Public Desktop (all users)
    #>
    
    Write-LogHeader "CREATING PUBLIC DESKTOP SHORTCUTS"
    
    if (-not $PublicDesktop) {
        Write-Log "Public Desktop shortcuts disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        $PublicDesktopPath = "C:\Users\Public\Desktop"
        
        if (-not (Test-Path $PublicDesktopPath)) {
            Write-Log "Public Desktop not found: $PublicDesktopPath" -Level "ERROR"
            return $false
        }
        
        Write-Log "Creating shortcuts on Public Desktop..." -Level "INFO"
        Write-Log "Path: $PublicDesktopPath" -Level "DEBUG"
        Write-Log "Shortcuts to create: $($Shortcuts.Count)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create $($Shortcuts.Count) shortcuts on Public Desktop" -Level "INFO"
        }
        
        foreach ($Shortcut in $Shortcuts) {
            New-DesktopShortcut -ShortcutDefinition $Shortcut -DestinationPath $PublicDesktopPath
        }
        
        Write-Log "Public Desktop shortcuts created successfully" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception creating public desktop shortcuts: $_" -Level "ERROR"
        return $false
    }
}

function New-DefaultUserShortcuts {
    <#
    .SYNOPSIS
        Creates shortcuts in default user profile (new users)
    #>
    
    Write-LogHeader "CREATING DEFAULT USER SHORTCUTS"
    
    if (-not $ApplyToAllUsers) {
        Write-Log "Default user shortcuts disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        $DefaultDesktopPath = "C:\Users\Default\Desktop"
        
        if (-not (Test-Path $DefaultDesktopPath)) {
            Write-Log "Creating default user Desktop folder..." -Level "INFO"
            New-Item -Path $DefaultDesktopPath -ItemType Directory -Force | Out-Null
        }
        
        Write-Log "Creating shortcuts in default user profile..." -Level "INFO"
        Write-Log "Path: $DefaultDesktopPath" -Level "DEBUG"
        Write-Log "Shortcuts to create: $($Shortcuts.Count)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create $($Shortcuts.Count) shortcuts in default profile" -Level "INFO"
        }
        
        foreach ($Shortcut in $Shortcuts) {
            New-DesktopShortcut -ShortcutDefinition $Shortcut -DestinationPath $DefaultDesktopPath
        }
        
        Write-Log "Default user shortcuts created successfully" -Level "SUCCESS"
        $Global:Stats.ProfilesProcessed++
        
        return $true
    }
    catch {
        Write-Log "Exception creating default user shortcuts: $_" -Level "ERROR"
        return $false
    }
}

function New-ExistingUserShortcuts {
    <#
    .SYNOPSIS
        Creates shortcuts for all existing user profiles
    #>
    
    Write-LogHeader "CREATING EXISTING USER SHORTCUTS"
    
    if (-not $ApplyToExistingUsers) {
        Write-Log "Existing user shortcuts disabled by parameter" -Level "INFO"
        return $true
    }
    
    Write-Log "WARNING: This will place shortcuts on existing users' desktops" -Level "WARNING"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create shortcuts for existing users" -Level "INFO"
            return $true
        }
        
        # Get all user profiles
        $UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
            $_.Name -notlike "Default*" -and
            $_.Name -ne "Public" -and
            (Test-Path "$($_.FullName)\Desktop")
        }
        
        Write-Log "Found $($UserProfiles.Count) user profile(s)" -Level "INFO"
        
        foreach ($Profile in $UserProfiles) {
            $DesktopPath = Join-Path $Profile.FullName "Desktop"
            
            Write-Log "Processing profile: $($Profile.Name)" -Level "INFO"
            
            foreach ($Shortcut in $Shortcuts) {
                New-DesktopShortcut -ShortcutDefinition $Shortcut -DestinationPath $DesktopPath
            }
            
            $Global:Stats.ProfilesProcessed++
        }
        
        Write-Log "Existing user shortcuts created successfully" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception creating existing user shortcuts: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-ShortcutCreation {
    <#
    .SYNOPSIS
        Validates shortcuts were created
    #>
    
    Write-LogHeader "VALIDATING SHORTCUT CREATION"
    
    try {
        Write-Log "Validating created shortcuts..." -Level "INFO"
        Write-Log " " -Level "INFO"
        
        $ValidationPaths = @()
        
        if ($PublicDesktop) {
            $ValidationPaths += "C:\Users\Public\Desktop"
        }
        
        if ($ApplyToAllUsers) {
            $ValidationPaths += "C:\Users\Default\Desktop"
        }
        
        foreach ($Path in $ValidationPaths) {
            Write-Log "Checking: $Path" -Level "DEBUG"
            
            if (Test-Path $Path) {
                $Files = Get-ChildItem -Path $Path -Include "*.lnk", "*.url" -ErrorAction SilentlyContinue
                Write-Log "  Found $($Files.Count) shortcut(s)" -Level "INFO"
                
                foreach ($File in $Files) {
                    Write-Log "  ✓ $($File.Name)" -Level "SUCCESS"
                }
            }
            else {
                Write-Log "  Path not found: $Path" -Level "WARNING"
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
    
    Write-Log " " -Level "INFO"
    Write-Log "Shortcut Creation Results:" -Level "INFO"
    Write-Log "  Shortcuts Created: $($Global:Stats.ShortcutsCreated)" -Level "SUCCESS"
    Write-Log "  Shortcuts Skipped: $($Global:Stats.ShortcutsSkipped)" -Level $(if($Global:Stats.ShortcutsSkipped -gt 0){"INFO"}else{"INFO"})
    Write-Log "  Shortcuts Updated: $($Global:Stats.ShortcutsUpdated)" -Level $(if($Global:Stats.ShortcutsUpdated -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Profiles Processed: $($Global:Stats.ProfilesProcessed)" -Level $(if($Global:Stats.ProfilesProcessed -gt 0){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Public Desktop: $PublicDesktop" -Level "INFO"
    Write-Log "  Apply To All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log "  Apply To Existing Users: $ApplyToExistingUsers" -Level "INFO"
    Write-Log "  Shortcuts Defined: $($Shortcuts.Count)" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Shortcuts Created:" -Level "INFO"
    foreach ($Shortcut in $Shortcuts) {
        Write-Log "  - $($Shortcut.Name) → $($Shortcut.Target)" -Level "INFO"
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
║        CREATE DESKTOP SHORTCUTS                               ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (creating shortcuts)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "SHORTCUT CREATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Public Desktop: $PublicDesktop" -Level "INFO"
    Write-Log "  Apply To All Users: $ApplyToAllUsers" -Level "INFO"
    Write-Log "  Apply To Existing Users: $ApplyToExistingUsers" -Level "INFO"
    Write-Log "  Shortcuts to Create: $($Shortcuts.Count)" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Create shortcuts on Public Desktop
    if ($PublicDesktop) {
        New-PublicDesktopShortcuts
    }
    
    # Create shortcuts in default user profile
    if ($ApplyToAllUsers) {
        New-DefaultUserShortcuts
    }
    
    # Create shortcuts for existing users
    if ($ApplyToExistingUsers) {
        New-ExistingUserShortcuts
    }
    
    # Validate shortcuts
    Test-ShortcutCreation
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Desktop shortcuts created successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Shortcut creation completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
