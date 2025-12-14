<#
.SYNOPSIS
    Enterprise Desktop/Laptop Orchestration - Master Engine (Enhanced)
    
.DESCRIPTION
    Master orchestration engine that coordinates post-imaging configuration
    for Windows 11 Professional and Enterprise workstations. Handles 3000+ devices
    with full error handling, logging, checkpointing, auto-resume, and SCCM integration.
    
    NEW: Built-in auto-resume support via scheduled task - automatically resumes
    after reboots without manual intervention.
    
.PARAMETER ConfigFile
    Path to the configuration file. Default: .\Orchestration-Config.ps1
    
.PARAMETER Phase
    Run specific phase only (Phase1, Phase2, etc.). Default: Run all phases
    
.PARAMETER DryRun
    Simulate execution without making changes
    
.PARAMETER Resume
    Resume from last checkpoint after reboot or failure
    
.PARAMETER Force
    Force execution even if prerequisites fail
    
.PARAMETER NoAutoResume
    Disable automatic resume scheduled task creation
    
.EXAMPLE
    .\Orchestration-Master.ps1
    Runs full orchestration with auto-resume enabled
    
.EXAMPLE
    .\Orchestration-Master.ps1 -Phase Phase4 -DryRun
    Simulates Phase 4 (Applications) without making changes
    
.EXAMPLE
    .\Orchestration-Master.ps1 -Resume
    Manually resumes orchestration from last checkpoint
    
.NOTES
    Version:        2.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-07
    Purpose:        Post-imaging enterprise desktop configuration
    
    ENHANCEMENTS in v2.0:
    - Automatic resume after reboot via scheduled task
    - Enhanced checkpoint management
    - Reboot count tracking and limits
    - Self-cleanup of resume mechanisms
    - Improved error recovery
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = ".\Orchestration-Config.ps1",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","Phase1","Phase2","Phase3","Phase4","Phase5","Phase6","Phase7")]
    [string]$Phase = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false)]
    [switch]$Resume,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoAutoResume
)

#region INITIALIZATION
#==============================================================================

# Script version and metadata
$ScriptVersion = "2.0.0"
$ScriptStartTime = Get-Date

# Ensure we always have the full absolute path, even when run via PsExec
if ($MyInvocation.MyCommand.Path) {
    $ScriptPath = $MyInvocation.MyCommand.Path
    # Convert to absolute path if it's relative
    if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
        $ScriptPath = Join-Path (Get-Location).Path $ScriptPath
    }
    $ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
} else {
    # Fallback if path cannot be determined
    $ScriptPath = Join-Path (Get-Location).Path "Orchestration-Master.ps1"
    $ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
}

# Global variables
$Global:OrchestrationState = @{}
$Global:Config = $null
$Global:LogFile = $null
$Global:TranscriptFile = $null
$Global:CheckpointFile = "C:\ProgramData\OrchestrationLogs\Checkpoint.xml"
$Global:RebootCount = 0
$Global:ErrorCount = 0
$Global:WarningCount = 0
$Global:SuccessCount = 0
$Global:ExecutionResults = @()
$Global:IsResuming = $Resume.IsPresent

# Auto-resume configuration
$AutoResumeTaskName = "OrchestrationAutoResume"
$AutoResumeEnabled = -not $NoAutoResume.IsPresent

#endregion

#region CORE FUNCTIONS
#==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes messages to log file and console
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    if ($Global:LogFile) {
        try {
            Add-Content -Path $Global:LogFile -Value $LogMessage -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
    
    # Write to console with color
    if (-not $NoConsole) {
        switch ($Level) {
            "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
            "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
            "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
            "DEBUG"   { Write-Host $LogMessage -ForegroundColor Cyan }
            default   { Write-Host $LogMessage -ForegroundColor White }
        }
    }
    
    # Write to event log if enabled
    if ($Global:Config -and $Global:Config.Logging.EnableEventLog) {
        try {
            $EventType = switch ($Level) {
                "ERROR" { "Error" }
                "WARNING" { "Warning" }
                default { "Information" }
            }
            Write-EventLog -LogName Application -Source $Global:Config.Logging.EventLogSource -EntryType $EventType -EventId 1000 -Message $Message -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if event log writing fails
        }
    }
}

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes logging infrastructure
    #>
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  ORCHESTRATION ENGINE INITIALIZING" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    try {
        # Create log directory
        $LogPath = $Global:Config.Logging.LogPath
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }
        
        # Create log file
        $LogFileName = $Global:Config.Logging.LogFileName `
            -replace '{ComputerName}', $env:COMPUTERNAME `
            -replace '{DateTime}', (Get-Date -Format "yyyyMMdd-HHmmss")
        $Global:LogFile = Join-Path $LogPath $LogFileName
        
        # Create transcript directory
        if ($Global:Config.Logging.EnableTranscript) {
            $TranscriptPath = $Global:Config.Logging.TranscriptPath
            if (-not (Test-Path $TranscriptPath)) {
                New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
            }
            
            $TranscriptFileName = "Transcript_{0}_{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format "yyyyMMdd-HHmmss")
            $Global:TranscriptFile = Join-Path $TranscriptPath $TranscriptFileName
            Start-Transcript -Path $Global:TranscriptFile -Force
        }
        
        # Create event log source
        if ($Global:Config.Logging.EnableEventLog) {
            $EventSource = $Global:Config.Logging.EventLogSource
            if (-not ([System.Diagnostics.EventLog]::SourceExists($EventSource))) {
                New-EventLog -LogName Application -Source $EventSource
            }
        }
        
        Write-Log "Logging initialized successfully" -Level "SUCCESS"
        Write-Log "Log file: $Global:LogFile" -Level "INFO"
        if ($Global:TranscriptFile) {
            Write-Log "Transcript file: $Global:TranscriptFile" -Level "INFO"
        }
        
        return $true
    }
    catch {
        Write-Host "ERROR: Failed to initialize logging: $_" -ForegroundColor Red
        return $false
    }
}

function Load-Configuration {
    <#
    .SYNOPSIS
        Loads configuration file
    #>
    
    try {
        Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Cyan
        
        if (-not (Test-Path $ConfigFile)) {
            throw "Configuration file not found: $ConfigFile"
        }
        
        # Load configuration
        $Global:Config = & $ConfigFile
        
        if (-not $Global:Config) {
            throw "Configuration file did not return valid configuration object"
        }
        
        Write-Log "Configuration loaded successfully" -Level "SUCCESS"
        Write-Log "Configuration Version: $($Global:Config.ConfigVersion)" -Level "INFO"
        Write-Log "Orchestration: $($Global:Config.Orchestration.OrchestrationName) v$($Global:Config.Orchestration.Version)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Host "ERROR: Failed to load configuration: $_" -ForegroundColor Red
        return $false
    }
}

function Show-ExecutionPlan {
    <#
    .SYNOPSIS
        Displays execution plan showing enabled/disabled tasks
    #>

    Write-Host "`n" -NoNewline
    Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                       ║" -ForegroundColor Cyan
    Write-Host "║                       EXECUTION PLAN PREVIEW                          ║" -ForegroundColor Cyan
    Write-Host "║                                                                       ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $EnabledTasks = @()
    $DisabledTasks = @()

    # Scan all phases
    foreach ($PhaseKey in $Global:Config.Phases.Keys | Sort-Object) {
        $PhaseConfig = $Global:Config.Phases[$PhaseKey]

        if (-not $PhaseConfig.Enabled) {
            # Entire phase is disabled
            foreach ($Task in $PhaseConfig.Tasks) {
                $DisabledTasks += [PSCustomObject]@{
                    Phase = $PhaseConfig.PhaseName
                    TaskID = $Task.TaskID
                    TaskName = $Task.TaskName
                    Reason = "Phase Disabled"
                }
            }
            continue
        }

        # Phase is enabled - check individual tasks
        foreach ($Task in $PhaseConfig.Tasks) {
            if ($Task.Enabled) {
                $EnabledTasks += [PSCustomObject]@{
                    Phase = $PhaseConfig.PhaseName
                    TaskID = $Task.TaskID
                    TaskName = $Task.TaskName
                    Critical = $Task.Critical
                }
            }
            else {
                $DisabledTasks += [PSCustomObject]@{
                    Phase = $PhaseConfig.PhaseName
                    TaskID = $Task.TaskID
                    TaskName = $Task.TaskName
                    Reason = "Task Disabled"
                }
            }
        }
    }

    # Display ENABLED tasks
    Write-Host "┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "│ " -ForegroundColor Green -NoNewline
    Write-Host "ENABLED TASKS - WILL BE EXECUTED" -ForegroundColor White -NoNewline
    Write-Host " ($($EnabledTasks.Count) tasks)                       │" -ForegroundColor Green
    Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""

    if ($EnabledTasks.Count -eq 0) {
        Write-Host "  No tasks enabled" -ForegroundColor Yellow
    }
    else {
        $CurrentPhase = ""
        foreach ($Task in $EnabledTasks) {
            if ($Task.Phase -ne $CurrentPhase) {
                $CurrentPhase = $Task.Phase
                Write-Host ""
                Write-Host "  [$CurrentPhase]" -ForegroundColor Cyan
            }
            $CriticalMark = if ($Task.Critical) { " [CRITICAL]" } else { "" }
            Write-Host "    ✓ " -ForegroundColor Green -NoNewline
            Write-Host "$($Task.TaskID): $($Task.TaskName)" -ForegroundColor White -NoNewline
            if ($Task.Critical) {
                Write-Host $CriticalMark -ForegroundColor Yellow
            }
            else {
                Write-Host ""
            }
        }
    }

    Write-Host ""
    Write-Host ""

    # Display DISABLED tasks
    Write-Host "┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│ " -ForegroundColor DarkGray -NoNewline
    Write-Host "DISABLED TASKS - WILL BE SKIPPED" -ForegroundColor Gray -NoNewline
    Write-Host " ($($DisabledTasks.Count) tasks)                        │" -ForegroundColor DarkGray
    Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    if ($DisabledTasks.Count -eq 0) {
        Write-Host "  No tasks disabled" -ForegroundColor DarkGray
    }
    else {
        $CurrentPhase = ""
        foreach ($Task in $DisabledTasks) {
            if ($Task.Phase -ne $CurrentPhase) {
                $CurrentPhase = $Task.Phase
                Write-Host ""
                Write-Host "  [$CurrentPhase]" -ForegroundColor DarkGray
            }
            Write-Host "    ✗ " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($Task.TaskID): $($Task.TaskName)" -ForegroundColor Gray -NoNewline
            Write-Host " ($($Task.Reason))" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Press ANY KEY to begin execution..." -ForegroundColor Yellow -NoNewline
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host " Starting!`n" -ForegroundColor Green
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates prerequisites before orchestration
    #>
    
    Write-Log "=== PREREQUISITE VALIDATION ===" -Level "INFO"
    $AllPassed = $true
    
    # Check if running as administrator
    if ($Global:Config.Orchestration.RequireAdminRights) {
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($IsAdmin) {
            Write-Log "✓ Running with administrator privileges" -Level "SUCCESS"
        }
        else {
            Write-Log "✗ Not running as administrator" -Level "ERROR"
            $AllPassed = $false
        }
    }
    
    # Check Windows version
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $OSBuild = [int]$OSInfo.BuildNumber
    Write-Log "Operating System: $($OSInfo.Caption) (Build $OSBuild)" -Level "INFO"
    
    if ($Global:Config.Device.RequireWindows11 -and $OSBuild -lt $Global:Config.Device.MinimumOSBuild) {
        Write-Log "✗ Windows 11 required. Current build: $OSBuild, Required: $($Global:Config.Device.MinimumOSBuild)" -Level "ERROR"
        $AllPassed = $false
    }
    else {
        Write-Log "✓ Operating system version meets requirements" -Level "SUCCESS"
    }
    
    # Detect device type
    $ChassisType = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes[0]
    $DeviceType = if ($ChassisType -in @(8,9,10,11,12,14,18,21,30,31,32)) { "Laptop" } else { "Desktop" }
    Write-Log "Device Type: $DeviceType (Chassis: $ChassisType)" -Level "INFO"
    $Global:OrchestrationState.DeviceType = $DeviceType
    
    # Check domain join status
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $IsDomainJoined = $ComputerSystem.PartOfDomain
    Write-Log "Domain Joined: $IsDomainJoined" -Level "INFO"
    
    if ($Global:Config.Device.RequireDomainJoin -and -not $IsDomainJoined) {
        Write-Log "✗ Device must be domain joined" -Level "ERROR"
        $AllPassed = $false
    }
    
    # Check disk space
    $SystemDrive = $env:SystemDrive
    $Disk = Get-PSDrive -Name $SystemDrive.TrimEnd(':') -ErrorAction SilentlyContinue
    if ($Disk) {
        $FreeSpaceGB = [math]::Round($Disk.Free / 1GB, 2)
        Write-Log "Free Disk Space: $FreeSpaceGB GB" -Level "INFO"
        
        if ($FreeSpaceGB -lt $Global:Config.Performance.MinimumFreeDiskSpaceGB) {
            Write-Log "✗ Insufficient disk space. Required: $($Global:Config.Performance.MinimumFreeDiskSpaceGB) GB" -Level "ERROR"
            $AllPassed = $false
        }
        else {
            Write-Log "✓ Sufficient disk space available" -Level "SUCCESS"
        }
    }
    
    # Check source paths accessibility
    Write-Log "Checking source path accessibility..." -Level "INFO"
    $SourceFound = $false
    
    foreach ($SourcePath in @($Global:Config.Source.PrimarySourcePath, $Global:Config.Source.SecondarySourcePath, $Global:Config.Source.TertiarySourcePath)) {
        if ($SourcePath -and (Test-Path $SourcePath)) {
            Write-Log "✓ Source path accessible: $SourcePath" -Level "SUCCESS"
            $Global:OrchestrationState.ActiveSourcePath = $SourcePath
            $SourceFound = $true
            break
        }
    }
    
    if (-not $SourceFound) {
        Write-Log "⚠ No source paths accessible - scripts must be local" -Level "WARNING"
    }
    
    Write-Log "=== PREREQUISITE VALIDATION COMPLETE ===" -Level "INFO"
    
    if ($AllPassed) {
        Write-Log "All critical prerequisites passed" -Level "SUCCESS"
        return $true
    }
    else {
        Write-Log "One or more critical prerequisites failed" -Level "ERROR"
        if ($Force) {
            Write-Log "Forcing execution despite failures (-Force parameter used)" -Level "WARNING"
            return $true
        }
        return $false
    }
}

#endregion

#region AUTO-RESUME FUNCTIONS
#==============================================================================

function Register-AutoResumeTask {
    <#
    .SYNOPSIS
        Creates registry Run key for automatic resume after reboot
    #>

    if (-not $AutoResumeEnabled) {
        Write-Log "Auto-resume disabled via -NoAutoResume parameter" -Level "INFO"
        return $false
    }

    Write-Log "Registering auto-resume using scheduled task..." -Level "INFO"

    try {
        # Check if scheduled task already exists and is configured
        $ExistingTask = Get-ScheduledTask -TaskName $AutoResumeTaskName -ErrorAction SilentlyContinue

        if ($ExistingTask) {
            Write-Log "Auto-resume task already exists - verifying configuration" -Level "INFO"

            # Verify it's configured correctly
            $TaskAction = $ExistingTask.Actions[0]
            if ($TaskAction.Arguments -like "*$ScriptPath*") {
                Write-Log "✓ Task is correctly configured" -Level "SUCCESS"
                Enable-ScheduledTask -TaskName $AutoResumeTaskName -ErrorAction Stop | Out-Null
                return $true
            }
            else {
                Write-Log "Task points to different script - will recreate" -Level "WARNING"
                Unregister-ScheduledTask -TaskName $AutoResumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        Write-Log "Creating scheduled task for auto-resume..." -Level "DEBUG"

        # Get delay from config (default 60 seconds if not specified)
        $ResumeDelaySeconds = 60
        if ($Global:Config -and $Global:Config.Reboot.ResumeDelaySeconds) {
            $ResumeDelaySeconds = $Global:Config.Reboot.ResumeDelaySeconds
        }

        # Pure PowerShell approach - call pwsh.exe directly with -File
        # CRITICAL: Use -File not -Command for scheduled tasks running as SYSTEM
        # -Command with Start-Sleep fails silently in SYSTEM context at boot
        $Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -Resume"

        Write-Log "Task will execute: pwsh.exe $Arguments" -Level "DEBUG"

        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument $Arguments

        # Startup trigger with delay via trigger property
        # AtStartup with Delay is more reliable than Start-Sleep in -Command
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Trigger.Delay = "PT$($ResumeDelaySeconds)S"  # ISO 8601 duration format

        Write-Log "Resume delay: $ResumeDelaySeconds seconds (via trigger delay)" -Level "INFO"

        # SYSTEM principal (highest privileges, runs without user login)
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Task settings
        $Settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -Hidden

        # Register the task
        $Task = Register-ScheduledTask `
            -TaskName $AutoResumeTaskName `
            -Action $Action `
            -Trigger $Trigger `
            -Principal $Principal `
            -Settings $Settings `
            -Description "Automatic resume for Orchestration Engine after reboot" `
            -Force

        if ($Task) {
            Write-Log "✓ Auto-resume scheduled task created successfully" -Level "SUCCESS"
            Write-Log "Task will run at system boot as SYSTEM (no login required)" -Level "INFO"
            Write-Log "Delay: $ResumeDelaySeconds seconds (configured in Reboot.ResumeDelaySeconds)" -Level "INFO"
            Write-Log "Script path: $ScriptPath" -Level "DEBUG"

            # Verify the task was created correctly
            $VerifyTask = Get-ScheduledTask -TaskName $AutoResumeTaskName -ErrorAction SilentlyContinue
            if ($VerifyTask) {
                Write-Log "Task verification: State=$($VerifyTask.State), Enabled=$($VerifyTask.Settings.Enabled)" -Level "DEBUG"
            }

            return $true
        }
        else {
            Write-Log "✗ Failed to create scheduled task" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error creating auto-resume task: $_" -Level "ERROR"
        return $false
    }
}

function Unregister-AutoResumeTask {
    <#
    .SYNOPSIS
        Removes auto-resume scheduled task when orchestration completes
    #>

    Write-Log "Removing auto-resume scheduled task..." -Level "INFO"

    try {
        # Remove scheduled task
        $Task = Get-ScheduledTask -TaskName $AutoResumeTaskName -ErrorAction SilentlyContinue
        if ($Task) {
            Unregister-ScheduledTask -TaskName $AutoResumeTaskName -Confirm:$false -ErrorAction Stop
            Write-Log "✓ Auto-resume scheduled task removed successfully" -Level "SUCCESS"
        }
        else {
            Write-Log "Auto-resume task not found (already removed or never created)" -Level "DEBUG"
        }

        # No wrapper files to clean up - task calls cmd.exe directly

        # Clean up any old registry keys from previous implementations
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $RegName = "OrchestrationAutoResume"
        $ExistingValue = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue
        if ($ExistingValue) {
            Remove-ItemProperty -Path $RegPath -Name $RegName -Force -ErrorAction SilentlyContinue
            Write-Log "✓ Old registry key also removed" -Level "DEBUG"
        }

        return $true
    }
    catch {
        Write-Log "Warning: Could not remove auto-resume task: $_" -Level "WARNING"
        return $false
    }
}

function Test-AutoResumeTaskExists {
    <#
    .SYNOPSIS
        Checks if auto-resume task exists
    #>
    
    try {
        $Task = Get-ScheduledTask -TaskName $AutoResumeTaskName -ErrorAction SilentlyContinue
        return ($null -ne $Task)
    }
    catch {
        return $false
    }
}

#endregion

#region CHECKPOINT FUNCTIONS
#==============================================================================

function Save-Checkpoint {
    <#
    .SYNOPSIS
        Saves current orchestration state to checkpoint file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CurrentPhase,
        
        [Parameter(Mandatory=$true)]
        [string]$CurrentTask,
        
        [Parameter(Mandatory=$true)]
        [string]$Status
    )
    
    try {
        $CheckpointData = @{
            ComputerName = $env:COMPUTERNAME
            LastUpdate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            LastUpdateTicks = (Get-Date).Ticks
            CurrentPhase = $CurrentPhase
            CurrentTask = $CurrentTask
            Status = $Status
            RebootCount = $Global:RebootCount
            CompletedTasks = $Global:OrchestrationState.CompletedTasks
            FailedTasks = $Global:OrchestrationState.FailedTasks
            ExecutionResults = $Global:ExecutionResults
            ScriptVersion = $ScriptVersion
            ConfigVersion = $Global:Config.ConfigVersion
        }
        
        $CheckpointDir = Split-Path $Global:CheckpointFile -Parent
        if (-not (Test-Path $CheckpointDir)) {
            New-Item -Path $CheckpointDir -ItemType Directory -Force | Out-Null
        }
        
        $CheckpointData | Export-Clixml -Path $Global:CheckpointFile -Force
        Write-Log "Checkpoint saved: Phase=$CurrentPhase, Task=$CurrentTask, Status=$Status" -Level "DEBUG"
        
        return $true
    }
    catch {
        Write-Log "Failed to save checkpoint: $_" -Level "WARNING"
        return $false
    }
}

function Load-Checkpoint {
    <#
    .SYNOPSIS
        Loads orchestration state from checkpoint file
    #>
    
    try {
        if (Test-Path $Global:CheckpointFile) {
            $CheckpointData = Import-Clixml -Path $Global:CheckpointFile
            
            Write-Log "========================================" -Level "INFO"
            Write-Log "RESUMING FROM CHECKPOINT" -Level "INFO"
            Write-Log "========================================" -Level "INFO"
            Write-Log "Last checkpoint: $($CheckpointData.LastUpdate)" -Level "INFO"
            Write-Log "Last phase: $($CheckpointData.CurrentPhase)" -Level "INFO"
            Write-Log "Last task: $($CheckpointData.CurrentTask)" -Level "INFO"
            Write-Log "Status: $($CheckpointData.Status)" -Level "INFO"
            Write-Log "Reboot count: $($CheckpointData.RebootCount)" -Level "INFO"
            Write-Log "Completed tasks: $($CheckpointData.CompletedTasks.Count)" -Level "INFO"
            
            # Validate checkpoint is not too old (more than 7 days)
            $LastUpdateTime = [DateTime]::new($CheckpointData.LastUpdateTicks)
            $Age = (Get-Date) - $LastUpdateTime
            
            if ($Age.TotalDays -gt 7) {
                Write-Log "⚠ WARNING: Checkpoint is $([math]::Round($Age.TotalDays, 1)) days old" -Level "WARNING"
                Write-Log "Consider starting fresh if this is unexpected" -Level "WARNING"
            }
            
            return $CheckpointData
        }
        else {
            Write-Log "No checkpoint file found - starting fresh" -Level "INFO"
            return $null
        }
    }
    catch {
        Write-Log "Failed to load checkpoint: $_" -Level "WARNING"
        Write-Log "Will start fresh orchestration" -Level "INFO"
        return $null
    }
}

function Remove-Checkpoint {
    <#
    .SYNOPSIS
        Removes checkpoint file after successful completion
    #>
    
    try {
        if (Test-Path $Global:CheckpointFile) {
            Remove-Item -Path $Global:CheckpointFile -Force -ErrorAction Stop
            Write-Log "✓ Checkpoint file removed" -Level "SUCCESS"
        }
        return $true
    }
    catch {
        Write-Log "Warning: Could not remove checkpoint file: $_" -Level "WARNING"
        return $false
    }
}

#endregion

#region TASK EXECUTION FUNCTIONS
#==============================================================================

function Invoke-Task {
    <#
    .SYNOPSIS
        Executes a single task from configuration
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Task,
        
        [Parameter(Mandatory=$true)]
        [string]$PhaseName
    )
    
    $TaskID = $Task.TaskID
    $TaskName = $Task.TaskName
    $ScriptPath = $Task.ScriptPath
    
    Write-Log "`n--- Executing Task: $TaskID - $TaskName ---" -Level "INFO"
    
    # Check if task is enabled
    if (-not $Task.Enabled) {
        Write-Log "Task disabled - skipping" -Level "WARNING"
        return @{
            TaskID = $TaskID
            TaskName = $TaskName
            Status = "Skipped"
            Message = "Task is disabled in configuration"
            Duration = 0
            RequiresReboot = $false
        }
    }
    
    # Check if already completed (from checkpoint)
    if ($Global:OrchestrationState.CompletedTasks -contains $TaskID) {
        Write-Log "✓ Task already completed in previous run - skipping" -Level "SUCCESS"
        return @{
            TaskID = $TaskID
            TaskName = $TaskName
            Status = "Skipped"
            Message = "Task already completed in previous run"
            Duration = 0
            RequiresReboot = $false
        }
    }
    
    # Build script path
    $FullScriptPath = if ($Global:OrchestrationState.ActiveSourcePath) {
        Join-Path $Global:OrchestrationState.ActiveSourcePath $ScriptPath
    } else {
        $ScriptPath
    }
    
    # Check if script exists
    if (-not (Test-Path $FullScriptPath)) {
        Write-Log "✗ Script not found: $FullScriptPath" -Level "ERROR"
        $Global:ErrorCount++
        return @{
            TaskID = $TaskID
            TaskName = $TaskName
            Status = "Failed"
            Message = "Script file not found: $FullScriptPath"
            Duration = 0
            RequiresReboot = $false
        }
    }
    
    Write-Log "Script path: $FullScriptPath" -Level "INFO"
    Write-Log "Description: $($Task.Description)" -Level "INFO"
    Write-Log "Timeout: $($Task.Timeout) seconds" -Level "INFO"
    
    # Dry run mode
    if ($DryRun -or $Global:Config.Orchestration.EnableDryRun) {
        Write-Log "[DRY RUN] Would execute: $FullScriptPath" -Level "INFO"
        return @{
            TaskID = $TaskID
            TaskName = $TaskName
            Status = "DryRun"
            Message = "Dry run - no changes made"
            Duration = 0
            RequiresReboot = $false
        }
    }
    
    # Execute task
    $TaskStartTime = Get-Date
    $AttemptCount = 0
    $MaxAttempts = if ($Task.AllowRetry -and $Global:Config.Orchestration.EnableRetry) { 
        $Global:Config.Orchestration.MaxRetryAttempts 
    } else { 
        1 
    }
    
    $TaskResult = $null
    
    while ($AttemptCount -lt $MaxAttempts) {
        $AttemptCount++
        
        if ($AttemptCount -gt 1) {
            Write-Log "Retry attempt $AttemptCount of $MaxAttempts" -Level "WARNING"
            Start-Sleep -Seconds $Global:Config.Orchestration.RetryDelaySeconds
        }
        
        try {
            Write-Log "Executing task (Attempt $AttemptCount)..." -Level "INFO"
            
            # Build parameter splatting
            $ScriptParams = @{}
            if ($Task.Parameters) {
                $ScriptParams = $Task.Parameters
            }
            
            # Execute script with timeout
            $Job = Start-Job -ScriptBlock {
                param($Script, $Params)
                & $Script @Params
            } -ArgumentList $FullScriptPath, $ScriptParams
            
            $Completed = Wait-Job -Job $Job -Timeout $Task.Timeout
            
            if ($Completed) {
                $Output = Receive-Job -Job $Job
                $JobExitCode = $Job.State
                
                if ($Job.State -eq "Completed") {
                    # Get actual exit code from job
                    $ActualExitCode = 0
                    if ($Job.ChildJobs[0].Output -match "LASTEXITCODE:(\d+)") {
                        $ActualExitCode = [int]$Matches[1]
                    }
                    
                    Write-Log "✓ Task completed successfully" -Level "SUCCESS"
                    $Global:SuccessCount++
                    
                    # Check if reboot required (exit code 5 or RequiresReboot flag)
                    $RebootNeeded = ($Task.RequiresReboot) -or ($ActualExitCode -eq 5)
                    
                    $TaskResult = @{
                        TaskID = $TaskID
                        TaskName = $TaskName
                        Status = "Success"
                        Message = "Task completed successfully"
                        Output = $Output
                        Duration = ((Get-Date) - $TaskStartTime).TotalSeconds
                        Attempt = $AttemptCount
                        RequiresReboot = $RebootNeeded
                        ExitCode = $ActualExitCode
                    }
                    
                    # Add to completed tasks
                    if (-not $Global:OrchestrationState.CompletedTasks) {
                        $Global:OrchestrationState.CompletedTasks = @()
                    }
                    $Global:OrchestrationState.CompletedTasks += $TaskID
                    
                    break
                }
                else {
                    throw "Job state: $($Job.State)"
                }
            }
            else {
                Stop-Job -Job $Job
                throw "Task exceeded timeout of $($Task.Timeout) seconds"
            }
        }
        catch {
            Write-Log "✗ Task failed: $_" -Level "ERROR"
            $Global:ErrorCount++
            
            $TaskResult = @{
                TaskID = $TaskID
                TaskName = $TaskName
                Status = "Failed"
                Message = $_.Exception.Message
                Duration = ((Get-Date) - $TaskStartTime).TotalSeconds
                Attempt = $AttemptCount
                RequiresReboot = $false
            }
            
            # Add to failed tasks
            if (-not $Global:OrchestrationState.FailedTasks) {
                $Global:OrchestrationState.FailedTasks = @()
            }
            if ($Global:OrchestrationState.FailedTasks -notcontains $TaskID) {
                $Global:OrchestrationState.FailedTasks += $TaskID
            }
            
            # If not last attempt, continue to retry
            if ($AttemptCount -lt $MaxAttempts) {
                continue
            }
        }
        finally {
            # Clean up job
            if ($Job) {
                Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Check if task is critical and failed
    if ($TaskResult.Status -eq "Failed" -and $Task.Critical) {
        Write-Log "✗ CRITICAL TASK FAILED - This may impact subsequent operations" -Level "ERROR"
        
        if ($Global:Config.ErrorHandling.StopOnCriticalError -and -not $Global:Config.Orchestration.ContinueOnError) {
            throw "Critical task failed: $TaskID - $TaskName"
        }
    }
    
    Write-Log "Task duration: $([math]::Round($TaskResult.Duration, 2)) seconds" -Level "INFO"
    
    return $TaskResult
}

function Invoke-Phase {
    <#
    .SYNOPSIS
        Executes all tasks in a phase
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$PhaseConfig,
        
        [Parameter(Mandatory=$true)]
        [string]$PhaseNumber
    )
    
    $PhaseName = $PhaseConfig.PhaseName
    $PhaseDescription = $PhaseConfig.PhaseDescription
    
    Write-Log "`n========================================" -Level "INFO"
    Write-Log "PHASE: $PhaseNumber - $PhaseName" -Level "INFO"
    Write-Log "Description: $PhaseDescription" -Level "INFO"
    Write-Log "========================================" -Level "INFO"
    
    if (-not $PhaseConfig.Enabled) {
        Write-Log "Phase disabled - skipping all tasks" -Level "WARNING"
        return @{
            PhaseNumber = $PhaseNumber
            PhaseName = $PhaseName
            Status = "Skipped"
            Tasks = @()
            RequiresReboot = $false
        }
    }
    
    $PhaseResults = @{
        PhaseNumber = $PhaseNumber
        PhaseName = $PhaseName
        Status = "InProgress"
        Tasks = @()
        RequiresReboot = $false
    }
    
    $PhaseStartTime = Get-Date
    
    # Execute each task in phase
    foreach ($Task in $PhaseConfig.Tasks) {
        try {
            $TaskResult = Invoke-Task -Task $Task -PhaseName $PhaseName
            $PhaseResults.Tasks += $TaskResult
            
            # Save checkpoint after each task
            if ($Global:Config.Orchestration.EnableCheckpoints) {
                Save-Checkpoint -CurrentPhase $PhaseNumber -CurrentTask $Task.TaskID -Status $TaskResult.Status
            }
            
            # Check if reboot required
            if ($TaskResult.RequiresReboot) {
                Write-Log "⚠ Task requires reboot" -Level "WARNING"
                $PhaseResults.RequiresReboot = $true
                
                # Handle reboot
                if ($Global:Config.Reboot.AutoRebootAfterPhase) {
                    Write-Log "Auto-reboot is enabled - will reboot after phase completes" -Level "WARNING"
                    break  # Exit task loop to complete phase and reboot
                }
            }
            
            # Check if we should stop on failure
            if ($TaskResult.Status -eq "Failed") {
                if ($PhaseConfig.StopOnPhaseFailure -and -not $Global:Config.Orchestration.ContinueOnError) {
                    Write-Log "Phase configured to stop on failure - halting phase execution" -Level "ERROR"
                    $PhaseResults.Status = "Failed"
                    break
                }
            }
        }
        catch {
            Write-Log "Unhandled error executing task: $_" -Level "ERROR"
            $Global:ErrorCount++
            
            if ($PhaseConfig.StopOnPhaseFailure -and -not $Global:Config.Orchestration.ContinueOnError) {
                $PhaseResults.Status = "Failed"
                break
            }
        }
    }
    
    # Calculate phase status
    $FailedTasks = ($PhaseResults.Tasks | Where-Object { $_.Status -eq "Failed" }).Count
    $SuccessTasks = ($PhaseResults.Tasks | Where-Object { $_.Status -eq "Success" }).Count
    
    if ($PhaseResults.Status -ne "Failed") {
        if ($FailedTasks -eq 0) {
            $PhaseResults.Status = "Success"
        }
        elseif ($SuccessTasks -gt 0) {
            $PhaseResults.Status = "PartialSuccess"
        }
        else {
            $PhaseResults.Status = "Failed"
        }
    }
    
    $PhaseDuration = ((Get-Date) - $PhaseStartTime).TotalMinutes
    Write-Log "`nPhase Summary: $PhaseNumber - $PhaseName" -Level "INFO"
    Write-Log "Status: $($PhaseResults.Status)" -Level "INFO"
    Write-Log "Duration: $([math]::Round($PhaseDuration, 2)) minutes" -Level "INFO"
    Write-Log "Tasks: Success=$SuccessTasks, Failed=$FailedTasks, Total=$($PhaseResults.Tasks.Count)" -Level "INFO"
    
    # Handle reboot if required
    if ($PhaseResults.RequiresReboot -and $Global:Config.Reboot.AutoRebootAfterPhase) {
        Write-Log "`n⚠ Phase requires reboot - initiating reboot sequence" -Level "WARNING"
        
        # Save final checkpoint before reboot
        Save-Checkpoint -CurrentPhase $PhaseNumber -CurrentTask "PhaseComplete" -Status "RebootRequired"
        
        # Invoke reboot
        Invoke-Reboot -Reason "Phase $PhaseNumber completed - reboot required"
        
        # Exit script - will resume after reboot via scheduled task
        Write-Log "Exiting script - will resume after reboot" -Level "INFO"
        if ($Global:TranscriptFile) {
            try {
                Stop-Transcript
            }
            catch {
                # Transcript may already be stopped
            }
        }
        exit 0
    }
    
    return $PhaseResults
}

function Invoke-Reboot {
    <#
    .SYNOPSIS
        Handles system reboot with proper notifications and state saving
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Reason
    )
    
    Write-Log "========================================" -Level "WARNING"
    Write-Log "REBOOT REQUIRED" -Level "WARNING"
    Write-Log "========================================" -Level "WARNING"
    Write-Log "Reason: $Reason" -Level "WARNING"
    
    $Global:RebootCount++
    
    if ($Global:RebootCount -gt $Global:Config.Reboot.MaxRebootsAllowed) {
        Write-Log "✗ Maximum reboot count exceeded ($($Global:Config.Reboot.MaxRebootsAllowed))" -Level "ERROR"
        Write-Log "This may indicate a reboot loop - manual intervention required" -Level "ERROR"
        return
    }
    
    Write-Log "Reboot count: $Global:RebootCount of $($Global:Config.Reboot.MaxRebootsAllowed)" -Level "INFO"
    
    # Ensure auto-resume task is registered
    if ($AutoResumeEnabled) {
        $TaskExists = Test-AutoResumeTaskExists
        if (-not $TaskExists) {
            Write-Log "Auto-resume task not found - re-registering" -Level "WARNING"
            Register-AutoResumeTask
        }
    }
    
    # Notify user
    if ($Global:Config.Reboot.NotifyUserBeforeReboot) {
        $NotificationSeconds = $Global:Config.Reboot.UserNotificationSeconds
        $Message = $Global:Config.Reboot.RebootMessage
        Write-Log "Notifying user - $NotificationSeconds second countdown" -Level "INFO"
        
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $notification = New-Object System.Windows.Forms.NotifyIcon
            $notification.Icon = [System.Drawing.SystemIcons]::Information
            $notification.BalloonTipTitle = "System Restart Required"
            $notification.BalloonTipText = "$Message (Reboot $Global:RebootCount of $($Global:Config.Reboot.MaxRebootsAllowed))"
            $notification.Visible = $True
            $notification.ShowBalloonTip(30000)
        }
        catch {
            Write-Log "Failed to show user notification: $_" -Level "DEBUG"
        }
        
        # Brief countdown
        $SleepSeconds = [Math]::Min(30, $NotificationSeconds)
        Start-Sleep -Seconds $SleepSeconds
    }
    
    Write-Log "Initiating system restart..." -Level "WARNING"
    
    # Stop transcript before reboot
    if ($Global:TranscriptFile) {
        try {
            Stop-Transcript
        }
        catch {
            # Transcript may already be stopped
        }
    }
    
    # Restart computer
    Restart-Computer -Force
}

#endregion

#region REPORTING FUNCTIONS
#==============================================================================

function Generate-FinalReport {
    <#
    .SYNOPSIS
        Generates final orchestration report
    #>
    
    Write-Log "`n========================================" -Level "INFO"
    Write-Log "ORCHESTRATION COMPLETE - FINAL REPORT" -Level "INFO"
    Write-Log "========================================" -Level "INFO"
    
    $TotalDuration = ((Get-Date) - $ScriptStartTime).TotalMinutes
    $TotalTasks = 0
    foreach ($PhaseResult in $Global:ExecutionResults) {
        $TotalTasks += $PhaseResult.Tasks.Count
    }
    
    Write-Log "`nExecution Summary:" -Level "INFO"
    Write-Log "  Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $(Get-Date)" -Level "INFO"
    Write-Log "  Total Duration: $([math]::Round($TotalDuration, 2)) minutes" -Level "INFO"
    Write-Log "  Total Phases: $($Global:ExecutionResults.Count)" -Level "INFO"
    Write-Log "  Total Tasks: $TotalTasks" -Level "INFO"
    Write-Log "  Successful: $Global:SuccessCount" -Level "SUCCESS"
    Write-Log "  Failed: $Global:ErrorCount" -Level $(if($Global:ErrorCount -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $Global:WarningCount" -Level $(if($Global:WarningCount -gt 0){"WARNING"}else{"INFO"})
    Write-Log "  Reboots: $Global:RebootCount" -Level "INFO"
    
    # Phase-by-phase summary
    Write-Log "`nPhase Results:" -Level "INFO"
    foreach ($PhaseResult in $Global:ExecutionResults) {
        # Skip entries with empty PhaseNumber or PhaseName
        if ([string]::IsNullOrWhiteSpace($PhaseResult.PhaseNumber) -or [string]::IsNullOrWhiteSpace($PhaseResult.PhaseName)) {
            continue
        }

        $PhaseStatus = $PhaseResult.Status
        $StatusLevel = switch ($PhaseStatus) {
            "Success" { "SUCCESS" }
            "Failed" { "ERROR" }
            "PartialSuccess" { "WARNING" }
            default { "INFO" }
        }
        Write-Log "  $($PhaseResult.PhaseNumber): $($PhaseResult.PhaseName) - $PhaseStatus" -Level $StatusLevel
    }
    
    # Failed tasks detail
    if ($Global:ErrorCount -gt 0) {
        Write-Log "`nFailed Tasks:" -Level "ERROR"
        foreach ($PhaseResult in $Global:ExecutionResults) {
            $FailedTasks = $PhaseResult.Tasks | Where-Object { $_.Status -eq "Failed" }
            foreach ($Task in $FailedTasks) {
                Write-Log "  [$($Task.TaskID)] $($Task.TaskName): $($Task.Message)" -Level "ERROR"
            }
        }
    }
    
    Write-Log "========================================`n" -Level "INFO"
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    # Clear screen and show banner
    Clear-Host
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ENTERPRISE DESKTOP/LAPTOP ORCHESTRATION ENGINE                    ║
║                                                                       ║
║     Windows Desktop PC Configuration Tool                             ║
║                                                                       ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($Global:IsResuming){'RESUME'}else{'INITIAL RUN'})`n" -ForegroundColor $(if($Global:IsResuming){'Yellow'}else{'Green'})
    
    # Initialize state
    $Global:OrchestrationState = @{
        CompletedTasks = @()
        FailedTasks = @()
        ActiveSourcePath = $null
        DeviceType = "Unknown"
    }
    
    # Load configuration
    if (-not (Load-Configuration)) {
        Write-Host "`nFATAL ERROR: Failed to load configuration. Exiting." -ForegroundColor Red
        exit 1
    }
    
    # Initialize logging
    if (-not (Initialize-Logging)) {
        Write-Host "`nFATAL ERROR: Failed to initialize logging. Exiting." -ForegroundColor Red
        exit 1
    }
    
    Write-Log "========================================" -Level "INFO"
    Write-Log "ORCHESTRATION ENGINE STARTED" -Level "INFO"
    Write-Log "========================================" -Level "INFO"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Script Path: $ScriptPath" -Level "INFO"
    Write-Log "Execution Mode: $($Global:Config.Orchestration.ExecutionMode)" -Level "INFO"
    Write-Log "Dry Run: $($DryRun -or $Global:Config.Orchestration.EnableDryRun)" -Level "INFO"
    Write-Log "Auto-Resume: $AutoResumeEnabled" -Level "INFO"
    
    # Load checkpoint if resuming
    if ($Resume -or $Global:IsResuming) {
        $CheckpointData = Load-Checkpoint
        if ($CheckpointData) {
            $Global:OrchestrationState.CompletedTasks = $CheckpointData.CompletedTasks
            $Global:OrchestrationState.FailedTasks = $CheckpointData.FailedTasks
            $Global:RebootCount = $CheckpointData.RebootCount
            $Global:ExecutionResults = $CheckpointData.ExecutionResults

            Write-Log "Resumed with $($Global:OrchestrationState.CompletedTasks.Count) completed tasks" -Level "SUCCESS"
        }
        else {
            Write-Log "No valid checkpoint found - starting fresh" -Level "WARNING"
        }
    }
    else {
        # Initial run - register auto-resume task
        if ($AutoResumeEnabled) {
            Register-AutoResumeTask
        }
    }

    # Show execution plan (only on initial run, not resume)
    if (-not $Global:IsResuming) {
        Show-ExecutionPlan
    }

    # Run prerequisites (skip if resuming and already passed)
    if (-not $Global:IsResuming -or $Global:OrchestrationState.CompletedTasks.Count -eq 0) {
        Write-Log "`nRunning prerequisite checks..." -Level "INFO"
        if (-not (Test-Prerequisites)) {
            Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
            Unregister-AutoResumeTask
            exit 1
        }
    }
    else {
        Write-Log "`nSkipping prerequisite checks (resuming from checkpoint)" -Level "INFO"
    }
    
    # Determine which phases to run
    $PhasesToRun = if ($Phase -eq "All") {
        @("Phase1", "Phase2", "Phase3", "Phase4", "Phase5", "Phase6", "Phase7")
    } else {
        @($Phase)
    }
    
    Write-Log "`nPhases to execute: $($PhasesToRun -join ', ')" -Level "INFO"
    
    # Execute phases
    foreach ($PhaseKey in $PhasesToRun) {
        $PhaseConfig = $Global:Config.Phases[$PhaseKey]
        
        if (-not $PhaseConfig) {
            Write-Log "Phase configuration not found: $PhaseKey" -Level "WARNING"
            continue
        }
        
        try {
            $PhaseResult = Invoke-Phase -PhaseConfig $PhaseConfig -PhaseNumber $PhaseKey
            $Global:ExecutionResults += $PhaseResult
            
            # Check if we should stop
            if ($PhaseResult.Status -eq "Failed" -and $PhaseConfig.StopOnPhaseFailure) {
                Write-Log "Critical phase failed - stopping orchestration" -Level "ERROR"
                break
            }
        }
        catch {
            Write-Log "Unhandled error in phase $PhaseKey : $_" -Level "ERROR"
            $Global:ErrorCount++
            
            if ($PhaseConfig.StopOnPhaseFailure) {
                Write-Log "Stopping orchestration due to phase failure" -Level "ERROR"
                break
            }
        }
    }
    
    # Generate final report
    Generate-FinalReport
    
    # Clean up auto-resume task (orchestration complete)
    if ($AutoResumeEnabled) {
        Unregister-AutoResumeTask
    }
    
    # Clean up checkpoint file on successful completion
    if ($Global:ErrorCount -eq 0) {
        Remove-Checkpoint
    }
    else {
        Write-Log "Checkpoint file retained due to errors - can be used for troubleshooting" -Level "INFO"
    }
    
    # Final exit code
    $ExitCode = if ($Global:ErrorCount -eq 0) { 0 } else { 1 }
    
    Write-Log "`nOrchestration engine exiting with code: $ExitCode" -Level "INFO"
    
    # Stop transcript
    if ($Global:TranscriptFile) {
        try {
            Stop-Transcript
        }
        catch {
            # Already stopped or never started
        }
    }
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    # Try to clean up
    if ($AutoResumeEnabled) {
        Unregister-AutoResumeTask
    }
    
    if ($Global:TranscriptFile) {
        try {
            Stop-Transcript
        }
        catch {
            # Ignore
        }
    }
    
    exit 99
}

#endregion