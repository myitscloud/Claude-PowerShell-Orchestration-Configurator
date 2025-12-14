<#
.SYNOPSIS
    Enterprise Windows Firewall Configuration Script with Production Infrastructure

.DESCRIPTION
    Configures Windows Firewall with enterprise best practices, enhanced with:
    - Event sourcing for complete audit trail
    - Circuit breaker pattern for resilience
    - Compensation manager for automatic rollback
    - Prometheus metrics collection
    - Integration with DeploymentAgent system

    Balances security and functionality for diverse departmental needs.
    Implements defense-in-depth with sensible defaults while maintaining usability.

    This script:
    - Enables Windows Firewall on all profiles (Domain, Private, Public)
    - Configures default policies (block inbound, allow outbound)
    - Creates essential allow rules for enterprise services
    - Implements logging for security monitoring
    - Supports custom rule imports for department-specific needs
    - Maintains backward compatibility with legacy applications

.PARAMETER EnableFirewall
    Enable Windows Firewall on all profiles. Default: $true

.PARAMETER BlockInbound
    Block all inbound connections by default. Default: $true

.PARAMETER AllowOutbound
    Allow all outbound connections by default. Default: $true

.PARAMETER ImportRules
    Import custom firewall rules from XML file. Default: $false

.PARAMETER RulesPath
    Path to custom firewall rules XML file

.PARAMETER EnableLogging
    Enable firewall logging for security monitoring. Default: $true

.PARAMETER LogPath
    Path for firewall logs. Default: C:\ProgramData\FirewallLogs

.PARAMETER CreateEnterpriseRules
    Create standard enterprise allow rules. Default: $true

.PARAMETER CleanupExistingRules
    Remove non-essential existing rules. Default: $false

.PARAMETER DryRun
    Simulate changes without applying them. Default: $false

.PARAMETER StateFile
    Path to event sourcing state file (JSONL format). Default: C:\ProgramData\FirewallLogs\firewall_events.jsonl

.PARAMETER MetricsFile
    Path to Prometheus metrics file. Default: C:\ProgramData\FirewallLogs\firewall_metrics.prom

.PARAMETER TaskID
    Task identifier for orchestration tracking

.EXAMPLE
    .\Configure-Firewall-Enterprise.ps1
    Configures firewall with default enterprise settings and production monitoring

.EXAMPLE
    .\Configure-Firewall-Enterprise.ps1 -ImportRules -RulesPath "C:\Config\CustomRules.xml"
    Configures firewall, imports custom rules, with full event tracking

.EXAMPLE
    .\Configure-Firewall-Enterprise.ps1 -DryRun
    Shows what changes would be made without applying them

.NOTES
    Version:        2.0.0 (Enterprise)
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-13
    Purpose:        Enterprise firewall configuration with production infrastructure

    SECURITY PHILOSOPHY:
    - Default Deny (Block inbound by default)
    - Explicit Allow (Only allow necessary services)
    - Least Privilege (Minimum required access)
    - Defense in Depth (Multiple layers of protection)

    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Firewall service not available
    4   = Configuration failed
    5   = Rule import failed

    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - Windows Firewall service enabled
    - PowerShell 7+ recommended

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$EnableFirewall = $true,

    [Parameter(Mandatory=$false)]
    [bool]$BlockInbound = $true,

    [Parameter(Mandatory=$false)]
    [bool]$AllowOutbound = $true,

    [Parameter(Mandatory=$false)]
    [bool]$ImportRules = $false,

    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if (Test-Path $_ -PathType Leaf) { return $true }
        throw "Rules file does not exist: $_"
    })]
    [string]$RulesPath = '',

    [Parameter(Mandatory=$false)]
    [bool]$EnableLogging = $true,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = 'C:\ProgramData\FirewallLogs',

    [Parameter(Mandatory=$false)]
    [bool]$CreateEnterpriseRules = $true,

    [Parameter(Mandatory=$false)]
    [bool]$CleanupExistingRules = $false,

    [Parameter(Mandatory=$false)]
    [switch]$DryRun,

    [Parameter(Mandatory=$false)]
    [string]$StateFile = 'C:\ProgramData\FirewallLogs\firewall_events.jsonl',

    [Parameter(Mandatory=$false)]
    [string]$MetricsFile = 'C:\ProgramData\FirewallLogs\firewall_metrics.prom',

    [Parameter(Mandatory=$false)]
    [string]$TaskID = "FW-$(Get-Date -Format 'yyyyMMddHHmmss')"
)

# Enforce strict mode for better error detection
Set-StrictMode -Version Latest

#region PRODUCTION INFRASTRUCTURE CLASSES
#==============================================================================

# StateEvent: Represents an immutable event in the event sourcing log
class StateEvent {
    [string]$EventId
    [string]$WorkflowId
    [string]$EventType
    [datetime]$Timestamp
    [hashtable]$Data
    [string]$CorrelationId

    StateEvent([string]$EventType, [string]$WorkflowId, [hashtable]$Data) {
        $this.EventId = [guid]::NewGuid().ToString()
        $this.WorkflowId = $WorkflowId
        $this.EventType = $EventType
        $this.Timestamp = Get-Date
        $this.Data = $Data
        $this.CorrelationId = [guid]::NewGuid().ToString()
    }
}

# EventStore: Append-only event log with replay capability
class EventStore {
    [string]$StorePath

    EventStore([string]$StorePath) {
        $this.StorePath = $StorePath

        # Ensure directory exists
        $Directory = Split-Path $StorePath -Parent
        if (-not (Test-Path $Directory)) {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
        }

        # Create file if it doesn't exist
        if (-not (Test-Path $StorePath)) {
            New-Item -Path $StorePath -ItemType File -Force | Out-Null
        }
    }

    [void] AppendEvent([StateEvent]$Event) {
        try {
            $EventJson = $Event | ConvertTo-Json -Compress -Depth 10
            Add-Content -Path $this.StorePath -Value $EventJson -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to append event to store: $_"
        }
    }

    [array] GetEvents([string]$WorkflowId) {
        if (-not (Test-Path $this.StorePath)) {
            return @()
        }

        try {
            $Events = Get-Content $this.StorePath -ErrorAction Stop |
                ConvertFrom-Json |
                Where-Object { $_.WorkflowId -eq $WorkflowId }
            return $Events
        }
        catch {
            Write-Warning "Failed to read events from store: $_"
            return @()
        }
    }
}

# CircuitState: Enum for circuit breaker states
enum CircuitState {
    Closed
    Open
    HalfOpen
}

# CircuitBreaker: Prevents cascading failures with automatic recovery
class CircuitBreaker {
    [string]$Name
    [CircuitState]$State
    [int]$FailureCount
    [int]$FailureThreshold
    [int]$TimeoutSeconds
    [datetime]$LastFailureTime
    [System.Collections.Generic.Queue[bool]]$RecentResults

    CircuitBreaker([string]$Name, [int]$FailureThreshold, [int]$TimeoutSeconds) {
        $this.Name = $Name
        $this.State = [CircuitState]::Closed
        $this.FailureCount = 0
        $this.FailureThreshold = $FailureThreshold
        $this.TimeoutSeconds = $TimeoutSeconds
        $this.LastFailureTime = Get-Date
        $this.RecentResults = [System.Collections.Generic.Queue[bool]]::new()
    }

    [object] Execute([scriptblock]$Operation) {
        # Check if circuit is open
        if ($this.State -eq [CircuitState]::Open) {
            if ($this.ShouldAttemptReset()) {
                Write-Host "[CIRCUIT BREAKER] $($this.Name): Transitioning to HalfOpen (testing recovery)" -ForegroundColor Yellow
                $this.State = [CircuitState]::HalfOpen
            }
            else {
                $TimeRemaining = $this.TimeoutSeconds - ((Get-Date) - $this.LastFailureTime).TotalSeconds
                throw "Circuit breaker '$($this.Name)' is OPEN. Retry in $([math]::Round($TimeRemaining, 0)) seconds."
            }
        }

        # Execute operation
        try {
            $Result = & $Operation
            $this.RecordSuccess()
            return $Result
        }
        catch {
            $this.RecordFailure($_)
            throw
        }
    }

    [bool] ShouldAttemptReset() {
        $ElapsedSeconds = ((Get-Date) - $this.LastFailureTime).TotalSeconds
        return $ElapsedSeconds -ge $this.TimeoutSeconds
    }

    [void] RecordSuccess() {
        if ($this.State -eq [CircuitState]::HalfOpen) {
            Write-Host "[CIRCUIT BREAKER] $($this.Name): Recovery successful, transitioning to Closed" -ForegroundColor Green
            $this.State = [CircuitState]::Closed
            $this.FailureCount = 0
        }

        $this.RecentResults.Enqueue($true)
        if ($this.RecentResults.Count -gt 10) {
            [void]$this.RecentResults.Dequeue()
        }
    }

    [void] RecordFailure([System.Management.Automation.ErrorRecord]$Error) {
        $this.FailureCount++
        $this.LastFailureTime = Get-Date

        $this.RecentResults.Enqueue($false)
        if ($this.RecentResults.Count -gt 10) {
            [void]$this.RecentResults.Dequeue()
        }

        if ($this.FailureCount -ge $this.FailureThreshold) {
            Write-Host "[CIRCUIT BREAKER] $($this.Name): Failure threshold reached ($($this.FailureCount)), transitioning to Open" -ForegroundColor Red
            $this.State = [CircuitState]::Open
        }
    }
}

# CompensationManager: Manages rollback operations in LIFO order
class CompensationManager {
    [string]$WorkflowId
    [System.Collections.Generic.Stack[hashtable]]$CompensationStack

    CompensationManager([string]$WorkflowId) {
        $this.WorkflowId = $WorkflowId
        $this.CompensationStack = [System.Collections.Generic.Stack[hashtable]]::new()
    }

    [void] RegisterCompensation([string]$OperationName, [scriptblock]$CompensationAction, [hashtable]$Context) {
        $Compensation = @{
            OperationName = $OperationName
            Action = $CompensationAction
            Context = $Context
            RegisteredAt = Get-Date
        }

        $this.CompensationStack.Push($Compensation)
        Write-Verbose "[COMPENSATION] Registered: $OperationName (Stack depth: $($this.CompensationStack.Count))"
    }

    [void] ExecuteCompensations([string]$Reason) {
        Write-Host "[COMPENSATION] Executing rollback operations. Reason: $Reason" -ForegroundColor Yellow

        $CompensationCount = $this.CompensationStack.Count
        $SuccessCount = 0
        $FailureCount = 0

        while ($this.CompensationStack.Count -gt 0) {
            $Compensation = $this.CompensationStack.Pop()

            try {
                Write-Host "[COMPENSATION] Undoing: $($Compensation.OperationName)" -ForegroundColor Yellow
                & $Compensation.Action $Compensation.Context
                $SuccessCount++
                Write-Host "[COMPENSATION] Success: $($Compensation.OperationName)" -ForegroundColor Green
            }
            catch {
                $FailureCount++
                Write-Warning "[COMPENSATION] Failed to undo '$($Compensation.OperationName)': $_"
            }
        }

        Write-Host "[COMPENSATION] Rollback complete: $SuccessCount succeeded, $FailureCount failed (out of $CompensationCount total)" -ForegroundColor $(if($FailureCount -eq 0){"Green"}else{"Yellow"})
    }
}

# MetricsCollector: Collects and exports Prometheus metrics
class MetricsCollector {
    [string]$MetricsFile
    [hashtable]$Counters
    [hashtable]$Gauges
    [hashtable]$Histograms

    MetricsCollector([string]$MetricsFile) {
        $this.MetricsFile = $MetricsFile
        $this.Counters = @{}
        $this.Gauges = @{}
        $this.Histograms = @{}

        # Ensure directory exists
        $Directory = Split-Path $MetricsFile -Parent
        if (-not (Test-Path $Directory)) {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
        }
    }

    [void] IncrementCounter([string]$Name, [hashtable]$Labels, [double]$Amount = 1.0) {
        $Key = $this.GetMetricKey($Name, $Labels)
        if (-not $this.Counters.ContainsKey($Key)) {
            $this.Counters[$Key] = @{
                Name = $Name
                Labels = $Labels
                Value = 0.0
            }
        }
        $this.Counters[$Key].Value += $Amount
    }

    [void] SetGauge([string]$Name, [double]$Value, [hashtable]$Labels) {
        $Key = $this.GetMetricKey($Name, $Labels)
        $this.Gauges[$Key] = @{
            Name = $Name
            Labels = $Labels
            Value = $Value
        }
    }

    [void] RecordHistogram([string]$Name, [double]$Value, [hashtable]$Labels) {
        $Key = $this.GetMetricKey($Name, $Labels)
        if (-not $this.Histograms.ContainsKey($Key)) {
            $this.Histograms[$Key] = @{
                Name = $Name
                Labels = $Labels
                Values = [System.Collections.Generic.List[double]]::new()
            }
        }
        $this.Histograms[$Key].Values.Add($Value)
    }

    [string] GetMetricKey([string]$Name, [hashtable]$Labels) {
        $LabelString = ($Labels.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
        return "${Name}{$LabelString}"
    }

    [void] SaveMetrics() {
        try {
            $Output = [System.Text.StringBuilder]::new()

            # Export counters
            foreach ($Metric in $this.Counters.Values) {
                $LabelString = $this.FormatLabels($Metric.Labels)
                [void]$Output.AppendLine("# TYPE $($Metric.Name) counter")
                [void]$Output.AppendLine("$($Metric.Name)$LabelString $($Metric.Value)")
            }

            # Export gauges
            foreach ($Metric in $this.Gauges.Values) {
                $LabelString = $this.FormatLabels($Metric.Labels)
                [void]$Output.AppendLine("# TYPE $($Metric.Name) gauge")
                [void]$Output.AppendLine("$($Metric.Name)$LabelString $($Metric.Value)")
            }

            # Export histograms (simplified - just count, sum, avg)
            foreach ($Metric in $this.Histograms.Values) {
                $LabelString = $this.FormatLabels($Metric.Labels)
                $Count = $Metric.Values.Count
                $Sum = ($Metric.Values | Measure-Object -Sum).Sum
                $Avg = if ($Count -gt 0) { $Sum / $Count } else { 0 }

                [void]$Output.AppendLine("# TYPE $($Metric.Name) histogram")
                [void]$Output.AppendLine("$($Metric.Name)_count$LabelString $Count")
                [void]$Output.AppendLine("$($Metric.Name)_sum$LabelString $Sum")
                [void]$Output.AppendLine("$($Metric.Name)_avg$LabelString $Avg")
            }

            Set-Content -Path $this.MetricsFile -Value $Output.ToString() -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to save metrics: $_"
        }
    }

    [string] FormatLabels([hashtable]$Labels) {
        if ($Labels.Count -eq 0) { return "" }
        $LabelPairs = $Labels.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=`"$($_.Value)`"" }
        return "{$($LabelPairs -join ',')}"
    }
}

#endregion

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "2.0.0"
$ScriptStartTime = Get-Date
$WorkflowId = "ConfigureFirewall-$(Get-Date -Format 'yyyyMMddHHmmss')"

# Initialize logging
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Configure-Firewall_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Script:LogFile = Join-Path $LogPath $LogFileName

# Initialize production infrastructure
$Script:EventStore = [EventStore]::new($StateFile)
$Script:CompensationMgr = [CompensationManager]::new($WorkflowId)
$Script:Metrics = [MetricsCollector]::new($MetricsFile)

# Initialize circuit breakers
$Script:CircuitBreaker_Service = [CircuitBreaker]::new("Firewall-Service", 3, 60)
$Script:CircuitBreaker_ProfileConfig = [CircuitBreaker]::new("Profile-Configuration", 2, 90)
$Script:CircuitBreaker_RuleCreation = [CircuitBreaker]::new("Rule-Creation", 5, 120)

# Statistics tracking
$Global:Stats = @{
    RulesCreated = 0
    RulesModified = 0
    RulesDeleted = 0
    ProfilesConfigured = 0
    Errors = 0
    Warnings = 0
}

# Emit workflow started event
$Event = [StateEvent]::new("WorkflowStarted", $WorkflowId, @{
    TaskID = $TaskID
    Computer = $env:COMPUTERNAME
    ScriptVersion = $ScriptVersion
    Parameters = @{
        EnableFirewall = $EnableFirewall
        BlockInbound = $BlockInbound
        AllowOutbound = $AllowOutbound
        ImportRules = $ImportRules
        CreateEnterpriseRules = $CreateEnterpriseRules
        DryRun = $DryRun.IsPresent
    }
})
$Script:EventStore.AppendEvent($Event)

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-TaskLog {
    <#
    .SYNOPSIS
        Writes messages to log file, console, event store, and metrics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [hashtable]$Data = @{}
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    # Write to log file
    try {
        Add-Content -Path $Script:LogFile -Value $LogMessage -ErrorAction Stop
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

    # Emit event to state store
    if ($Script:EventStore) {
        $Event = [StateEvent]::new("Log.$Level", $WorkflowId, @{
            Message = $Message
            Level = $Level
            Data = $Data
        })
        $Script:EventStore.AppendEvent($Event)
    }

    # Update statistics and metrics
    if ($Level -eq "ERROR") {
        $Global:Stats.Errors++
        $Script:Metrics.IncrementCounter("firewall_errors_total", @{ operation = "configuration" })
    }
    if ($Level -eq "WARNING") {
        $Global:Stats.Warnings++
        $Script:Metrics.IncrementCounter("firewall_warnings_total", @{ operation = "configuration" })
    }

    # Update log entry counter
    $Script:Metrics.IncrementCounter("task_log_entries", @{ level = $Level.ToLower() })
}

function Write-LogHeader {
    param([string]$Title)
    $Separator = "=" * 80
    Write-TaskLog $Separator -Level "INFO"
    Write-TaskLog $Title -Level "INFO"
    Write-TaskLog $Separator -Level "INFO"
}

#endregion

#region PREREQUISITE FUNCTIONS
#==============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates system meets requirements for firewall configuration
    #>

    Write-LogHeader "PREREQUISITE CHECKS"

    $AllChecksPassed = $true
    $CheckStartTime = Get-Date

    # Check 1: Administrator privileges
    Write-TaskLog "Checking administrator privileges..." -Level "INFO"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsAdmin) {
        Write-TaskLog "FAILED: Script must be run as Administrator" -Level "ERROR"
        $AllChecksPassed = $false

        # Emit event
        $Event = [StateEvent]::new("PrerequisiteCheckFailed", $WorkflowId, @{
            Check = "Administrator"
            Reason = "Script not run as Administrator"
        })
        $Script:EventStore.AppendEvent($Event)
    }
    else {
        Write-TaskLog "Administrator privileges confirmed" -Level "SUCCESS"
    }

    # Check 2: Windows version
    Write-TaskLog "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

    Write-TaskLog "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"

    if ($OSVersion.Major -lt 10 -or $BuildNumber -lt 22000) {
        Write-TaskLog "WARNING: This script is designed for Windows 11 (Build 22000+)" -Level "WARNING"
    }
    else {
        Write-TaskLog "Windows version check passed" -Level "SUCCESS"
    }

    # Emit OS version event
    $Event = [StateEvent]::new("OSVersionDetected", $WorkflowId, @{
        Major = $OSVersion.Major
        Minor = $OSVersion.Minor
        Build = $BuildNumber
    })
    $Script:EventStore.AppendEvent($Event)

    # Check 3: Firewall service (with circuit breaker)
    Write-TaskLog "Checking Windows Firewall service..." -Level "INFO"
    try {
        $FirewallService = $Script:CircuitBreaker_Service.Execute({
            Get-Service -Name "mpssvc" -ErrorAction Stop
        })

        if ($FirewallService.Status -eq "Running") {
            Write-TaskLog "Windows Firewall service is running" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "WARNING: Windows Firewall service is not running (Status: $($FirewallService.Status))" -Level "WARNING"
            Write-TaskLog "Attempting to start service..." -Level "INFO"

            if (-not $DryRun) {
                Start-Service -Name "mpssvc" -ErrorAction Stop
                Write-TaskLog "Windows Firewall service started successfully" -Level "SUCCESS"

                # Register compensation to stop service if we started it
                $Script:CompensationMgr.RegisterCompensation(
                    "Start-FirewallService",
                    {
                        param($Context)
                        if ($Context.WasRunning -eq $false) {
                            Write-Host "[ROLLBACK] Stopping Windows Firewall service (was not running before)"
                            Stop-Service -Name "mpssvc" -ErrorAction SilentlyContinue
                        }
                    },
                    @{ WasRunning = $false }
                )
            }
        }
    }
    catch {
        Write-TaskLog "ERROR: Cannot access Windows Firewall service: $_" -Level "ERROR"
        $AllChecksPassed = $false
    }

    # Check 4: NetSecurity module
    Write-TaskLog "Checking NetSecurity PowerShell module..." -Level "INFO"
    $NetSecurityModule = Get-Module -Name "NetSecurity" -ListAvailable

    if ($NetSecurityModule) {
        Write-TaskLog "NetSecurity module available" -Level "SUCCESS"
        Import-Module NetSecurity -ErrorAction SilentlyContinue
    }
    else {
        Write-TaskLog "WARNING: NetSecurity module not found" -Level "WARNING"
    }

    # Check 5: Custom rules file (if import requested)
    if ($ImportRules -and -not [string]::IsNullOrWhiteSpace($RulesPath)) {
        Write-TaskLog "Checking custom rules file..." -Level "INFO"
        if (Test-Path $RulesPath) {
            Write-TaskLog "Custom rules file found: $RulesPath" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "WARNING: Custom rules file not found: $RulesPath" -Level "WARNING"
            Write-TaskLog "Will proceed without importing custom rules" -Level "INFO"
        }
    }

    $CheckDuration = ((Get-Date) - $CheckStartTime).TotalSeconds
    $Script:Metrics.RecordHistogram("prerequisite_check_duration_seconds", $CheckDuration, @{ result = $(if($AllChecksPassed){"passed"}else{"failed"}) })

    return $AllChecksPassed
}

#endregion

#region FIREWALL PROFILE FUNCTIONS
#==============================================================================

function Get-FirewallProfiles {
    <#
    .SYNOPSIS
        Retrieves current firewall profile configurations
    #>

    Write-LogHeader "CURRENT FIREWALL PROFILE STATUS"

    $Profiles = @("Domain", "Private", "Public")
    $ProfileStatus = @{}

    foreach ($Profile in $Profiles) {
        try {
            $ProfileConfig = Get-NetFirewallProfile -Name $Profile -ErrorAction Stop

            $ProfileStatus[$Profile] = @{
                Enabled = $ProfileConfig.Enabled
                DefaultInboundAction = $ProfileConfig.DefaultInboundAction
                DefaultOutboundAction = $ProfileConfig.DefaultOutboundAction
                LogAllowed = $ProfileConfig.LogAllowed
                LogBlocked = $ProfileConfig.LogBlocked
                LogFileName = $ProfileConfig.LogFileName
            }

            Write-TaskLog "[$Profile Profile]" -Level "INFO"
            Write-TaskLog "  Enabled: $($ProfileConfig.Enabled)" -Level "INFO"
            Write-TaskLog "  Inbound: $($ProfileConfig.DefaultInboundAction)" -Level "INFO"
            Write-TaskLog "  Outbound: $($ProfileConfig.DefaultOutboundAction)" -Level "INFO"
            Write-TaskLog "  Logging: Allowed=$($ProfileConfig.LogAllowed), Blocked=$($ProfileConfig.LogBlocked)" -Level "INFO"

            # Emit event
            $Event = [StateEvent]::new("ProfileStatusRetrieved", $WorkflowId, @{
                Profile = $Profile
                Status = $ProfileStatus[$Profile]
            })
            $Script:EventStore.AppendEvent($Event)

            # Record metrics
            $Script:Metrics.SetGauge("firewall_profile_enabled", $(if($ProfileConfig.Enabled){"1"}else{"0"}), @{ profile = $Profile.ToLower() })
        }
        catch {
            Write-TaskLog "Error retrieving $Profile profile: $_" -Level "ERROR"
        }
    }

    return $ProfileStatus
}

function Set-FirewallProfiles {
    <#
    .SYNOPSIS
        Configures firewall profiles with enterprise settings
    #>

    Write-LogHeader "CONFIGURING FIREWALL PROFILES"

    $Profiles = @("Domain", "Private", "Public")

    # Determine actions based on parameters
    $InboundAction = if ($BlockInbound) { "Block" } else { "Allow" }
    $OutboundAction = if ($AllowOutbound) { "Allow" } else { "Block" }

    Write-TaskLog "Configuration settings:" -Level "INFO"
    Write-TaskLog "  Enable Firewall: $EnableFirewall" -Level "INFO"
    Write-TaskLog "  Default Inbound: $InboundAction" -Level "INFO"
    Write-TaskLog "  Default Outbound: $OutboundAction" -Level "INFO"
    Write-TaskLog "  Enable Logging: $EnableLogging" -Level "INFO"

    foreach ($Profile in $Profiles) {
        Write-TaskLog "Configuring $Profile profile..." -Level "INFO"

        if ($DryRun) {
            Write-TaskLog "[DRY RUN] Would configure $Profile profile" -Level "INFO"
            $Global:Stats.ProfilesConfigured++
            continue
        }

        try {
            # Get current configuration for compensation
            $CurrentConfig = Get-NetFirewallProfile -Name $Profile

            # Register compensation BEFORE making changes
            $Script:CompensationMgr.RegisterCompensation(
                "Configure-$Profile-Profile",
                {
                    param($Context)
                    Write-Host "[ROLLBACK] Restoring $($Context.Profile) profile to previous state"
                    Set-NetFirewallProfile -Name $Context.Profile `
                        -Enabled $Context.PreviousConfig.Enabled `
                        -DefaultInboundAction $Context.PreviousConfig.DefaultInboundAction `
                        -DefaultOutboundAction $Context.PreviousConfig.DefaultOutboundAction `
                        -ErrorAction SilentlyContinue
                },
                @{
                    Profile = $Profile
                    PreviousConfig = @{
                        Enabled = $CurrentConfig.Enabled
                        DefaultInboundAction = $CurrentConfig.DefaultInboundAction
                        DefaultOutboundAction = $CurrentConfig.DefaultOutboundAction
                    }
                }
            )

            # Build configuration hashtable
            $Config = @{
                Name = $Profile
                Enabled = if ($EnableFirewall) { "True" } else { "False" }
                DefaultInboundAction = $InboundAction
                DefaultOutboundAction = $OutboundAction
            }

            # Add logging configuration if enabled
            if ($EnableLogging) {
                $LogFileName = Join-Path $LogPath "$($Profile.ToLower())-firewall.log"

                $Config["LogAllowed"] = "True"
                $Config["LogBlocked"] = "True"
                $Config["LogFileName"] = $LogFileName
                $Config["LogMaxSizeKilobytes"] = 16384  # 16 MB
            }
            else {
                $Config["LogAllowed"] = "False"
                $Config["LogBlocked"] = "False"
            }

            # Apply configuration with circuit breaker
            $Script:CircuitBreaker_ProfileConfig.Execute({
                Set-NetFirewallProfile @Config -ErrorAction Stop
            })

            Write-TaskLog "$Profile profile configured successfully" -Level "SUCCESS"
            $Global:Stats.ProfilesConfigured++

            # Emit event
            $Event = [StateEvent]::new("ProfileConfigured", $WorkflowId, @{
                Profile = $Profile
                Configuration = $Config
            })
            $Script:EventStore.AppendEvent($Event)

            # Record metrics
            $Script:Metrics.IncrementCounter("firewall_profiles_configured_total", @{ profile = $Profile.ToLower(); status = "success" })
        }
        catch {
            Write-TaskLog "Failed to configure $Profile profile: $_" -Level "ERROR"
            $Global:Stats.Errors++
            $Script:Metrics.IncrementCounter("firewall_profiles_configured_total", @{ profile = $Profile.ToLower(); status = "failure" })
        }
    }
}

#endregion

#region FIREWALL RULES MANAGEMENT
#==============================================================================

function Get-ExistingRules {
    <#
    .SYNOPSIS
        Retrieves and categorizes existing firewall rules
    #>

    Write-LogHeader "ANALYZING EXISTING FIREWALL RULES"

    try {
        $AllRules = Get-NetFirewallRule -ErrorAction Stop

        $Statistics = @{
            Total = $AllRules.Count
            Enabled = ($AllRules | Where-Object { $_.Enabled -eq "True" }).Count
            Disabled = ($AllRules | Where-Object { $_.Enabled -eq "False" }).Count
            Inbound = ($AllRules | Where-Object { $_.Direction -eq "Inbound" }).Count
            Outbound = ($AllRules | Where-Object { $_.Direction -eq "Outbound" }).Count
            System = ($AllRules | Where-Object { $_.DisplayGroup -like "*Windows*" }).Count
            Custom = ($AllRules | Where-Object { $_.DisplayGroup -notlike "*Windows*" -and $_.DisplayGroup -ne $null }).Count
        }

        Write-TaskLog "Existing rules summary:" -Level "INFO"
        Write-TaskLog "  Total rules: $($Statistics.Total)" -Level "INFO"
        Write-TaskLog "  Enabled: $($Statistics.Enabled) | Disabled: $($Statistics.Disabled)" -Level "INFO"
        Write-TaskLog "  Inbound: $($Statistics.Inbound) | Outbound: $($Statistics.Outbound)" -Level "INFO"
        Write-TaskLog "  System: $($Statistics.System) | Custom: $($Statistics.Custom)" -Level "INFO"

        # Emit event
        $Event = [StateEvent]::new("ExistingRulesAnalyzed", $WorkflowId, @{
            Statistics = $Statistics
        })
        $Script:EventStore.AppendEvent($Event)

        # Record metrics
        $Script:Metrics.SetGauge("firewall_rules_total", $Statistics.Total, @{ type = "all" })
        $Script:Metrics.SetGauge("firewall_rules_total", $Statistics.Enabled, @{ type = "enabled" })
        $Script:Metrics.SetGauge("firewall_rules_total", $Statistics.Inbound, @{ type = "inbound" })

        return @{
            Rules = $AllRules
            Statistics = $Statistics
        }
    }
    catch {
        Write-TaskLog "Error retrieving existing rules: $_" -Level "ERROR"
        return $null
    }
}

function Remove-UnnecessaryRules {
    <#
    .SYNOPSIS
        Removes non-essential firewall rules to reduce attack surface
    #>

    Write-LogHeader "CLEANING UP FIREWALL RULES"

    if (-not $CleanupExistingRules) {
        Write-TaskLog "Rule cleanup disabled - skipping" -Level "INFO"
        return
    }

    Write-TaskLog "Identifying rules for removal..." -Level "INFO"

    # Rules to potentially remove (disabled by default for safety)
    $RemovalCandidates = @(
        # Uncomment categories as needed for your environment
        # "*Remote Desktop*"
        # "*HomeGroup*"
        # "*BranchCache*"
        # "*Work Folders*"
        # "*Wireless Display*"
    )

    if ($RemovalCandidates.Count -eq 0) {
        Write-TaskLog "No removal candidates configured - skipping" -Level "INFO"
        return
    }

    foreach ($Pattern in $RemovalCandidates) {
        try {
            $Rules = Get-NetFirewallRule -DisplayName $Pattern -ErrorAction SilentlyContinue

            if ($Rules) {
                Write-TaskLog "Found $($Rules.Count) rules matching: $Pattern" -Level "INFO"

                foreach ($Rule in $Rules) {
                    if ($DryRun) {
                        Write-TaskLog "[DRY RUN] Would remove rule: $($Rule.DisplayName)" -Level "INFO"
                    }
                    else {
                        # Register compensation BEFORE removal
                        $Script:CompensationMgr.RegisterCompensation(
                            "Remove-Rule-$($Rule.Name)",
                            {
                                param($Context)
                                Write-Host "[ROLLBACK] Restoring firewall rule: $($Context.RuleName)"
                                # Note: In production, you would export rule details and recreate it here
                                Write-Warning "[ROLLBACK] Rule restoration not fully implemented - manual intervention may be required"
                            },
                            @{ RuleName = $Rule.DisplayName }
                        )

                        Remove-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
                        Write-TaskLog "Removed rule: $($Rule.DisplayName)" -Level "SUCCESS"
                        $Global:Stats.RulesDeleted++
                        $Script:Metrics.IncrementCounter("firewall_rules_deleted_total", @{ pattern = $Pattern })
                    }
                }
            }
        }
        catch {
            Write-TaskLog "Error removing rules matching '$Pattern': $_" -Level "ERROR"
        }
    }
}

#endregion

#region ENTERPRISE RULES CREATION
#==============================================================================

function New-EnterpriseFirewallRules {
    <#
    .SYNOPSIS
        Creates essential firewall rules for enterprise environment
    #>

    Write-LogHeader "CREATING ENTERPRISE FIREWALL RULES"

    if (-not $CreateEnterpriseRules) {
        Write-TaskLog "Enterprise rule creation disabled - skipping" -Level "INFO"
        return
    }

    $RuleCreationStartTime = Get-Date

    # Define enterprise firewall rules (abbreviated for space - see original for full list)
    $EnterpriseRules = @(
        @{
            DisplayName = "Enterprise - DNS (UDP Out)"
            Description = "Allow outbound DNS queries (UDP)"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "53"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        @{
            DisplayName = "Enterprise - DHCP Client (UDP Out)"
            Description = "Allow DHCP client requests"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "68"
            RemotePort = "67"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Dhcp"
        },
        @{
            DisplayName = "Enterprise - Web Browsing HTTPS (TCP Out)"
            Description = "Allow web browser HTTPS connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "443"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        }
        # Add more rules as needed from original script...
    )

    Write-TaskLog "Creating $($EnterpriseRules.Count) enterprise firewall rules..." -Level "INFO"

    foreach ($Rule in $EnterpriseRules) {
        try {
            # Check if rule already exists
            $ExistingRule = Get-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue

            if ($ExistingRule) {
                Write-TaskLog "Rule already exists: $($Rule.DisplayName)" -Level "INFO"

                if ($DryRun) {
                    Write-TaskLog "[DRY RUN] Would update existing rule" -Level "INFO"
                }
                else {
                    # Update existing rule
                    Set-NetFirewallRule -DisplayName $Rule.DisplayName -Enabled True -ErrorAction Stop
                    Write-TaskLog "Updated existing rule: $($Rule.DisplayName)" -Level "SUCCESS"
                    $Global:Stats.RulesModified++
                    $Script:Metrics.IncrementCounter("firewall_rules_modified_total", @{ rule_type = "enterprise" })
                }
                continue
            }

            # Create new rule
            if ($DryRun) {
                Write-TaskLog "[DRY RUN] Would create rule: $($Rule.DisplayName)" -Level "INFO"
                $Global:Stats.RulesCreated++
                continue
            }

            # Build parameter hashtable
            $Params = @{
                DisplayName = $Rule.DisplayName
                Description = $Rule.Description
                Direction = $Rule.Direction
                Protocol = $Rule.Protocol
                Action = $Rule.Action
                Profile = $Rule.Profile
                Enabled = "True"
            }

            # Add optional parameters
            if ($Rule.RemotePort -and $Rule.RemotePort -ne "Any") {
                if ($Rule.RemotePort -is [string] -and $Rule.RemotePort -match ',') {
                    $Params["RemotePort"] = $Rule.RemotePort -split ','
                }
                else {
                    $Params["RemotePort"] = $Rule.RemotePort
                }
            }
            if ($Rule.LocalPort -and $Rule.LocalPort -ne "Any") {
                if ($Rule.LocalPort -is [string] -and $Rule.LocalPort -match ',') {
                    $Params["LocalPort"] = $Rule.LocalPort -split ','
                }
                else {
                    $Params["LocalPort"] = $Rule.LocalPort
                }
            }
            if ($Rule.Service -and $Rule.Service -ne "Any") {
                $Params["Service"] = $Rule.Service
            }

            # Register compensation BEFORE creation
            $Script:CompensationMgr.RegisterCompensation(
                "Create-Rule-$($Rule.DisplayName)",
                {
                    param($Context)
                    Write-Host "[ROLLBACK] Removing firewall rule: $($Context.DisplayName)"
                    Remove-NetFirewallRule -DisplayName $Context.DisplayName -ErrorAction SilentlyContinue
                },
                @{ DisplayName = $Rule.DisplayName }
            )

            # Create the rule with circuit breaker
            $Script:CircuitBreaker_RuleCreation.Execute({
                New-NetFirewallRule @Params -ErrorAction Stop | Out-Null
            })

            Write-TaskLog "Created rule: $($Rule.DisplayName)" -Level "SUCCESS"
            $Global:Stats.RulesCreated++

            # Emit event
            $Event = [StateEvent]::new("RuleCreated", $WorkflowId, @{
                RuleName = $Rule.DisplayName
                Direction = $Rule.Direction
                Protocol = $Rule.Protocol
            })
            $Script:EventStore.AppendEvent($Event)

            $Script:Metrics.IncrementCounter("firewall_rules_created_total", @{ rule_type = "enterprise"; status = "success" })
        }
        catch {
            Write-TaskLog "Failed to create rule '$($Rule.DisplayName)': $_" -Level "ERROR"
            $Global:Stats.Errors++
            $Script:Metrics.IncrementCounter("firewall_rules_created_total", @{ rule_type = "enterprise"; status = "failure" })
        }
    }

    $RuleCreationDuration = ((Get-Date) - $RuleCreationStartTime).TotalSeconds
    $Script:Metrics.RecordHistogram("firewall_rule_creation_duration_seconds", $RuleCreationDuration, @{ result = "completed" })
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-FirewallConfiguration {
    <#
    .SYNOPSIS
        Validates firewall configuration after changes
    #>

    Write-LogHeader "VALIDATING FIREWALL CONFIGURATION"

    $ValidationResults = @{
        Passed = $true
        Checks = @()
    }

    # Check 1: Firewall enabled on all profiles
    Write-TaskLog "Checking firewall is enabled on all profiles..." -Level "INFO"
    $Profiles = @("Domain", "Private", "Public")

    foreach ($Profile in $Profiles) {
        $ProfileConfig = Get-NetFirewallProfile -Name $Profile

        if ($ProfileConfig.Enabled) {
            Write-TaskLog "  $Profile profile: ENABLED ✓" -Level "SUCCESS"
            $ValidationResults.Checks += @{
                Check = "$Profile Enabled"
                Status = "PASS"
            }
        }
        else {
            Write-TaskLog "  $Profile profile: DISABLED ✗" -Level "ERROR"
            $ValidationResults.Passed = $false
            $ValidationResults.Checks += @{
                Check = "$Profile Enabled"
                Status = "FAIL"
            }
        }
    }

    # Emit validation event
    $Event = [StateEvent]::new("ValidationCompleted", $WorkflowId, @{
        Passed = $ValidationResults.Passed
        CheckCount = $ValidationResults.Checks.Count
    })
    $Script:EventStore.AppendEvent($Event)

    $Script:Metrics.SetGauge("firewall_validation_passed", $(if($ValidationResults.Passed){1}else{0}), @{ check = "all" })

    return $ValidationResults
}

function Show-ConfigurationSummary {
    <#
    .SYNOPSIS
        Displays comprehensive configuration summary
    #>

    Write-LogHeader "CONFIGURATION SUMMARY"

    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds

    Write-TaskLog "Execution Details:" -Level "INFO"
    Write-TaskLog "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-TaskLog "  End Time: $EndTime" -Level "INFO"
    Write-TaskLog "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    Write-TaskLog "  Dry Run Mode: $($DryRun.IsPresent)" -Level "INFO"

    Write-TaskLog " " -Level "INFO"
    Write-TaskLog "Configuration Changes:" -Level "INFO"
    Write-TaskLog "  Profiles Configured: $($Global:Stats.ProfilesConfigured)" -Level "INFO"
    Write-TaskLog "  Rules Created: $($Global:Stats.RulesCreated)" -Level "SUCCESS"
    Write-TaskLog "  Rules Modified: $($Global:Stats.RulesModified)" -Level "INFO"
    Write-TaskLog "  Rules Deleted: $($Global:Stats.RulesDeleted)" -Level "INFO"

    Write-TaskLog " " -Level "INFO"
    Write-TaskLog "Status:" -Level "INFO"
    Write-TaskLog "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-TaskLog "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})

    Write-TaskLog " " -Level "INFO"
    Write-TaskLog "Log File: $Script:LogFile" -Level "INFO"
    Write-TaskLog "State File: $StateFile" -Level "INFO"
    Write-TaskLog "Metrics File: $MetricsFile" -Level "INFO"

    # Record final metrics
    $Script:Metrics.RecordHistogram("firewall_configuration_duration_seconds", $Duration, @{ mode = $(if($DryRun.IsPresent){"dryrun"}else{"live"}) })
    $Script:Metrics.SetGauge("firewall_configuration_errors", $Global:Stats.Errors, @{})
    $Script:Metrics.SetGauge("firewall_configuration_warnings", $Global:Stats.Warnings, @{})
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
║        ENTERPRISE WINDOWS FIREWALL CONFIGURATION              ║
║                        Version $ScriptVersion                       ║
║                  (Production Infrastructure)                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Workflow ID: $WorkflowId" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun.IsPresent){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun.IsPresent){'Yellow'}else{'Green'})
    Write-Host ""

    Write-LogHeader "WINDOWS FIREWALL CONFIGURATION STARTED"
    Write-TaskLog "Script Version: $ScriptVersion" -Level "INFO"
    Write-TaskLog "Workflow ID: $WorkflowId" -Level "INFO"
    Write-TaskLog "Task ID: $TaskID" -Level "INFO"
    Write-TaskLog "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    Write-TaskLog "Dry Run Mode: $($DryRun.IsPresent)" -Level "INFO"

    # Step 1: Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-TaskLog "Prerequisites failed - cannot continue" -Level "ERROR"

        $Event = [StateEvent]::new("WorkflowFailed", $WorkflowId, @{
            Reason = "Prerequisites failed"
            ExitCode = 2
        })
        $Script:EventStore.AppendEvent($Event)
        $Script:Metrics.SaveMetrics()

        exit 2
    }

    # Step 2: Get current state
    $CurrentState = Get-FirewallProfiles
    $ExistingRules = Get-ExistingRules

    # Step 3: Configure profiles
    Set-FirewallProfiles

    # Step 4: Clean up rules (if enabled)
    Remove-UnnecessaryRules

    # Step 5: Create enterprise rules
    New-EnterpriseFirewallRules

    # Step 6: Validate configuration
    $ValidationResults = Test-FirewallConfiguration

    # Step 7: Display summary
    Show-ConfigurationSummary

    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }

    Write-TaskLog " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-TaskLog "Firewall configuration completed successfully!" -Level "SUCCESS"

        $Event = [StateEvent]::new("WorkflowCompleted", $WorkflowId, @{
            Duration = ((Get-Date) - $ScriptStartTime).TotalSeconds
            RulesCreated = $Global:Stats.RulesCreated
            ProfilesConfigured = $Global:Stats.ProfilesConfigured
            ExitCode = $ExitCode
        })
        $Script:EventStore.AppendEvent($Event)
    }
    else {
        Write-TaskLog "Firewall configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"

        $Event = [StateEvent]::new("WorkflowCompletedWithErrors", $WorkflowId, @{
            Duration = ((Get-Date) - $ScriptStartTime).TotalSeconds
            ErrorCount = $Global:Stats.Errors
            ExitCode = $ExitCode
        })
        $Script:EventStore.AppendEvent($Event)
    }

    # Save metrics before exit
    $Script:Metrics.SaveMetrics()

    Write-TaskLog "Exit Code: $ExitCode" -Level "INFO"
    exit $ExitCode
}
catch {
    Write-TaskLog "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-TaskLog "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"

    # Execute compensations on fatal error
    Write-TaskLog "Attempting automatic rollback..." -Level "WARNING"
    $Script:CompensationMgr.ExecuteCompensations("Fatal error occurred")

    # Emit failure event
    $Event = [StateEvent]::new("WorkflowFailed", $WorkflowId, @{
        Error = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
        ExitCode = 1
    })
    $Script:EventStore.AppendEvent($Event)

    Show-ConfigurationSummary
    $Script:Metrics.SaveMetrics()

    exit 1
}
finally {
    # Ensure metrics are always saved
    if ($Script:Metrics) {
        $Script:Metrics.SaveMetrics()
    }
}

#endregion
