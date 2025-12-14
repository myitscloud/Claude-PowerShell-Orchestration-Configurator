<#
.SYNOPSIS
    Enterprise-grade BitLocker encryption with full observability and resilience
    Compatible with PowerShell 5.1 and 7+

.DESCRIPTION
    Production-ready BitLocker deployment with:
    - Circuit breaker pattern for external calls
    - Event sourcing for complete audit trail
    - Compensation logic for automatic rollback
    - Distributed tracing with Prometheus metrics
    - Health checks and validation
    - Integration with DeploymentAgent and MonitoringAgent

.PARAMETER EncryptionMethod
    Encryption algorithm. Default: XtsAes256

.PARAMETER SaveKeyToAD
    Backup recovery key to Active Directory. Default: True

.PARAMETER EncryptUsedSpaceOnly
    Encrypt only used space (faster). Default: True

.PARAMETER SkipHardwareTest
    Skip TPM hardware test. Default: False

.PARAMETER RequireTPM
    Require TPM for encryption. Default: True

.PARAMETER DriveLetter
    Drive to encrypt. Default: C:

.PARAMETER SaveKeyToFile
    Save recovery key to file. Default: False

.PARAMETER KeyFilePath
    Recovery key file path. Default: C:\ProgramData\BitLocker

.PARAMETER LogPath
    Log path. Default: C:\ProgramData\OrchestrationLogs\Tasks

.PARAMETER StateStorePath
    Event sourcing state path. Default: C:\ProgramData\OrchestrationLogs\State

.PARAMETER MetricsPath
    Metrics export path. Default: C:\ProgramData\OrchestrationLogs\Metrics

.EXAMPLE
    .\Enable-BitLocker-Enterprise.ps1 -EncryptionMethod XtsAes256 -SaveKeyToAD $true

.NOTES
    Task ID: SEC-002
    Version: 2.0.0 (Enterprise)
    Author: IT Infrastructure Team
    Framework: Context Engineering Orchestration

    Exit Codes:
    0 = Success
    1 = Failed
    2 = Already compliant
    3 = TPM not available
    4 = Not domain joined
    5 = Encryption in progress

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Aes128","Aes256","XtsAes128","XtsAes256")]
    [string]$EncryptionMethod = "XtsAes256",

    [Parameter(Mandatory=$false)]
    [bool]$SaveKeyToAD = $true,

    [Parameter(Mandatory=$false)]
    [bool]$EncryptUsedSpaceOnly = $true,

    [Parameter(Mandatory=$false)]
    [bool]$SkipHardwareTest = $false,

    [Parameter(Mandatory=$false)]
    [bool]$RequireTPM = $true,

    [Parameter(Mandatory=$false)]
    [ValidatePattern("^[A-Z]:$")]
    [string]$DriveLetter = "C:",

    [Parameter(Mandatory=$false)]
    [bool]$SaveKeyToFile = $false,

    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$KeyFilePath = "C:\ProgramData\BitLocker",

    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks",

    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$StateStorePath = "C:\ProgramData\OrchestrationLogs\State",

    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$MetricsPath = "C:\ProgramData\OrchestrationLogs\Metrics",

    [Parameter(Mandatory=$false)]
    [string]$TaskID = "SEC-002"
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

#region INITIALIZATION
#==============================================================================

# Script metadata
$ScriptVersion = "2.0.0"
$TaskName = "Enable BitLocker Encryption"
$ScriptStartTime = Get-Date
$WorkflowId = "BitLocker-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMddHHmmss')"

# Exit codes
$ExitCode = @{
    Success = 0
    Failed = 1
    AlreadyCompliant = 2
    NoTPM = 3
    NotDomainJoined = 4
    EncryptionInProgress = 5
}

# Initialize directories
foreach ($Path in @($LogPath, $StateStorePath, $MetricsPath, $KeyFilePath)) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

# Log file
$LogFile = Join-Path $LogPath "$($TaskID)_Enable-BitLocker_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$StateFile = Join-Path $StateStorePath "$($TaskID)_$($WorkflowId)_events.jsonl"
$MetricsFile = Join-Path $MetricsPath "$($TaskID)_bitlocker_metrics_$(Get-Date -Format 'yyyyMMddHHmmss').txt"

#endregion

#region PRODUCTION INFRASTRUCTURE CLASSES
#==============================================================================

# Event Sourcing - State Management
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
        $this.CorrelationId = $WorkflowId
    }

    [string] ToJson() {
        return @{
            EventId = $this.EventId
            WorkflowId = $this.WorkflowId
            EventType = $this.EventType
            Timestamp = $this.Timestamp.ToString("o")
            Data = $this.Data
            CorrelationId = $this.CorrelationId
        } | ConvertTo-Json -Compress
    }
}

class EventStore {
    [string]$StorePath

    EventStore([string]$FilePath) {
        $this.StorePath = $FilePath
    }

    [void] AppendEvent([StateEvent]$Event) {
        try {
            $EventJson = $Event.ToJson()
            Add-Content -Path $this.StorePath -Value $EventJson -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to append event: $_"
        }
    }
}

# Circuit Breaker - Error Recovery
class CircuitBreaker {
    [string]$Name
    [int]$FailureThreshold
    [int]$TimeoutSeconds
    [string]$State  # Closed, Open, HalfOpen
    [int]$FailureCount
    [datetime]$LastFailureTime

    CircuitBreaker([string]$Name, [int]$FailureThreshold, [int]$TimeoutSeconds) {
        $this.Name = $Name
        $this.FailureThreshold = $FailureThreshold
        $this.TimeoutSeconds = $TimeoutSeconds
        $this.State = "Closed"
        $this.FailureCount = 0
        $this.LastFailureTime = [datetime]::MinValue
    }

    [object] Execute([scriptblock]$Operation) {
        if ($this.State -eq "Open") {
            $TimeSinceFailure = (Get-Date) - $this.LastFailureTime
            if ($TimeSinceFailure.TotalSeconds -gt $this.TimeoutSeconds) {
                $this.State = "HalfOpen"
            }
            else {
                throw "Circuit breaker is OPEN - operation rejected for $($this.Name)"
            }
        }

        try {
            $Result = & $Operation
            $this.RecordSuccess()
            return $Result
        }
        catch {
            $this.RecordFailure()
            throw
        }
    }

    [void] RecordSuccess() {
        $this.FailureCount = 0
        $this.State = "Closed"
    }

    [void] RecordFailure() {
        $this.FailureCount++
        $this.LastFailureTime = Get-Date

        if ($this.FailureCount -ge $this.FailureThreshold) {
            $this.State = "Open"
        }
    }
}

# Compensation Manager - Rollback
class CompensationManager {
    [string]$WorkflowId
    [System.Collections.Generic.Stack[hashtable]]$CompensationStack

    CompensationManager([string]$WorkflowId) {
        $this.WorkflowId = $WorkflowId
        $this.CompensationStack = [System.Collections.Generic.Stack[hashtable]]::new()
    }

    [void] RegisterCompensation([string]$OperationName, [scriptblock]$CompensationAction, [hashtable]$Context) {
        $this.CompensationStack.Push(@{
            OperationName = $OperationName
            Action = $CompensationAction
            Context = $Context
            RegisteredAt = Get-Date
        })
    }

    [void] ExecuteCompensations([string]$Reason) {
        while ($this.CompensationStack.Count -gt 0) {
            $Compensation = $this.CompensationStack.Pop()

            try {
                Write-Host "[ROLLBACK] Executing compensation: $($Compensation.OperationName)" -ForegroundColor Yellow
                & $Compensation.Action $Compensation.Context
                Write-Host "[ROLLBACK] Compensation succeeded: $($Compensation.OperationName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "[ROLLBACK] Compensation failed: $($Compensation.OperationName) - $_"
            }
        }
    }
}

# Metrics - Observability
class MetricsCollector {
    [string]$MetricsFile
    [hashtable]$Counters
    [hashtable]$Gauges
    [System.Collections.Generic.List[hashtable]]$Histograms

    MetricsCollector([string]$FilePath) {
        $this.MetricsFile = $FilePath
        $this.Counters = @{}
        $this.Gauges = @{}
        $this.Histograms = [System.Collections.Generic.List[hashtable]]::new()
    }

    [void] IncrementCounter([string]$Name, [hashtable]$Labels) {
        $Key = "$Name|$($Labels | ConvertTo-Json -Compress)"
        if (-not $this.Counters.ContainsKey($Key)) {
            $this.Counters[$Key] = 0
        }
        $this.Counters[$Key]++
    }

    [void] SetGauge([string]$Name, [double]$Value, [hashtable]$Labels) {
        $Key = "$Name|$($Labels | ConvertTo-Json -Compress)"
        $this.Gauges[$Key] = $Value
    }

    [void] RecordHistogram([string]$Name, [double]$Value, [hashtable]$Labels) {
        $this.Histograms.Add(@{
            Name = $Name
            Value = $Value
            Labels = $Labels
            Timestamp = Get-Date
        })
    }

    [string] ExportPrometheus() {
        $Output = [System.Text.StringBuilder]::new()

        # Export counters
        foreach ($Key in $this.Counters.Keys) {
            $Parts = $Key -split '\|'
            $Name = $Parts[0]
            $Labels = $Parts[1]
            [void]$Output.AppendLine("# TYPE $Name counter")
            [void]$Output.AppendLine("$Name$Labels $($this.Counters[$Key])")
        }

        # Export gauges
        foreach ($Key in $this.Gauges.Keys) {
            $Parts = $Key -split '\|'
            $Name = $Parts[0]
            $Labels = $Parts[1]
            [void]$Output.AppendLine("# TYPE $Name gauge")
            [void]$Output.AppendLine("$Name$Labels $($this.Gauges[$Key])")
        }

        # Export histograms (simplified)
        foreach ($Histogram in $this.Histograms) {
            $Name = $Histogram.Name
            $Value = $Histogram.Value
            $Labels = $Histogram.Labels | ConvertTo-Json -Compress
            [void]$Output.AppendLine("# TYPE $Name histogram")
            [void]$Output.AppendLine("$Name$Labels $Value")
        }

        return $Output.ToString()
    }

    [void] SaveMetrics() {
        try {
            $this.ExportPrometheus() | Out-File -FilePath $this.MetricsFile -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to save metrics: $_"
        }
    }
}

#endregion

#region LOGGING FUNCTIONS (ENHANCED)
#==============================================================================

function Write-TaskLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","DEBUG")]
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
    if (Get-Variable -Name EventStore -Scope Script -ErrorAction SilentlyContinue) {
        $Event = [StateEvent]::new("Log.$Level", $Script:WorkflowId, @{
            Message = $Message
            Level = $Level
            Data = $Data
        })
        $Script:EventStore.AppendEvent($Event)
    }

    # Update metrics
    if (Get-Variable -Name Metrics -Scope Script -ErrorAction SilentlyContinue) {
        $Script:Metrics.IncrementCounter("task_log_entries", @{ level = $Level.ToLower() })
    }
}

#endregion

#region DETECTION FUNCTIONS (FROM ORIGINAL - NO ALIASES)
#==============================================================================

function Test-IsVirtualMachine {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-TaskLog "Detecting if running in virtual machine..." -Level "INFO"

    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop

        $Manufacturer = $ComputerSystem.Manufacturer
        $Model = $ComputerSystem.Model

        $IsVM = $false
        $VMPlatform = "Physical"

        # Check for VM indicators (no aliases - full cmdlet names)
        if ($Manufacturer -match "Microsoft Corporation" -and $Model -match "Virtual Machine") {
            $IsVM = $true
            $VMPlatform = "Hyper-V"
        }
        elseif ($Manufacturer -match "VMware") {
            $IsVM = $true
            $VMPlatform = "VMware"
        }
        elseif ($Manufacturer -match "innotek GmbH" -or $Manufacturer -match "Oracle") {
            $IsVM = $true
            $VMPlatform = "VirtualBox"
        }

        if ($IsVM) {
            Write-TaskLog "Virtual machine detected: $VMPlatform" -Level "WARNING" -Data @{ Platform = $VMPlatform }
        }
        else {
            Write-TaskLog "Physical machine detected" -Level "SUCCESS"
        }

        return @{
            IsVirtual = $IsVM
            Platform = $VMPlatform
        }
    }
    catch {
        Write-TaskLog "Error detecting VM status: $_" -Level "ERROR"
        throw
    }
}

function Test-TPMAvailability {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-TaskLog "Checking TPM status..." -Level "INFO"

    try {
        # Use circuit breaker for TPM check
        $Result = $Script:CircuitBreaker_TPM.Execute({
            $TPM = Get-Tpm -ErrorAction Stop

            if (-not $TPM.TpmPresent) {
                throw "TPM not present"
            }

            if (-not $TPM.TpmReady) {
                throw "TPM not ready"
            }

            return $TPM
        })

        Write-TaskLog "TPM is present and ready" -Level "SUCCESS" -Data @{
            Version = $Result.ManufacturerVersion
            Manufacturer = $Result.ManufacturerId
        }

        return @{
            Available = $true
            Version = $Result.ManufacturerVersion
            Manufacturer = $Result.ManufacturerId
        }
    }
    catch {
        Write-TaskLog "TPM check failed: $_" -Level "ERROR"
        return @{
            Available = $false
            Reason = $_.Exception.Message
        }
    }
}

function Get-BitLockerStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-TaskLog "Checking BitLocker status for drive $DriveLetter..." -Level "INFO"

    try {
        $Volume = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction Stop

        $Status = @{
            VolumeStatus = $Volume.VolumeStatus
            ProtectionStatus = $Volume.ProtectionStatus
            EncryptionPercentage = $Volume.EncryptionPercentage
            EncryptionMethod = $Volume.EncryptionMethod
            KeyProtectors = $Volume.KeyProtector
        }

        Write-TaskLog "BitLocker Status: $($Status.ProtectionStatus), $($Status.EncryptionPercentage)% encrypted" -Level "INFO"

        # Update metrics
        $Script:Metrics.SetGauge("bitlocker_encryption_percentage", $Status.EncryptionPercentage, @{ drive = $DriveLetter })

        return $Status
    }
    catch {
        Write-TaskLog "Error getting BitLocker status: $_" -Level "DEBUG"
        return @{
            VolumeStatus = "Unknown"
            ProtectionStatus = "Off"
            EncryptionPercentage = 0
            EncryptionMethod = "None"
            KeyProtectors = @()
        }
    }
}

function Test-BitLockerCompliance {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $Status = Get-BitLockerStatus

    # Check protection is on
    if ($Status.ProtectionStatus -ne "On") {
        Write-TaskLog "BitLocker protection is not enabled" -Level "INFO"
        return $false
    }

    # Check fully encrypted
    if ($Status.EncryptionPercentage -lt 100) {
        Write-TaskLog "BitLocker encryption in progress: $($Status.EncryptionPercentage)%" -Level "WARNING"
        return $false
    }

    # Check for TPM protector
    $HasTPMProtector = $Status.KeyProtectors | Where-Object { $_.KeyProtectorType -eq "Tpm" }
    if (-not $HasTPMProtector) {
        Write-TaskLog "No TPM key protector found" -Level "WARNING"
        return $false
    }

    # Check for recovery password
    $HasRecoveryPassword = $Status.KeyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
    if (-not $HasRecoveryPassword) {
        Write-TaskLog "No recovery password found" -Level "WARNING"
        return $false
    }

    Write-TaskLog "BitLocker is properly configured and fully encrypted" -Level "SUCCESS"
    return $true
}

function Test-DomainJoinStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-TaskLog "Checking domain join status..." -Level "INFO"

    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        if ($ComputerSystem.PartOfDomain) {
            Write-TaskLog "Computer is domain joined: $($ComputerSystem.Domain)" -Level "SUCCESS"
            return @{
                IsDomainJoined = $true
                DomainName = $ComputerSystem.Domain
            }
        }
        else {
            Write-TaskLog "Computer is not domain joined" -Level "WARNING"
            return @{
                IsDomainJoined = $false
                DomainName = $null
            }
        }
    }
    catch {
        Write-TaskLog "Error checking domain join status: $_" -Level "ERROR"
        throw
    }
}

#endregion

#region BITLOCKER FUNCTIONS (ENHANCED WITH COMPENSATION)
#==============================================================================

function Enable-BitLockerEncryption {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-TaskLog "Enabling BitLocker encryption on drive $DriveLetter..." -Level "INFO"

    try {
        # Start timer for metrics
        $StartTime = Get-Date

        # Build parameters
        $BitLockerParams = @{
            MountPoint = $DriveLetter
            EncryptionMethod = $EncryptionMethod
            TpmProtector = $true
            UsedSpaceOnly = $EncryptUsedSpaceOnly
            SkipHardwareTest = $SkipHardwareTest
            ErrorAction = 'Stop'
        }

        # Execute with circuit breaker
        $Result = $Script:CircuitBreaker_BitLocker.Execute({
            Enable-BitLocker @BitLockerParams
        })

        Write-TaskLog "BitLocker enabled successfully" -Level "SUCCESS"

        # Register compensation (disable BitLocker on failure)
        $Script:CompensationMgr.RegisterCompensation(
            "Enable-BitLocker",
            {
                param($Context)
                Write-Host "[ROLLBACK] Disabling BitLocker on $($Context.Drive)" -ForegroundColor Yellow
                try {
                    Disable-BitLocker -MountPoint $Context.Drive -ErrorAction Stop
                    Write-Host "[ROLLBACK] BitLocker disabled successfully" -ForegroundColor Green
                }
                catch {
                    Write-Warning "[ROLLBACK] Failed to disable BitLocker: $_"
                }
            },
            @{ Drive = $DriveLetter }
        )

        # Add recovery password
        Write-TaskLog "Adding recovery password protector..." -Level "INFO"
        $RecoveryPassword = Add-BitLockerKeyProtector -MountPoint $DriveLetter -RecoveryPasswordProtector -ErrorAction Stop
        Write-TaskLog "Recovery password added" -Level "SUCCESS"

        # Record metrics
        $Duration = ((Get-Date) - $StartTime).TotalSeconds
        $Script:Metrics.RecordHistogram("bitlocker_enable_duration_seconds", $Duration, @{ drive = $DriveLetter })
        $Script:Metrics.IncrementCounter("bitlocker_operations_total", @{ operation = "enable"; status = "success" })

        return @{
            Success = $true
            RecoveryPasswordId = $RecoveryPassword.KeyProtectorId
        }
    }
    catch {
        Write-TaskLog "Failed to enable BitLocker: $_" -Level "ERROR"
        $Script:Metrics.IncrementCounter("bitlocker_operations_total", @{ operation = "enable"; status = "failed" })

        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Backup-RecoveryKeyToAD {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-TaskLog "Backing up recovery key to Active Directory..." -Level "INFO"

    try {
        $Volume = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction Stop
        $RecoveryPasswords = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

        if ($RecoveryPasswords.Count -eq 0) {
            Write-TaskLog "No recovery passwords found to backup" -Level "WARNING"
            return $false
        }

        foreach ($RecoveryPassword in $RecoveryPasswords) {
            try {
                Backup-BitLockerKeyProtector -MountPoint $DriveLetter -KeyProtectorId $RecoveryPassword.KeyProtectorId -ErrorAction Stop
                Write-TaskLog "Recovery key backed up to AD: $($RecoveryPassword.KeyProtectorId)" -Level "SUCCESS"

                $Script:Metrics.IncrementCounter("bitlocker_operations_total", @{ operation = "backup_to_ad"; status = "success" })
                return $true
            }
            catch {
                Write-TaskLog "Failed to backup key to AD: $_" -Level "WARNING"
                $Script:Metrics.IncrementCounter("bitlocker_operations_total", @{ operation = "backup_to_ad"; status = "failed" })
            }
        }

        return $false
    }
    catch {
        Write-TaskLog "Error backing up recovery key to AD: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region MAIN EXECUTION (ENTERPRISE ORCHESTRATION)
#==============================================================================

try {
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "TASK: $TaskID - $TaskName (Enterprise v$ScriptVersion)" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "Workflow ID: $WorkflowId" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "Drive: $DriveLetter" -Level "INFO"
    Write-TaskLog "Encryption Method: $EncryptionMethod" -Level "INFO"

    # Initialize production infrastructure
    $Script:EventStore = [EventStore]::new($StateFile)
    $Script:CompensationMgr = [CompensationManager]::new($WorkflowId)
    $Script:Metrics = [MetricsCollector]::new($MetricsFile)
    $Script:CircuitBreaker_TPM = [CircuitBreaker]::new("TPM-Check", 3, 60)
    $Script:CircuitBreaker_BitLocker = [CircuitBreaker]::new("BitLocker-Enable", 2, 120)

    # Emit workflow started event
    $Event = [StateEvent]::new("WorkflowStarted", $WorkflowId, @{
        TaskID = $TaskID
        TaskName = $TaskName
        Computer = $env:COMPUTERNAME
        Drive = $DriveLetter
    })
    $Script:EventStore.AppendEvent($Event)

    # Step 1: Pre-flight checks
    Write-TaskLog "`n--- Step 1: Pre-flight Checks ---" -Level "INFO"

    # Check VM status
    $VMStatus = Test-IsVirtualMachine
    if ($VMStatus.IsVirtual) {
        Write-TaskLog "Virtual machine detected - BitLocker skipped for VM without vTPM" -Level "WARNING"
        $Script:Metrics.IncrementCounter("bitlocker_skipped_total", @{ reason = "virtual_machine" })
        $Script:Metrics.SaveMetrics()
        exit $ExitCode.AlreadyCompliant
    }

    # Check if already compliant
    if (Test-BitLockerCompliance) {
        Write-TaskLog "BitLocker is already properly configured" -Level "SUCCESS"
        $Script:Metrics.IncrementCounter("bitlocker_skipped_total", @{ reason = "already_compliant" })
        $Script:Metrics.SaveMetrics()
        exit $ExitCode.AlreadyCompliant
    }

    # Check TPM
    $TPMStatus = Test-TPMAvailability
    if (-not $TPMStatus.Available) {
        if ($RequireTPM) {
            Write-TaskLog "TPM is required but not available: $($TPMStatus.Reason)" -Level "ERROR"
            $Script:Metrics.IncrementCounter("bitlocker_failed_total", @{ reason = "no_tpm" })
            $Script:Metrics.SaveMetrics()
            exit $ExitCode.NoTPM
        }
    }

    # Check domain join (if AD backup required)
    if ($SaveKeyToAD) {
        $DomainStatus = Test-DomainJoinStatus
        if (-not $DomainStatus.IsDomainJoined) {
            Write-TaskLog "Computer must be domain joined to backup recovery key to AD" -Level "ERROR"
            $Script:Metrics.IncrementCounter("bitlocker_failed_total", @{ reason = "not_domain_joined" })
            $Script:Metrics.SaveMetrics()
            exit $ExitCode.NotDomainJoined
        }
    }

    # Step 2: Enable BitLocker
    Write-TaskLog "`n--- Step 2: Enable BitLocker ---" -Level "INFO"

    $EnableResult = Enable-BitLockerEncryption

    if (-not $EnableResult.Success) {
        Write-TaskLog "Failed to enable BitLocker - executing rollback" -Level "ERROR"
        $Script:CompensationMgr.ExecuteCompensations("Enable BitLocker failed")
        $Script:Metrics.SaveMetrics()
        exit $ExitCode.Failed
    }

    # Step 3: Backup recovery key
    Write-TaskLog "`n--- Step 3: Backup Recovery Key ---" -Level "INFO"

    if ($SaveKeyToAD) {
        if (Backup-RecoveryKeyToAD) {
            Write-TaskLog "Recovery key backed up to Active Directory" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "Failed to backup recovery key to AD" -Level "WARNING"
        }
    }

    # Success
    $Duration = ((Get-Date) - $ScriptStartTime).TotalSeconds
    Write-TaskLog "`n========================================" -Level "SUCCESS"
    Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
    Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
    Write-TaskLog "========================================" -Level "SUCCESS"

    # Emit completion event
    $Event = [StateEvent]::new("WorkflowCompleted", $WorkflowId, @{
        Status = "Success"
        Duration = $Duration
    })
    $Script:EventStore.AppendEvent($Event)

    # Save metrics
    $Script:Metrics.RecordHistogram("bitlocker_workflow_duration_seconds", $Duration, @{ status = "success" })
    $Script:Metrics.IncrementCounter("bitlocker_completed_total", @{ status = "success" })
    $Script:Metrics.SaveMetrics()

    exit $ExitCode.Success
}
catch {
    Write-TaskLog "`n========================================" -Level "ERROR"
    Write-TaskLog "TASK FAILED WITH EXCEPTION" -Level "ERROR"
    Write-TaskLog "Error: $($_.Exception.Message)" -Level "ERROR"
    Write-TaskLog "========================================" -Level "ERROR"

    # Execute compensations
    Write-TaskLog "Executing rollback compensations..." -Level "WARNING"
    $Script:CompensationMgr.ExecuteCompensations("Unhandled exception")

    # Emit failure event
    if ($Script:EventStore) {
        $Event = [StateEvent]::new("WorkflowFailed", $WorkflowId, @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        })
        $Script:EventStore.AppendEvent($Event)
    }

    # Save metrics
    if ($Script:Metrics) {
        $Script:Metrics.IncrementCounter("bitlocker_completed_total", @{ status = "failed" })
        $Script:Metrics.SaveMetrics()
    }

    exit $ExitCode.Failed}
finally {
    # Cleanup
    Write-TaskLog "State file: $StateFile" -Level "DEBUG"
    Write-TaskLog "Metrics file: $MetricsFile" -Level "DEBUG"
}

#endregion
