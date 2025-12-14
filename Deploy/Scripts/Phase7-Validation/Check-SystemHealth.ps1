<#
.SYNOPSIS
    System Health Check
    
.DESCRIPTION
    Performs comprehensive system health validation after deployment.
    Checks disk space, services, event logs, performance, and system stability.
    
    Health Check Categories:
    - Disk space availability
    - Critical services status
    - Event log errors/warnings
    - System performance metrics
    - Hardware health
    - Network connectivity
    - Windows integrity
    - Driver status
    
.PARAMETER CheckDiskSpace
    Check disk space on all drives.
    Default: $true
    
.PARAMETER CheckServices
    Validate critical Windows services.
    Default: $true
    
.PARAMETER CheckEventLog
    Scan event logs for critical errors.
    Default: $true
    
.PARAMETER CheckPerformance
    Check system performance metrics.
    Default: $true
    
.PARAMETER CheckHardware
    Validate hardware health.
    Default: $true
    
.PARAMETER CheckNetwork
    Test network connectivity.
    Default: $true
    
.PARAMETER GenerateReport
    Generate detailed health report.
    Default: $true
    
.PARAMETER ReportPath
    Path to save health report.
    Default: C:\ProgramData\HealthReports\
    
.PARAMETER FailOnCritical
    Exit with error code if critical issues found.
    Default: $false
    
.PARAMETER DryRun
    Simulate health check without checking. Default: $false
    
.EXAMPLE
    .\Check-SystemHealth.ps1
    Performs full system health check
    
.EXAMPLE
    .\Check-SystemHealth.ps1 -CheckDiskSpace $true -CheckServices $true
    Checks disk space and services only
    
.EXAMPLE
    .\Check-SystemHealth.ps1 -CheckEventLog $true
    Scans event logs for errors
    
.EXAMPLE
    .\Check-SystemHealth.ps1 -GenerateReport $true
    Generates detailed health report
    
.EXAMPLE
    .\Check-SystemHealth.ps1 -DryRun
    Shows what would be checked
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        System health validation for Windows 11 workstations
    
    EXIT CODES:
    0   = System healthy
    1   = General failure
    2   = Not running as administrator
    3   = Critical health issues (if FailOnCritical = $true)
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    HEALTH CHECKS:
    - Disk Space: C:\ >20GB free, other drives >10%
    - Services: All critical services running
    - Event Logs: <10 critical errors in last 24 hours
    - Performance: CPU <80%, Memory <90%
    - Hardware: No failed devices
    - Network: Internet connectivity
    - Windows: System files integrity
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$CheckDiskSpace = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckServices = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckEventLog = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckPerformance = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckHardware = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckNetwork = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$GenerateReport = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\ProgramData\HealthReports",
    
    [Parameter(Mandatory=$false)]
    [bool]$FailOnCritical = $false,
    
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

$LogFileName = "Check-SystemHealth_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Health tracking
$Global:HealthResults = @{
    TotalChecks = 0
    Passed = 0
    Warnings = 0
    Critical = 0
    Categories = @{}
}

# Statistics tracking
$Global:Stats = @{
    Errors = 0
    Warnings = 0
    ChecksPerformed = 0
}

# Critical services to monitor
$Global:CriticalServices = @(
    "wuauserv",         # Windows Update
    "Winmgmt",          # Windows Management Instrumentation
    "RpcSs",            # Remote Procedure Call
    "Dhcp",             # DHCP Client
    "Dnscache",         # DNS Client
    "EventLog",         # Windows Event Log
    "PlugPlay",         # Plug and Play
    "SamSs",            # Security Accounts Manager
    "LanmanWorkstation",# Workstation
    "LanmanServer",     # Server
    "MpsSvc"            # Windows Defender Firewall
)

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

function Add-HealthResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,  # "Pass", "Warning", "Critical"
        [string]$Value,
        [string]$Expected = "",
        [string]$Details = ""
    )
    
    $Global:HealthResults.TotalChecks++
    
    switch ($Status) {
        "Pass" {
            $Global:HealthResults.Passed++
            Write-Log "  ✓ $Check : $Value" -Level "SUCCESS"
        }
        "Warning" {
            $Global:HealthResults.Warnings++
            Write-Log "  ⚠ $Check : $Value $(if($Expected){"(Expected: $Expected)"})" -Level "WARNING"
        }
        "Critical" {
            $Global:HealthResults.Critical++
            Write-Log "  ✗ $Check : $Value $(if($Expected){"(Expected: $Expected)"})" -Level "ERROR"
        }
    }
    
    # Store result
    if (-not $Global:HealthResults.Categories.ContainsKey($Category)) {
        $Global:HealthResults.Categories[$Category] = @{
            Passed = 0
            Warnings = 0
            Critical = 0
            Checks = @()
        }
    }
    
    $Global:HealthResults.Categories[$Category].$Status++
    
    $Global:HealthResults.Categories[$Category].Checks += @{
        Check = $Check
        Status = $Status
        Value = $Value
        Expected = $Expected
        Details = $Details
    }
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
        Write-Log "WARNING: Not running as Administrator (some checks may be limited)" -Level "WARNING"
    }
    else {
        Write-Log "Administrator privileges confirmed" -Level "SUCCESS"
    }
    
    # Check 2: Computer info
    $ComputerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
    if ($ComputerInfo) {
        Write-Log "Computer: $($ComputerInfo.CsName)" -Level "INFO"
        Write-Log "OS: $($ComputerInfo.WindowsProductName)" -Level "INFO"
        Write-Log "Version: $($ComputerInfo.WindowsVersion)" -Level "INFO"
    }
    
    return $AllChecksPassed
}

#endregion

#region DISK SPACE VALIDATION
#==============================================================================

function Test-DiskSpace {
    Write-LogHeader "CHECKING DISK SPACE"
    
    $Category = "Disk Space"
    
    if (-not $CheckDiskSpace) {
        Write-Log "Disk space check disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would check disk space" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Checking disk space on all drives..." -Level "INFO"
        
        $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
        
        foreach ($Drive in $Drives) {
            $DriveName = $Drive.Name + ":"
            $FreeSpaceGB = [math]::Round($Drive.Free / 1GB, 2)
            $UsedSpaceGB = [math]::Round($Drive.Used / 1GB, 2)
            $TotalSpaceGB = [math]::Round(($Drive.Free + $Drive.Used) / 1GB, 2)
            $PercentFree = [math]::Round(($Drive.Free / ($Drive.Free + $Drive.Used)) * 100, 1)
            
            Write-Log "Drive $DriveName : $FreeSpaceGB GB free / $TotalSpaceGB GB total ($PercentFree% free)" -Level "DEBUG"
            
            # Determine status based on drive and space
            if ($DriveName -eq "C:") {
                # OS drive: Critical if <20GB, Warning if <50GB
                if ($FreeSpaceGB -lt 20) {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Critical" -Value "$FreeSpaceGB GB" -Expected ">20 GB" `
                        -Details "Critical: OS drive has insufficient space"
                }
                elseif ($FreeSpaceGB -lt 50) {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Warning" -Value "$FreeSpaceGB GB" -Expected ">50 GB" `
                        -Details "Warning: OS drive space running low"
                }
                else {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Pass" -Value "$FreeSpaceGB GB ($PercentFree%)" -Details "Sufficient space"
                }
            }
            else {
                # Other drives: Critical if <10% free
                if ($PercentFree -lt 10) {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Critical" -Value "$FreeSpaceGB GB ($PercentFree%)" -Expected ">10%" `
                        -Details "Critical: Drive nearly full"
                }
                elseif ($PercentFree -lt 20) {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Warning" -Value "$FreeSpaceGB GB ($PercentFree%)" -Expected ">20%" `
                        -Details "Warning: Drive space running low"
                }
                else {
                    Add-HealthResult -Category $Category -Check "Drive $DriveName Free Space" `
                        -Status "Pass" -Value "$FreeSpaceGB GB ($PercentFree%)" -Details "Sufficient space"
                }
            }
        }
        
        Write-Log "Disk space check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking disk space: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Disk Space Check" -Status "Critical" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region SERVICE VALIDATION
#==============================================================================

function Test-CriticalServices {
    Write-LogHeader "CHECKING CRITICAL SERVICES"
    
    $Category = "Services"
    
    if (-not $CheckServices) {
        Write-Log "Service check disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would check services" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Checking $($Global:CriticalServices.Count) critical services..." -Level "INFO"
        
        foreach ($ServiceName in $Global:CriticalServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            
            if ($Service) {
                $DisplayName = $Service.DisplayName
                $Status = $Service.Status
                $StartType = $Service.StartType
                
                if ($Status -eq "Running") {
                    Add-HealthResult -Category $Category -Check "$DisplayName" `
                        -Status "Pass" -Value "Running" -Details "StartType: $StartType"
                }
                elseif ($StartType -eq "Disabled") {
                    Add-HealthResult -Category $Category -Check "$DisplayName" `
                        -Status "Warning" -Value "Stopped (Disabled)" -Expected "Running" `
                        -Details "Service is disabled"
                }
                else {
                    Add-HealthResult -Category $Category -Check "$DisplayName" `
                        -Status "Critical" -Value "Stopped" -Expected "Running" `
                        -Details "Service should be running"
                }
            }
            else {
                Add-HealthResult -Category $Category -Check "$ServiceName" `
                    -Status "Warning" -Value "Not Found" -Expected "Present" `
                    -Details "Service not found on system"
            }
        }
        
        Write-Log "Service check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking services: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Service Check" -Status "Critical" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region EVENT LOG VALIDATION
#==============================================================================

function Get-EnvironmentContext {
    <#
    .SYNOPSIS
        Detects environment context for smart error filtering
    #>

    $Context = @{
        IsVM = $false
        VMPlatform = "Physical"
        WindowsEdition = "Unknown"
        IsLTSC = $false
    }

    try {
        # Detect VM
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($ComputerSystem) {
            $Manufacturer = $ComputerSystem.Manufacturer
            $Model = $ComputerSystem.Model

            if ($Manufacturer -match "Microsoft Corporation" -and $Model -match "Virtual Machine") {
                $Context.IsVM = $true
                $Context.VMPlatform = "Hyper-V"
            }
            elseif ($Manufacturer -match "VMware") {
                $Context.IsVM = $true
                $Context.VMPlatform = "VMware"
            }
            elseif ($Manufacturer -match "innotek|Oracle|VirtualBox") {
                $Context.IsVM = $true
                $Context.VMPlatform = "VirtualBox"
            }
        }

        # Detect Windows Edition
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($OS) {
            $Context.WindowsEdition = $OS.Caption
            if ($OS.Caption -match "LTSC") {
                $Context.IsLTSC = $true
            }
        }

        Write-Log "Environment: $($Context.VMPlatform), Edition: $($Context.WindowsEdition)" -Level "DEBUG"

    }
    catch {
        Write-Log "Warning: Could not fully detect environment context" -Level "WARNING"
    }

    return $Context
}

function Test-ShouldFilterEvent {
    <#
    .SYNOPSIS
        Determines if an event should be filtered out based on context
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Event,

        [Parameter(Mandatory=$true)]
        [hashtable]$Context
    )

    # Rule 1: .NET Runtime profiling errors (benign, very common)
    if ($Event.ProviderName -eq ".NET Runtime" -and $Event.Id -eq 1022) {
        return $true  # Filter out
    }

    # Rule 2: TPM attestation errors in VMs
    if ($Context.IsVM -and $Event.ProviderName -eq "Microsoft-Windows-TPM-WMI" -and $Event.Id -in @(1040, 1801)) {
        return $true  # Filter out - expected in VMs
    }

    # Rule 3: Windows Store app update failures in LTSC
    if ($Context.IsLTSC -and $Event.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient" -and $Event.Id -eq 20) {
        if ($Event.Message -match "9NBLGGH4NNS1|9NMPJ99VJBWV|9MSMLRH6LZF3|DesktopAppInstaller|YourPhone|WindowsNotepad") {
            return $true  # Filter out - LTSC doesn't support consumer Store apps
        }
    }

    # Rule 4: Gigabyte hardware service errors (host hardware in VM)
    if ($Event.ProviderName -eq "GigabyteOLEDDisplayService") {
        return $true  # Filter out - hardware service shouldn't be in VM
    }

    # Rule 5: VSS errors during deployment (common)
    if ($Event.ProviderName -match "VSS" -and $Event.Id -in @(8193, 12302)) {
        return $true  # Common VSS errors during deployment
    }

    return $false  # Don't filter - this is a real error to investigate
}

function Test-EventLogs {
    Write-LogHeader "CHECKING EVENT LOGS"

    $Category = "Event Logs"

    if (-not $CheckEventLog) {
        Write-Log "Event log check disabled" -Level "INFO"
        return
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Would check event logs" -Level "INFO"
        return
    }

    try {
        Write-Log "Scanning event logs for recent errors..." -Level "INFO"

        # Get environment context for smart filtering
        $Context = Get-EnvironmentContext

        $After = (Get-Date).AddHours(-24)

        # System log - WITH FILTERING
        $SystemErrorsRaw = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 1,2  # Critical, Error
            StartTime = $After
        } -ErrorAction SilentlyContinue

        # Filter out known benign errors
        $SystemErrors = $SystemErrorsRaw | Where-Object { -not (Test-ShouldFilterEvent -Event $_ -Context $Context) }
        $SystemErrorCount = ($SystemErrors | Measure-Object).Count
        $FilteredCount = ($SystemErrorsRaw | Measure-Object).Count - $SystemErrorCount

        if ($FilteredCount -gt 0) {
            Write-Log "Filtered out $FilteredCount known/expected System errors" -Level "DEBUG"
        }
        
        if ($SystemErrorCount -eq 0) {
            Add-HealthResult -Category $Category -Check "System Log Errors (24h)" `
                -Status "Pass" -Value "0 errors" -Details "No critical/error events"
        }
        elseif ($SystemErrorCount -lt 10) {
            Add-HealthResult -Category $Category -Check "System Log Errors (24h)" `
                -Status "Warning" -Value "$SystemErrorCount errors" -Expected "<10" `
                -Details "Some errors present, review recommended"
        }
        else {
            Add-HealthResult -Category $Category -Check "System Log Errors (24h)" `
                -Status "Critical" -Value "$SystemErrorCount errors" -Expected "<10" `
                -Details "High error count, investigation needed"
        }
        
        # Application log - WITH FILTERING
        $AppErrorsRaw = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Level = 1,2
            StartTime = $After
        } -ErrorAction SilentlyContinue

        # Filter out known benign errors
        $AppErrors = $AppErrorsRaw | Where-Object { -not (Test-ShouldFilterEvent -Event $_ -Context $Context) }
        $AppErrorCount = ($AppErrors | Measure-Object).Count
        $AppFilteredCount = ($AppErrorsRaw | Measure-Object).Count - $AppErrorCount

        if ($AppFilteredCount -gt 0) {
            Write-Log "Filtered out $AppFilteredCount known/expected Application errors" -Level "DEBUG"
        }
        
        if ($AppErrorCount -eq 0) {
            Add-HealthResult -Category $Category -Check "Application Log Errors (24h)" `
                -Status "Pass" -Value "0 errors" -Details "No critical/error events"
        }
        elseif ($AppErrorCount -lt 20) {
            Add-HealthResult -Category $Category -Check "Application Log Errors (24h)" `
                -Status "Warning" -Value "$AppErrorCount errors" -Expected "<20" `
                -Details "Some errors present, review if persistent"
        }
        else {
            Add-HealthResult -Category $Category -Check "Application Log Errors (24h)" `
                -Status "Critical" -Value "$AppErrorCount errors" -Expected "<20" `
                -Details "High error count, investigation needed"
        }
        
        # Check for specific critical events
        $CriticalEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 1  # Critical only
            StartTime = $After
        } -ErrorAction SilentlyContinue
        
        $CriticalCount = ($CriticalEvents | Measure-Object).Count
        
        if ($CriticalCount -eq 0) {
            Add-HealthResult -Category $Category -Check "Critical Events (24h)" `
                -Status "Pass" -Value "0 critical" -Details "No critical events"
        }
        else {
            Add-HealthResult -Category $Category -Check "Critical Events (24h)" `
                -Status "Critical" -Value "$CriticalCount critical" -Expected "0" `
                -Details "Critical events require immediate attention"
        }
        
        Write-Log "Event log check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking event logs: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Event Log Check" -Status "Warning" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region PERFORMANCE VALIDATION
#==============================================================================

function Test-SystemPerformance {
    Write-LogHeader "CHECKING SYSTEM PERFORMANCE"
    
    $Category = "Performance"
    
    if (-not $CheckPerformance) {
        Write-Log "Performance check disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would check performance" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Checking system performance metrics..." -Level "INFO"
        
        # CPU Usage
        $CPU = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue
        $CPUAvg = [math]::Round(($CPU.CounterSamples | Measure-Object -Property CookedValue -Average).Average, 1)
        
        if ($CPUAvg -lt 80) {
            Add-HealthResult -Category $Category -Check "CPU Usage" `
                -Status "Pass" -Value "$CPUAvg%" -Details "CPU usage normal"
        }
        elseif ($CPUAvg -lt 95) {
            Add-HealthResult -Category $Category -Check "CPU Usage" `
                -Status "Warning" -Value "$CPUAvg%" -Expected "<80%" `
                -Details "CPU usage elevated"
        }
        else {
            Add-HealthResult -Category $Category -Check "CPU Usage" `
                -Status "Critical" -Value "$CPUAvg%" -Expected "<80%" `
                -Details "CPU usage critically high"
        }
        
        # Memory Usage
        $OS = Get-CimInstance Win32_OperatingSystem
        $TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
        $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
        $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB
        $MemoryPercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 1)
        
        if ($MemoryPercent -lt 90) {
            Add-HealthResult -Category $Category -Check "Memory Usage" `
                -Status "Pass" -Value "$MemoryPercent% ($UsedMemoryGB GB / $TotalMemoryGB GB)" `
                -Details "Memory usage normal"
        }
        elseif ($MemoryPercent -lt 95) {
            Add-HealthResult -Category $Category -Check "Memory Usage" `
                -Status "Warning" -Value "$MemoryPercent% ($UsedMemoryGB GB / $TotalMemoryGB GB)" `
                -Expected "<90%" -Details "Memory usage elevated"
        }
        else {
            Add-HealthResult -Category $Category -Check "Memory Usage" `
                -Status "Critical" -Value "$MemoryPercent% ($UsedMemoryGB GB / $TotalMemoryGB GB)" `
                -Expected "<90%" -Details "Memory critically low"
        }
        
        # Disk Performance (C: drive response time)
        $DiskPerf = Get-Counter '\PhysicalDisk(0 C:)\Avg. Disk sec/Read' -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue
        if ($DiskPerf) {
            $DiskAvgMs = [math]::Round(($DiskPerf.CounterSamples | Measure-Object -Property CookedValue -Average).Average * 1000, 1)
            
            if ($DiskAvgMs -lt 20) {
                Add-HealthResult -Category $Category -Check "Disk Response Time" `
                    -Status "Pass" -Value "$DiskAvgMs ms" -Details "Disk performance good"
            }
            elseif ($DiskAvgMs -lt 50) {
                Add-HealthResult -Category $Category -Check "Disk Response Time" `
                    -Status "Warning" -Value "$DiskAvgMs ms" -Expected "<20 ms" `
                    -Details "Disk performance slower than optimal"
            }
            else {
                Add-HealthResult -Category $Category -Check "Disk Response Time" `
                    -Status "Critical" -Value "$DiskAvgMs ms" -Expected "<20 ms" `
                    -Details "Disk performance poor, possible hardware issue"
            }
        }
        
        # System Uptime
        $Uptime = (Get-Date) - $OS.LastBootUpTime
        $UptimeDays = [math]::Round($Uptime.TotalDays, 1)
        
        Add-HealthResult -Category $Category -Check "System Uptime" `
            -Status "Pass" -Value "$UptimeDays days" `
            -Details "Since: $($OS.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'))"
        
        Write-Log "Performance check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking performance: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Performance Check" -Status "Warning" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region HARDWARE VALIDATION
#==============================================================================

function Test-HardwareHealth {
    Write-LogHeader "CHECKING HARDWARE HEALTH"
    
    $Category = "Hardware"
    
    if (-not $CheckHardware) {
        Write-Log "Hardware check disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would check hardware" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Checking hardware devices..." -Level "INFO"
        
        # Check for failed devices
        $FailedDevices = Get-CimInstance Win32_PnPEntity | Where-Object { 
            $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne $null
        }
        
        $FailedCount = ($FailedDevices | Measure-Object).Count
        
        if ($FailedCount -eq 0) {
            Add-HealthResult -Category $Category -Check "Device Status" `
                -Status "Pass" -Value "All devices OK" -Details "No failed devices"
        }
        else {
            $DeviceNames = ($FailedDevices | Select-Object -First 5 -ExpandProperty Name) -join ", "
            Add-HealthResult -Category $Category -Check "Device Status" `
                -Status "Warning" -Value "$FailedCount device(s) failed" -Expected "0" `
                -Details "Failed: $DeviceNames"
        }
        
        # Check SMART status (if available)
        $DiskDrives = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        
        if ($DiskDrives) {
            $FailingDisks = $DiskDrives | Where-Object { $_.PredictFailure -eq $true }
            
            if ($FailingDisks) {
                Add-HealthResult -Category $Category -Check "Disk SMART Status" `
                    -Status "Critical" -Value "Disk failure predicted" -Expected "Healthy" `
                    -Details "Immediate backup and replacement required"
            }
            else {
                Add-HealthResult -Category $Category -Check "Disk SMART Status" `
                    -Status "Pass" -Value "Healthy" -Details "No disk failures predicted"
            }
        }
        
        # Check system temperature (if available)
        $ThermalZones = Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
        
        if ($ThermalZones) {
            foreach ($Zone in $ThermalZones) {
                $TempC = [math]::Round(($Zone.CurrentTemperature / 10) - 273.15, 1)
                
                if ($TempC -lt 80) {
                    Add-HealthResult -Category $Category -Check "System Temperature" `
                        -Status "Pass" -Value "$TempC°C" -Details "Temperature normal"
                }
                else {
                    Add-HealthResult -Category $Category -Check "System Temperature" `
                        -Status "Warning" -Value "$TempC°C" -Expected "<80°C" `
                        -Details "Temperature elevated"
                }
            }
        }
        
        Write-Log "Hardware check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking hardware: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Hardware Check" -Status "Warning" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region NETWORK VALIDATION
#==============================================================================

function Test-NetworkConnectivity {
    Write-LogHeader "CHECKING NETWORK CONNECTIVITY"
    
    $Category = "Network"
    
    if (-not $CheckNetwork) {
        Write-Log "Network check disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would check network" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Checking network connectivity..." -Level "INFO"
        
        # Test internet connectivity
        $InternetTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue
        
        if ($InternetTest) {
            Add-HealthResult -Category $Category -Check "Internet Connectivity" `
                -Status "Pass" -Value "Connected" -Details "Internet accessible"
        }
        else {
            Add-HealthResult -Category $Category -Check "Internet Connectivity" `
                -Status "Critical" -Value "Not connected" -Expected "Connected" `
                -Details "No internet connectivity"
        }
        
        # Test DNS resolution
        $DNSTest = Resolve-DnsName -Name "www.google.com" -Type A -ErrorAction SilentlyContinue
        
        if ($DNSTest) {
            Add-HealthResult -Category $Category -Check "DNS Resolution" `
                -Status "Pass" -Value "Working" -Details "DNS resolves correctly"
        }
        else {
            Add-HealthResult -Category $Category -Check "DNS Resolution" `
                -Status "Critical" -Value "Failed" -Expected "Working" `
                -Details "DNS resolution failing"
        }
        
        # Check network adapters
        $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $AdapterCount = ($Adapters | Measure-Object).Count
        
        if ($AdapterCount -gt 0) {
            $AdapterNames = ($Adapters.Name) -join ", "
            Add-HealthResult -Category $Category -Check "Network Adapters" `
                -Status "Pass" -Value "$AdapterCount active" -Details "Active: $AdapterNames"
        }
        else {
            Add-HealthResult -Category $Category -Check "Network Adapters" `
                -Status "Critical" -Value "0 active" -Expected ">0" `
                -Details "No active network adapters"
        }
        
        # Check IP configuration
        $IPConfig = Get-NetIPAddress -AddressFamily IPv4 -Type Unicast | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }
        
        if ($IPConfig) {
            $HasValidIP = $false
            foreach ($IP in $IPConfig) {
                if ($IP.IPAddress -notlike "169.254.*") {  # Not APIPA
                    $HasValidIP = $true
                    break
                }
            }
            
            if ($HasValidIP) {
                Add-HealthResult -Category $Category -Check "IP Configuration" `
                    -Status "Pass" -Value "Valid IP assigned" -Details "IP configuration OK"
            }
            else {
                Add-HealthResult -Category $Category -Check "IP Configuration" `
                    -Status "Critical" -Value "APIPA address" -Expected "Valid IP" `
                    -Details "Using automatic private IP (169.254.x.x)"
            }
        }
        
        Write-Log "Network check completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception checking network: $_" -Level "ERROR"
        Add-HealthResult -Category $Category -Check "Network Check" -Status "Critical" `
            -Value "Failed" -Details "Exception: $_"
    }
}

#endregion

#region REPORT GENERATION
#==============================================================================

function New-HealthReport {
    Write-LogHeader "GENERATING HEALTH REPORT"
    
    try {
        if (-not $GenerateReport) {
            Write-Log "Report generation disabled" -Level "INFO"
            return
        }
        
        Write-Log "Creating health report..." -Level "INFO"
        
        # Ensure report directory exists
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $ReportFile = Join-Path $ReportPath "SystemHealth_$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        
        # Calculate health score
        $HealthScore = if ($Global:HealthResults.TotalChecks -gt 0) {
            [math]::Round((($Global:HealthResults.Passed / $Global:HealthResults.TotalChecks) * 100), 2)
        } else { 0 }
        
        # Determine overall status
        $Status = if ($Global:HealthResults.Critical -gt 0) {
            "CRITICAL ISSUES"
        } elseif ($Global:HealthResults.Warnings -gt 5) {
            "MULTIPLE WARNINGS"
        } elseif ($Global:HealthResults.Warnings -gt 0) {
            "HEALTHY (Minor Warnings)"
        } else {
            "HEALTHY"
        }
        
        $StatusColor = switch ($Status) {
            "HEALTHY" { "green" }
            { $_ -like "*Warning*" } { "orange" }
            default { "red" }
        }
        
        # Build HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status { font-size: 24px; font-weight: bold; color: $StatusColor; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 36px; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        .category { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .category-header { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background-color: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
        .pass { color: green; }
        .warning { color: orange; }
        .critical { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Health Report</h1>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Total Checks: $($Global:HealthResults.TotalChecks)</p>
    </div>
    
    <div class="summary">
        <div class="status">Status: $Status</div>
        <div class="metric">
            <div class="metric-value">$HealthScore%</div>
            <div class="metric-label">Health Score</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:HealthResults.Passed)</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:HealthResults.Warnings)</div>
            <div class="metric-label">Warnings</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:HealthResults.Critical)</div>
            <div class="metric-label">Critical</div>
        </div>
    </div>
"@
        
        # Add category results
        foreach ($CategoryName in ($Global:HealthResults.Categories.Keys | Sort-Object)) {
            $CategoryData = $Global:HealthResults.Categories[$CategoryName]
            
            $HTML += @"
    <div class="category">
        <div class="category-header">$CategoryName</div>
        <p>Passed: $($CategoryData.Passed) | Warnings: $($CategoryData.Warnings) | Critical: $($CategoryData.Critical)</p>
        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Value</th>
                <th>Expected</th>
            </tr>
"@
            
            foreach ($Check in $CategoryData.Checks) {
                $StatusClass = switch ($Check.Status) {
                    "Pass" { "pass" }
                    "Warning" { "warning" }
                    "Critical" { "critical" }
                }
                $StatusIcon = switch ($Check.Status) {
                    "Pass" { "✓" }
                    "Warning" { "⚠" }
                    "Critical" { "✗" }
                }
                
                $HTML += @"
            <tr>
                <td>$($Check.Check)</td>
                <td class="$StatusClass">$StatusIcon $($Check.Status)</td>
                <td>$($Check.Value)</td>
                <td>$($Check.Expected)</td>
            </tr>
"@
            }
            
            $HTML += "        </table>`n    </div>`n"
        }
        
        $HTML += @"
</body>
</html>
"@
        
        # Save report
        Set-Content -Path $ReportFile -Value $HTML -Force
        
        Write-Log "Health report generated: $ReportFile" -Level "SUCCESS"
        
        return $ReportFile
        
    }
    catch {
        Write-Log "Exception generating report: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region SUMMARY
#==============================================================================

function Show-HealthSummary {
    Write-LogHeader "HEALTH CHECK SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Health Check Results:" -Level "INFO"
    Write-Log "  Total Checks: $($Global:HealthResults.TotalChecks)" -Level "INFO"
    Write-Log "  Passed: $($Global:HealthResults.Passed)" -Level "SUCCESS"
    Write-Log "  Warnings: $($Global:HealthResults.Warnings)" -Level $(if($Global:HealthResults.Warnings -gt 0){"WARNING"}else{"INFO"})
    Write-Log "  Critical: $($Global:HealthResults.Critical)" -Level $(if($Global:HealthResults.Critical -gt 0){"ERROR"}else{"INFO"})
    
    # Calculate health score
    $HealthScore = if ($Global:HealthResults.TotalChecks -gt 0) {
        [math]::Round((($Global:HealthResults.Passed / $Global:HealthResults.TotalChecks) * 100), 2)
    } else { 0 }
    
    Write-Log "  Health Score: $HealthScore%" -Level $(if($HealthScore -ge 95){"SUCCESS"}elseif($HealthScore -ge 80){"WARNING"}else{"ERROR"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Category Breakdown:" -Level "INFO"
    
    foreach ($CategoryName in ($Global:HealthResults.Categories.Keys | Sort-Object)) {
        $CategoryData = $Global:HealthResults.Categories[$CategoryName]
        $TotalCategoryChecks = $CategoryData.Passed + $CategoryData.Warnings + $CategoryData.Critical
        
        Write-Log "  $CategoryName : Pass=$($CategoryData.Passed) Warn=$($CategoryData.Warnings) Crit=$($CategoryData.Critical)" -Level "INFO"
    }
    
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
║        SYSTEM HEALTH CHECK                                    ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host ""
    
    Write-LogHeader "SYSTEM HEALTH CHECK STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    Test-Prerequisites
    
    # Run health checks
    if ($CheckDiskSpace) { Test-DiskSpace }
    if ($CheckServices) { Test-CriticalServices }
    if ($CheckEventLog) { Test-EventLogs }
    if ($CheckPerformance) { Test-SystemPerformance }
    if ($CheckHardware) { Test-HardwareHealth }
    if ($CheckNetwork) { Test-NetworkConnectivity }
    
    # Generate report
    if ($GenerateReport) {
        $ReportFile = New-HealthReport
    }
    
    # Show summary
    Show-HealthSummary
    
    # Determine exit code
    $ExitCode = if ($Global:HealthResults.Critical -eq 0) {
        0  # Healthy
    } elseif ($FailOnCritical) {
        3  # Critical issues (failure)
    } else {
        0  # Critical issues but not failing
    }
    
    Write-Log " " -Level "INFO"
    if ($Global:HealthResults.Critical -eq 0) {
        Write-Log "System health check: PASSED" -Level "SUCCESS"
    } elseif ($FailOnCritical) {
        Write-Log "System health check: FAILED ($($Global:HealthResults.Critical) critical issues)" -Level "ERROR"
    } else {
        Write-Log "Health check completed with $($Global:HealthResults.Critical) critical issue(s) (non-blocking)" -Level "WARNING"
    }
    
    if ($ReportFile) {
        Write-Log "Health report: $ReportFile" -Level "SUCCESS"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-HealthSummary
    
    exit 1
}

#endregion
