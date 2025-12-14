<#
.SYNOPSIS
    Generate Deployment Report
    
.DESCRIPTION
    Generates comprehensive final deployment report consolidating all phases.
    Creates detailed HTML report with system inventory, validation results,
    and deployment summary.
    
    Report Contents:
    - Deployment summary (phases, tasks, duration)
    - System inventory (hardware, software, configuration)
    - Security compliance results
    - Application validation results
    - System health status
    - Event log summary
    - Configuration details
    - Recommendations
    
.PARAMETER ReportPath
    Path to save deployment report.
    Default: C:\ProgramData\OrchestrationLogs\Reports
    
.PARAMETER IncludeInventory
    Include detailed system inventory.
    Default: $true
    
.PARAMETER IncludeScreenshots
    Include desktop/settings screenshots.
    Default: $false
    
.PARAMETER UploadToShare
    Upload report to network share.
    Default: $false
    
.PARAMETER SharePath
    Network share path for report upload.
    Default: \\FileServer\Deployment\Reports
    
.PARAMETER CompressReport
    Create ZIP archive of report and logs.
    Default: $false
    
.PARAMETER DryRun
    Simulate report generation. Default: $false
    
.EXAMPLE
    .\Generate-Report.ps1
    Generates standard deployment report
    
.EXAMPLE
    .\Generate-Report.ps1 -IncludeInventory $true
    Generates report with full system inventory
    
.EXAMPLE
    .\Generate-Report.ps1 -UploadToShare $true -SharePath "\\Server\Reports"
    Generates and uploads report to network share
    
.EXAMPLE
    .\Generate-Report.ps1 -CompressReport $true
    Generates report and creates ZIP archive
    
.EXAMPLE
    .\Generate-Report.ps1 -DryRun
    Shows what would be included in report
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Final deployment report for Windows 11 workstations
    
    EXIT CODES:
    0   = Report generated successfully
    1   = General failure
    2   = Not running as administrator
    3   = Report generation failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    - Access to orchestration logs
    
    REPORT SECTIONS:
    1. Executive Summary
    2. Deployment Details
    3. System Inventory
    4. Security Compliance
    5. Application Validation
    6. System Health
    7. Configuration Summary
    8. Recommendations
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\ProgramData\OrchestrationLogs\Reports",
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeInventory = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeScreenshots = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$UploadToShare = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$SharePath = "\\FileServer\Deployment\Reports",
    
    [Parameter(Mandatory=$false)]
    [bool]$CompressReport = $false,
    
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

$LogFileName = "Generate-Report_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Report data collection
$Global:ReportData = @{
    Computer = $env:COMPUTERNAME
    Timestamp = Get-Date
    DeploymentPhases = @()
    SystemInventory = @{}
    SecurityCompliance = @{}
    ApplicationValidation = @{}
    SystemHealth = @{}
    Recommendations = @()
}

# Statistics tracking
$Global:Stats = @{
    Errors = 0
    Warnings = 0
    DataPointsCollected = 0
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

#region DATA COLLECTION FUNCTIONS
#==============================================================================

function Get-SystemInventory {
    <#
    .SYNOPSIS
        Collects comprehensive system inventory
    #>
    
    Write-LogHeader "COLLECTING SYSTEM INVENTORY"
    
    if (-not $IncludeInventory) {
        Write-Log "Inventory collection disabled" -Level "INFO"
        return
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would collect system inventory" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Collecting system information..." -Level "INFO"
        
        # Computer System
        $ComputerSystem = Get-CimInstance Win32_ComputerSystem
        $Global:ReportData.SystemInventory.ComputerName = $ComputerSystem.Name
        $Global:ReportData.SystemInventory.Domain = $ComputerSystem.Domain
        $Global:ReportData.SystemInventory.Manufacturer = $ComputerSystem.Manufacturer
        $Global:ReportData.SystemInventory.Model = $ComputerSystem.Model
        $Global:ReportData.SystemInventory.TotalMemoryGB = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
        
        # Operating System
        $OS = Get-CimInstance Win32_OperatingSystem
        $Global:ReportData.SystemInventory.OSName = $OS.Caption
        $Global:ReportData.SystemInventory.OSVersion = $OS.Version
        $Global:ReportData.SystemInventory.OSBuild = $OS.BuildNumber
        $Global:ReportData.SystemInventory.OSArchitecture = $OS.OSArchitecture
        $Global:ReportData.SystemInventory.InstallDate = $OS.InstallDate
        $Global:ReportData.SystemInventory.LastBootTime = $OS.LastBootUpTime
        
        # BIOS
        $BIOS = Get-CimInstance Win32_BIOS
        $Global:ReportData.SystemInventory.BIOSVersion = $BIOS.SMBIOSBIOSVersion
        $Global:ReportData.SystemInventory.BIOSManufacturer = $BIOS.Manufacturer
        $Global:ReportData.SystemInventory.SerialNumber = $BIOS.SerialNumber
        
        # Processor
        $Processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        $Global:ReportData.SystemInventory.Processor = $Processor.Name
        $Global:ReportData.SystemInventory.ProcessorCores = $Processor.NumberOfCores
        $Global:ReportData.SystemInventory.ProcessorLogical = $Processor.NumberOfLogicalProcessors
        
        # Disk
        $Disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        $Global:ReportData.SystemInventory.Disks = @()
        foreach ($Disk in $Disks) {
            $Global:ReportData.SystemInventory.Disks += @{
                Drive = $Disk.DeviceID
                Size = [math]::Round($Disk.Size / 1GB, 2)
                Free = [math]::Round($Disk.FreeSpace / 1GB, 2)
                PercentFree = [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 1)
            }
        }
        
        # Network Adapters
        $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $Global:ReportData.SystemInventory.NetworkAdapters = @()
        foreach ($Adapter in $Adapters) {
            $IPConfig = Get-NetIPAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
            $Global:ReportData.SystemInventory.NetworkAdapters += @{
                Name = $Adapter.Name
                Description = $Adapter.InterfaceDescription
                MACAddress = $Adapter.MacAddress
                IPAddress = if ($IPConfig) { $IPConfig.IPAddress } else { "N/A" }
                Speed = $Adapter.LinkSpeed
            }
        }
        
        # Video Card
        $VideoCard = Get-CimInstance Win32_VideoController | Select-Object -First 1
        if ($VideoCard) {
            $Global:ReportData.SystemInventory.VideoCard = $VideoCard.Name
            $Global:ReportData.SystemInventory.VideoRAM = [math]::Round($VideoCard.AdapterRAM / 1GB, 2)
        }
        
        Write-Log "System inventory collected successfully" -Level "SUCCESS"
        $Global:Stats.DataPointsCollected += 20
        
    }
    catch {
        Write-Log "Exception collecting inventory: $_" -Level "ERROR"
    }
}

function Get-InstalledApplicationsList {
    <#
    .SYNOPSIS
        Gets list of installed applications
    #>
    
    Write-Log "Collecting installed applications..." -Level "DEBUG"
    
    if ($DryRun) {
        return @()
    }
    
    try {
        $UninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $Apps = @()
        foreach ($Path in $UninstallPaths) {
            $RegApps = Get-ItemProperty $Path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            
            $Apps += $RegApps
        }
        
        # Deduplicate by DisplayName
        $UniqueApps = $Apps | Sort-Object DisplayName -Unique
        
        Write-Log "Found $($UniqueApps.Count) installed applications" -Level "DEBUG"
        $Global:Stats.DataPointsCollected += $UniqueApps.Count
        
        return $UniqueApps
        
    }
    catch {
        Write-Log "Exception collecting applications: $_" -Level "ERROR"
        return @()
    }
}

function Get-DeploymentLogs {
    <#
    .SYNOPSIS
        Parses orchestration logs for deployment details
    #>
    
    Write-LogHeader "PARSING DEPLOYMENT LOGS"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would parse deployment logs" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Searching for orchestration logs..." -Level "INFO"
        
        $LogFiles = Get-ChildItem $LogPath -Filter "Orchestration-Master_*.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if ($LogFiles) {
            Write-Log "Found orchestration log: $($LogFiles.Name)" -Level "SUCCESS"
            
            # Parse log for phase information
            $LogContent = Get-Content $LogFiles.FullName
            
            # Extract phase information
            $PhasePattern = "\[INFO\] Phase \d+:"
            $PhaseLines = $LogContent | Select-String -Pattern $PhasePattern
            
            Write-Log "Extracted $($PhaseLines.Count) phase entries" -Level "DEBUG"
            
            # Extract task completion
            $TaskPattern = "Task \[.*?\] completed"
            $TaskLines = $LogContent | Select-String -Pattern $TaskPattern
            
            Write-Log "Extracted $($TaskLines.Count) task completions" -Level "DEBUG"
            
            $Global:Stats.DataPointsCollected += ($PhaseLines.Count + $TaskLines.Count)
        }
        else {
            Write-Log "No orchestration logs found" -Level "WARNING"
        }
        
    }
    catch {
        Write-Log "Exception parsing logs: $_" -Level "ERROR"
    }
}

function Get-ValidationResults {
    <#
    .SYNOPSIS
        Collects results from validation scripts
    #>
    
    Write-LogHeader "COLLECTING VALIDATION RESULTS"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would collect validation results" -Level "INFO"
        return
    }
    
    try {
        # Security Compliance
        $ComplianceLogs = Get-ChildItem $LogPath -Filter "Check-SecurityCompliance_*.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if ($ComplianceLogs) {
            Write-Log "Found security compliance log" -Level "SUCCESS"
            $Global:ReportData.SecurityCompliance.LogFile = $ComplianceLogs.FullName
            $Global:ReportData.SecurityCompliance.Status = "Available"
        }
        else {
            Write-Log "No security compliance log found" -Level "WARNING"
            $Global:ReportData.SecurityCompliance.Status = "Not Available"
        }
        
        # Application Validation
        $AppLogs = Get-ChildItem $LogPath -Filter "Validate-Applications_*.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if ($AppLogs) {
            Write-Log "Found application validation log" -Level "SUCCESS"
            $Global:ReportData.ApplicationValidation.LogFile = $AppLogs.FullName
            $Global:ReportData.ApplicationValidation.Status = "Available"
        }
        else {
            Write-Log "No application validation log found" -Level "WARNING"
            $Global:ReportData.ApplicationValidation.Status = "Not Available"
        }
        
        # System Health
        $HealthLogs = Get-ChildItem $LogPath -Filter "Check-SystemHealth_*.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if ($HealthLogs) {
            Write-Log "Found system health log" -Level "SUCCESS"
            $Global:ReportData.SystemHealth.LogFile = $HealthLogs.FullName
            $Global:ReportData.SystemHealth.Status = "Available"
        }
        else {
            Write-Log "No system health log found" -Level "WARNING"
            $Global:ReportData.SystemHealth.Status = "Not Available"
        }
        
        $Global:Stats.DataPointsCollected += 3
        
    }
    catch {
        Write-Log "Exception collecting validation results: $_" -Level "ERROR"
    }
}

function Add-Recommendations {
    <#
    .SYNOPSIS
        Generates recommendations based on collected data
    #>
    
    Write-Log "Generating recommendations..." -Level "INFO"
    
    if ($DryRun) {
        return
    }
    
    try {
        # Check disk space
        if ($Global:ReportData.SystemInventory.Disks) {
            foreach ($Disk in $Global:ReportData.SystemInventory.Disks) {
                if ($Disk.Drive -eq "C:" -and $Disk.Free -lt 50) {
                    $Global:ReportData.Recommendations += "Consider increasing C:\ drive space (currently $($Disk.Free) GB free)"
                }
                if ($Disk.PercentFree -lt 20) {
                    $Global:ReportData.Recommendations += "Drive $($Disk.Drive) has low free space ($($Disk.PercentFree)% free)"
                }
            }
        }
        
        # Check memory
        if ($Global:ReportData.SystemInventory.TotalMemoryGB -lt 8) {
            $Global:ReportData.Recommendations += "Consider adding more RAM (currently $($Global:ReportData.SystemInventory.TotalMemoryGB) GB)"
        }
        
        # Check validation status
        if ($Global:ReportData.SecurityCompliance.Status -eq "Not Available") {
            $Global:ReportData.Recommendations += "Security compliance validation not run - recommend running Check-SecurityCompliance.ps1"
        }
        
        if ($Global:ReportData.ApplicationValidation.Status -eq "Not Available") {
            $Global:ReportData.Recommendations += "Application validation not run - recommend running Validate-Applications.ps1"
        }
        
        if ($Global:ReportData.SystemHealth.Status -eq "Not Available") {
            $Global:ReportData.Recommendations += "System health check not run - recommend running Check-SystemHealth.ps1"
        }
        
        # If no recommendations
        if ($Global:ReportData.Recommendations.Count -eq 0) {
            $Global:ReportData.Recommendations += "System is well-configured - no immediate recommendations"
        }
        
        Write-Log "Generated $($Global:ReportData.Recommendations.Count) recommendation(s)" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception generating recommendations: $_" -Level "ERROR"
    }
}

#endregion

#region REPORT GENERATION
#==============================================================================

function New-DeploymentReport {
    <#
    .SYNOPSIS
        Generates comprehensive HTML deployment report
    #>
    
    Write-LogHeader "GENERATING DEPLOYMENT REPORT"
    
    try {
        Write-Log "Creating deployment report..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would generate HTML report" -Level "INFO"
            return $null
        }
        
        # Ensure report directory exists
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $ReportFile = Join-Path $ReportPath "DeploymentReport_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        
        # Get installed applications
        $InstalledApps = Get-InstalledApplicationsList
        
        # Build HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Deployment Report - $($Global:ReportData.Computer)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { background-color: white; padding: 20px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section-title { font-size: 20px; font-weight: bold; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background-color: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
        .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 10px; }
        .info-label { font-weight: bold; color: #2c3e50; }
        .info-value { color: #555; }
        .status-ok { color: green; font-weight: bold; }
        .status-warning { color: orange; font-weight: bold; }
        .status-error { color: red; font-weight: bold; }
        .recommendation { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 5px 0; }
        ul { margin: 10px 0; padding-left: 20px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows 11 Deployment Report</h1>
        <p><strong>Computer:</strong> $($Global:ReportData.Computer)</p>
        <p><strong>Generated:</strong> $($Global:ReportData.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p><strong>Script Version:</strong> $ScriptVersion</p>
    </div>
    
    <div class="section">
        <div class="section-title">Executive Summary</div>
        <p>This report provides a comprehensive overview of the Windows 11 deployment for computer <strong>$($Global:ReportData.Computer)</strong>.</p>
        <p>The deployment was completed through a multi-phase orchestration process covering security configuration, 
        network setup, application installation, system configuration, user experience customization, and validation.</p>
        
        <h3>Deployment Status</h3>
        <div class="info-grid">
            <div class="info-label">Computer Name:</div>
            <div class="info-value">$($Global:ReportData.Computer)</div>
            
            <div class="info-label">Report Date:</div>
            <div class="info-value">$($Global:ReportData.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</div>
            
            <div class="info-label">Security Compliance:</div>
            <div class="info-value $(if($Global:ReportData.SecurityCompliance.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
                $($Global:ReportData.SecurityCompliance.Status)
            </div>
            
            <div class="info-label">Application Validation:</div>
            <div class="info-value $(if($Global:ReportData.ApplicationValidation.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
                $($Global:ReportData.ApplicationValidation.Status)
            </div>
            
            <div class="info-label">System Health:</div>
            <div class="info-value $(if($Global:ReportData.SystemHealth.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
                $($Global:ReportData.SystemHealth.Status)
            </div>
        </div>
    </div>
"@

        # System Inventory Section
        if ($IncludeInventory -and $Global:ReportData.SystemInventory.Count -gt 0) {
            $HTML += @"
    
    <div class="section">
        <div class="section-title">System Inventory</div>
        
        <h3>Hardware Information</h3>
        <div class="info-grid">
            <div class="info-label">Manufacturer:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.Manufacturer)</div>
            
            <div class="info-label">Model:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.Model)</div>
            
            <div class="info-label">Serial Number:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.SerialNumber)</div>
            
            <div class="info-label">Processor:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.Processor)</div>
            
            <div class="info-label">Processor Cores:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.ProcessorCores) physical, $($Global:ReportData.SystemInventory.ProcessorLogical) logical</div>
            
            <div class="info-label">Total Memory:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.TotalMemoryGB) GB</div>
            
            <div class="info-label">Video Card:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.VideoCard) ($($Global:ReportData.SystemInventory.VideoRAM) GB)</div>
            
            <div class="info-label">BIOS Version:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.BIOSVersion) ($($Global:ReportData.SystemInventory.BIOSManufacturer))</div>
        </div>
        
        <h3>Operating System</h3>
        <div class="info-grid">
            <div class="info-label">OS Name:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.OSName)</div>
            
            <div class="info-label">Version:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.OSVersion) (Build $($Global:ReportData.SystemInventory.OSBuild))</div>
            
            <div class="info-label">Architecture:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.OSArchitecture)</div>
            
            <div class="info-label">Install Date:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.InstallDate.ToString('yyyy-MM-dd HH:mm:ss'))</div>
            
            <div class="info-label">Last Boot:</div>
            <div class="info-value">$($Global:ReportData.SystemInventory.LastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))</div>
        </div>
        
        <h3>Disk Storage</h3>
        <table>
            <tr>
                <th>Drive</th>
                <th>Total Size (GB)</th>
                <th>Free Space (GB)</th>
                <th>Percent Free</th>
            </tr>
"@
            foreach ($Disk in $Global:ReportData.SystemInventory.Disks) {
                $HTML += @"
            <tr>
                <td>$($Disk.Drive)</td>
                <td>$($Disk.Size)</td>
                <td>$($Disk.Free)</td>
                <td>$($Disk.PercentFree)%</td>
            </tr>
"@
            }
            
            $HTML += @"
        </table>
        
        <h3>Network Adapters</h3>
        <table>
            <tr>
                <th>Name</th>
                <th>Description</th>
                <th>MAC Address</th>
                <th>IP Address</th>
                <th>Speed</th>
            </tr>
"@
            foreach ($Adapter in $Global:ReportData.SystemInventory.NetworkAdapters) {
                $HTML += @"
            <tr>
                <td>$($Adapter.Name)</td>
                <td>$($Adapter.Description)</td>
                <td>$($Adapter.MACAddress)</td>
                <td>$($Adapter.IPAddress)</td>
                <td>$($Adapter.Speed)</td>
            </tr>
"@
            }
            
            $HTML += "        </table>`n    </div>`n"
        }

        # Installed Applications Section
        if ($InstalledApps.Count -gt 0) {
            # Key applications to highlight
            $KeyApps = @("Microsoft Office", "Google Chrome", "Adobe", "7-Zip", "VLC", "Microsoft Teams")
            $HighlightedApps = $InstalledApps | Where-Object { 
                $AppName = $_.DisplayName
                $KeyApps | Where-Object { $AppName -like "*$_*" }
            }
            
            $HTML += @"
    
    <div class="section">
        <div class="section-title">Installed Applications</div>
        <p><strong>Total Applications Installed:</strong> $($InstalledApps.Count)</p>
        
        <h3>Key Applications</h3>
        <table>
            <tr>
                <th>Application</th>
                <th>Version</th>
                <th>Publisher</th>
            </tr>
"@
            foreach ($App in $HighlightedApps | Select-Object -First 20) {
                $HTML += @"
            <tr>
                <td>$($App.DisplayName)</td>
                <td>$($App.DisplayVersion)</td>
                <td>$($App.Publisher)</td>
            </tr>
"@
            }
            
            $HTML += "        </table>`n    </div>`n"
        }

        # Validation Results Section
        $HTML += @"
    
    <div class="section">
        <div class="section-title">Validation Results</div>
        
        <h3>Security Compliance</h3>
        <p>Status: <span class="$(if($Global:ReportData.SecurityCompliance.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
            $($Global:ReportData.SecurityCompliance.Status)
        </span></p>
"@
        if ($Global:ReportData.SecurityCompliance.Status -eq "Available") {
            $HTML += "<p>Detailed security compliance report available in validation reports folder.</p>`n"
        }
        
        $HTML += @"
        
        <h3>Application Validation</h3>
        <p>Status: <span class="$(if($Global:ReportData.ApplicationValidation.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
            $($Global:ReportData.ApplicationValidation.Status)
        </span></p>
"@
        if ($Global:ReportData.ApplicationValidation.Status -eq "Available") {
            $HTML += "<p>Detailed application validation report available in validation reports folder.</p>`n"
        }
        
        $HTML += @"
        
        <h3>System Health</h3>
        <p>Status: <span class="$(if($Global:ReportData.SystemHealth.Status -eq 'Available'){'status-ok'}else{'status-warning'})">
            $($Global:ReportData.SystemHealth.Status)
        </span></p>
"@
        if ($Global:ReportData.SystemHealth.Status -eq "Available") {
            $HTML += "<p>Detailed system health report available in health reports folder.</p>`n"
        }
        
        $HTML += "    </div>`n"

        # Recommendations Section
        if ($Global:ReportData.Recommendations.Count -gt 0) {
            $HTML += @"
    
    <div class="section">
        <div class="section-title">Recommendations</div>
"@
            foreach ($Rec in $Global:ReportData.Recommendations) {
                $HTML += "        <div class='recommendation'>$Rec</div>`n"
            }
            
            $HTML += "    </div>`n"
        }

        # Footer
        $HTML += @"
    
    <div class="section">
        <div class="section-title">Report Information</div>
        <p><strong>Report Generated By:</strong> Generate-Report.ps1 v$ScriptVersion</p>
        <p><strong>Generation Time:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Report Path:</strong> $ReportFile</p>
        <p><strong>Log Files:</strong> $LogPath</p>
    </div>
    
</body>
</html>
"@
        
        # Save report
        Set-Content -Path $ReportFile -Value $HTML -Force
        
        Write-Log "Deployment report generated: $ReportFile" -Level "SUCCESS"
        
        return $ReportFile
        
    }
    catch {
        Write-Log "Exception generating report: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region FILE OPERATIONS
#==============================================================================

function Copy-ReportToShare {
    <#
    .SYNOPSIS
        Uploads report to network share
    #>
    param([string]$ReportFile)
    
    Write-LogHeader "UPLOADING REPORT TO SHARE"
    
    if (-not $UploadToShare) {
        Write-Log "Upload to share disabled" -Level "INFO"
        return $true
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would upload to: $SharePath" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Uploading report to network share..." -Level "INFO"
        
        if (-not (Test-Path $SharePath)) {
            Write-Log "Creating share directory: $SharePath" -Level "INFO"
            New-Item -Path $SharePath -ItemType Directory -Force | Out-Null
        }
        
        $DestFile = Join-Path $SharePath (Split-Path $ReportFile -Leaf)
        Copy-Item -Path $ReportFile -Destination $DestFile -Force
        
        Write-Log "Report uploaded successfully: $DestFile" -Level "SUCCESS"
        
        return $true
        
    }
    catch {
        Write-Log "Exception uploading report: $_" -Level "ERROR"
        return $false
    }
}

function New-ReportArchive {
    <#
    .SYNOPSIS
        Creates ZIP archive of report and logs
    #>
    param([string]$ReportFile)
    
    Write-LogHeader "CREATING REPORT ARCHIVE"
    
    if (-not $CompressReport) {
        Write-Log "Report compression disabled" -Level "INFO"
        return $null
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create ZIP archive" -Level "INFO"
        return $null
    }
    
    try {
        Write-Log "Creating ZIP archive..." -Level "INFO"
        
        $ArchiveName = "DeploymentReport_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
        $ArchivePath = Join-Path $ReportPath $ArchiveName
        
        # Create temp directory for archive contents
        $TempDir = Join-Path $env:TEMP "DeploymentReport_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
        
        # Copy report
        Copy-Item -Path $ReportFile -Destination $TempDir -Force
        
        # Copy logs
        $LogFiles = Get-ChildItem $LogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
        foreach ($Log in $LogFiles) {
            Copy-Item -Path $Log.FullName -Destination $TempDir -Force
        }
        
        # Create ZIP
        Compress-Archive -Path "$TempDir\*" -DestinationPath $ArchivePath -Force
        
        # Cleanup temp directory
        Remove-Item -Path $TempDir -Recurse -Force
        
        Write-Log "Archive created: $ArchivePath" -Level "SUCCESS"
        
        return $ArchivePath
        
    }
    catch {
        Write-Log "Exception creating archive: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region SUMMARY
#==============================================================================

function Show-ReportSummary {
    Write-LogHeader "REPORT GENERATION SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Report Generation Results:" -Level "INFO"
    Write-Log "  Computer: $($Global:ReportData.Computer)" -Level "INFO"
    Write-Log "  Data Points Collected: $($Global:Stats.DataPointsCollected)" -Level "INFO"
    Write-Log "  Recommendations: $($Global:ReportData.Recommendations.Count)" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Validation Status:" -Level "INFO"
    Write-Log "  Security Compliance: $($Global:ReportData.SecurityCompliance.Status)" -Level $(if($Global:ReportData.SecurityCompliance.Status -eq 'Available'){'SUCCESS'}else{'WARNING'})
    Write-Log "  Application Validation: $($Global:ReportData.ApplicationValidation.Status)" -Level $(if($Global:ReportData.ApplicationValidation.Status -eq 'Available'){'SUCCESS'}else{'WARNING'})
    Write-Log "  System Health: $($Global:ReportData.SystemHealth.Status)" -Level $(if($Global:ReportData.SystemHealth.Status -eq 'Available'){'SUCCESS'}else{'WARNING'})
    
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
║        DEPLOYMENT REPORT GENERATION                           ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Report Path: $ReportPath" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host ""
    
    Write-LogHeader "DEPLOYMENT REPORT GENERATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Include Inventory: $IncludeInventory" -Level "INFO"
    Write-Log "Upload to Share: $UploadToShare" -Level "INFO"
    Write-Log "Compress Report: $CompressReport" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Collect data
    Get-SystemInventory
    Get-DeploymentLogs
    Get-ValidationResults
    Add-Recommendations
    
    # Generate report
    $ReportFile = New-DeploymentReport
    
    if ($ReportFile) {
        # Upload if requested
        if ($UploadToShare) {
            Copy-ReportToShare -ReportFile $ReportFile
        }
        
        # Compress if requested
        if ($CompressReport) {
            $ArchiveFile = New-ReportArchive -ReportFile $ReportFile
        }
    }
    
    # Show summary
    Show-ReportSummary
    
    # Determine exit code
    $ExitCode = if ($ReportFile) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ReportFile) {
        Write-Log "Deployment report generated successfully!" -Level "SUCCESS"
        Write-Log "Report: $ReportFile" -Level "SUCCESS"

        if ($ArchiveFile) {
            Write-Log "Archive: $ArchiveFile" -Level "SUCCESS"
        }
    }
    else {
        Write-Log "Report generation failed" -Level "ERROR"
    }

    # Display manual action notices
    Write-Log " " -Level "INFO"
    Write-Log "========================================================================" -Level "INFO"
    Write-Log " MANUAL ACTIONS REQUIRED - PLEASE REVIEW" -Level "WARNING"
    Write-Log "========================================================================" -Level "INFO"
    Write-Host ""
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host "Check Windows Defender is active and has latest definition updates" -ForegroundColor White
    Write-Host "      Run: " -ForegroundColor Gray -NoNewline
    Write-Host "Get-MpComputerStatus" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host "Check BitLocker status on physical machines" -ForegroundColor White
    Write-Host "      Manual start of encryption may be required" -ForegroundColor Gray
    Write-Host "      Run: " -ForegroundColor Gray -NoNewline
    Write-Host "Get-BitLockerVolume -MountPoint C:" -ForegroundColor Cyan
    Write-Host ""
    Write-Log "========================================================================" -Level "INFO"
    Write-Log " " -Level "INFO"

    Write-Log "Exit Code: $ExitCode" -Level "INFO"

    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-ReportSummary
    
    exit 1
}

#endregion
