<#
.SYNOPSIS
    Trigger SCCM Inventory
    
.DESCRIPTION
    Triggers SCCM/Configuration Manager hardware and software inventory cycles.
    Forces immediate inventory collection and reporting to SCCM server.
    
    Inventory Types:
    - Hardware Inventory (system specs, devices, configuration)
    - Software Inventory (installed applications, files, versions)
    - Discovery Data Collection (network, AD, user info)
    - Software Metering (application usage tracking)
    
.PARAMETER TriggerHardware
    Trigger hardware inventory cycle.
    Default: $true
    
.PARAMETER TriggerSoftware
    Trigger software inventory cycle.
    Default: $true
    
.PARAMETER TriggerDiscovery
    Trigger discovery data collection.
    Default: $false
    
.PARAMETER TriggerSoftwareMetering
    Trigger software metering cycle.
    Default: $false
    
.PARAMETER WaitForCompletion
    Wait for inventory cycles to complete.
    Default: $false
    
.PARAMETER CompletionTimeout
    Timeout for waiting (seconds).
    Default: 180 (3 minutes)
    
.PARAMETER DryRun
    Simulate inventory trigger. Default: $false
    
.EXAMPLE
    .\Trigger-SCCMInventory.ps1
    Triggers hardware and software inventory
    
.EXAMPLE
    .\Trigger-SCCMInventory.ps1 -TriggerHardware $true -TriggerSoftware $true
    Triggers both hardware and software inventory
    
.EXAMPLE
    .\Trigger-SCCMInventory.ps1 -WaitForCompletion $true
    Triggers inventory and waits for completion
    
.EXAMPLE
    .\Trigger-SCCMInventory.ps1 -TriggerDiscovery $true
    Triggers discovery data collection
    
.EXAMPLE
    .\Trigger-SCCMInventory.ps1 -DryRun
    Shows what would be triggered
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Trigger SCCM inventory for Windows 11 workstations
    
    EXIT CODES:
    0   = Inventory triggered successfully
    1   = General failure
    2   = SCCM client not installed
    3   = Inventory trigger failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - SCCM/ConfigMgr client installed
    - Administrator privileges (SYSTEM recommended)
    - Network connectivity to SCCM server
    
    INVENTORY SCHEDULE IDs:
    {00000000-0000-0000-0000-000000000001} = Hardware Inventory
    {00000000-0000-0000-0000-000000000002} = Software Inventory
    {00000000-0000-0000-0000-000000000003} = Discovery Data Collection
    {00000000-0000-0000-0000-000000000010} = Software Metering
    {00000000-0000-0000-0000-000000000021} = Machine Policy Retrieval
    {00000000-0000-0000-0000-000000000022} = Machine Policy Evaluation
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$TriggerHardware = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$TriggerSoftware = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$TriggerDiscovery = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$TriggerSoftwareMetering = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$WaitForCompletion = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$CompletionTimeout = 180,
    
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

$LogFileName = "Trigger-SCCMInventory_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# SCCM Schedule IDs
$Global:ScheduleIDs = @{
    HardwareInventory = "{00000000-0000-0000-0000-000000000001}"
    SoftwareInventory = "{00000000-0000-0000-0000-000000000002}"
    DiscoveryData = "{00000000-0000-0000-0000-000000000003}"
    SoftwareMetering = "{00000000-0000-0000-0000-000000000010}"
    MachinePolicyRetrieval = "{00000000-0000-0000-0000-000000000021}"
    MachinePolicyEvaluation = "{00000000-0000-0000-0000-000000000022}"
}

# Statistics tracking
$Global:Stats = @{
    Triggered = 0
    Failed = 0
    Completed = 0
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
}

function Write-LogHeader {
    param([string]$Title)
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region SCCM CLIENT FUNCTIONS
#==============================================================================

function Test-SCCMClientInstalled {
    <#
    .SYNOPSIS
        Checks if SCCM client is installed
    #>
    
    Write-LogHeader "CHECKING SCCM CLIENT"
    
    try {
        Write-Log "Checking for SCCM client installation..." -Level "INFO"
        
        # Check for CCMExec service
        $CCMService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        
        if ($CCMService) {
            Write-Log "SCCM client service found: $($CCMService.Status)" -Level "SUCCESS"
            
            # Check service is running
            if ($CCMService.Status -ne "Running") {
                Write-Log "WARNING: SCCM client service not running - attempting to start" -Level "WARNING"
                
                if (-not $DryRun) {
                    Start-Service -Name "CcmExec" -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 5
                    
                    $CCMService = Get-Service -Name "CcmExec"
                    if ($CCMService.Status -eq "Running") {
                        Write-Log "SCCM client service started successfully" -Level "SUCCESS"
                    }
                    else {
                        Write-Log "Failed to start SCCM client service" -Level "ERROR"
                        return $false
                    }
                }
            }
            
            # Get client version
            try {
                $CCMClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
                if ($CCMClient) {
                    Write-Log "SCCM client version: $($CCMClient.ClientVersion)" -Level "INFO"
                }
            }
            catch {
                Write-Log "Could not retrieve client version" -Level "DEBUG"
            }
            
            return $true
        }
        else {
            Write-Log "SCCM client not installed on this system" -Level "ERROR"
            return $false
        }
        
    }
    catch {
        Write-Log "Exception checking SCCM client: $_" -Level "ERROR"
        return $false
    }
}

function Get-SCCMClientInfo {
    <#
    .SYNOPSIS
        Gets SCCM client information
    #>
    
    Write-Log "Retrieving SCCM client information..." -Level "DEBUG"
    
    if ($DryRun) {
        return
    }
    
    try {
        # Get client info
        $ClientInfo = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
        
        if ($ClientInfo) {
            Write-Log "  Client Version: $($ClientInfo.ClientVersion)" -Level "DEBUG"
        }
        
        # Get assigned site
        $SiteInfo = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction SilentlyContinue
        
        if ($SiteInfo) {
            Write-Log "  Assigned Site: $($SiteInfo.CurrentManagementPoint)" -Level "DEBUG"
            Write-Log "  Site Code: $($SiteInfo.Name)" -Level "DEBUG"
        }
        
        # Get last inventory dates
        $InventoryAgent = Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus" -ErrorAction SilentlyContinue
        
        if ($InventoryAgent) {
            foreach ($Action in $InventoryAgent) {
                $LastRun = [Management.ManagementDateTimeConverter]::ToDateTime($Action.LastCycleStartedDate)
                Write-Log "  Last $($Action.InventoryActionID): $($LastRun.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "DEBUG"
            }
        }
        
    }
    catch {
        Write-Log "Exception retrieving client info: $_" -Level "DEBUG"
    }
}

#endregion

#region INVENTORY TRIGGER FUNCTIONS
#==============================================================================

function Invoke-SCCMInventoryCycle {
    <#
    .SYNOPSIS
        Triggers SCCM inventory cycle
    #>
    param(
        [string]$ScheduleID,
        [string]$Description
    )
    
    try {
        Write-Log "Triggering $Description..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would trigger: $ScheduleID" -Level "INFO"
            $Global:Stats.Triggered++
            return $true
        }
        
        # Get SCCM client
        $CCMClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction Stop
        
        # Trigger the schedule
        $Result = $CCMClient.TriggerSchedule($ScheduleID)
        
        if ($Result.ReturnValue -eq 0) {
            Write-Log "  ✓ $Description triggered successfully" -Level "SUCCESS"
            $Global:Stats.Triggered++
            return $true
        }
        else {
            Write-Log "  ✗ Failed to trigger $Description (Return code: $($Result.ReturnValue))" -Level "ERROR"
            $Global:Stats.Failed++
            return $false
        }
        
    }
    catch {
        Write-Log "Exception triggering $Description : $_" -Level "ERROR"
        $Global:Stats.Failed++
        return $false
    }
}

function Wait-InventoryCompletion {
    <#
    .SYNOPSIS
        Waits for inventory cycles to complete
    #>
    param(
        [string]$ScheduleID,
        [string]$Description
    )
    
    Write-Log "Waiting for $Description to complete..." -Level "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would wait for completion" -Level "INFO"
        return $true
    }
    
    try {
        $StartTime = Get-Date
        $Completed = $false
        
        while (-not $Completed -and ((Get-Date) - $StartTime).TotalSeconds -lt $CompletionTimeout) {
            Start-Sleep -Seconds 10
            
            # Check inventory status
            $InventoryAgent = Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus" -Filter "InventoryActionID='$ScheduleID'" -ErrorAction SilentlyContinue
            
            if ($InventoryAgent) {
                $LastMajorReportVersion = $InventoryAgent.LastMajorReportVersion
                $LastMinorReportVersion = $InventoryAgent.LastMinorReportVersion
                
                # Check if version incremented (indicates completion)
                Start-Sleep -Seconds 5
                $InventoryAgentNew = Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus" -Filter "InventoryActionID='$ScheduleID'" -ErrorAction SilentlyContinue
                
                if ($InventoryAgentNew.LastMajorReportVersion -gt $LastMajorReportVersion -or
                    $InventoryAgentNew.LastMinorReportVersion -gt $LastMinorReportVersion) {
                    $Completed = $true
                }
            }
            
            $Elapsed = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 0)
            Write-Log "  Waiting... ($Elapsed seconds elapsed)" -Level "DEBUG"
        }
        
        if ($Completed) {
            Write-Log "  ✓ $Description completed" -Level "SUCCESS"
            $Global:Stats.Completed++
            return $true
        }
        else {
            Write-Log "  ⚠ $Description did not complete within timeout" -Level "WARNING"
            Write-Log "    (This is normal - inventory may complete in background)" -Level "INFO"
            return $true  # Still return true as trigger was successful
        }
        
    }
    catch {
        Write-Log "Exception waiting for completion: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region MAIN INVENTORY FUNCTIONS
#==============================================================================

function Invoke-HardwareInventory {
    <#
    .SYNOPSIS
        Triggers hardware inventory
    #>
    
    Write-LogHeader "HARDWARE INVENTORY"
    
    if (-not $TriggerHardware) {
        Write-Log "Hardware inventory trigger disabled" -Level "INFO"
        return $true
    }
    
    $Success = Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.HardwareInventory -Description "Hardware Inventory"
    
    if ($Success -and $WaitForCompletion) {
        Wait-InventoryCompletion -ScheduleID $Global:ScheduleIDs.HardwareInventory -Description "Hardware Inventory"
    }
    
    return $Success
}

function Invoke-SoftwareInventory {
    <#
    .SYNOPSIS
        Triggers software inventory
    #>
    
    Write-LogHeader "SOFTWARE INVENTORY"
    
    if (-not $TriggerSoftware) {
        Write-Log "Software inventory trigger disabled" -Level "INFO"
        return $true
    }
    
    $Success = Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.SoftwareInventory -Description "Software Inventory"
    
    if ($Success -and $WaitForCompletion) {
        Wait-InventoryCompletion -ScheduleID $Global:ScheduleIDs.SoftwareInventory -Description "Software Inventory"
    }
    
    return $Success
}

function Invoke-DiscoveryDataCollection {
    <#
    .SYNOPSIS
        Triggers discovery data collection
    #>
    
    Write-LogHeader "DISCOVERY DATA COLLECTION"
    
    if (-not $TriggerDiscovery) {
        Write-Log "Discovery data collection disabled" -Level "INFO"
        return $true
    }
    
    $Success = Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.DiscoveryData -Description "Discovery Data Collection"
    
    return $Success
}

function Invoke-SoftwareMeteringCycle {
    <#
    .SYNOPSIS
        Triggers software metering cycle
    #>
    
    Write-LogHeader "SOFTWARE METERING"
    
    if (-not $TriggerSoftwareMetering) {
        Write-Log "Software metering cycle disabled" -Level "INFO"
        return $true
    }
    
    $Success = Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.SoftwareMetering -Description "Software Metering"
    
    return $Success
}

function Update-MachinePolicies {
    <#
    .SYNOPSIS
        Updates machine policies (optional)
    #>
    
    Write-Log "Updating machine policies..." -Level "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would update machine policies" -Level "INFO"
        return $true
    }
    
    try {
        # Trigger policy retrieval
        Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.MachinePolicyRetrieval -Description "Machine Policy Retrieval" | Out-Null
        Start-Sleep -Seconds 5
        
        # Trigger policy evaluation
        Invoke-SCCMInventoryCycle -ScheduleID $Global:ScheduleIDs.MachinePolicyEvaluation -Description "Machine Policy Evaluation" | Out-Null
        
        Write-Log "Machine policies updated" -Level "SUCCESS"
        return $true
        
    }
    catch {
        Write-Log "Exception updating policies: $_" -Level "WARNING"
        return $true  # Non-critical
    }
}

#endregion

#region SUMMARY
#==============================================================================

function Show-InventorySummary {
    Write-LogHeader "INVENTORY TRIGGER SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Inventory Trigger Results:" -Level "INFO"
    Write-Log "  Cycles Triggered: $($Global:Stats.Triggered)" -Level $(if($Global:Stats.Triggered -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Failed: $($Global:Stats.Failed)" -Level $(if($Global:Stats.Failed -gt 0){"ERROR"}else{"INFO"})
    
    if ($WaitForCompletion) {
        Write-Log "  Completed: $($Global:Stats.Completed)" -Level "INFO"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Triggered Inventory Types:" -Level "INFO"
    
    if ($TriggerHardware) {
        Write-Log "  ✓ Hardware Inventory" -Level "SUCCESS"
    }
    if ($TriggerSoftware) {
        Write-Log "  ✓ Software Inventory" -Level "SUCCESS"
    }
    if ($TriggerDiscovery) {
        Write-Log "  ✓ Discovery Data Collection" -Level "SUCCESS"
    }
    if ($TriggerSoftwareMetering) {
        Write-Log "  ✓ Software Metering" -Level "SUCCESS"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Note: Inventory data will be reported to SCCM server in background" -Level "INFO"
    Write-Log "      Check SCCM console for updated inventory in 15-30 minutes" -Level "INFO"
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
║        SCCM INVENTORY TRIGGER                                 ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host ""
    
    Write-LogHeader "SCCM INVENTORY TRIGGER STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Hardware Inventory: $TriggerHardware" -Level "INFO"
    Write-Log "Software Inventory: $TriggerSoftware" -Level "INFO"
    Write-Log "Discovery Data: $TriggerDiscovery" -Level "INFO"
    Write-Log "Software Metering: $TriggerSoftwareMetering" -Level "INFO"
    Write-Log "Wait for Completion: $WaitForCompletion" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Check SCCM client
    $ClientInstalled = Test-SCCMClientInstalled
    
    if (-not $ClientInstalled) {
        Write-Log "SCCM client not installed - cannot trigger inventory" -Level "ERROR"
        Write-Log "This system may not be managed by SCCM/ConfigMgr" -Level "WARNING"
        
        Show-InventorySummary
        exit 2
    }
    
    # Get client info
    Get-SCCMClientInfo
    
    # Trigger inventory cycles
    $HWSuccess = Invoke-HardwareInventory
    $SWSuccess = Invoke-SoftwareInventory
    $DDSuccess = Invoke-DiscoveryDataCollection
    $SMSuccess = Invoke-SoftwareMeteringCycle
    
    # Update policies
    Update-MachinePolicies
    
    # Show summary
    Show-InventorySummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Failed -eq 0) {
        0  # Success
    } else {
        3  # Some triggers failed
    }
    
    Write-Log " " -Level "INFO"
    if ($Global:Stats.Failed -eq 0) {
        Write-Log "SCCM inventory triggered successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Some inventory triggers failed ($($Global:Stats.Failed) failures)" -Level "WARNING"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-InventorySummary
    
    exit 1
}

#endregion
