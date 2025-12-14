<#
.SYNOPSIS
    Configures Windows power settings based on device type
    
.DESCRIPTION
    Task script for orchestration engine that configures power plans and settings.
    Automatically detects device type (Desktop/Laptop) and applies appropriate
    power configuration. Includes detection logic to skip if already configured.
    
.PARAMETER DesktopPowerPlan
    Power plan for desktop computers. Default: High Performance
    Options: Balanced, High Performance, Power Saver
    
.PARAMETER LaptopPowerPlan
    Power plan for laptop computers. Default: Balanced
    Options: Balanced, High Performance, Power Saver
    
.PARAMETER DisableHibernation
    Disable hibernation to save disk space. Default: False
    
.PARAMETER DisableSleep
    Disable sleep mode. Default: False (only for desktops)
    
.PARAMETER LidCloseAction
    Action when laptop lid is closed. Default: Sleep
    Options: DoNothing, Sleep, Hibernate, Shutdown
    
.PARAMETER ScreenTimeoutMinutes
    Minutes before screen turns off. Default: 15 for laptops, 0 for desktops
    
.PARAMETER DiskTimeoutMinutes
    Minutes before hard disk turns off. Default: 20
    
.PARAMETER StandbyTimeoutMinutes
    Minutes before entering standby. Default: 30 for laptops, 0 for desktops
    
.PARAMETER UsbSelectiveSuspend
    Enable USB selective suspend for power saving. Default: True for laptops
    
.PARAMETER ForceDeviceType
    Override automatic device detection. Options: Desktop, Laptop
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\Configure-PowerSettings.ps1 -DesktopPowerPlan "High Performance" -LaptopPowerPlan "Balanced"
    
.NOTES
    Task ID: SYS-001
    Version: 1.0.0
    Author: IT Infrastructure Team
    
.OUTPUTS
    Returns exit code:
    0 = Success (configured)
    1 = Failed
    2 = Already compliant (already configured)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Balanced","High Performance","Power Saver","Ultimate Performance")]
    [string]$DesktopPowerPlan = "High Performance",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Balanced","High Performance","Power Saver","Ultimate Performance")]
    [string]$LaptopPowerPlan = "Balanced",
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableHibernation = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableSleep = $false,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("DoNothing","Sleep","Hibernate","Shutdown")]
    [string]$LidCloseAction = "Sleep",
    
    [Parameter(Mandatory=$false)]
    [int]$ScreenTimeoutMinutes = -1,  # -1 = auto-detect based on device type
    
    [Parameter(Mandatory=$false)]
    [int]$DiskTimeoutMinutes = 20,
    
    [Parameter(Mandatory=$false)]
    [int]$StandbyTimeoutMinutes = -1,  # -1 = auto-detect based on device type
    
    [Parameter(Mandatory=$false)]
    [bool]$UsbSelectiveSuspend = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("","Desktop","Laptop")]
    [string]$ForceDeviceType = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.0"
$TaskID = "SYS-001"
$TaskName = "Configure Power Settings"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "Configure-PowerSettings_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Power plan GUIDs
$PowerPlanGUIDs = @{
    "Balanced" = "381b4222-f694-41f0-9685-ff5bb260df2e"
    "High Performance" = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    "Power Saver" = "a1841308-3541-4fab-bc81-f71556f20b4a"
    "Ultimate Performance" = "e9a42b02-d5df-448d-aa00-03f14749eb61"
}

# Lid close action values
$LidCloseActionValues = @{
    "DoNothing" = 0
    "Sleep" = 1
    "Hibernate" = 2
    "Shutdown" = 3
}

# Exit codes
$ExitCode_Success = 0
$ExitCode_Failed = 1
$ExitCode_AlreadyCompliant = 2

# Detected device type
$Global:DeviceType = $null

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-TaskLog {
    <#
    .SYNOPSIS
        Writes to task-specific log file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $LogMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Write to console with color
    switch ($Level) {
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "DEBUG"   { Write-Host $LogMessage -ForegroundColor Cyan }
        default   { Write-Host $LogMessage -ForegroundColor White }
    }
}

#endregion

#region DETECTION FUNCTIONS
#==============================================================================

function Get-DeviceType {
    <#
    .SYNOPSIS
        Detects if system is Desktop or Laptop
    #>
    
    Write-TaskLog "Detecting device type..." -Level "INFO"
    
    # Check if forced
    if ($ForceDeviceType) {
        Write-TaskLog "Device type forced to: $ForceDeviceType" -Level "INFO"
        return $ForceDeviceType
    }
    
    try {
        # Method 1: Check chassis type
        $Chassis = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        $ChassisType = $Chassis.ChassisTypes[0]
        
        Write-TaskLog "Chassis type detected: $ChassisType" -Level "DEBUG"
        
        # Chassis types:
        # 3 = Desktop
        # 4 = Low Profile Desktop
        # 5 = Pizza Box
        # 6 = Mini Tower
        # 7 = Tower
        # 8 = Portable (Laptop)
        # 9 = Laptop
        # 10 = Notebook
        # 11 = Hand Held
        # 12 = Docking Station
        # 14 = Sub Notebook
        # 18 = Expansion Chassis
        # 21 = Peripheral Chassis
        # 30 = Tablet
        # 31 = Convertible
        # 32 = Detachable
        
        $LaptopChassisTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
        
        if ($ChassisType -in $LaptopChassisTypes) {
            Write-TaskLog "✓ Device detected as: Laptop" -Level "SUCCESS"
            return "Laptop"
        }
        else {
            Write-TaskLog "✓ Device detected as: Desktop" -Level "SUCCESS"
            return "Desktop"
        }
    }
    catch {
        Write-TaskLog "Error detecting device type: $_" -Level "WARNING"
        
        # Fallback: Check for battery
        try {
            $Battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
            if ($Battery) {
                Write-TaskLog "Battery detected - assuming Laptop" -Level "INFO"
                return "Laptop"
            }
            else {
                Write-TaskLog "No battery detected - assuming Desktop" -Level "INFO"
                return "Desktop"
            }
        }
        catch {
            Write-TaskLog "Could not determine device type - defaulting to Desktop" -Level "WARNING"
            return "Desktop"
        }
    }
}

function Get-CurrentPowerPlan {
    <#
    .SYNOPSIS
        Gets the currently active power plan
    #>
    
    Write-TaskLog "Getting current power plan..." -Level "INFO"
    
    try {
        $ActivePlan = powercfg /getactivescheme
        
        # Parse the output to get GUID and name
        if ($ActivePlan -match "GUID: ([a-f0-9-]+)\s+\((.+)\)") {
            $PlanGUID = $Matches[1]
            $PlanName = $Matches[2]
            
            Write-TaskLog "Current power plan: $PlanName" -Level "INFO"
            Write-TaskLog "Plan GUID: $PlanGUID" -Level "DEBUG"
            
            return @{
                GUID = $PlanGUID
                Name = $PlanName
            }
        }
        else {
            Write-TaskLog "Could not parse power plan information" -Level "WARNING"
            return $null
        }
    }
    catch {
        Write-TaskLog "Error getting current power plan: $_" -Level "ERROR"
        return $null
    }
}

function Get-PowerSetting {
    <#
    .SYNOPSIS
        Gets a specific power setting value
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SettingGUID,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("AC","DC")]
        [string]$PowerSource = "AC"
    )
    
    try {
        $CurrentPlan = Get-CurrentPowerPlan
        if (-not $CurrentPlan) {
            return $null
        }
        
        $ACDCFlag = if ($PowerSource -eq "AC") { "/SETACVALUEINDEX" } else { "/SETDCVALUEINDEX" }
        
        # Query the setting
        $Output = powercfg /query $($CurrentPlan.GUID) SUB_NONE $SettingGUID 2>&1
        
        if ($Output -match "Current $PowerSource Power Setting Index: 0x([0-9a-f]+)") {
            $Value = [Convert]::ToInt32($Matches[1], 16)
            return $Value
        }
        
        return $null
    }
    catch {
        Write-TaskLog "Error getting power setting $SettingGUID : $_" -Level "DEBUG"
        return $null
    }
}

function Test-PowerSettingsCompliance {
    <#
    .SYNOPSIS
        Checks if power settings match desired configuration
    #>
    
    Write-TaskLog "Checking current power configuration compliance..." -Level "INFO"
    
    # Determine target power plan
    $TargetPowerPlan = if ($Global:DeviceType -eq "Laptop") { $LaptopPowerPlan } else { $DesktopPowerPlan }
    Write-TaskLog "Target power plan for ${Global:DeviceType}: $TargetPowerPlan" -Level "INFO"
    
    # Check current power plan
    $CurrentPlan = Get-CurrentPowerPlan
    if (-not $CurrentPlan) {
        Write-TaskLog "Could not determine current power plan" -Level "WARNING"
        return $false
    }
    
    $TargetGUID = $PowerPlanGUIDs[$TargetPowerPlan]
    
    if ($CurrentPlan.GUID -eq $TargetGUID) {
        Write-TaskLog "✓ Current power plan matches target: $($CurrentPlan.Name)" -Level "SUCCESS"
        
        # Additional checks could go here (screen timeout, disk timeout, etc.)
        # For simplicity, if power plan matches, consider it compliant
        
        return $true
    }
    else {
        Write-TaskLog "Current plan ($($CurrentPlan.Name)) does not match target ($TargetPowerPlan)" -Level "INFO"
        return $false
    }
}

function Test-HibernationStatus {
    <#
    .SYNOPSIS
        Checks if hibernation is enabled
    #>
    
    try {
        $HibernateInfo = powercfg /availablesleepstates
        
        if ($HibernateInfo -match "Hibernation has not been enabled") {
            return $false
        }
        elseif ($HibernateInfo -match "Standby \(S[0-9]\)\s+Hibernate") {
            return $true
        }
        else {
            # Try to check hiberfil.sys
            $HiberFile = "$env:SystemDrive\hiberfil.sys"
            return (Test-Path $HiberFile)
        }
    }
    catch {
        Write-TaskLog "Error checking hibernation status: $_" -Level "DEBUG"
        return $false
    }
}

#endregion

#region POWER CONFIGURATION FUNCTIONS
#==============================================================================

function Set-PowerPlan {
    <#
    .SYNOPSIS
        Sets the active power plan
    #>
    param([string]$PlanName)
    
    Write-TaskLog "Setting power plan to: $PlanName" -Level "INFO"
    
    try {
        $PlanGUID = $PowerPlanGUIDs[$PlanName]
        
        if (-not $PlanGUID) {
            Write-TaskLog "Unknown power plan: $PlanName" -Level "ERROR"
            return $false
        }
        
        # Check if plan exists
        $AllPlans = powercfg /list
        
        if ($AllPlans -notmatch $PlanGUID) {
            Write-TaskLog "Power plan GUID not found on system: $PlanGUID" -Level "WARNING"

            # Try to create the power plan
            if ($PlanName -eq "Ultimate Performance") {
                Write-TaskLog "Attempting to create Ultimate Performance plan..." -Level "INFO"
                powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1 | Out-Null
                Start-Sleep -Seconds 2
            }
            elseif ($PlanName -eq "High Performance") {
                Write-TaskLog "Attempting to create High Performance plan..." -Level "INFO"
                powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
                Start-Sleep -Seconds 2
            }
            else {
                Write-TaskLog "Cannot create $PlanName plan - falling back to Balanced" -Level "WARNING"
                $PlanGUID = $PowerPlanGUIDs["Balanced"]
            }
        }
        
        # Set the power plan
        $Result = powercfg /setactive $PlanGUID 2>&1
        
        # Verify it was set
        Start-Sleep -Seconds 1
        $CurrentPlan = Get-CurrentPowerPlan
        
        if ($CurrentPlan.GUID -eq $PlanGUID) {
            Write-TaskLog "✓ Power plan set successfully: $PlanName" -Level "SUCCESS"
            return $true
        }
        else {
            Write-TaskLog "Failed to set power plan (verification failed)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-TaskLog "Error setting power plan: $_" -Level "ERROR"
        return $false
    }
}

function Set-DisplayTimeout {
    <#
    .SYNOPSIS
        Sets display timeout for AC and DC power
    #>
    param([int]$TimeoutMinutes)
    
    Write-TaskLog "Setting display timeout to $TimeoutMinutes minutes..." -Level "INFO"
    
    try {
        $TimeoutSeconds = $TimeoutMinutes * 60
        
        # Set for AC power (plugged in)
        powercfg /change monitor-timeout-ac $TimeoutMinutes | Out-Null
        
        # Set for DC power (battery) if laptop
        if ($Global:DeviceType -eq "Laptop") {
            powercfg /change monitor-timeout-dc $TimeoutMinutes | Out-Null
        }
        
        Write-TaskLog "✓ Display timeout configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error setting display timeout: $_" -Level "ERROR"
        return $false
    }
}

function Set-DiskTimeout {
    <#
    .SYNOPSIS
        Sets hard disk timeout
    #>
    param([int]$TimeoutMinutes)
    
    Write-TaskLog "Setting disk timeout to $TimeoutMinutes minutes..." -Level "INFO"
    
    try {
        # Set for AC power
        powercfg /change disk-timeout-ac $TimeoutMinutes | Out-Null
        
        # Set for DC power if laptop
        if ($Global:DeviceType -eq "Laptop") {
            powercfg /change disk-timeout-dc $TimeoutMinutes | Out-Null
        }
        
        Write-TaskLog "✓ Disk timeout configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error setting disk timeout: $_" -Level "ERROR"
        return $false
    }
}

function Set-StandbyTimeout {
    <#
    .SYNOPSIS
        Sets standby (sleep) timeout
    #>
    param([int]$TimeoutMinutes)
    
    Write-TaskLog "Setting standby timeout to $TimeoutMinutes minutes..." -Level "INFO"
    
    try {
        # Set for AC power
        powercfg /change standby-timeout-ac $TimeoutMinutes | Out-Null
        
        # Set for DC power if laptop
        if ($Global:DeviceType -eq "Laptop") {
            powercfg /change standby-timeout-dc $TimeoutMinutes | Out-Null
        }
        
        Write-TaskLog "✓ Standby timeout configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error setting standby timeout: $_" -Level "ERROR"
        return $false
    }
}

function Set-HibernationState {
    <#
    .SYNOPSIS
        Enables or disables hibernation
    #>
    param([bool]$Enable)
    
    $Action = if ($Enable) { "Enabling" } else { "Disabling" }
    Write-TaskLog "$Action hibernation..." -Level "INFO"
    
    try {
        if ($Enable) {
            powercfg /hibernate on 2>&1 | Out-Null
        }
        else {
            powercfg /hibernate off 2>&1 | Out-Null
        }
        
        # Verify
        Start-Sleep -Seconds 1
        $HibernationEnabled = Test-HibernationStatus
        
        if (($Enable -and $HibernationEnabled) -or (-not $Enable -and -not $HibernationEnabled)) {
            Write-TaskLog "✓ Hibernation $Action completed" -Level "SUCCESS"
            return $true
        }
        else {
            Write-TaskLog "Hibernation state change verification failed" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-TaskLog "Error configuring hibernation: $_" -Level "ERROR"
        return $false
    }
}

function Set-LidCloseActionSetting {
    <#
    .SYNOPSIS
        Sets the action when laptop lid is closed
    #>
    param([string]$Action)
    
    if ($Global:DeviceType -ne "Laptop") {
        Write-TaskLog "Lid close action only applies to laptops - skipping" -Level "INFO"
        return $true
    }
    
    Write-TaskLog "Setting lid close action to: $Action" -Level "INFO"
    
    try {
        $ActionValue = $LidCloseActionValues[$Action]
        
        # Lid close action GUID: 5ca83367-6e45-459f-a27b-476b1d01c936
        $LidCloseGUID = "5ca83367-6e45-459f-a27b-476b1d01c936"
        $CurrentPlan = Get-CurrentPowerPlan
        
        # Set for AC power
        powercfg /setacvalueindex $($CurrentPlan.GUID) SUB_BUTTONS $LidCloseGUID $ActionValue | Out-Null
        
        # Set for DC power (battery)
        powercfg /setdcvalueindex $($CurrentPlan.GUID) SUB_BUTTONS $LidCloseGUID $ActionValue | Out-Null
        
        # Apply the changes
        powercfg /setactive $($CurrentPlan.GUID) | Out-Null
        
        Write-TaskLog "✓ Lid close action configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error setting lid close action: $_" -Level "ERROR"
        return $false
    }
}

function Set-USBSelectiveSuspend {
    <#
    .SYNOPSIS
        Configures USB selective suspend
    #>
    param([bool]$Enable)
    
    $Action = if ($Enable) { "Enabling" } else { "Disabling" }
    Write-TaskLog "$Action USB selective suspend..." -Level "INFO"
    
    try {
        # USB selective suspend GUID: 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
        $USBGUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
        $CurrentPlan = Get-CurrentPowerPlan
        $Value = if ($Enable) { 1 } else { 0 }
        
        # Set for AC power
        powercfg /setacvalueindex $($CurrentPlan.GUID) SUB_USB $USBGUID $Value | Out-Null
        
        # Set for DC power if laptop
        if ($Global:DeviceType -eq "Laptop") {
            powercfg /setdcvalueindex $($CurrentPlan.GUID) SUB_USB $USBGUID $Value | Out-Null
        }
        
        # Apply changes
        powercfg /setactive $($CurrentPlan.GUID) | Out-Null
        
        Write-TaskLog "✓ USB selective suspend configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error configuring USB selective suspend: $_" -Level "ERROR"
        return $false
    }
}

function Set-FastStartup {
    <#
    .SYNOPSIS
        Configures fast startup (hybrid boot)
    #>
    param([bool]$Enable)
    
    Write-TaskLog "Configuring fast startup..." -Level "INFO"
    
    try {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
        $RegName = "HiberbootEnabled"
        $Value = if ($Enable) { 1 } else { 0 }
        
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $RegPath -Name $RegName -Value $Value -Type DWord -Force
        
        Write-TaskLog "✓ Fast startup configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error configuring fast startup: $_" -Level "WARNING"
        return $false
    }
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Test-PowerConfiguration {
    <#
    .SYNOPSIS
        Validates power configuration
    #>
    
    Write-TaskLog "Validating power configuration..." -Level "INFO"
    
    $ValidationResults = @{
        PowerPlanCorrect = $false
        DisplayTimeoutCorrect = $false
        StandbyTimeoutCorrect = $false
        HibernationCorrect = $false
    }
    
    # Check power plan
    $TargetPowerPlan = if ($Global:DeviceType -eq "Laptop") { $LaptopPowerPlan } else { $DesktopPowerPlan }
    $CurrentPlan = Get-CurrentPowerPlan
    $TargetGUID = $PowerPlanGUIDs[$TargetPowerPlan]
    
    if ($CurrentPlan.GUID -eq $TargetGUID) {
        Write-TaskLog "✓ Power plan is correct: $($CurrentPlan.Name)" -Level "SUCCESS"
        $ValidationResults.PowerPlanCorrect = $true
    }
    else {
        Write-TaskLog "✗ Power plan mismatch: Current=$($CurrentPlan.Name), Expected=$TargetPowerPlan" -Level "ERROR"
    }
    
    # Check hibernation
    $HibernationEnabled = Test-HibernationStatus
    $ExpectedHibernation = -not $DisableHibernation
    
    if ($HibernationEnabled -eq $ExpectedHibernation) {
        Write-TaskLog "✓ Hibernation state is correct" -Level "SUCCESS"
        $ValidationResults.HibernationCorrect = $true
    }
    else {
        Write-TaskLog "✗ Hibernation state incorrect" -Level "WARNING"
    }
    
    # Overall validation
    $AllCriticalChecksPassed = $ValidationResults.PowerPlanCorrect
    
    if ($AllCriticalChecksPassed) {
        Write-TaskLog "✓ Critical validation checks passed" -Level "SUCCESS"
        return $true
    }
    else {
        Write-TaskLog "✗ One or more critical validation checks failed" -Level "ERROR"
        return $false
    }
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "TASK: $TaskID - $TaskName" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "Script Version: $ScriptVersion" -Level "INFO"
    Write-TaskLog "Desktop Power Plan: $DesktopPowerPlan" -Level "INFO"
    Write-TaskLog "Laptop Power Plan: $LaptopPowerPlan" -Level "INFO"
    Write-TaskLog "Disable Hibernation: $DisableHibernation" -Level "INFO"
    Write-TaskLog "Disable Sleep: $DisableSleep" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    
    # Step 1: Detect device type
    Write-TaskLog "`n--- Step 1: Device Detection ---" -Level "INFO"
    $Global:DeviceType = Get-DeviceType
    
    # Auto-configure timeouts based on device type
    if ($ScreenTimeoutMinutes -eq -1) {
        $ScreenTimeoutMinutes = if ($Global:DeviceType -eq "Laptop") { 15 } else { 0 }
        Write-TaskLog "Auto-configured screen timeout: $ScreenTimeoutMinutes minutes" -Level "INFO"
    }
    
    if ($StandbyTimeoutMinutes -eq -1) {
        $StandbyTimeoutMinutes = if ($Global:DeviceType -eq "Laptop") { 30 } else { 0 }
        Write-TaskLog "Auto-configured standby timeout: $StandbyTimeoutMinutes minutes" -Level "INFO"
    }
    
    # Step 2: Check if already compliant
    Write-TaskLog "`n--- Step 2: Compliance Check ---" -Level "INFO"
    
    if (Test-PowerSettingsCompliance) {
        Write-TaskLog "Power settings are already configured correctly - no action needed" -Level "SUCCESS"
        Write-TaskLog "Task completed in $([math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)) seconds" -Level "INFO"
        exit $ExitCode_AlreadyCompliant
    }
    
    # Step 3: Configure power plan
    Write-TaskLog "`n--- Step 3: Configure Power Plan ---" -Level "INFO"
    
    $TargetPowerPlan = if ($Global:DeviceType -eq "Laptop") { $LaptopPowerPlan } else { $DesktopPowerPlan }
    
    if (-not (Set-PowerPlan -PlanName $TargetPowerPlan)) {
        Write-TaskLog "Failed to set power plan" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    # Step 4: Configure timeouts
    Write-TaskLog "`n--- Step 4: Configure Timeouts ---" -Level "INFO"
    
    Set-DisplayTimeout -TimeoutMinutes $ScreenTimeoutMinutes
    Set-DiskTimeout -TimeoutMinutes $DiskTimeoutMinutes
    
    if (-not $DisableSleep) {
        Set-StandbyTimeout -TimeoutMinutes $StandbyTimeoutMinutes
    }
    else {
        Set-StandbyTimeout -TimeoutMinutes 0
        Write-TaskLog "Sleep disabled as requested" -Level "INFO"
    }
    
    # Step 5: Configure hibernation
    Write-TaskLog "`n--- Step 5: Configure Hibernation ---" -Level "INFO"
    
    if ($DisableHibernation) {
        Set-HibernationState -Enable $false
    }
    else {
        Set-HibernationState -Enable $true
    }
    
    # Step 6: Laptop-specific settings
    if ($Global:DeviceType -eq "Laptop") {
        Write-TaskLog "`n--- Step 6: Laptop-Specific Settings ---" -Level "INFO"
        
        Set-LidCloseActionSetting -Action $LidCloseAction
        Set-USBSelectiveSuspend -Enable $UsbSelectiveSuspend
    }
    
    # Step 7: Additional optimizations
    Write-TaskLog "`n--- Step 7: Additional Optimizations ---" -Level "INFO"
    
    # Enable fast startup for better boot performance
    Set-FastStartup -Enable $true
    
    # Step 8: Validate configuration
    Write-TaskLog "`n--- Step 8: Validate Configuration ---" -Level "INFO"
    
    if (-not (Test-PowerConfiguration)) {
        Write-TaskLog "Power configuration validation failed" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    # Success
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)
    Write-TaskLog "`n========================================" -Level "SUCCESS"
    Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
    Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
    Write-TaskLog "========================================" -Level "SUCCESS"
    
    # Display final configuration
    Write-TaskLog "`nFinal Power Configuration:" -Level "INFO"
    $FinalPlan = Get-CurrentPowerPlan
    Write-TaskLog "  Device Type: $Global:DeviceType" -Level "INFO"
    Write-TaskLog "  Active Power Plan: $($FinalPlan.Name)" -Level "INFO"
    Write-TaskLog "  Screen Timeout: $ScreenTimeoutMinutes minutes" -Level "INFO"
    Write-TaskLog "  Standby Timeout: $StandbyTimeoutMinutes minutes" -Level "INFO"
    Write-TaskLog "  Hibernation Enabled: $(-not $DisableHibernation)" -Level "INFO"
    
    if ($Global:DeviceType -eq "Laptop") {
        Write-TaskLog "  Lid Close Action: $LidCloseAction" -Level "INFO"
        Write-TaskLog "  USB Selective Suspend: $UsbSelectiveSuspend" -Level "INFO"
    }
    
    exit $ExitCode_Success
}
catch {
    Write-TaskLog "`n========================================" -Level "ERROR"
    Write-TaskLog "TASK FAILED WITH EXCEPTION" -Level "ERROR"
    Write-TaskLog "Error: $($_.Exception.Message)" -Level "ERROR"
    Write-TaskLog "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-TaskLog "========================================" -Level "ERROR"
    
    exit $ExitCode_Failed
}

#endregion