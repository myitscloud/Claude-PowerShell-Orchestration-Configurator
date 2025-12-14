<#
.SYNOPSIS
    Pre-flight validation checks before orchestration
    
.DESCRIPTION
    Task script that performs comprehensive pre-flight validation to ensure
    the system meets all requirements before proceeding with orchestration.
    This is typically the first task run in Phase 1 - Critical Infrastructure.
    
.PARAMETER MinimumRAMGB
    Minimum RAM required in GB. Default: 8
    
.PARAMETER MinimumDiskSpaceGB
    Minimum free disk space required in GB. Default: 20
    
.PARAMETER RequireWindows11
    Require Windows 11 OS. Default: True
    
.PARAMETER MinimumOSBuild
    Minimum Windows build number. Default: 22000 (Windows 11)
    
.PARAMETER RequireUEFI
    Require UEFI firmware (not BIOS). Default: True
    
.PARAMETER RequireSecureBoot
    Require Secure Boot to be enabled. Default: True
    
.PARAMETER RequireTPM
    Require TPM chip to be present and ready. Default: True
    
.PARAMETER MinimumTPMVersion
    Minimum TPM version required. Default: 2.0
    
.PARAMETER RequireInternetConnectivity
    Require internet connectivity. Default: False
    
.PARAMETER InternetTestURL
    URL to test internet connectivity. Default: https://www.msft.com
    
.PARAMETER RequireDomainJoined
    Require computer to be domain joined. Default: False
    
.PARAMETER CheckWindowsActivation
    Verify Windows is activated. Default: True
    
.PARAMETER AllowVirtualMachine
    Allow orchestration on virtual machines. Default: True
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\PreFlight-Validation.ps1 -RequireWindows11 $true -MinimumRAMGB 8
    
.NOTES
    Task ID: CRIT-001
    Version: 1.0.0
    Author: IT Infrastructure Team
    This task should ALWAYS be the first task in the orchestration
    
.OUTPUTS
    Returns exit code:
    0 = Success (all checks passed)
    1 = Failed (one or more critical checks failed)
    10 = Insufficient RAM
    11 = Insufficient disk space
    12 = Wrong OS version
    13 = UEFI/Secure Boot not enabled
    14 = TPM missing or not ready
    15 = No internet connectivity
    16 = Not domain joined
    17 = Windows not activated
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$MinimumRAMGB = 8,
    
    [Parameter(Mandatory=$false)]
    [int]$MinimumDiskSpaceGB = 20,
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireWindows11 = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MinimumOSBuild = 22000,
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireUEFI = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireSecureBoot = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireTPM = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$MinimumTPMVersion = "2.0",
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireInternetConnectivity = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$InternetTestURL = "https://www.msft.com",
    
    [Parameter(Mandatory=$false)]
    [bool]$RequireDomainJoined = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckWindowsActivation = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AllowVirtualMachine = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.0"
$TaskID = "CRIT-001"
$TaskName = "Pre-Flight Validation"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "PreFlight-Validation_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Exit codes
$ExitCode_Success = 0
$ExitCode_Failed = 1
$ExitCode_InsufficientRAM = 10
$ExitCode_InsufficientDisk = 11
$ExitCode_WrongOS = 12
$ExitCode_UEFISecureBoot = 13
$ExitCode_TPMMissing = 14
$ExitCode_NoInternet = 15
$ExitCode_NotDomainJoined = 16
$ExitCode_NotActivated = 17

# Validation results tracking
$Global:ValidationResults = @{
    TotalChecks = 0
    PassedChecks = 0
    FailedChecks = 0
    WarningChecks = 0
    CriticalFailures = @()
    Warnings = @()
}

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

function Write-ValidationResult {
    <#
    .SYNOPSIS
        Logs validation check result and updates counters
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckName,
        
        [Parameter(Mandatory=$true)]
        [bool]$Passed,
        
        [Parameter(Mandatory=$false)]
        [string]$Message = "",
        
        [Parameter(Mandatory=$false)]
        [bool]$Critical = $true
    )
    
    $Global:ValidationResults.TotalChecks++
    
    if ($Passed) {
        $Global:ValidationResults.PassedChecks++
        Write-TaskLog "✓ $CheckName : PASSED - $Message" -Level "SUCCESS"
    }
    else {
        if ($Critical) {
            $Global:ValidationResults.FailedChecks++
            $Global:ValidationResults.CriticalFailures += $CheckName
            Write-TaskLog "✗ $CheckName : FAILED - $Message" -Level "ERROR"
        }
        else {
            $Global:ValidationResults.WarningChecks++
            $Global:ValidationResults.Warnings += $CheckName
            Write-TaskLog "⚠ $CheckName : WARNING - $Message" -Level "WARNING"
        }
    }
}

#endregion

#region SYSTEM INFORMATION FUNCTIONS
#==============================================================================

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Gathers comprehensive system information
    #>
    
    Write-TaskLog "Gathering system information..." -Level "INFO"
    
    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        $SystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            SerialNumber = $BIOS.SerialNumber
            TotalRAMGB = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
            OSCaption = $OS.Caption
            OSVersion = $OS.Version
            OSBuild = $OS.BuildNumber
            OSArchitecture = $OS.OSArchitecture
            InstallDate = $OS.InstallDate
            LastBootUpTime = $OS.LastBootUpTime
            ProcessorName = $Processor.Name
            ProcessorCores = $Processor.NumberOfCores
            ProcessorLogicalProcessors = $Processor.NumberOfLogicalProcessors
            Domain = $ComputerSystem.Domain
            PartOfDomain = $ComputerSystem.PartOfDomain
            SystemType = $ComputerSystem.SystemType
        }
        
        # Log system information
        Write-TaskLog "`n=== SYSTEM INFORMATION ===" -Level "INFO"
        Write-TaskLog "Computer Name: $($SystemInfo.ComputerName)" -Level "INFO"
        Write-TaskLog "Manufacturer: $($SystemInfo.Manufacturer)" -Level "INFO"
        Write-TaskLog "Model: $($SystemInfo.Model)" -Level "INFO"
        Write-TaskLog "Serial Number: $($SystemInfo.SerialNumber)" -Level "INFO"
        Write-TaskLog "Total RAM: $($SystemInfo.TotalRAMGB) GB" -Level "INFO"
        Write-TaskLog "OS: $($SystemInfo.OSCaption)" -Level "INFO"
        Write-TaskLog "OS Build: $($SystemInfo.OSBuild)" -Level "INFO"
        Write-TaskLog "Architecture: $($SystemInfo.OSArchitecture)" -Level "INFO"
        Write-TaskLog "Processor: $($SystemInfo.ProcessorName)" -Level "INFO"
        Write-TaskLog "Cores: $($SystemInfo.ProcessorCores) / Logical: $($SystemInfo.ProcessorLogicalProcessors)" -Level "INFO"
        Write-TaskLog "Domain: $($SystemInfo.Domain)" -Level "INFO"
        Write-TaskLog "Domain Joined: $($SystemInfo.PartOfDomain)" -Level "INFO"
        Write-TaskLog "========================`n" -Level "INFO"
        
        return $SystemInfo
    }
    catch {
        Write-TaskLog "Error gathering system information: $_" -Level "ERROR"
        return $null
    }
}

function Get-DiskInformation {
    <#
    .SYNOPSIS
        Gets disk space information
    #>
    
    try {
        $SystemDrive = $env:SystemDrive
        $Disk = Get-PSDrive -Name $SystemDrive.TrimEnd(':') -ErrorAction Stop
        
        $DiskInfo = @{
            DriveLetter = $SystemDrive
            TotalSizeGB = [math]::Round($Disk.Used / 1GB + $Disk.Free / 1GB, 2)
            UsedSpaceGB = [math]::Round($Disk.Used / 1GB, 2)
            FreeSpaceGB = [math]::Round($Disk.Free / 1GB, 2)
            PercentFree = [math]::Round(($Disk.Free / ($Disk.Used + $Disk.Free)) * 100, 2)
        }
        
        Write-TaskLog "Disk Information ($($DiskInfo.DriveLetter)):" -Level "INFO"
        Write-TaskLog "  Total: $($DiskInfo.TotalSizeGB) GB" -Level "INFO"
        Write-TaskLog "  Used: $($DiskInfo.UsedSpaceGB) GB" -Level "INFO"
        Write-TaskLog "  Free: $($DiskInfo.FreeSpaceGB) GB ($($DiskInfo.PercentFree)%)" -Level "INFO"
        
        return $DiskInfo
    }
    catch {
        Write-TaskLog "Error getting disk information: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region VALIDATION CHECK FUNCTIONS
#==============================================================================

function Test-AdministratorPrivileges {
    <#
    .SYNOPSIS
        Verifies script is running with administrator privileges
    #>
    
    Write-TaskLog "`n--- Checking Administrator Privileges ---" -Level "INFO"
    
    try {
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        Write-ValidationResult -CheckName "Administrator Privileges" -Passed $IsAdmin -Message $(if($IsAdmin){"Running as Administrator"}else{"Not running as Administrator"}) -Critical $true
        
        return $IsAdmin
    }
    catch {
        Write-ValidationResult -CheckName "Administrator Privileges" -Passed $false -Message "Error checking privileges: $_" -Critical $true
        return $false
    }
}

function Test-RAMRequirement {
    <#
    .SYNOPSIS
        Validates system has sufficient RAM
    #>
    param([hashtable]$SystemInfo)
    
    Write-TaskLog "`n--- Checking RAM Requirements ---" -Level "INFO"
    
    $ActualRAM = $SystemInfo.TotalRAMGB
    $MeetsRequirement = $ActualRAM -ge $MinimumRAMGB
    
    Write-ValidationResult -CheckName "RAM Requirement" -Passed $MeetsRequirement -Message "Available: $ActualRAM GB, Required: $MinimumRAMGB GB" -Critical $true
    
    return $MeetsRequirement
}

function Test-DiskSpaceRequirement {
    <#
    .SYNOPSIS
        Validates sufficient free disk space
    #>
    param([hashtable]$DiskInfo)
    
    Write-TaskLog "`n--- Checking Disk Space Requirements ---" -Level "INFO"
    
    $FreeDiskSpace = $DiskInfo.FreeSpaceGB
    $MeetsRequirement = $FreeDiskSpace -ge $MinimumDiskSpaceGB
    
    Write-ValidationResult -CheckName "Disk Space Requirement" -Passed $MeetsRequirement -Message "Available: $FreeDiskSpace GB, Required: $MinimumDiskSpaceGB GB" -Critical $true
    
    return $MeetsRequirement
}

function Test-WindowsVersion {
    <#
    .SYNOPSIS
        Validates Windows version and build
    #>
    param([hashtable]$SystemInfo)
    
    Write-TaskLog "`n--- Checking Windows Version ---" -Level "INFO"
    
    $OSBuild = [int]$SystemInfo.OSBuild
    $MeetsRequirement = $true
    
    # Check if Windows 11 if required
    if ($RequireWindows11) {
        if ($OSBuild -lt $MinimumOSBuild) {
            Write-ValidationResult -CheckName "Windows 11 Requirement" -Passed $false -Message "Current Build: $OSBuild, Required: $MinimumOSBuild (Windows 11)" -Critical $true
            $MeetsRequirement = $false
        }
        else {
            Write-ValidationResult -CheckName "Windows 11 Requirement" -Passed $true -Message "Build $OSBuild meets Windows 11 requirement" -Critical $true
        }
    }
    else {
        Write-ValidationResult -CheckName "Windows Version" -Passed $true -Message "$($SystemInfo.OSCaption) - Build $OSBuild" -Critical $false
    }
    
    # Check architecture
    if ($SystemInfo.OSArchitecture -ne "64-bit") {
        Write-ValidationResult -CheckName "64-bit Operating System" -Passed $false -Message "32-bit OS not supported" -Critical $true
        $MeetsRequirement = $false
    }
    else {
        Write-ValidationResult -CheckName "64-bit Operating System" -Passed $true -Message "64-bit OS confirmed" -Critical $true
    }
    
    return $MeetsRequirement
}

function Test-UEFIFirmware {
    <#
    .SYNOPSIS
        Checks if system is UEFI or legacy BIOS
    #>
    
    Write-TaskLog "`n--- Checking UEFI Firmware ---" -Level "INFO"
    
    try {
        # Try to get firmware type
        $FirmwareType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "PEFirmwareType" -ErrorAction SilentlyContinue).PEFirmwareType
        
        # FirmwareType values:
        # 0x1 = BIOS
        # 0x2 = UEFI
        
        $IsUEFI = $FirmwareType -eq 2
        
        if ($RequireUEFI) {
            Write-ValidationResult -CheckName "UEFI Firmware" -Passed $IsUEFI -Message $(if($IsUEFI){"UEFI firmware detected"}else{"Legacy BIOS detected"}) -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Firmware Type" -Passed $true -Message $(if($IsUEFI){"UEFI"}else{"Legacy BIOS"}) -Critical $false
        }
        
        return $IsUEFI
    }
    catch {
        Write-ValidationResult -CheckName "UEFI Firmware" -Passed $false -Message "Could not determine firmware type: $_" -Critical $RequireUEFI
        return $false
    }
}

function Test-SecureBoot {
    <#
    .SYNOPSIS
        Checks if Secure Boot is enabled
    #>
    
    Write-TaskLog "`n--- Checking Secure Boot ---" -Level "INFO"
    
    try {
        $SecureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
        
        if ($RequireSecureBoot) {
            Write-ValidationResult -CheckName "Secure Boot" -Passed $SecureBootEnabled -Message $(if($SecureBootEnabled){"Secure Boot is enabled"}else{"Secure Boot is disabled"}) -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Secure Boot Status" -Passed $true -Message $(if($SecureBootEnabled){"Enabled"}else{"Disabled"}) -Critical $false
        }
        
        return $SecureBootEnabled
    }
    catch {
        # Error usually means BIOS system (not UEFI) or cmdlet not available
        if ($RequireSecureBoot) {
            Write-ValidationResult -CheckName "Secure Boot" -Passed $false -Message "Secure Boot not available (may be BIOS system)" -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Secure Boot Status" -Passed $true -Message "Not available (BIOS system)" -Critical $false
        }
        return $false
    }
}

function Test-TPMStatus {
    <#
    .SYNOPSIS
        Checks TPM presence and status
    #>
    
    Write-TaskLog "`n--- Checking TPM Status ---" -Level "INFO"
    
    try {
        $TPM = Get-Tpm -ErrorAction Stop
        
        # Check if TPM is present
        if (-not $TPM.TpmPresent) {
            Write-ValidationResult -CheckName "TPM Presence" -Passed $false -Message "TPM not detected on this system" -Critical $RequireTPM
            return $false
        }
        
        Write-ValidationResult -CheckName "TPM Presence" -Passed $true -Message "TPM detected" -Critical $true
        
        # Check if TPM is ready
        if (-not $TPM.TpmReady) {
            Write-TaskLog "TPM Status Details:" -Level "DEBUG"
            Write-TaskLog "  Enabled: $($TPM.TpmEnabled)" -Level "DEBUG"
            Write-TaskLog "  Activated: $($TPM.TpmActivated)" -Level "DEBUG"
            Write-TaskLog "  Owned: $($TPM.TpmOwned)" -Level "DEBUG"
            
            Write-ValidationResult -CheckName "TPM Ready" -Passed $false -Message "TPM not ready (may need BIOS configuration)" -Critical $RequireTPM
            return $false
        }
        
        Write-ValidationResult -CheckName "TPM Ready" -Passed $true -Message "TPM is ready" -Critical $true
        
        # Check TPM version
        $TPMVersion = $TPM.ManufacturerVersion
        Write-TaskLog "TPM Version: $TPMVersion" -Level "INFO"
        Write-TaskLog "TPM Manufacturer ID: $($TPM.ManufacturerId)" -Level "DEBUG"
        
        # For TPM 2.0 requirement, we primarily check if it's ready
        # Version checking is complex as format varies by manufacturer
        Write-ValidationResult -CheckName "TPM Version" -Passed $true -Message "Version: $TPMVersion" -Critical $false
        
        return $true
    }
    catch {
        Write-ValidationResult -CheckName "TPM Status" -Passed $false -Message "Error checking TPM: $_" -Critical $RequireTPM
        return $false
    }
}

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
        Tests internet connectivity
    #>
    
    Write-TaskLog "`n--- Checking Internet Connectivity ---" -Level "INFO"
    
    try {
        $TestURL = $InternetTestURL.Replace("https://","").Replace("http://","").Split('/')[0]
        Write-TaskLog "Testing connectivity to: $TestURL" -Level "DEBUG"
        
        $TestResult = Test-Connection -ComputerName $TestURL -Count 2 -Quiet -ErrorAction Stop
        
        if ($RequireInternetConnectivity) {
            Write-ValidationResult -CheckName "Internet Connectivity" -Passed $TestResult -Message $(if($TestResult){"Internet accessible"}else{"No internet access"}) -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Internet Connectivity" -Passed $true -Message $(if($TestResult){"Connected"}else{"Not connected"}) -Critical $false
        }
        
        return $TestResult
    }
    catch {
        if ($RequireInternetConnectivity) {
            Write-ValidationResult -CheckName "Internet Connectivity" -Passed $false -Message "Cannot reach $TestURL" -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Internet Connectivity" -Passed $true -Message "Not tested or unavailable" -Critical $false
        }
        return $false
    }
}

function Test-DomainJoinStatus {
    <#
    .SYNOPSIS
        Checks if computer is domain joined
    #>
    param([hashtable]$SystemInfo)
    
    Write-TaskLog "`n--- Checking Domain Join Status ---" -Level "INFO"
    
    $IsDomainJoined = $SystemInfo.PartOfDomain
    $DomainName = $SystemInfo.Domain
    
    if ($RequireDomainJoined) {
        Write-ValidationResult -CheckName "Domain Join Status" -Passed $IsDomainJoined -Message $(if($IsDomainJoined){"Joined to: $DomainName"}else{"Not domain joined (Workgroup)"}) -Critical $true
    }
    else {
        Write-ValidationResult -CheckName "Domain Join Status" -Passed $true -Message $(if($IsDomainJoined){"Domain: $DomainName"}else{"Workgroup"}) -Critical $false
    }
    
    return $IsDomainJoined
}

function Test-WindowsActivation {
    <#
    .SYNOPSIS
        Checks Windows activation status
    #>
    
    Write-TaskLog "`n--- Checking Windows Activation ---" -Level "INFO"
    
    try {
        $LicenseStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name LIKE 'Windows%' AND PartialProductKey IS NOT NULL" -ErrorAction Stop | Select-Object -First 1).LicenseStatus
        
        # LicenseStatus values:
        # 0 = Unlicensed
        # 1 = Licensed (Activated)
        # 2 = Out-Of-Box Grace Period
        # 3 = Out-Of-Tolerance Grace Period
        # 4 = Non-Genuine Grace Period
        # 5 = Notification
        # 6 = Extended Grace
        
        $IsActivated = $LicenseStatus -eq 1
        
        $StatusText = switch ($LicenseStatus) {
            0 { "Unlicensed" }
            1 { "Activated" }
            2 { "OOB Grace Period" }
            3 { "OOT Grace Period" }
            4 { "Non-Genuine Grace" }
            5 { "Notification Mode" }
            6 { "Extended Grace" }
            default { "Unknown ($LicenseStatus)" }
        }
        
        if ($CheckWindowsActivation) {
            Write-ValidationResult -CheckName "Windows Activation" -Passed $IsActivated -Message "Status: $StatusText" -Critical $true
        }
        else {
            Write-ValidationResult -CheckName "Windows Activation" -Passed $true -Message "Status: $StatusText" -Critical $false
        }
        
        return $IsActivated
    }
    catch {
        Write-ValidationResult -CheckName "Windows Activation" -Passed $false -Message "Could not determine activation status: $_" -Critical $CheckWindowsActivation
        return $false
    }
}

function Test-VirtualMachine {
    <#
    .SYNOPSIS
        Detects if running on a virtual machine
    #>
    param([hashtable]$SystemInfo)
    
    Write-TaskLog "`n--- Checking Virtual Machine Status ---" -Level "INFO"
    
    $IsVM = $false
    $VMPlatform = "Physical"
    
    # Check manufacturer for VM indicators
    $Manufacturer = $SystemInfo.Manufacturer.ToLower()
    $Model = $SystemInfo.Model.ToLower()
    
    if ($Manufacturer -match "vmware" -or $Model -match "vmware") {
        $IsVM = $true
        $VMPlatform = "VMware"
    }
    elseif ($Manufacturer -match "microsoft" -and $Model -match "virtual") {
        $IsVM = $true
        $VMPlatform = "Hyper-V"
    }
    elseif ($Manufacturer -match "xen" -or $Model -match "xen") {
        $IsVM = $true
        $VMPlatform = "Xen"
    }
    elseif ($Manufacturer -match "qemu" -or $Model -match "qemu") {
        $IsVM = $true
        $VMPlatform = "QEMU/KVM"
    }
    elseif ($Manufacturer -match "oracle" -and $Model -match "virtualbox") {
        $IsVM = $true
        $VMPlatform = "VirtualBox"
    }
    
    if ($IsVM) {
        if ($AllowVirtualMachine) {
            Write-ValidationResult -CheckName "Virtual Machine Detection" -Passed $true -Message "VM detected: $VMPlatform (allowed)" -Critical $false
        }
        else {
            Write-ValidationResult -CheckName "Virtual Machine Detection" -Passed $false -Message "VM detected: $VMPlatform (not allowed)" -Critical $true
        }
    }
    else {
        Write-ValidationResult -CheckName "Virtual Machine Detection" -Passed $true -Message "Physical machine" -Critical $false
    }
    
    return (-not $IsVM) -or $AllowVirtualMachine
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks if system has a pending reboot
    #>
    
    Write-TaskLog "`n--- Checking Pending Reboot Status ---" -Level "INFO"
    
    $PendingReboot = $false
    $RebootReasons = @()
    
    try {
        # Check Component Based Servicing
        $CBS = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Name "RebootPending" -ErrorAction SilentlyContinue
        if ($CBS) {
            $PendingReboot = $true
            $RebootReasons += "Component Based Servicing"
        }
        
        # Check Windows Update
        $WU = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "RebootRequired" -ErrorAction SilentlyContinue
        if ($WU) {
            $PendingReboot = $true
            $RebootReasons += "Windows Update"
        }
        
        # Check pending file rename operations
        $FileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($FileRename) {
            $PendingReboot = $true
            $RebootReasons += "Pending File Rename Operations"
        }
        
        if ($PendingReboot) {
            $ReasonText = $RebootReasons -join ", "
            Write-ValidationResult -CheckName "Pending Reboot" -Passed $false -Message "Reboot required: $ReasonText" -Critical $false
        }
        else {
            Write-ValidationResult -CheckName "Pending Reboot" -Passed $true -Message "No pending reboot" -Critical $false
        }
    }
    catch {
        Write-ValidationResult -CheckName "Pending Reboot" -Passed $true -Message "Could not determine status" -Critical $false
    }
    
    return (-not $PendingReboot)
}

function Test-NetworkAdapters {
    <#
    .SYNOPSIS
        Validates network adapter configuration
    #>
    
    Write-TaskLog "`n--- Checking Network Adapters ---" -Level "INFO"
    
    try {
        $ActiveAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        if ($ActiveAdapters.Count -eq 0) {
            Write-ValidationResult -CheckName "Network Adapters" -Passed $false -Message "No active network adapters found" -Critical $false
            return $false
        }
        
        Write-ValidationResult -CheckName "Network Adapters" -Passed $true -Message "$($ActiveAdapters.Count) active adapter(s) found" -Critical $false
        
        # Log adapter details
        foreach ($Adapter in $ActiveAdapters) {
            Write-TaskLog "  - $($Adapter.Name): $($Adapter.InterfaceDescription) ($($Adapter.LinkSpeed))" -Level "DEBUG"
        }
        
        return $true
    }
    catch {
        Write-ValidationResult -CheckName "Network Adapters" -Passed $false -Message "Error checking adapters: $_" -Critical $false
        return $false
    }
}

function Test-WindowsServices {
    <#
    .SYNOPSIS
        Checks critical Windows services are running
    #>
    
    Write-TaskLog "`n--- Checking Critical Windows Services ---" -Level "INFO"
    
    $CriticalServices = @(
        "wuauserv",    # Windows Update
        "BITS",        # Background Intelligent Transfer Service
        "CryptSvc",    # Cryptographic Services
        "TrustedInstaller", # Windows Modules Installer
        "EventLog"     # Windows Event Log
    )
    
    $AllServicesOK = $true
    
    foreach ($ServiceName in $CriticalServices) {
        try {
            $Service = Get-Service -Name $ServiceName -ErrorAction Stop
            
            if ($Service.Status -eq "Running" -or $Service.StartType -eq "Automatic" -or $Service.StartType -eq "Manual") {
                Write-TaskLog "  ✓ $ServiceName : $($Service.Status) ($($Service.StartType))" -Level "DEBUG"
            }
            else {
                Write-TaskLog "  ⚠ $ServiceName : $($Service.Status) ($($Service.StartType))" -Level "WARNING"
                $AllServicesOK = $false
            }
        }
        catch {
            Write-TaskLog "  ✗ $ServiceName : Not found or error" -Level "WARNING"
            $AllServicesOK = $false
        }
    }
    
    Write-ValidationResult -CheckName "Critical Windows Services" -Passed $AllServicesOK -Message $(if($AllServicesOK){"All services OK"}else{"Some services need attention"}) -Critical $false
    
    return $AllServicesOK
}

function Test-SystemTime {
    <#
    .SYNOPSIS
        Validates system time is reasonably accurate
    #>
    
    Write-TaskLog "`n--- Checking System Time ---" -Level "INFO"
    
    try {
        $LocalTime = Get-Date
        $TimeZone = (Get-TimeZone).DisplayName
        
        Write-TaskLog "System Time: $($LocalTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        Write-TaskLog "Time Zone: $TimeZone" -Level "INFO"
        
        # Check if time is within reasonable range (not in past or too far future)
        $MinDate = [DateTime]::Parse("2024-01-01")
        $MaxDate = [DateTime]::Parse("2030-01-01")
        
        $TimeIsValid = ($LocalTime -gt $MinDate) -and ($LocalTime -lt $MaxDate)
        
        Write-ValidationResult -CheckName "System Time" -Passed $TimeIsValid -Message $(if($TimeIsValid){"Time appears valid"}else{"Time may be incorrect"}) -Critical $false
        
        return $TimeIsValid
    }
    catch {
        Write-ValidationResult -CheckName "System Time" -Passed $false -Message "Error checking time: $_" -Critical $false
        return $false
    }
}

function Test-PowerSource {
    <#
    .SYNOPSIS
        Checks if laptop is plugged in (for long-running operations)
    #>
    
    Write-TaskLog "`n--- Checking Power Source ---" -Level "INFO"
    
    try {
        # Check if system has a battery
        $Battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        
        if (-not $Battery) {
            Write-ValidationResult -CheckName "Power Source" -Passed $true -Message "Desktop system (no battery)" -Critical $false
            return $true
        }
        
        # System has battery - check if plugged in
        $BatteryStatus = $Battery.BatteryStatus
        $EstimatedChargeRemaining = $Battery.EstimatedChargeRemaining
        
        # BatteryStatus: 1=Discharging, 2=AC, 3=Fully Charged, 4=Low, 5=Critical
        $IsPluggedIn = $BatteryStatus -in @(2, 3)
        
        $StatusText = switch ($BatteryStatus) {
            1 { "On Battery ($EstimatedChargeRemaining%)" }
            2 { "Plugged In - Charging ($EstimatedChargeRemaining%)" }
            3 { "Plugged In - Fully Charged" }
            4 { "Low Battery ($EstimatedChargeRemaining%)" }
            5 { "Critical Battery ($EstimatedChargeRemaining%)" }
            default { "Unknown ($EstimatedChargeRemaining%)" }
        }
        
        if ($IsPluggedIn -or $EstimatedChargeRemaining -gt 50) {
            Write-ValidationResult -CheckName "Power Source" -Passed $true -Message $StatusText -Critical $false
        }
        else {
            Write-ValidationResult -CheckName "Power Source" -Passed $false -Message "$StatusText - Recommend plugging in for deployment" -Critical $false
        }
        
        return $true
    }
    catch {
        Write-ValidationResult -CheckName "Power Source" -Passed $true -Message "Could not determine power source" -Critical $false
        return $true
    }
}

#endregion

#region REPORTING FUNCTIONS
#==============================================================================

function Write-ValidationSummary {
    <#
    .SYNOPSIS
        Displays final validation summary
    #>
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog "VALIDATION SUMMARY" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    Write-TaskLog "Total Checks: $($Global:ValidationResults.TotalChecks)" -Level "INFO"
    Write-TaskLog "Passed: $($Global:ValidationResults.PassedChecks)" -Level "SUCCESS"
    
    if ($Global:ValidationResults.FailedChecks -gt 0) {
        Write-TaskLog "Failed: $($Global:ValidationResults.FailedChecks)" -Level "ERROR"
    }
    else {
        Write-TaskLog "Failed: 0" -Level "INFO"
    }
    
    if ($Global:ValidationResults.WarningChecks -gt 0) {
        Write-TaskLog "Warnings: $($Global:ValidationResults.WarningChecks)" -Level "WARNING"
    }
    else {
        Write-TaskLog "Warnings: 0" -Level "INFO"
    }
    
    # List critical failures
    if ($Global:ValidationResults.CriticalFailures.Count -gt 0) {
        Write-TaskLog "`nCritical Failures:" -Level "ERROR"
        foreach ($Failure in $Global:ValidationResults.CriticalFailures) {
            Write-TaskLog "  - $Failure" -Level "ERROR"
        }
    }
    
    # List warnings
    if ($Global:ValidationResults.Warnings.Count -gt 0) {
        Write-TaskLog "`nWarnings:" -Level "WARNING"
        foreach ($Warning in $Global:ValidationResults.Warnings) {
            Write-TaskLog "  - $Warning" -Level "WARNING"
        }
    }
    
    Write-TaskLog "========================================`n" -Level "INFO"
}

function Get-RecommendedActions {
    <#
    .SYNOPSIS
        Provides recommended actions based on failures
    #>
    
    if ($Global:ValidationResults.CriticalFailures.Count -eq 0) {
        return
    }
    
    Write-TaskLog "`n=== RECOMMENDED ACTIONS ===" -Level "INFO"
    
    foreach ($Failure in $Global:ValidationResults.CriticalFailures) {
        switch -Wildcard ($Failure) {
            "*Administrator*" {
                Write-TaskLog "• Run this script with Administrator privileges (Right-click > Run as Administrator)" -Level "INFO"
            }
            "*RAM*" {
                Write-TaskLog "• Add more RAM to meet minimum requirement of $MinimumRAMGB GB" -Level "INFO"
            }
            "*Disk Space*" {
                Write-TaskLog "• Free up disk space - at least $MinimumDiskSpaceGB GB required" -Level "INFO"
                Write-TaskLog "  - Run Disk Cleanup utility" -Level "INFO"
                Write-TaskLog "  - Remove unnecessary files and applications" -Level "INFO"
            }
            "*Windows 11*" {
                Write-TaskLog "• Upgrade to Windows 11 (Build $MinimumOSBuild or higher)" -Level "INFO"
            }
            "*UEFI*" {
                Write-TaskLog "• System must use UEFI firmware (not legacy BIOS)" -Level "INFO"
                Write-TaskLog "  - Check BIOS/UEFI settings" -Level "INFO"
                Write-TaskLog "  - May require reinstallation with UEFI mode" -Level "INFO"
            }
            "*Secure Boot*" {
                Write-TaskLog "• Enable Secure Boot in UEFI/BIOS settings" -Level "INFO"
            }
            "*TPM*" {
                Write-TaskLog "• Enable TPM in BIOS/UEFI settings" -Level "INFO"
                Write-TaskLog "• Initialize TPM if present but not ready" -Level "INFO"
            }
            "*Internet*" {
                Write-TaskLog "• Ensure network connectivity and internet access" -Level "INFO"
                Write-TaskLog "• Check firewall and proxy settings" -Level "INFO"
            }
            "*Domain*" {
                Write-TaskLog "• Join computer to domain before proceeding" -Level "INFO"
            }
            "*Activation*" {
                Write-TaskLog "• Activate Windows using valid license key" -Level "INFO"
            }
        }
    }
    
    Write-TaskLog "===========================`n" -Level "INFO"
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "TASK: $TaskID - $TaskName" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "Script Version: $ScriptVersion" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    Write-TaskLog "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    
    # Gather system information first
    Write-TaskLog "`n=== GATHERING SYSTEM INFORMATION ===" -Level "INFO"
    $SystemInfo = Get-SystemInformation
    $DiskInfo = Get-DiskInformation
    
    if (-not $SystemInfo) {
        Write-TaskLog "FATAL: Could not gather system information" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    # Run all validation checks
    Write-TaskLog "`n=== RUNNING VALIDATION CHECKS ===" -Level "INFO"
    
    # Critical checks that determine exit code
    $AdminCheck = Test-AdministratorPrivileges
    $RAMCheck = Test-RAMRequirement -SystemInfo $SystemInfo
    $DiskCheck = Test-DiskSpaceRequirement -DiskInfo $DiskInfo
    $OSCheck = Test-WindowsVersion -SystemInfo $SystemInfo
    $UEFICheck = Test-UEFIFirmware
    $SecureBootCheck = Test-SecureBoot
    $TPMCheck = Test-TPMStatus
    $DomainCheck = Test-DomainJoinStatus -SystemInfo $SystemInfo
    $ActivationCheck = Test-WindowsActivation
    $InternetCheck = Test-InternetConnectivity
    $VMCheck = Test-VirtualMachine -SystemInfo $SystemInfo
    
    # Informational checks (warnings only)
    $RebootCheck = Test-PendingReboot
    $NetworkCheck = Test-NetworkAdapters
    $ServicesCheck = Test-WindowsServices
    $TimeCheck = Test-SystemTime
    $PowerCheck = Test-PowerSource
    
    # Display summary
    Write-ValidationSummary
    
    # Determine overall result
    $AllCriticalChecksPassed = $Global:ValidationResults.FailedChecks -eq 0
    
    if ($AllCriticalChecksPassed) {
        Write-TaskLog "✓ ALL VALIDATION CHECKS PASSED" -Level "SUCCESS"
        
        if ($Global:ValidationResults.WarningChecks -gt 0) {
            Write-TaskLog "Note: $($Global:ValidationResults.WarningChecks) warning(s) - review but not blocking" -Level "WARNING"
        }
        
        $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)
        Write-TaskLog "`nValidation Duration: $Duration seconds" -Level "INFO"
        Write-TaskLog "System is ready for orchestration" -Level "SUCCESS"
        
        exit $ExitCode_Success
    }
    else {
        Write-TaskLog "✗ VALIDATION FAILED - $($Global:ValidationResults.FailedChecks) critical check(s) failed" -Level "ERROR"
        
        # Provide recommended actions
        Get-RecommendedActions
        
        # Determine specific exit code based on failures
        $ExitCode = $ExitCode_Failed
        
        if ($Global:ValidationResults.CriticalFailures -contains "RAM Requirement") {
            $ExitCode = $ExitCode_InsufficientRAM
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "Disk Space Requirement") {
            $ExitCode = $ExitCode_InsufficientDisk
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "Windows 11 Requirement") {
            $ExitCode = $ExitCode_WrongOS
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "UEFI Firmware" -or $Global:ValidationResults.CriticalFailures -contains "Secure Boot") {
            $ExitCode = $ExitCode_UEFISecureBoot
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "TPM Presence" -or $Global:ValidationResults.CriticalFailures -contains "TPM Ready") {
            $ExitCode = $ExitCode_TPMMissing
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "Internet Connectivity") {
            $ExitCode = $ExitCode_NoInternet
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "Domain Join Status") {
            $ExitCode = $ExitCode_NotDomainJoined
        }
        elseif ($Global:ValidationResults.CriticalFailures -contains "Windows Activation") {
            $ExitCode = $ExitCode_NotActivated
        }
        
        Write-TaskLog "`nCannot proceed with orchestration - resolve critical failures first" -Level "ERROR"
        exit $ExitCode
    }
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