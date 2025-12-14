<#
.SYNOPSIS
    Disables Insecure Windows Features, Protocols, and Services
    
.DESCRIPTION
    Hardens Windows 11 workstations by disabling insecure, obsolete, and legacy
    protocols and features that pose security risks. Implements defense-in-depth
    by removing unnecessary attack surface while maintaining business functionality.
    
    This script disables:
    - SMBv1 (WannaCry/NotPetya vulnerability)
    - LLMNR (credential theft via poisoning)
    - NetBIOS over TCP/IP (legacy, unencrypted)
    - WPAD (auto-proxy hijacking)
    - Telnet (plaintext protocol)
    - FTP (unencrypted file transfer)
    - Windows Script Host (malware delivery)
    - Remote Registry (unauthorized access)
    - Remote Assistance (security risk)
    - Autorun/Autoplay (USB malware)
    - IPv6 (if not used)
    - Print Spooler (on workstations, PrintNightmare)
    - Various obsolete Windows features
    
    RDP is RESTRICTED (not disabled) with NLA enforcement and security hardening.
    
.PARAMETER DisableSMBv1
    Disable SMBv1 protocol. Default: $true
    
.PARAMETER DisableLLMNR
    Disable Link-Local Multicast Name Resolution. Default: $true
    
.PARAMETER DisableNetBIOS
    Disable NetBIOS over TCP/IP on all adapters. Default: $true
    
.PARAMETER DisableWPAD
    Disable Web Proxy Auto-Discovery. Default: $true
    
.PARAMETER DisableTelnet
    Disable Telnet client. Default: $true
    
.PARAMETER DisableWSH
    Disable Windows Script Host (VBScript/JScript). Default: $true
    
.PARAMETER DisableRemoteRegistry
    Disable Remote Registry service. Default: $true
    
.PARAMETER DisableRemoteAssistance
    Disable Remote Assistance. Default: $true
    
.PARAMETER DisableAutorun
    Disable Autorun/Autoplay for removable media. Default: $true
    
.PARAMETER DisableIPv6
    Disable IPv6 protocol. Default: $true
    
.PARAMETER DisablePrintSpooler
    Disable Print Spooler service (PrintNightmare mitigation). Default: $false
    WARNING: This prevents printing. Only enable on non-printing workstations.
    
.PARAMETER SecureRDP
    Harden RDP security (enable NLA, restrict settings). Default: $true
    Note: This RESTRICTS RDP, does not disable it.
    
.PARAMETER DisableRDP
    Completely disable RDP. Default: $false
    Use this only if RDP is not needed at all.
    
.PARAMETER DisableSNMP
    Disable SNMP service. Default: $true
    
.PARAMETER DisableSSDPUPnP
    Disable SSDP/UPnP service. Default: $true
    
.PARAMETER DisableWebDAV
    Disable WebDAV client. Default: $true
    
.PARAMETER DisableObsoleteFeatures
    Disable obsolete Windows features (XPS, Windows Media Player, etc.). Default: $true
    
.PARAMETER DisableBluetooth
    Disable Bluetooth on desktops. Default: $false
    WARNING: Breaks Bluetooth keyboards/mice on laptops.
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Disable-Insecure-Features-Protocols.ps1
    Disables all insecure features with defaults (RDP hardened, not disabled)
    
.EXAMPLE
    .\Disable-Insecure-Features-Protocols.ps1 -DryRun
    Shows what would be disabled without making changes
    
.EXAMPLE
    .\Disable-Insecure-Features-Protocols.ps1 -DisablePrintSpooler $true
    Disables all defaults + Print Spooler (for non-printing workstations)
    
.EXAMPLE
    .\Disable-Insecure-Features-Protocols.ps1 -DisableRDP $true
    Disables all defaults + completely disables RDP
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Security hardening for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Reboot required
    
    REQUIRES:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - PowerShell 5.1 or higher
    
    TESTED ON:
    - Windows 11 Professional (Build 22000+)
    - Windows 11 Enterprise (Build 22000+)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$DisableSMBv1 = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableLLMNR = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableNetBIOS = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableWPAD = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableTelnet = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableWSH = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableRemoteRegistry = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableRemoteAssistance = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableAutorun = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableIPv6 = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisablePrintSpooler = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$SecureRDP = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableRDP = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableSNMP = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableSSDPUPnP = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableWebDAV = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableObsoleteFeatures = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableBluetooth = $false,
    
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

$LogFileName = "Disable-Insecure-Features_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    FeaturesDisabled = 0
    ServicesDisabled = 0
    ProtocolsDisabled = 0
    RegistryChanges = 0
    Errors = 0
    Warnings = 0
    RebootRequired = $false
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
    
    # Check 2: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($OSVersion.Major -lt 10) {
        Write-Log "WARNING: This script is designed for Windows 10/11" -Level "WARNING"
    }
    else {
        Write-Log "Windows version check passed" -Level "SUCCESS"
    }
    
    # Check 3: PowerShell version
    Write-Log "Checking PowerShell version..." -Level "INFO"
    $PSVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell Version: $PSVersion" -Level "INFO"
    
    if ($PSVersion.Major -lt 5) {
        Write-Log "WARNING: PowerShell 5.1 or higher recommended" -Level "WARNING"
    }
    
    return $AllChecksPassed
}

#endregion

#region CRITICAL PROTOCOLS - DISABLE IMMEDIATELY
#==============================================================================

function Disable-SMBv1Protocol {
    <#
    .SYNOPSIS
        Disables SMBv1 protocol (WannaCry/NotPetya vulnerability)
    #>
    
    if (-not $DisableSMBv1) {
        Write-Log "SMBv1 disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING SMBv1 PROTOCOL"
    
    try {
        # Check current status
        $SMBv1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        
        if ($SMBv1Status.State -eq "Disabled") {
            Write-Log "SMBv1 is already disabled" -Level "SUCCESS"
            return
        }
        
        Write-Log "Current SMBv1 status: $($SMBv1Status.State)" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable SMBv1 protocol" -Level "INFO"
            return
        }
        
        # Disable SMBv1
        Write-Log "Disabling SMBv1 protocol..." -Level "INFO"
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        
        # Also disable via registry for extra safety
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction Stop
        
        Write-Log "SMBv1 protocol disabled successfully" -Level "SUCCESS"
        $Global:Stats.ProtocolsDisabled++
        $Global:Stats.RebootRequired = $true
        
        Write-Log "⚠️ REBOOT REQUIRED for SMBv1 disable to take effect" -Level "WARNING"
    }
    catch {
        Write-Log "Failed to disable SMBv1: $_" -Level "ERROR"
    }
}

function Disable-LLMNRProtocol {
    <#
    .SYNOPSIS
        Disables LLMNR (Link-Local Multicast Name Resolution)
    #>
    
    if (-not $DisableLLMNR) {
        Write-Log "LLMNR disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING LLMNR"
    
    try {
        # Check current status
        $LLMNRStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        
        if ($LLMNRStatus.EnableMulticast -eq 0) {
            Write-Log "LLMNR is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable LLMNR" -Level "INFO"
            return
        }
        
        # Create registry path if it doesn't exist
        $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        
        # Disable LLMNR
        Set-ItemProperty -Path $RegPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
        
        Write-Log "LLMNR disabled successfully" -Level "SUCCESS"
        $Global:Stats.ProtocolsDisabled++
        $Global:Stats.RegistryChanges++
    }
    catch {
        Write-Log "Failed to disable LLMNR: $_" -Level "ERROR"
    }
}

function Disable-NetBIOSOverTCPIP {
    <#
    .SYNOPSIS
        Disables NetBIOS over TCP/IP on all network adapters
    #>
    
    if (-not $DisableNetBIOS) {
        Write-Log "NetBIOS disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING NETBIOS OVER TCP/IP"
    
    try {
        $Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
        
        if (-not $Adapters) {
            Write-Log "No enabled network adapters found" -Level "WARNING"
            return
        }
        
        Write-Log "Found $($Adapters.Count) enabled network adapter(s)" -Level "INFO"
        
        foreach ($Adapter in $Adapters) {
            # $AdapterName = $Adapter.Description
            $AdapterName = if ($Adapter.Description) { $Adapter.Description } else { "Unknown Adapter (Index: $($Adapter.Index))" }
            $CurrentSetting = $Adapter.TcpipNetbiosOptions
            
            # TcpipNetbiosOptions: 0=Default, 1=Enabled, 2=Disabled
            if ($CurrentSetting -eq 2) {
                Write-Log "NetBIOS already disabled on: $AdapterName" -Level "SUCCESS"
                continue
            }
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable NetBIOS on: $AdapterName" -Level "INFO"
                continue
            }
            
            # Disable NetBIOS over TCP/IP
            $Result = $Adapter.SetTcpipNetbios(2)
            
            if ($Result.ReturnValue -eq 0) {
                Write-Log "NetBIOS disabled on: $AdapterName" -Level "SUCCESS"
                $Global:Stats.ProtocolsDisabled++
            }
            else {
                Write-Log "Failed to disable NetBIOS on: $AdapterName (Error: $($Result.ReturnValue))" -Level "ERROR"
            }
        }
    }
    catch {
        Write-Log "Failed to disable NetBIOS: $_" -Level "ERROR"
    }
}

function Disable-WPADService {
    <#
    .SYNOPSIS
        Disables Web Proxy Auto-Discovery (WPAD)
    #>
    
    if (-not $DisableWPAD) {
        Write-Log "WPAD disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING WPAD"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable WPAD" -Level "INFO"
            return
        }
        
        # Disable WinHTTP auto-proxy service
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc"
        if (Test-Path $RegPath) {
            Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -Type DWord -Force
            Write-Log "WinHTTP Auto-Proxy service disabled" -Level "SUCCESS"
            $Global:Stats.ServicesDisabled++
        }
        
        # Disable WPAD in Internet Settings
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "WpadDetection" -Value 0 -Type DWord -Force
        
        Write-Log "WPAD disabled successfully" -Level "SUCCESS"
        $Global:Stats.RegistryChanges++
    }
    catch {
        Write-Log "Failed to disable WPAD: $_" -Level "ERROR"
    }
}

function Disable-TelnetClient {
    <#
    .SYNOPSIS
        Disables Telnet client
    #>
    
    if (-not $DisableTelnet) {
        Write-Log "Telnet disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING TELNET CLIENT"
    
    try {
        $TelnetStatus = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
        
        if (-not $TelnetStatus) {
            Write-Log "Telnet client is not installed" -Level "SUCCESS"
            return
        }
        
        if ($TelnetStatus.State -eq "Disabled") {
            Write-Log "Telnet client is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Telnet client" -Level "INFO"
            return
        }
        
        Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction Stop | Out-Null
        
        Write-Log "Telnet client disabled successfully" -Level "SUCCESS"
        $Global:Stats.FeaturesDisabled++
    }
    catch {
        Write-Log "Failed to disable Telnet: $_" -Level "ERROR"
    }
}

#endregion

#region HIGH PRIORITY DISABLES
#==============================================================================

function Disable-WindowsScriptHost {
    <#
    .SYNOPSIS
        Disables Windows Script Host (VBScript/JScript execution)
    #>
    
    if (-not $DisableWSH) {
        Write-Log "Windows Script Host disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING WINDOWS SCRIPT HOST"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Windows Script Host" -Level "INFO"
            return
        }
        
        # Disable WSH for machine
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "Enabled" -Value 0 -Type DWord -Force
        
        # Disable WSH for current user
        $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "Enabled" -Value 0 -Type DWord -Force
        
        Write-Log "Windows Script Host disabled successfully" -Level "SUCCESS"
        Write-Log "Note: VBScript (.vbs) and JScript (.js) files will not execute" -Level "WARNING"
        $Global:Stats.FeaturesDisabled++
        $Global:Stats.RegistryChanges += 2
    }
    catch {
        Write-Log "Failed to disable Windows Script Host: $_" -Level "ERROR"
    }
}

function Disable-RemoteRegistryService {
    <#
    .SYNOPSIS
        Disables Remote Registry service
    #>
    
    if (-not $DisableRemoteRegistry) {
        Write-Log "Remote Registry disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING REMOTE REGISTRY SERVICE"
    
    try {
        $Service = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-Log "Remote Registry service not found" -Level "INFO"
            return
        }
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "Remote Registry service is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Remote Registry service" -Level "INFO"
            return
        }
        
        Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "RemoteRegistry" -StartupType Disabled
        
        Write-Log "Remote Registry service disabled successfully" -Level "SUCCESS"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable Remote Registry: $_" -Level "ERROR"
    }
}

function Disable-RemoteAssistanceFeature {
    <#
    .SYNOPSIS
        Disables Windows Remote Assistance
    #>
    
    if (-not $DisableRemoteAssistance) {
        Write-Log "Remote Assistance disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING REMOTE ASSISTANCE"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Remote Assistance" -Level "INFO"
            return
        }
        
        # Disable solicited Remote Assistance
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
        Set-ItemProperty -Path $RegPath -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
        
        # Disable unsolicited Remote Assistance
        Set-ItemProperty -Path $RegPath -Name "fAllowFullControl" -Value 0 -Type DWord -Force
        
        Write-Log "Remote Assistance disabled successfully" -Level "SUCCESS"
        $Global:Stats.FeaturesDisabled++
        $Global:Stats.RegistryChanges += 2
    }
    catch {
        Write-Log "Failed to disable Remote Assistance: $_" -Level "ERROR"
    }
}

function Disable-AutorunAutoplay {
    <#
    .SYNOPSIS
        Disables Autorun and Autoplay for removable media
    #>
    
    if (-not $DisableAutorun) {
        Write-Log "Autorun/Autoplay disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING AUTORUN/AUTOPLAY"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Autorun/Autoplay" -Level "INFO"
            return
        }
        
        # Disable Autorun on all drives
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
        
        # Disable Autoplay
        $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord -Force
        
        Write-Log "Autorun/Autoplay disabled successfully" -Level "SUCCESS"
        $Global:Stats.FeaturesDisabled++
        $Global:Stats.RegistryChanges += 2
    }
    catch {
        Write-Log "Failed to disable Autorun/Autoplay: $_" -Level "ERROR"
    }
}

function Disable-IPv6Protocol {
    <#
    .SYNOPSIS
        Disables IPv6 protocol (if not used in environment)
    #>
    
    if (-not $DisableIPv6) {
        Write-Log "IPv6 disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING IPv6"
    
    try {
        # Check current status
        $IPv6Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
        
        if ($IPv6Status.DisabledComponents -eq 0xFF) {
            Write-Log "IPv6 is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable IPv6" -Level "INFO"
            return
        }
        
        # Disable IPv6 via registry (preferred method)
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        
        # DisabledComponents = 0xFF disables all IPv6 components
        New-ItemProperty -Path $RegPath -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force | Out-Null
        
        Write-Log "IPv6 disabled successfully" -Level "SUCCESS"
        Write-Log "⚠️ REBOOT REQUIRED for IPv6 disable to take effect" -Level "WARNING"
        $Global:Stats.ProtocolsDisabled++
        $Global:Stats.RegistryChanges++
        $Global:Stats.RebootRequired = $true
    }
    catch {
        Write-Log "Failed to disable IPv6: $_" -Level "ERROR"
    }
}

function Disable-PrintSpoolerService {
    <#
    .SYNOPSIS
        Disables Print Spooler service (PrintNightmare mitigation)
    #>
    
    if (-not $DisablePrintSpooler) {
        Write-Log "Print Spooler disable skipped (parameter disabled)" -Level "INFO"
        Write-Log "Note: Print Spooler is enabled (default for functionality)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING PRINT SPOOLER SERVICE"
    
    try {
        $Service = Get-Service -Name "Spooler" -ErrorAction Stop
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "Print Spooler service is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Print Spooler service" -Level "INFO"
            return
        }
        
        Write-Log "⚠️ WARNING: Disabling Print Spooler will prevent printing!" -Level "WARNING"
        
        Stop-Service -Name "Spooler" -Force
        Set-Service -Name "Spooler" -StartupType Disabled
        
        Write-Log "Print Spooler service disabled successfully" -Level "SUCCESS"
        Write-Log "This workstation cannot print (PrintNightmare mitigation)" -Level "WARNING"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable Print Spooler: $_" -Level "ERROR"
    }
}

#endregion

#region RDP HARDENING
#==============================================================================

function Set-RDPSecurity {
    <#
    .SYNOPSIS
        Hardens RDP security or disables RDP completely
    #>
    
    Write-LogHeader "CONFIGURING RDP SECURITY"
    
    if ($DisableRDP) {
        Write-Log "RDP will be COMPLETELY DISABLED" -Level "WARNING"
        
        try {
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable RDP completely" -Level "INFO"
                return
            }
            
            # Disable RDP
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
            
            # Disable RDP firewall rules
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            
            Write-Log "RDP disabled completely" -Level "SUCCESS"
            $Global:Stats.FeaturesDisabled++
            return
        }
        catch {
            Write-Log "Failed to disable RDP: $_" -Level "ERROR"
            return
        }
    }
    
    if (-not $SecureRDP) {
        Write-Log "RDP security hardening skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-Log "Hardening RDP security (not disabling)..." -Level "INFO"
    
    try {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would harden RDP security" -Level "INFO"
            return
        }
        
        # Enable Network Level Authentication (NLA)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force
        Write-Log "Enabled Network Level Authentication (NLA)" -Level "SUCCESS"
        
        # Require secure RPC communication
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord -Force
        Write-Log "Enabled secure RPC communication" -Level "SUCCESS"
        
        # Set encryption level to High
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force
        Write-Log "Set encryption level to High" -Level "SUCCESS"
        
        # Disable "Allow connections from computers running any version of Remote Desktop"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # Set idle timeout (15 minutes)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # Set disconnect timeout (15 minutes)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 900000 -Type DWord -Force -ErrorAction SilentlyContinue
        
        Write-Log "RDP security hardened successfully" -Level "SUCCESS"
        Write-Log "RDP remains enabled but with enhanced security" -Level "INFO"
        $Global:Stats.RegistryChanges += 6
    }
    catch {
        Write-Log "Failed to harden RDP security: $_" -Level "ERROR"
    }
}

#endregion

#region MODERATE PRIORITY SERVICES
#==============================================================================

function Disable-SNMPService {
    <#
    .SYNOPSIS
        Disables SNMP service
    #>
    
    if (-not $DisableSNMP) {
        Write-Log "SNMP disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING SNMP SERVICE"
    
    try {
        $Service = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-Log "SNMP service not installed" -Level "INFO"
            return
        }
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "SNMP service is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable SNMP service" -Level "INFO"
            return
        }
        
        Stop-Service -Name "SNMP" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "SNMP" -StartupType Disabled
        
        Write-Log "SNMP service disabled successfully" -Level "SUCCESS"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable SNMP: $_" -Level "ERROR"
    }
}

function Disable-SSDPUPnPService {
    <#
    .SYNOPSIS
        Disables SSDP Discovery service (UPnP)
    #>
    
    if (-not $DisableSSDPUPnP) {
        Write-Log "SSDP/UPnP disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING SSDP/UPnP SERVICE"
    
    try {
        $Service = Get-Service -Name "SSDPSRV" -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-Log "SSDP service not found" -Level "INFO"
            return
        }
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "SSDP service is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable SSDP service" -Level "INFO"
            return
        }
        
        Stop-Service -Name "SSDPSRV" -Force
        Set-Service -Name "SSDPSRV" -StartupType Disabled
        
        Write-Log "SSDP/UPnP service disabled successfully" -Level "SUCCESS"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable SSDP: $_" -Level "ERROR"
    }
}

function Disable-WebDAVClient {
    <#
    .SYNOPSIS
        Disables WebDAV client service
    #>
    
    if (-not $DisableWebDAV) {
        Write-Log "WebDAV disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING WEBDAV CLIENT"
    
    try {
        $Service = Get-Service -Name "WebClient" -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-Log "WebDAV client service not found" -Level "INFO"
            return
        }
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "WebDAV client is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable WebDAV client" -Level "INFO"
            return
        }
        
        Stop-Service -Name "WebClient" -Force
        Set-Service -Name "WebClient" -StartupType Disabled
        
        Write-Log "WebDAV client disabled successfully" -Level "SUCCESS"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable WebDAV: $_" -Level "ERROR"
    }
}

#endregion

#region OBSOLETE WINDOWS FEATURES
#==============================================================================

function Disable-ObsoleteWindowsFeatures {
    <#
    .SYNOPSIS
        Disables obsolete Windows features (XPS, Windows Media Player, etc.)
    #>
    
    if (-not $DisableObsoleteFeatures) {
        Write-Log "Obsolete features disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING OBSOLETE WINDOWS FEATURES"
    
    $FeaturesToDisable = @(
        @{ Name = "WindowsMediaPlayer"; Description = "Windows Media Player" },
        @{ Name = "Printing-XPSServices-Features"; Description = "XPS Services" },
        @{ Name = "WorkFolders-Client"; Description = "Work Folders Client" }
    )
    
    foreach ($Feature in $FeaturesToDisable) {
        try {
            $FeatureStatus = Get-WindowsOptionalFeature -Online -FeatureName $Feature.Name -ErrorAction SilentlyContinue
            
            if (-not $FeatureStatus) {
                Write-Log "$($Feature.Description) not installed" -Level "INFO"
                continue
            }
            
            if ($FeatureStatus.State -eq "Disabled") {
                Write-Log "$($Feature.Description) already disabled" -Level "SUCCESS"
                continue
            }
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable $($Feature.Description)" -Level "INFO"
                continue
            }
            
            Disable-WindowsOptionalFeature -Online -FeatureName $Feature.Name -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "$($Feature.Description) disabled successfully" -Level "SUCCESS"
            $Global:Stats.FeaturesDisabled++
        }
        catch {
            Write-Log "Failed to disable $($Feature.Description): $_" -Level "ERROR"
        }
    }
}

#endregion

#region OPTIONAL FEATURES
#==============================================================================

function Disable-BluetoothService {
    <#
    .SYNOPSIS
        Disables Bluetooth service (typically for desktops only)
    #>
    
    if (-not $DisableBluetooth) {
        Write-Log "Bluetooth disable skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DISABLING BLUETOOTH"
    
    try {
        $Service = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-Log "Bluetooth service not found (may not have Bluetooth hardware)" -Level "INFO"
            return
        }
        
        if ($Service.StartType -eq "Disabled") {
            Write-Log "Bluetooth service is already disabled" -Level "SUCCESS"
            return
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable Bluetooth service" -Level "INFO"
            return
        }
        
        Write-Log "⚠️ WARNING: This will disable Bluetooth keyboards/mice!" -Level "WARNING"
        
        Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "bthserv" -StartupType Disabled
        
        Write-Log "Bluetooth service disabled successfully" -Level "SUCCESS"
        $Global:Stats.ServicesDisabled++
    }
    catch {
        Write-Log "Failed to disable Bluetooth: $_" -Level "ERROR"
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-SecurityConfiguration {
    <#
    .SYNOPSIS
        Validates security hardening after changes
    #>
    
    Write-LogHeader "VALIDATING SECURITY CONFIGURATION"
    
    $ValidationResults = @()
    
    # Check SMBv1
    if ($DisableSMBv1) {
        $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $Status = if ($SMBv1.State -eq "Disabled") { "✓ PASS" } else { "✗ FAIL" }
        Write-Log "SMBv1: $Status" -Level $(if($SMBv1.State -eq "Disabled"){"SUCCESS"}else{"ERROR"})
        $ValidationResults += @{ Check = "SMBv1 Disabled"; Status = $Status }
    }
    
    # Check LLMNR
    if ($DisableLLMNR) {
        $LLMNR = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        $Status = if ($LLMNR.EnableMulticast -eq 0) { "✓ PASS" } else { "✗ FAIL" }
        Write-Log "LLMNR: $Status" -Level $(if($LLMNR.EnableMulticast -eq 0){"SUCCESS"}else{"ERROR"})
        $ValidationResults += @{ Check = "LLMNR Disabled"; Status = $Status }
    }
    
    # Check Remote Registry
    if ($DisableRemoteRegistry) {
        $RemoteReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        $Status = if ($RemoteReg.StartType -eq "Disabled") { "✓ PASS" } else { "✗ FAIL" }
        Write-Log "Remote Registry: $Status" -Level $(if($RemoteReg.StartType -eq "Disabled"){"SUCCESS"}else{"ERROR"})
        $ValidationResults += @{ Check = "Remote Registry Disabled"; Status = $Status }
    }
    
    # Check RDP NLA (if securing RDP)
    if ($SecureRDP -and -not $DisableRDP) {
        $NLA = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        $Status = if ($NLA.UserAuthentication -eq 1) { "✓ PASS" } else { "✗ FAIL" }
        Write-Log "RDP NLA Enabled: $Status" -Level $(if($NLA.UserAuthentication -eq 1){"SUCCESS"}else{"ERROR"})
        $ValidationResults += @{ Check = "RDP NLA Enabled"; Status = $Status }
    }
    
    # Check IPv6
    if ($DisableIPv6) {
        $IPv6 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
        $Status = if ($IPv6.DisabledComponents -eq 0xFF) { "✓ PASS" } else { "✗ FAIL" }
        Write-Log "IPv6: $Status" -Level $(if($IPv6.DisabledComponents -eq 0xFF){"SUCCESS"}else{"WARNING"})
        $ValidationResults += @{ Check = "IPv6 Disabled"; Status = $Status }
    }
    
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
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    Write-Log "  Dry Run Mode: $DryRun" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Security Hardening Results:" -Level "INFO"
    Write-Log "  Features Disabled: $($Global:Stats.FeaturesDisabled)" -Level "SUCCESS"
    Write-Log "  Services Disabled: $($Global:Stats.ServicesDisabled)" -Level "SUCCESS"
    Write-Log "  Protocols Disabled: $($Global:Stats.ProtocolsDisabled)" -Level "SUCCESS"
    Write-Log "  Registry Changes: $($Global:Stats.RegistryChanges)" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    if ($Global:Stats.RebootRequired) {
        Write-Log " " -Level "INFO"
        Write-Log "⚠️⚠️⚠️ REBOOT REQUIRED ⚠️⚠️⚠️" -Level "WARNING"
        Write-Log "Changes to SMBv1 and/or IPv6 require a system reboot to take effect" -Level "WARNING"
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
║     DISABLE INSECURE FEATURES & PROTOCOLS                     ║
║                  Version $ScriptVersion                            ║
║                                                               ║
║     Windows Security Hardening Script                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "SECURITY HARDENING STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Critical protocols (disable immediately)
    Disable-SMBv1Protocol
    Disable-LLMNRProtocol
    Disable-NetBIOSOverTCPIP
    Disable-WPADService
    Disable-TelnetClient
    
    # High priority
    Disable-WindowsScriptHost
    Disable-RemoteRegistryService
    Disable-RemoteAssistanceFeature
    Disable-AutorunAutoplay
    Disable-IPv6Protocol
    Disable-PrintSpoolerService
    
    # RDP security
    Set-RDPSecurity
    
    # Moderate priority services
    Disable-SNMPService
    Disable-SSDPUPnPService
    Disable-WebDAVClient
    
    # Obsolete features
    Disable-ObsoleteWindowsFeatures
    
    # Optional
    Disable-BluetoothService
    
    # Validation
    $ValidationResults = Test-SecurityConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 
        if ($Global:Stats.RebootRequired) { 3 } else { 0 }
    } else { 
        1 
    }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Security hardening completed successfully!" -Level "SUCCESS"
    }
    elseif ($ExitCode -eq 3) {
        Write-Log "Security hardening completed successfully - REBOOT REQUIRED" -Level "WARNING"
    }
    else {
        Write-Log "Security hardening completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
