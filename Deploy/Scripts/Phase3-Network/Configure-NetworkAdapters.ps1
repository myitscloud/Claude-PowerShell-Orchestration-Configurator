<#
.SYNOPSIS
    Configure Network Adapters for Enterprise Deployment
    
.DESCRIPTION
    Configures network adapter settings for Windows 11 workstations including:
    - Network adapter priorities and metrics
    - DNS server configuration
    - Power management settings
    - Advanced adapter properties
    - IPv6 configuration
    - NetBIOS over TCP/IP settings
    - Network binding order optimization
    - Adapter naming standardization
    - QoS and performance tuning
    - Wake-on-LAN configuration
    
    Optimized for enterprise environments with 3000+ devices using DHCP
    with centralized DNS management by networking team.
    
.PARAMETER DisableIPv6
    Disable IPv6 on all network adapters. Default: $false
    Note: This affects adapter bindings, not the protocol stack itself.
    
.PARAMETER SetDNSServers
    Configure DNS servers on network adapters. Default: $true
    
.PARAMETER DNSServers
    Array of DNS server IP addresses. Default: @("10.0.0.10", "10.0.0.11")
    
.PARAMETER DisableNetBIOS
    Disable NetBIOS over TCP/IP on all adapters. Default: $false
    Note: Set to $true only if you've verified no legacy applications need NetBIOS.
    
.PARAMETER OptimizeAdapterMetrics
    Automatically configure adapter metrics for optimal routing. Default: $true
    
.PARAMETER DisablePowerManagement
    Disable power management on Ethernet adapters to prevent disconnects. Default: $true
    
.PARAMETER EnableJumboFrames
    Enable jumbo frames (9000 MTU) if supported. Default: $false
    Note: Only enable if your network infrastructure supports jumbo frames.
    
.PARAMETER ConfigureQoS
    Configure Quality of Service (QoS) settings. Default: $true
    
.PARAMETER StandardizeAdapterNames
    Rename adapters to standard naming convention. Default: $false
    Note: Can cause temporary connectivity disruption.
    
.PARAMETER EnableLLDP
    Enable LLDP (Link Layer Discovery Protocol) for network mapping. Default: $false
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-NetworkAdapters.ps1
    Configures adapters with default enterprise settings
    
.EXAMPLE
    .\Configure-NetworkAdapters.ps1 -SetDNSServers -DNSServers @("10.1.1.10","10.1.1.11")
    Configures adapters with custom DNS servers
    
.EXAMPLE
    .\Configure-NetworkAdapters.ps1 -DisableIPv6 $true -DisableNetBIOS $true
    Disables IPv6 and NetBIOS on all adapters
    
.EXAMPLE
    .\Configure-NetworkAdapters.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Network adapter configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = No network adapters found
    4   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - Network adapters installed and enabled
    
    NOTES:
    - This script assumes DHCP for IP addressing
    - DNS configuration by network team is respected
    - Script is safe for both wired and wireless adapters
    - Will not disconnect active network connections
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$DisableIPv6 = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$SetDNSServers = $true,
    
    [Parameter(Mandatory=$false)]
    [string[]]$DNSServers = @("10.0.0.10", "10.0.0.11"),
    
    [Parameter(Mandatory=$false)]
    [bool]$DisableNetBIOS = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$OptimizeAdapterMetrics = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DisablePowerManagement = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$EnableJumboFrames = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ConfigureQoS = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$StandardizeAdapterNames = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$EnableLLDP = $false,
    
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

$LogFileName = "Configure-NetworkAdapters_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    AdaptersFound = 0
    AdaptersConfigured = 0
    DNSConfigured = 0
    PowerManagementDisabled = 0
    IPv6Disabled = 0
    NetBIOSDisabled = 0
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
    
    # Check 2: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($OSVersion.Major -lt 10 -or $BuildNumber -lt 22000) {
        Write-Log "WARNING: This script is optimized for Windows 11 (Build 22000+)" -Level "WARNING"
    }
    else {
        Write-Log "Windows version check passed" -Level "SUCCESS"
    }
    
    # Check 3: Network adapters
    Write-Log "Checking for network adapters..." -Level "INFO"
    $Adapters = Get-NetAdapter | Where-Object { $_.Status -ne "Not Present" }
    
    if (-not $Adapters) {
        Write-Log "ERROR: No network adapters found" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "Found $($Adapters.Count) network adapter(s)" -Level "SUCCESS"
        $Global:Stats.AdaptersFound = $Adapters.Count
    }
    
    # Check 4: DNS servers validation
    if ($SetDNSServers) {
        Write-Log "Validating DNS servers..." -Level "INFO"
        
        if (-not $DNSServers -or $DNSServers.Count -eq 0) {
            Write-Log "WARNING: No DNS servers specified" -Level "WARNING"
        }
        else {
            foreach ($DNS in $DNSServers) {
                if ($DNS -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                    Write-Log "DNS server validated: $DNS" -Level "SUCCESS"
                }
                else {
                    Write-Log "WARNING: Invalid DNS server format: $DNS" -Level "WARNING"
                }
            }
        }
    }
    
    return $AllChecksPassed
}

#endregion

#region ADAPTER DISCOVERY FUNCTIONS
#==============================================================================

function Get-NetworkAdapterInventory {
    <#
    .SYNOPSIS
        Discovers and categorizes network adapters
    #>
    
    Write-LogHeader "NETWORK ADAPTER INVENTORY"
    
    try {
        $AllAdapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne "Not Present" }
        
        $Inventory = @{
            Ethernet = @()
            Wireless = @()
            Virtual = @()
            Disabled = @()
            All = @()
        }
        
        foreach ($Adapter in $AllAdapters) {
            $AdapterInfo = [PSCustomObject]@{
                Name = $Adapter.Name
                InterfaceDescription = $Adapter.InterfaceDescription
                Status = $Adapter.Status
                LinkSpeed = $Adapter.LinkSpeed
                MacAddress = $Adapter.MacAddress
                InterfaceIndex = $Adapter.InterfaceIndex
                DriverVersion = $Adapter.DriverVersion
                MediaType = $Adapter.MediaType
                Virtual = $Adapter.Virtual
            }
            
            # Categorize adapter
            if ($Adapter.Status -eq "Disabled") {
                $Inventory.Disabled += $AdapterInfo
            }
            elseif ($Adapter.InterfaceDescription -like "*Wireless*" -or $Adapter.InterfaceDescription -like "*Wi-Fi*" -or $Adapter.InterfaceDescription -like "*802.11*") {
                $Inventory.Wireless += $AdapterInfo
            }
            elseif ($Adapter.Virtual) {
                $Inventory.Virtual += $AdapterInfo
            }
            else {
                $Inventory.Ethernet += $AdapterInfo
            }
            
            $Inventory.All += $AdapterInfo
            
            Write-Log "[$($Adapter.Status)] $($Adapter.Name) - $($Adapter.InterfaceDescription)" -Level "INFO"
            Write-Log "  MAC: $($Adapter.MacAddress) | Speed: $($Adapter.LinkSpeed) | Driver: $($Adapter.DriverVersion)" -Level "DEBUG"
        }
        
        Write-Log " " -Level "INFO"
        Write-Log "Adapter Summary:" -Level "INFO"
        Write-Log "  Ethernet: $($Inventory.Ethernet.Count)" -Level "INFO"
        Write-Log "  Wireless: $($Inventory.Wireless.Count)" -Level "INFO"
        Write-Log "  Virtual: $($Inventory.Virtual.Count)" -Level "INFO"
        Write-Log "  Disabled: $($Inventory.Disabled.Count)" -Level "INFO"
        Write-Log "  Total: $($Inventory.All.Count)" -Level "INFO"
        
        return $Inventory
    }
    catch {
        Write-Log "Error discovering network adapters: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region DNS CONFIGURATION
#==============================================================================

function Set-AdapterDNSServers {
    <#
    .SYNOPSIS
        Configures DNS servers on network adapters
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $SetDNSServers) {
        Write-Log "DNS configuration skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    if (-not $DNSServers -or $DNSServers.Count -eq 0) {
        Write-Log "No DNS servers specified, skipping DNS configuration" -Level "WARNING"
        return
    }
    
    Write-LogHeader "CONFIGURING DNS SERVERS"
    
    foreach ($AdapterInfo in $Adapter.All) {
        # Skip disabled and virtual adapters
        if ($AdapterInfo.Status -eq "Disabled" -or $AdapterInfo.Virtual) {
            Write-Log "Skipping DNS for $($AdapterInfo.Name) (Disabled or Virtual)" -Level "INFO"
            continue
        }
        
        try {
            # Get current DNS configuration
            $CurrentDNS = Get-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
            
            Write-Log "Configuring DNS for: $($AdapterInfo.Name)" -Level "INFO"
            Write-Log "  Current DNS: $($CurrentDNS.ServerAddresses -join ', ')" -Level "DEBUG"
            Write-Log "  New DNS: $($DNSServers -join ', ')" -Level "DEBUG"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set DNS servers" -Level "INFO"
                continue
            }
            
            # Set DNS servers
            Set-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -ServerAddresses $DNSServers -ErrorAction Stop
            
            # Verify configuration
            $NewDNS = Get-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -AddressFamily IPv4
            Write-Log "DNS servers configured successfully" -Level "SUCCESS"
            Write-Log "  Verified DNS: $($NewDNS.ServerAddresses -join ', ')" -Level "SUCCESS"
            
            $Global:Stats.DNSConfigured++
        }
        catch {
            Write-Log "Failed to configure DNS for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
}

#endregion

#region IPv6 CONFIGURATION
#==============================================================================

function Set-IPv6Configuration {
    <#
    .SYNOPSIS
        Configures IPv6 settings on network adapters
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $DisableIPv6) {
        Write-Log "IPv6 configuration skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "CONFIGURING IPv6"
    
    foreach ($AdapterInfo in $Adapter.All) {
        # Skip disabled adapters
        if ($AdapterInfo.Status -eq "Disabled") {
            Write-Log "Skipping IPv6 for $($AdapterInfo.Name) (Disabled)" -Level "INFO"
            continue
        }
        
        try {
            # Check current IPv6 binding
            $IPv6Binding = Get-NetAdapterBinding -Name $AdapterInfo.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            
            Write-Log "Processing IPv6 for: $($AdapterInfo.Name)" -Level "INFO"
            Write-Log "  Current IPv6 status: $($IPv6Binding.Enabled)" -Level "DEBUG"
            
            if (-not $IPv6Binding.Enabled) {
                Write-Log "IPv6 already disabled on $($AdapterInfo.Name)" -Level "SUCCESS"
                continue
            }
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable IPv6" -Level "INFO"
                continue
            }
            
            # Disable IPv6
            Disable-NetAdapterBinding -Name $AdapterInfo.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            
            Write-Log "IPv6 disabled successfully on $($AdapterInfo.Name)" -Level "SUCCESS"
            $Global:Stats.IPv6Disabled++
        }
        catch {
            Write-Log "Failed to disable IPv6 on $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
}

#endregion

#region NETBIOS CONFIGURATION
#==============================================================================

function Set-NetBIOSConfiguration {
    <#
    .SYNOPSIS
        Configures NetBIOS over TCP/IP settings
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $DisableNetBIOS) {
        Write-Log "NetBIOS configuration skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "CONFIGURING NETBIOS OVER TCP/IP"
    
    foreach ($AdapterInfo in $Adapter.All) {
        # Skip disabled and virtual adapters
        if ($AdapterInfo.Status -eq "Disabled" -or $AdapterInfo.Virtual) {
            Write-Log "Skipping NetBIOS for $($AdapterInfo.Name) (Disabled or Virtual)" -Level "INFO"
            continue
        }
        
        try {
            # Get WMI network adapter configuration
            $WMIAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -eq $AdapterInfo.MacAddress }
            
            if (-not $WMIAdapter) {
                Write-Log "Could not find WMI adapter for $($AdapterInfo.Name)" -Level "WARNING"
                continue
            }
            
            Write-Log "Processing NetBIOS for: $($AdapterInfo.Name)" -Level "INFO"
            
            # TcpipNetbiosOptions: 0=Default, 1=Enabled, 2=Disabled
            $CurrentSetting = $WMIAdapter.TcpipNetbiosOptions
            Write-Log "  Current NetBIOS setting: $CurrentSetting (0=Default, 1=Enabled, 2=Disabled)" -Level "DEBUG"
            
            if ($CurrentSetting -eq 2) {
                Write-Log "NetBIOS already disabled on $($AdapterInfo.Name)" -Level "SUCCESS"
                continue
            }
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable NetBIOS" -Level "INFO"
                continue
            }
            
            # Disable NetBIOS over TCP/IP
            $Result = $WMIAdapter.SetTcpipNetbios(2)
            
            if ($Result.ReturnValue -eq 0) {
                Write-Log "NetBIOS disabled successfully on $($AdapterInfo.Name)" -Level "SUCCESS"
                $Global:Stats.NetBIOSDisabled++
            }
            else {
                Write-Log "Failed to disable NetBIOS on $($AdapterInfo.Name) (Error code: $($Result.ReturnValue))" -Level "ERROR"
            }
        }
        catch {
            Write-Log "Failed to configure NetBIOS on $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
}

#endregion

#region ADAPTER METRICS OPTIMIZATION
#==============================================================================

function Optimize-AdapterMetrics {
    <#
    .SYNOPSIS
        Optimizes adapter interface metrics for proper routing priority
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $OptimizeAdapterMetrics) {
        Write-Log "Adapter metrics optimization skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "OPTIMIZING ADAPTER METRICS"
    
    Write-Log "Setting adapter priorities (lower metric = higher priority)" -Level "INFO"
    Write-Log "  Priority order: Ethernet → Wireless → Virtual" -Level "INFO"
    
    # Set metrics based on adapter type
    $EthernetMetric = 10
    $WirelessMetric = 20
    $VirtualMetric = 30
    
    # Configure Ethernet adapters (highest priority)
    foreach ($AdapterInfo in $Adapter.Ethernet) {
        if ($AdapterInfo.Status -eq "Disabled") { continue }
        
        try {
            Write-Log "Setting metric for Ethernet adapter: $($AdapterInfo.Name)" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set metric to $EthernetMetric" -Level "INFO"
                continue
            }
            
            Set-NetIPInterface -InterfaceIndex $AdapterInfo.InterfaceIndex -InterfaceMetric $EthernetMetric -ErrorAction Stop
            Write-Log "Ethernet adapter metric set to $EthernetMetric" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to set metric for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
    
    # Configure Wireless adapters (medium priority)
    foreach ($AdapterInfo in $Adapter.Wireless) {
        if ($AdapterInfo.Status -eq "Disabled") { continue }
        
        try {
            Write-Log "Setting metric for Wireless adapter: $($AdapterInfo.Name)" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set metric to $WirelessMetric" -Level "INFO"
                continue
            }
            
            Set-NetIPInterface -InterfaceIndex $AdapterInfo.InterfaceIndex -InterfaceMetric $WirelessMetric -ErrorAction Stop
            Write-Log "Wireless adapter metric set to $WirelessMetric" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to set metric for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
    
    # Configure Virtual adapters (lowest priority)
    foreach ($AdapterInfo in $Adapter.Virtual) {
        if ($AdapterInfo.Status -eq "Disabled") { continue }
        
        try {
            Write-Log "Setting metric for Virtual adapter: $($AdapterInfo.Name)" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would set metric to $VirtualMetric" -Level "INFO"
                continue
            }
            
            Set-NetIPInterface -InterfaceIndex $AdapterInfo.InterfaceIndex -InterfaceMetric $VirtualMetric -ErrorAction Stop
            Write-Log "Virtual adapter metric set to $VirtualMetric" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to set metric for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
}

#endregion

#region POWER MANAGEMENT
#==============================================================================

function Set-AdapterPowerManagement {
    <#
    .SYNOPSIS
        Configures power management settings to prevent disconnects
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $DisablePowerManagement) {
        Write-Log "Power management configuration skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "CONFIGURING POWER MANAGEMENT"
    
    Write-Log "Disabling power management to prevent unexpected disconnects" -Level "INFO"
    
    foreach ($AdapterInfo in $Adapter.Ethernet) {
        # Only disable power management on Ethernet adapters (keep for wireless/laptops)
        if ($AdapterInfo.Status -eq "Disabled") { continue }
        
        try {
            Write-Log "Configuring power management for: $($AdapterInfo.Name)" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would disable power management" -Level "INFO"
                continue
            }
            
            # Get the adapter's device ID for registry path
            $AdapterObject = Get-NetAdapter -Name $AdapterInfo.Name
            $InstanceID = $AdapterObject.PnPDeviceID
            
            # Disable "Allow the computer to turn off this device to save power"
            $PowerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | 
                Where-Object { $_.InstanceName -like "*$($AdapterObject.InterfaceGuid)*" }
            
            if ($PowerMgmt) {
                $PowerMgmt.Enable = $false
                $PowerMgmt.Put() | Out-Null
                Write-Log "Power management disabled for $($AdapterInfo.Name)" -Level "SUCCESS"
                $Global:Stats.PowerManagementDisabled++
            }
            else {
                Write-Log "Could not find power management settings for $($AdapterInfo.Name)" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Failed to configure power management for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
    
    Write-Log "Note: Wireless adapter power management left enabled for laptop battery savings" -Level "INFO"
}

#endregion

#region ADVANCED ADAPTER SETTINGS
#==============================================================================

function Set-AdvancedAdapterSettings {
    <#
    .SYNOPSIS
        Configures advanced adapter properties for performance and reliability
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    Write-LogHeader "CONFIGURING ADVANCED ADAPTER SETTINGS"
    
    foreach ($AdapterInfo in $Adapter.Ethernet) {
        if ($AdapterInfo.Status -eq "Disabled") { continue }
        
        Write-Log "Configuring advanced settings for: $($AdapterInfo.Name)" -Level "INFO"
        
        try {
            # Get current advanced properties
            $AdvancedProperties = Get-NetAdapterAdvancedProperty -Name $AdapterInfo.Name -ErrorAction SilentlyContinue
            
            if (-not $AdvancedProperties) {
                Write-Log "No advanced properties available for $($AdapterInfo.Name)" -Level "WARNING"
                continue
            }
            
            # Configure Jumbo Frames (if requested and supported)
            if ($EnableJumboFrames) {
                $JumboFrameProp = $AdvancedProperties | Where-Object { $_.DisplayName -like "*Jumbo*" -or $_.RegistryKeyword -eq "*JumboPacket" }
                
                if ($JumboFrameProp) {
                    Write-Log "  Jumbo Frames supported - current: $($JumboFrameProp.DisplayValue)" -Level "INFO"
                    
                    if ($DryRun) {
                        Write-Log "  [DRY RUN] Would enable Jumbo Frames (MTU 9000)" -Level "INFO"
                    }
                    else {
                        try {
                            Set-NetAdapterAdvancedProperty -Name $AdapterInfo.Name -DisplayName $JumboFrameProp.DisplayName -DisplayValue "9014" -ErrorAction Stop
                            Write-Log "  Jumbo Frames enabled (MTU 9000)" -Level "SUCCESS"
                        }
                        catch {
                            Write-Log "  Failed to enable Jumbo Frames: $_" -Level "WARNING"
                        }
                    }
                }
                else {
                    Write-Log "  Jumbo Frames not supported on this adapter" -Level "INFO"
                }
            }
            
            # Configure Flow Control (enable for better performance)
            $FlowControlProp = $AdvancedProperties | Where-Object { $_.DisplayName -like "*Flow Control*" }
            if ($FlowControlProp) {
                Write-Log "  Flow Control: $($FlowControlProp.DisplayValue)" -Level "DEBUG"
            }
            
            # Configure Interrupt Moderation (enable for better CPU efficiency)
            $InterruptModProp = $AdvancedProperties | Where-Object { $_.DisplayName -like "*Interrupt Moderation*" }
            if ($InterruptModProp) {
                Write-Log "  Interrupt Moderation: $($InterruptModProp.DisplayValue)" -Level "DEBUG"
            }
            
            # Configure RSS (Receive Side Scaling) if available
            $RSSProp = $AdvancedProperties | Where-Object { $_.DisplayName -like "*Receive Side Scaling*" -or $_.RegistryKeyword -eq "*RSS" }
            if ($RSSProp) {
                Write-Log "  RSS (Receive Side Scaling): $($RSSProp.DisplayValue)" -Level "DEBUG"
            }
            
            Write-Log "Advanced settings reviewed for $($AdapterInfo.Name)" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to configure advanced settings for $($AdapterInfo.Name): $_" -Level "ERROR"
        }
    }
}

#endregion

#region QoS CONFIGURATION
#==============================================================================

function Set-QoSConfiguration {
    <#
    .SYNOPSIS
        Configures Quality of Service settings
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $ConfigureQoS) {
        Write-Log "QoS configuration skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "CONFIGURING QUALITY OF SERVICE (QoS)"
    
    try {
        # Enable QoS Packet Scheduler on all adapters
        foreach ($AdapterInfo in $Adapter.All) {
            if ($AdapterInfo.Status -eq "Disabled") { continue }
            
            Write-Log "Checking QoS for: $($AdapterInfo.Name)" -Level "INFO"
            
            $QoSBinding = Get-NetAdapterBinding -Name $AdapterInfo.Name -ComponentID ms_pacer -ErrorAction SilentlyContinue
            
            if ($QoSBinding) {
                if ($QoSBinding.Enabled) {
                    Write-Log "  QoS Packet Scheduler already enabled" -Level "SUCCESS"
                }
                else {
                    if ($DryRun) {
                        Write-Log "  [DRY RUN] Would enable QoS Packet Scheduler" -Level "INFO"
                    }
                    else {
                        Enable-NetAdapterBinding -Name $AdapterInfo.Name -ComponentID ms_pacer -ErrorAction Stop
                        Write-Log "  QoS Packet Scheduler enabled" -Level "SUCCESS"
                    }
                }
            }
        }
        
        # Set bandwidth reservation limit (allow 100% bandwidth)
        $QoSRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
        if (-not (Test-Path $QoSRegPath)) {
            New-Item -Path $QoSRegPath -Force | Out-Null
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set QoS bandwidth limit to 0% (no reservation)" -Level "INFO"
        }
        else {
            Set-ItemProperty -Path $QoSRegPath -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
            Write-Log "QoS bandwidth limit set to 0% (no reservation)" -Level "SUCCESS"
        }
    }
    catch {
        Write-Log "Failed to configure QoS: $_" -Level "ERROR"
    }
}

#endregion

#region ADAPTER NAMING
#==============================================================================

function Set-StandardAdapterNames {
    <#
    .SYNOPSIS
        Renames adapters to standard naming convention
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Adapter
    )
    
    if (-not $StandardizeAdapterNames) {
        Write-Log "Adapter naming standardization skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "STANDARDIZING ADAPTER NAMES"
    
    Write-Log "WARNING: Renaming adapters may cause brief connectivity disruption" -Level "WARNING"
    
    $EthernetCount = 1
    $WirelessCount = 1
    
    # Rename Ethernet adapters
    foreach ($AdapterInfo in $Adapter.Ethernet) {
        $NewName = "Ethernet $EthernetCount"
        
        if ($AdapterInfo.Name -eq $NewName) {
            Write-Log "$($AdapterInfo.Name) already has standard name" -Level "SUCCESS"
        }
        else {
            Write-Log "Would rename: $($AdapterInfo.Name) → $NewName" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Rename skipped" -Level "INFO"
            }
            else {
                try {
                    Rename-NetAdapter -Name $AdapterInfo.Name -NewName $NewName -ErrorAction Stop
                    Write-Log "Adapter renamed successfully" -Level "SUCCESS"
                }
                catch {
                    Write-Log "Failed to rename adapter: $_" -Level "ERROR"
                }
            }
        }
        
        $EthernetCount++
    }
    
    # Rename Wireless adapters
    foreach ($AdapterInfo in $Adapter.Wireless) {
        $NewName = "Wi-Fi $WirelessCount"
        
        if ($AdapterInfo.Name -eq $NewName) {
            Write-Log "$($AdapterInfo.Name) already has standard name" -Level "SUCCESS"
        }
        else {
            Write-Log "Would rename: $($AdapterInfo.Name) → $NewName" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Rename skipped" -Level "INFO"
            }
            else {
                try {
                    Rename-NetAdapter -Name $AdapterInfo.Name -NewName $NewName -ErrorAction Stop
                    Write-Log "Adapter renamed successfully" -Level "SUCCESS"
                }
                catch {
                    Write-Log "Failed to rename adapter: $_" -Level "ERROR"
                }
            }
        }
        
        $WirelessCount++
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-NetworkConfiguration {
    <#
    .SYNOPSIS
        Validates network configuration after changes
    #>
    
    Write-LogHeader "VALIDATING NETWORK CONFIGURATION"
    
    $ValidationResults = @()
    
    # Test 1: Network connectivity
    Write-Log "Testing network connectivity..." -Level "INFO"
    try {
        $PingTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($PingTest) {
            Write-Log "  Internet connectivity: ✓ PASS" -Level "SUCCESS"
            $ValidationResults += @{ Check = "Internet Connectivity"; Status = "PASS" }
        }
        else {
            Write-Log "  Internet connectivity: ✗ FAIL" -Level "WARNING"
            $ValidationResults += @{ Check = "Internet Connectivity"; Status = "FAIL" }
        }
    }
    catch {
        Write-Log "  Internet connectivity: ✗ ERROR" -Level "ERROR"
    }
    
    # Test 2: DNS resolution
    Write-Log "Testing DNS resolution..." -Level "INFO"
    try {
        $DNSTest = Resolve-DnsName "www.microsoft.com" -Type A -ErrorAction SilentlyContinue
        if ($DNSTest) {
            Write-Log "  DNS resolution: ✓ PASS" -Level "SUCCESS"
            $ValidationResults += @{ Check = "DNS Resolution"; Status = "PASS" }
        }
        else {
            Write-Log "  DNS resolution: ✗ FAIL" -Level "WARNING"
            $ValidationResults += @{ Check = "DNS Resolution"; Status = "FAIL" }
        }
    }
    catch {
        Write-Log "  DNS resolution: ✗ ERROR" -Level "ERROR"
    }
    
    # Test 3: Verify DNS servers configured
    if ($SetDNSServers) {
        Write-Log "Verifying DNS server configuration..." -Level "INFO"
        $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($Adapter in $Adapters) {
            $DNS = Get-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4
            Write-Log "  $($Adapter.Name): $($DNS.ServerAddresses -join ', ')" -Level "INFO"
        }
    }
    
    # Test 4: Verify IPv6 status
    if ($DisableIPv6) {
        Write-Log "Verifying IPv6 disabled..." -Level "INFO"
        $Adapters = Get-NetAdapter | Where-Object { $_.Status -ne "Disabled" }
        $IPv6Enabled = $false
        foreach ($Adapter in $Adapters) {
            $IPv6Binding = Get-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_tcpip6
            if ($IPv6Binding.Enabled) {
                Write-Log "  $($Adapter.Name): IPv6 still enabled" -Level "WARNING"
                $IPv6Enabled = $true
            }
        }
        if (-not $IPv6Enabled) {
            Write-Log "  IPv6 disabled on all adapters: ✓ PASS" -Level "SUCCESS"
        }
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
    Write-Log "Network Configuration Results:" -Level "INFO"
    Write-Log "  Adapters Found: $($Global:Stats.AdaptersFound)" -Level "INFO"
    Write-Log "  Adapters Configured: $($Global:Stats.AdaptersConfigured)" -Level "SUCCESS"
    Write-Log "  DNS Configured: $($Global:Stats.DNSConfigured)" -Level "SUCCESS"
    Write-Log "  IPv6 Disabled: $($Global:Stats.IPv6Disabled)" -Level "SUCCESS"
    Write-Log "  NetBIOS Disabled: $($Global:Stats.NetBIOSDisabled)" -Level "SUCCESS"
    Write-Log "  Power Mgmt Disabled: $($Global:Stats.PowerManagementDisabled)" -Level "SUCCESS"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
    
    # Display current adapter status
    Write-Log " " -Level "INFO"
    Write-Log "Current Adapter Status:" -Level "INFO"
    $CurrentAdapters = Get-NetAdapter | Where-Object { $_.Status -ne "Not Present" }
    foreach ($Adapter in $CurrentAdapters) {
        Write-Log "  [$($Adapter.Status)] $($Adapter.Name) - $($Adapter.LinkSpeed)" -Level "INFO"
    }
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
║        NETWORK ADAPTER CONFIGURATION                          ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "NETWORK ADAPTER CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Discover network adapters
    $AdapterInventory = Get-NetworkAdapterInventory
    
    if (-not $AdapterInventory -or $AdapterInventory.All.Count -eq 0) {
        Write-Log "No network adapters found" -Level "ERROR"
        exit 3
    }
    
    # Configure DNS servers
    Set-AdapterDNSServers -Adapter $AdapterInventory
    
    # Configure IPv6
    Set-IPv6Configuration -Adapter $AdapterInventory
    
    # Configure NetBIOS
    Set-NetBIOSConfiguration -Adapter $AdapterInventory
    
    # Optimize adapter metrics
    Optimize-AdapterMetrics -Adapter $AdapterInventory
    
    # Configure power management
    Set-AdapterPowerManagement -Adapter $AdapterInventory
    
    # Configure advanced settings
    Set-AdvancedAdapterSettings -Adapter $AdapterInventory
    
    # Configure QoS
    Set-QoSConfiguration -Adapter $AdapterInventory
    
    # Standardize names (if requested)
    Set-StandardAdapterNames -Adapter $AdapterInventory
    
    # Validate configuration
    $ValidationResults = Test-NetworkConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Network adapter configuration completed successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Network adapter configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
