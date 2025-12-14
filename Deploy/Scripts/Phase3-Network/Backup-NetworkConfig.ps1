<#
.SYNOPSIS
    Backup Network Adapter Configuration
    
.DESCRIPTION
    Creates a comprehensive backup of all network adapter settings before making
    changes. This backup can be restored using Restore-NetworkConfig.ps1.
    
    Backs up:
    - DNS server settings
    - IPv6 binding status
    - NetBIOS over TCP/IP settings
    - Interface metrics
    - Advanced adapter properties
    - Adapter names and descriptions
    
.PARAMETER BackupPath
    Path where backup file will be saved. Default: C:\ProgramData\OrchestrationLogs\NetworkBackup
    
.EXAMPLE
    .\Backup-NetworkConfig.ps1
    Creates backup with automatic timestamp
    
.EXAMPLE
    .\Backup-NetworkConfig.ps1 -BackupPath "C:\Backups"
    Creates backup in custom location
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Network configuration backup before changes
    
    IMPORTANT: Run this BEFORE Configure-NetworkAdapters.ps1
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = "C:\ProgramData\OrchestrationLogs\NetworkBackup"
)

#region INITIALIZATION

$ScriptVersion = "1.0.0"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupFile = Join-Path $BackupPath "NetworkConfig_Backup_$Timestamp.xml"

# Create backup directory
if (-not (Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
}

#endregion

#region MAIN BACKUP

Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        NETWORK CONFIGURATION BACKUP                           ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Creating network configuration backup..." -ForegroundColor Yellow
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor White
Write-Host ""

# Backup data structure
$Backup = @{
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    ScriptVersion = $ScriptVersion
    Adapters = @()
}

# Get all network adapters
$Adapters = Get-NetAdapter | Where-Object { $_.Status -ne "Not Present" }

Write-Host "Found $($Adapters.Count) network adapter(s)" -ForegroundColor Cyan
Write-Host ""

foreach ($Adapter in $Adapters) {
    Write-Host "Backing up: $($Adapter.Name)" -ForegroundColor Yellow
    
    $AdapterBackup = @{
        Name = $Adapter.Name
        InterfaceDescription = $Adapter.InterfaceDescription
        InterfaceIndex = $Adapter.InterfaceIndex
        MacAddress = $Adapter.MacAddress
        Status = $Adapter.Status
        LinkSpeed = $Adapter.LinkSpeed
        MediaType = $Adapter.MediaType
        DriverVersion = $Adapter.DriverVersion
        
        # Configuration data
        IPv4Config = @{}
        IPv6Config = @{}
        DNSServers = @()
        NetBIOSSetting = $null
        IPv6Enabled = $null
        InterfaceMetric = $null
        AutomaticMetric = $null
        AdvancedProperties = @{}
        QoSEnabled = $null
    }
    
    # Get IPv4 configuration
    try {
        $IPv4 = Get-NetIPAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($IPv4) {
            $AdapterBackup.IPv4Config = @{
                IPAddress = $IPv4.IPAddress
                PrefixLength = $IPv4.PrefixLength
                AddressState = $IPv4.AddressState
            }
            Write-Host "  ✓ IPv4 configuration" -ForegroundColor Green
        }
    } 
    catch {
        Write-Host "  ⚠ No IPv4 configuration" -ForegroundColor DarkGray
    }
    
    # Get IPv6 configuration
    try {
        $IPv6 = Get-NetIPAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        if ($IPv6) {
            $AdapterBackup.IPv6Config = @{
                IPAddress = $IPv6.IPAddress | Select-Object -First 1
                PrefixLength = $IPv6.PrefixLength | Select-Object -First 1
                AddressState = $IPv6.AddressState | Select-Object -First 1
            }
            Write-Host "  ✓ IPv6 configuration" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ No IPv6 configuration" -ForegroundColor DarkGray
    }
    
    # Get DNS servers
    try {
        $DNS = Get-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($DNS -and $DNS.ServerAddresses) {
            $AdapterBackup.DNSServers = $DNS.ServerAddresses
            Write-Host "  ✓ DNS servers: $($DNS.ServerAddresses -join ', ')" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ No DNS configuration" -ForegroundColor DarkGray
    }
    
    # Get NetBIOS setting
    try {
        $WMIAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -eq $Adapter.MacAddress }
        if ($WMIAdapter) {
            $AdapterBackup.NetBIOSSetting = $WMIAdapter.TcpipNetbiosOptions
            $NetBIOSText = switch ($WMIAdapter.TcpipNetbiosOptions) {
                0 { "Default" }
                1 { "Enabled" }
                2 { "Disabled" }
                default { "Unknown" }
            }
            Write-Host "  ✓ NetBIOS: $NetBIOSText" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not read NetBIOS setting" -ForegroundColor DarkGray
    }
    
    # Get IPv6 binding status
    try {
        $IPv6Binding = Get-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        if ($IPv6Binding) {
            $AdapterBackup.IPv6Enabled = $IPv6Binding.Enabled
            Write-Host "  ✓ IPv6 binding: $($IPv6Binding.Enabled)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not read IPv6 binding" -ForegroundColor DarkGray
    }
    
    # Get interface metric
    try {
        $IPInterface = Get-NetIPInterface -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($IPInterface) {
            $AdapterBackup.InterfaceMetric = $IPInterface.InterfaceMetric
            $AdapterBackup.AutomaticMetric = $IPInterface.AutomaticMetric
            Write-Host "  ✓ Interface metric: $($IPInterface.InterfaceMetric) (Automatic: $($IPInterface.AutomaticMetric))" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not read interface metric" -ForegroundColor DarkGray
    }
    
    # Get QoS binding
    try {
        $QoSBinding = Get-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_pacer -ErrorAction SilentlyContinue
        if ($QoSBinding) {
            $AdapterBackup.QoSEnabled = $QoSBinding.Enabled
            Write-Host "  ✓ QoS: $($QoSBinding.Enabled)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not read QoS setting" -ForegroundColor DarkGray
    }
    
    # Get advanced properties
    try {
        $AdvProps = Get-NetAdapterAdvancedProperty -Name $Adapter.Name -ErrorAction SilentlyContinue
        if ($AdvProps) {
            $PropCount = 0
            foreach ($Prop in $AdvProps) {
                $AdapterBackup.AdvancedProperties[$Prop.RegistryKeyword] = @{
                    DisplayName = $Prop.DisplayName
                    DisplayValue = $Prop.DisplayValue
                    RegistryValue = $Prop.RegistryValue
                }
                $PropCount++
            }
            Write-Host "  ✓ Advanced properties: $PropCount" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not read advanced properties" -ForegroundColor DarkGray
    }
    
    $Backup.Adapters += $AdapterBackup
    Write-Host ""
}

# Export to XML
try {
    $Backup | Export-Clixml -Path $BackupFile -Force
    
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "✓ Backup created successfully!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Backup Details:" -ForegroundColor Cyan
    Write-Host "  File: $BackupFile" -ForegroundColor White
    Write-Host "  Size: $([math]::Round((Get-Item $BackupFile).Length / 1KB, 2)) KB" -ForegroundColor White
    Write-Host "  Adapters: $($Backup.Adapters.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "To restore this backup, run:" -ForegroundColor Yellow
    Write-Host "  .\Restore-NetworkConfig.ps1 -BackupFile '$BackupFile'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To see all available backups, run:" -ForegroundColor Yellow
    Write-Host "  .\Restore-NetworkConfig.ps1 -ListBackups" -ForegroundColor Cyan
    Write-Host ""
    
    exit 0
}
catch {
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "✗ ERROR: Failed to create backup" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

#endregion
