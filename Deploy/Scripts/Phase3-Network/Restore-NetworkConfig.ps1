<#
.SYNOPSIS
    Restore Network Adapter Configuration
    
.DESCRIPTION
    Restores network adapter configuration from backup created by
    Backup-NetworkConfig.ps1. Can restore from specific backup file
    or automatically use the most recent backup.
    
.PARAMETER BackupFile
    Path to specific backup file to restore. If not specified, uses most recent.
    
.PARAMETER ListBackups
    Lists all available backup files
    
.PARAMETER Force
    Skip confirmation prompt
    
.EXAMPLE
    .\Restore-NetworkConfig.ps1
    Restores from most recent backup (with confirmation)
    
.EXAMPLE
    .\Restore-NetworkConfig.ps1 -BackupFile "C:\...\NetworkConfig_Backup_20241208-143000.xml"
    Restores from specific backup file
    
.EXAMPLE
    .\Restore-NetworkConfig.ps1 -ListBackups
    Lists all available backups
    
.EXAMPLE
    .\Restore-NetworkConfig.ps1 -Force
    Restores without confirmation (automated scenarios)
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Network configuration restore after failed changes
    
    EXIT CODES:
    0 = Success
    1 = Backup file not found or read error
    2 = User cancelled
    3 = Restore failed
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$BackupFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$ListBackups,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

#region INITIALIZATION

$ScriptVersion = "1.0.0"
$BackupPath = "C:\ProgramData\OrchestrationLogs\NetworkBackup"

# Statistics tracking
$Stats = @{
    AdaptersFound = 0
    AdaptersRestored = 0
    DNSRestored = 0
    IPv6Restored = 0
    NetBIOSRestored = 0
    MetricsRestored = 0
    Errors = 0
    Warnings = 0
}

#endregion

#region LIST BACKUPS

if ($ListBackups) {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        AVAILABLE NETWORK CONFIGURATION BACKUPS                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    if (-not (Test-Path $BackupPath)) {
        Write-Host "Backup directory not found: $BackupPath" -ForegroundColor Red
        exit 1
    }
    
    $Backups = Get-ChildItem -Path $BackupPath -Filter "NetworkConfig_Backup_*.xml" -ErrorAction SilentlyContinue | 
               Sort-Object LastWriteTime -Descending
    
    if (-not $Backups -or $Backups.Count -eq 0) {
        Write-Host "No backup files found in $BackupPath" -ForegroundColor Yellow
        exit 0
    }
    
    Write-Host "Found $($Backups.Count) backup file(s):" -ForegroundColor Cyan
    Write-Host ""
    
    $Index = 1
    foreach ($Backup in $Backups) {
        # Try to read backup info
        try {
            $BackupData = Import-Clixml -Path $Backup.FullName
            $Computer = $BackupData.ComputerName
            $AdapterCount = $BackupData.Adapters.Count
            $Age = (Get-Date) - $Backup.LastWriteTime
            
            Write-Host "[$Index] $($Backup.Name)" -ForegroundColor Yellow
            Write-Host "    Created: $($Backup.LastWriteTime)" -ForegroundColor White
            Write-Host "    Computer: $Computer" -ForegroundColor White
            Write-Host "    Adapters: $AdapterCount" -ForegroundColor White
            Write-Host "    Age: $([math]::Round($Age.TotalHours, 1)) hours ago" -ForegroundColor White
            Write-Host "    Size: $([math]::Round($Backup.Length / 1KB, 2)) KB" -ForegroundColor White
            Write-Host ""
        }
        catch {
            Write-Host "[$Index] $($Backup.Name)" -ForegroundColor Yellow
            Write-Host "    Created: $($Backup.LastWriteTime)" -ForegroundColor White
            Write-Host "    ⚠ Could not read backup details" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        $Index++
    }
    
    Write-Host "To restore a backup, run:" -ForegroundColor Cyan
    Write-Host "  .\Restore-NetworkConfig.ps1 -BackupFile '<path-to-backup-file>'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Or restore most recent:" -ForegroundColor Cyan
    Write-Host "  .\Restore-NetworkConfig.ps1" -ForegroundColor Yellow
    Write-Host ""
    
    exit 0
}

#endregion

#region FIND BACKUP FILE

Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        RESTORE NETWORK CONFIGURATION                          ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Find most recent backup if not specified
if ([string]::IsNullOrWhiteSpace($BackupFile)) {
    Write-Host "No backup file specified, finding most recent..." -ForegroundColor Yellow
    
    if (-not (Test-Path $BackupPath)) {
        Write-Host "ERROR: Backup directory not found: $BackupPath" -ForegroundColor Red
        exit 1
    }
    
    $LatestBackup = Get-ChildItem -Path $BackupPath -Filter "NetworkConfig_Backup_*.xml" -ErrorAction SilentlyContinue | 
                    Sort-Object LastWriteTime -Descending | 
                    Select-Object -First 1
    
    if ($LatestBackup) {
        $BackupFile = $LatestBackup.FullName
        Write-Host "Using most recent backup: $($LatestBackup.Name)" -ForegroundColor Cyan
    }
    else {
        Write-Host "ERROR: No backup files found in $BackupPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please run Backup-NetworkConfig.ps1 first to create a backup" -ForegroundColor Yellow
        exit 1
    }
}

# Verify backup file exists
if (-not (Test-Path $BackupFile)) {
    Write-Host "ERROR: Backup file not found: $BackupFile" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Backup file: $BackupFile" -ForegroundColor Yellow
Write-Host ""

#endregion

#region LOAD BACKUP

# Import backup
try {
    $Backup = Import-Clixml -Path $BackupFile
}
catch {
    Write-Host "ERROR: Failed to read backup file: $_" -ForegroundColor Red
    exit 1
}

# Display backup info
Write-Host "Backup Information:" -ForegroundColor Cyan
Write-Host "  Created: $($Backup.Timestamp)" -ForegroundColor White
Write-Host "  Computer: $($Backup.ComputerName)" -ForegroundColor White
Write-Host "  Adapters in backup: $($Backup.Adapters.Count)" -ForegroundColor White
Write-Host ""

# Check if backup is from this computer
if ($Backup.ComputerName -ne $env:COMPUTERNAME) {
    Write-Host "⚠ WARNING: This backup is from a different computer!" -ForegroundColor Yellow
    Write-Host "  Backup from: $($Backup.ComputerName)" -ForegroundColor Yellow
    Write-Host "  Current computer: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host ""
}

# Confirmation
if (-not $Force) {
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "⚠ This will restore network adapter configuration" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    
    $Confirm = Read-Host "Continue with restore? (yes/no)"
    if ($Confirm -ne "yes") {
        Write-Host "Restore cancelled by user" -ForegroundColor Yellow
        exit 2
    }
    Write-Host ""
}

#endregion

#region RESTORE CONFIGURATION

Write-Host "Starting network configuration restore..." -ForegroundColor Cyan
Write-Host ""

foreach ($AdapterBackup in $Backup.Adapters) {
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Restoring: $($AdapterBackup.Name)" -ForegroundColor Yellow
    Write-Host "  Description: $($AdapterBackup.InterfaceDescription)" -ForegroundColor White
    Write-Host "  MAC Address: $($AdapterBackup.MacAddress)" -ForegroundColor White
    Write-Host ""
    
    # Find current adapter by MAC address (most reliable identifier)
    $CurrentAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.MacAddress -eq $AdapterBackup.MacAddress }
    
    if (-not $CurrentAdapter) {
        Write-Host "  ⚠ WARNING: Adapter not found (may have been removed or renamed)" -ForegroundColor Yellow
        Write-Host ""
        $Stats.Warnings++
        continue
    }
    
    Write-Host "  Found adapter: $($CurrentAdapter.Name) [Status: $($CurrentAdapter.Status)]" -ForegroundColor Green
    Write-Host ""
    
    $Stats.AdaptersFound++
    
    # Restore DNS servers
    if ($AdapterBackup.DNSServers -and $AdapterBackup.DNSServers.Count -gt 0) {
        try {
            Write-Host "  [DNS] Restoring DNS servers: $($AdapterBackup.DNSServers -join ', ')" -ForegroundColor Yellow
            Set-DnsClientServerAddress -InterfaceIndex $CurrentAdapter.InterfaceIndex -ServerAddresses $AdapterBackup.DNSServers -ErrorAction Stop
            Write-Host "  [DNS] ✓ DNS servers restored" -ForegroundColor Green
            $Stats.DNSRestored++
        }
        catch {
            Write-Host "  [DNS] ✗ Failed to restore DNS: $_" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    else {
        Write-Host "  [DNS] No DNS configuration to restore (DHCP)" -ForegroundColor DarkGray
    }
    
    # Restore NetBIOS setting
    if ($null -ne $AdapterBackup.NetBIOSSetting) {
        try {
            $NetBIOSText = switch ($AdapterBackup.NetBIOSSetting) {
                0 { "Default" }
                1 { "Enabled" }
                2 { "Disabled" }
                default { "Unknown ($($AdapterBackup.NetBIOSSetting))" }
            }
            
            Write-Host "  [NetBIOS] Restoring NetBIOS setting: $NetBIOSText" -ForegroundColor Yellow
            $WMIAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -eq $CurrentAdapter.MacAddress }
            
            if ($WMIAdapter) {
                $Result = $WMIAdapter.SetTcpipNetbios($AdapterBackup.NetBIOSSetting)
                if ($Result.ReturnValue -eq 0) {
                    Write-Host "  [NetBIOS] ✓ NetBIOS setting restored" -ForegroundColor Green
                    $Stats.NetBIOSRestored++
                }
                else {
                    Write-Host "  [NetBIOS] ✗ Failed (Error code: $($Result.ReturnValue))" -ForegroundColor Red
                    $Stats.Errors++
                }
            }
            else {
                Write-Host "  [NetBIOS] ✗ Could not find WMI adapter" -ForegroundColor Red
                $Stats.Errors++
            }
        }
        catch {
            Write-Host "  [NetBIOS] ✗ Failed to restore NetBIOS: $_" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    
    # Restore IPv6 binding
    if ($null -ne $AdapterBackup.IPv6Enabled) {
        try {
            Write-Host "  [IPv6] Restoring IPv6 binding: $($AdapterBackup.IPv6Enabled)" -ForegroundColor Yellow
            
            if ($AdapterBackup.IPv6Enabled) {
                Enable-NetAdapterBinding -Name $CurrentAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop
                Write-Host "  [IPv6] ✓ IPv6 enabled" -ForegroundColor Green
            }
            else {
                Disable-NetAdapterBinding -Name $CurrentAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop
                Write-Host "  [IPv6] ✓ IPv6 disabled" -ForegroundColor Green
            }
            $Stats.IPv6Restored++
        }
        catch {
            Write-Host "  [IPv6] ✗ Failed to restore IPv6: $_" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    
    # Restore interface metric
    if ($null -ne $AdapterBackup.InterfaceMetric) {
        try {
            Write-Host "  [Metric] Restoring interface metric: $($AdapterBackup.InterfaceMetric)" -ForegroundColor Yellow
            
            if ($AdapterBackup.AutomaticMetric) {
                # Restore automatic metric
                Set-NetIPInterface -InterfaceIndex $CurrentAdapter.InterfaceIndex -AutomaticMetric Enabled -ErrorAction Stop
                Write-Host "  [Metric] ✓ Automatic metric enabled" -ForegroundColor Green
            }
            else {
                # Restore manual metric
                Set-NetIPInterface -InterfaceIndex $CurrentAdapter.InterfaceIndex -InterfaceMetric $AdapterBackup.InterfaceMetric -ErrorAction Stop
                Write-Host "  [Metric] ✓ Interface metric restored to $($AdapterBackup.InterfaceMetric)" -ForegroundColor Green
            }
            $Stats.MetricsRestored++
        }
        catch {
            Write-Host "  [Metric] ✗ Failed to restore metric: $_" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    
    # Restore QoS binding
    if ($null -ne $AdapterBackup.QoSEnabled) {
        try {
            Write-Host "  [QoS] Restoring QoS: $($AdapterBackup.QoSEnabled)" -ForegroundColor Yellow
            
            if ($AdapterBackup.QoSEnabled) {
                Enable-NetAdapterBinding -Name $CurrentAdapter.Name -ComponentID ms_pacer -ErrorAction Stop
                Write-Host "  [QoS] ✓ QoS enabled" -ForegroundColor Green
            }
            else {
                Disable-NetAdapterBinding -Name $CurrentAdapter.Name -ComponentID ms_pacer -ErrorAction Stop
                Write-Host "  [QoS] ✓ QoS disabled" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [QoS] ✗ Failed to restore QoS: $_" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    
    Write-Host ""
    $Stats.AdaptersRestored++
}

#endregion

#region VALIDATION & SUMMARY

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "RESTORE SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Adapters in backup: $($Backup.Adapters.Count)" -ForegroundColor White
Write-Host "Adapters found: $($Stats.AdaptersFound)" -ForegroundColor White
Write-Host "Adapters restored: $($Stats.AdaptersRestored)" -ForegroundColor White
Write-Host ""
Write-Host "Configuration restored:" -ForegroundColor White
Write-Host "  DNS: $($Stats.DNSRestored)" -ForegroundColor White
Write-Host "  IPv6: $($Stats.IPv6Restored)" -ForegroundColor White
Write-Host "  NetBIOS: $($Stats.NetBIOSRestored)" -ForegroundColor White
Write-Host "  Metrics: $($Stats.MetricsRestored)" -ForegroundColor White
Write-Host ""
Write-Host "Status:" -ForegroundColor White
Write-Host "  Errors: $($Stats.Errors)" -ForegroundColor $(if($Stats.Errors -gt 0){"Red"}else{"Green"})
Write-Host "  Warnings: $($Stats.Warnings)" -ForegroundColor $(if($Stats.Warnings -gt 0){"Yellow"}else{"Green"})
Write-Host ""

if ($Stats.Errors -eq 0) {
    Write-Host "✓ Network configuration restored successfully!" -ForegroundColor Green
}
else {
    Write-Host "⚠ Network configuration restored with $($Stats.Errors) error(s)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "TESTING NETWORK CONNECTIVITY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Test network connectivity
Write-Host "Testing adapters..." -ForegroundColor Yellow
$ActiveAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($Adapter in $ActiveAdapters) {
    Write-Host "  ✓ $($Adapter.Name): $($Adapter.Status) - $($Adapter.LinkSpeed)" -ForegroundColor Green
}
Write-Host ""

Write-Host "Testing internet connectivity..." -ForegroundColor Yellow
try {
    $PingTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($PingTest) {
        Write-Host "  ✓ Internet connectivity: OK" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Internet connectivity: FAILED" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ✗ Internet connectivity: ERROR" -ForegroundColor Red
}
Write-Host ""

Write-Host "Testing DNS resolution..." -ForegroundColor Yellow
try {
    $DNSTest = Resolve-DnsName "www.microsoft.com" -Type A -ErrorAction SilentlyContinue
    if ($DNSTest) {
        Write-Host "  ✓ DNS resolution: OK" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ DNS resolution: FAILED" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ✗ DNS resolution: ERROR" -ForegroundColor Red
}
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($Stats.Errors -eq 0) {
    Write-Host "Restore completed successfully!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "Restore completed with errors - please verify network connectivity" -ForegroundColor Yellow
    exit 3
}

#endregion
