# SYSTEM HEALTH CHECK - DOCUMENTATION

## Overview

Comprehensive guide for **Check-SystemHealth.ps1** — validating overall system health after deployment completion.

**Script Location:** `Phase7-Validation\Check-SystemHealth.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## Quick Start

### Basic Usage

```powershell
# Full health check (all categories)
.\Check-SystemHealth.ps1

# Specific categories
.\Check-SystemHealth.ps1 -CheckDiskSpace $true -CheckServices $true

# Generate HTML report
.\Check-SystemHealth.ps1 -GenerateReport $true

# Test without checking
.\Check-SystemHealth.ps1 -DryRun
```

---

## What It Does

Validates system health across 6 critical categories:

- ✅ **Disk Space** - Free space on all drives
- ✅ **Services** - 11 critical Windows services
- ✅ **Event Logs** - Recent errors/warnings (24 hours)
- ✅ **Performance** - CPU, memory, disk response time
- ✅ **Hardware** - Device status, SMART, temperature
- ✅ **Network** - Internet, DNS, adapters, IP configuration
- ✅ **HTML Report** - Detailed health report with scoring

---

## Configuration from Orchestration

```powershell
TaskID: VAL-003
Parameters = @{
    CheckDiskSpace = $true
    CheckServices = $true
    CheckEventLog = $true
    CheckPerformance = $true
}
```

### What This Validates

**6 Health Categories:**

**1. Disk Space**
```
C:\ Drive: >20 GB free (Critical), >50 GB (Optimal)
Other Drives: >10% free (Critical), >20% (Optimal)

Checks:
✓ All drive free space
✓ OS drive specific threshold
✓ Data drive percentage-based
```

**2. Critical Services (11 services)**
```
✓ Windows Update (wuauserv)
✓ WMI (Winmgmt)
✓ RPC (RpcSs)
✓ DHCP Client (Dhcp)
✓ DNS Client (Dnscache)
✓ Event Log (EventLog)
✓ Plug and Play (PlugPlay)
✓ SAM (SamSs)
✓ Workstation (LanmanWorkstation)
✓ Server (LanmanServer)
✓ Windows Firewall (MpsSvc)

All should be: Running
```

**3. Event Logs (24-hour scan)**
```
System Log: <10 errors (Critical/Error level)
Application Log: <20 errors
Critical Events: 0 critical events

Scans:
- System log (Level 1,2)
- Application log (Level 1,2)
- Critical events only (Level 1)
```

**4. Performance Metrics**
```
CPU Usage: <80% (3-second average)
Memory Usage: <90% of total
Disk Response: <20ms average
System Uptime: Reported (informational)

Real-time measurements taken
```

**5. Hardware Health**
```
Device Status: 0 failed devices
Disk SMART: No failures predicted
System Temperature: <80°C (if available)

Hardware validation
```

**6. Network Connectivity**
```
Internet: Connected (ping 8.8.8.8)
DNS: Working (resolve www.google.com)
Adapters: >0 active
IP Config: Valid (not APIPA 169.254.x.x)

Network validation
```

---

## Health Check Categories

### 1. Disk Space Validation

**What's Checked:**

**C:\ Drive (OS Drive) - Special Handling:**
```
✓ PASS:     >50 GB free (optimal)
⚠ WARNING:  20-50 GB free (acceptable)
✗ CRITICAL: <20 GB free (insufficient)

Why Different:
- OS updates need space (10-20 GB)
- Page file needs space
- Temp files accumulate
- Application installs
```

**Other Drives - Percentage Based:**
```
✓ PASS:     >20% free
⚠ WARNING:  10-20% free
✗ CRITICAL: <10% free

Why Percentage:
- Drive size varies
- Data drives can be large
- Percentage more meaningful
```

**Example Results:**
```
Drive C:\ : 75.2 GB free / 237.0 GB total (31.7% free) ✓
Drive D:\ : 450.8 GB free / 931.5 GB total (48.4% free) ✓
Drive E:\ : 15.3 GB free / 200.0 GB total (7.7% free) ✗ CRITICAL
```

---

### 2. Critical Services Validation

**11 Services Monitored:**

**1. Windows Update (wuauserv)**
```
Purpose: System updates
Impact if stopped: No updates, security vulnerability
Status: Must be Running
```

**2. WMI (Winmgmt)**
```
Purpose: Management instrumentation
Impact if stopped: Scripts fail, monitoring broken
Status: Must be Running
```

**3. Remote Procedure Call (RpcSs)**
```
Purpose: Core Windows communication
Impact if stopped: System unstable, apps fail
Status: Must be Running (CRITICAL)
```

**4. DHCP Client (Dhcp)**
```
Purpose: IP address acquisition
Impact if stopped: No network if using DHCP
Status: Must be Running
```

**5. DNS Client (Dnscache)**
```
Purpose: Name resolution caching
Impact if stopped: Slow DNS, connectivity issues
Status: Must be Running
```

**6. Windows Event Log (EventLog)**
```
Purpose: Event logging
Impact if stopped: No logs, troubleshooting impossible
Status: Must be Running
```

**7. Plug and Play (PlugPlay)**
```
Purpose: Hardware detection
Impact if stopped: New hardware not recognized
Status: Must be Running
```

**8. Security Accounts Manager (SamSs)**
```
Purpose: User account management
Impact if stopped: Login failures, permission issues
Status: Must be Running (CRITICAL)
```

**9. Workstation (LanmanWorkstation)**
```
Purpose: Network connections to servers
Impact if stopped: Cannot access file shares
Status: Must be Running
```

**10. Server (LanmanServer)**
```
Purpose: File/printer sharing
Impact if stopped: Others cannot access this PC
Status: Should be Running
```

**11. Windows Defender Firewall (MpsSvc)**
```
Purpose: Network security
Impact if stopped: Unprotected from network attacks
Status: Must be Running (CRITICAL)
```

**Service Status Logic:**
```
Running + Auto/Manual = ✓ PASS
Stopped + Disabled = ⚠ WARNING (intentional?)
Stopped + Auto/Manual = ✗ CRITICAL (should be running)
```

---

### 3. Event Log Validation

**What's Scanned:**

**Time Period:** Last 24 hours
**Log Types:** System, Application, Security

**System Log:**
```
Levels Scanned:
- Level 1: Critical
- Level 2: Error

Thresholds:
✓ PASS:     0 errors
⚠ WARNING:  1-9 errors
✗ CRITICAL: 10+ errors

Common Sources:
- Disk
- Service Control Manager
- BIOS
- DistributedCOM
```

**Application Log:**
```
Levels Scanned:
- Level 1: Critical  
- Level 2: Error

Thresholds:
✓ PASS:     0 errors
⚠ WARNING:  1-19 errors
✗ CRITICAL: 20+ errors

Common Sources:
- Application crashes
- Software errors
- Installation failures
```

**Critical Events Check:**
```
Level 1 Only (Critical)
Any Source

Threshold:
✓ PASS:     0 critical
✗ CRITICAL: Any critical events

These always require investigation
```

---

### 4. Performance Validation

**What's Measured:**

**CPU Usage (3-second average):**
```
Method: Get-Counter '\Processor(_Total)\% Processor Time'
Sample: 3 measurements over 3 seconds
Average: Mean of 3 samples

Thresholds:
✓ PASS:     <80% (normal)
⚠ WARNING:  80-94% (elevated)
✗ CRITICAL: 95%+ (overloaded)

Why 80%:
- Leaves headroom for spikes
- User experience degrades >80%
- Sustained high CPU = problem
```

**Memory Usage:**
```
Method: Win32_OperatingSystem (WMI)
Calculation: (Total - Free) / Total * 100

Thresholds:
✓ PASS:     <90% (normal)
⚠ WARNING:  90-94% (tight)
✗ CRITICAL: 95%+ (critically low)

Why 90%:
- Windows manages memory aggressively
- 90% is typical for active system
- >95% = actual pressure
```

**Disk Response Time:**
```
Method: Get-Counter '\PhysicalDisk(0 C:)\Avg. Disk sec/Read'
Sample: 3 measurements, convert to milliseconds
Unit: Milliseconds (ms)

Thresholds:
✓ PASS:     <20ms (SSD or good HDD)
⚠ WARNING:  20-49ms (acceptable HDD)
✗ CRITICAL: 50ms+ (slow disk, possible failure)

Why 20ms:
- SSDs: <1-5ms typical
- HDD: 10-20ms typical
- >50ms indicates problem
```

**System Uptime:**
```
Method: LastBootUpTime from WMI
Purpose: Informational only
No Pass/Fail: Just reports days since boot

Useful for:
- Pending reboot detection
- Stability tracking
- Update cycles
```

---

### 5. Hardware Health Validation

**What's Checked:**

**Device Status:**
```
Method: Win32_PnPEntity WMI class
Check: ConfigManagerErrorCode field

Logic:
Code = 0: Device OK ✓
Code ≠ 0: Device failed ✗

Reports:
- Number of failed devices
- Device names (first 5)

Common Failures:
- Unknown devices (missing drivers)
- Disabled devices
- Hardware conflicts
```

**Disk SMART Status:**
```
Method: MSStorageDriver_FailurePredictStatus (WMI root\wmi)
Check: PredictFailure boolean

Logic:
False: Disk healthy ✓
True: Failure predicted ✗ CRITICAL

Action if predicted:
- Immediate backup
- Schedule replacement
- Monitor closely

Note: Not all disks support SMART
```

**System Temperature:**
```
Method: MSAcpi_ThermalZoneTemperature (WMI root\wmi)
Convert: Kelvin → Celsius (K/10 - 273.15)
Unit: Celsius (°C)

Thresholds:
✓ PASS:     <80°C (normal)
⚠ WARNING:  80-90°C (warm)
✗ CRITICAL: 90°C+ (dangerous)

Note: Not available on all systems
Desktop: Rarely available
Laptop: Usually available
```

---

### 6. Network Connectivity Validation

**What's Tested:**

**Internet Connectivity:**
```
Method: Test-Connection to 8.8.8.8 (Google DNS)
Count: 2 pings
Timeout: Default (5 seconds)

Logic:
Success: Internet accessible ✓
Failure: No internet ✗ CRITICAL

Why 8.8.8.8:
- Highly available
- Known good endpoint
- Not blocked by most firewalls
```

**DNS Resolution:**
```
Method: Resolve-DnsName www.google.com
Type: A record (IPv4)

Logic:
Success: DNS working ✓
Failure: DNS broken ✗ CRITICAL

Why Important:
- Most apps need DNS
- No DNS = no internet (from user perspective)
- Can break domain authentication
```

**Network Adapters:**
```
Method: Get-NetAdapter where Status = "Up"
Count: Active adapters

Logic:
>0 adapters: OK ✓
0 adapters: No network ✗ CRITICAL

Reports:
- Number of active adapters
- Adapter names (Wi-Fi, Ethernet, etc.)
```

**IP Configuration:**
```
Method: Get-NetIPAddress (IPv4, Unicast, not Loopback)
Check: IP address not 169.254.x.x (APIPA)

Logic:
Valid IP: Configured ✓
APIPA (169.254.x.x): DHCP failed ✗ CRITICAL

APIPA Meaning:
- Automatic Private IP Addressing
- Self-assigned when DHCP fails
- Cannot reach network
```

---

## HTML Health Report

### Report Structure

**Summary Dashboard:**
```html
╔═══════════════════════════════════════════╗
║ Status: HEALTHY                           ║
║ Health Score: 98%                         ║
║                                           ║
║ ✓ Passed:   45                            ║
║ ⚠ Warnings:  1                            ║
║ ✗ Critical:  0                            ║
╚═══════════════════════════════════════════╝
```

**Category Breakdown:**
```
Disk Space:    Pass=2  Warn=0  Crit=0
Services:      Pass=11 Warn=0  Crit=0
Event Logs:    Pass=3  Warn=0  Crit=0
Performance:   Pass=4  Warn=0  Crit=0
Hardware:      Pass=2  Warn=0  Crit=0
Network:       Pass=4  Warn=0  Crit=0
```

**Detailed Results Table:**
- Each check with status (✓/⚠/✗)
- Value (actual measurement)
- Expected (threshold)
- Color-coded for visibility

**Report Location:**
```
C:\ProgramData\HealthReports\
SystemHealth_20241209-150000.html
```

---

## Health Scoring

### How Scoring Works

**Calculation:**
```
Health Score = (Passed Checks / Total Checks) × 100

Example:
45 passed / 46 total = 97.8%
```

**Status Determination:**
```
100% Health:       HEALTHY
95-99% Health:     HEALTHY (Minor Warnings)
80-94% Health:     MULTIPLE WARNINGS
<80% Health:       CRITICAL ISSUES
Any Critical:      CRITICAL ISSUES (overrides %)
```

---

## Running the Script

### Method 1: Via SCCM (Production)

```
Step Type: Run PowerShell Script
Script: Check-SystemHealth.ps1
Run as: SYSTEM
Success Codes: 0
Timeout: 600 seconds
```

---

### Method 2: Via PsExec (Manual)

```powershell
# Launch SYSTEM PowerShell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# Run health check
cd C:\DeploymentScripts\Phase7-Validation
.\Check-SystemHealth.ps1

# View report
Start-Process "C:\ProgramData\HealthReports\SystemHealth_*.html"
```

---

## Troubleshooting

### Issue 1: Low Disk Space on C:\

**Symptom:** C:\ drive <20 GB free

**Common Causes:**
1. Windows Update cache
2. Temp files
3. Large user profiles
4. Application installs

**Solutions:**

```powershell
# Disk Cleanup
cleanmgr /sageset:1
cleanmgr /sagerun:1

# Clear Windows Update cache
Stop-Service wuauserv
Remove-Item C:\Windows\SoftwareDistribution\Download\* -Recurse -Force
Start-Service wuauserv

# Clear temp files
Remove-Item $env:TEMP\* -Recurse -Force
Remove-Item C:\Windows\Temp\* -Recurse -Force

# Check large files
Get-ChildItem C:\ -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 20 |
    Format-Table Name, Length, Directory
```

---

### Issue 2: Critical Service Not Running

**Symptom:** Service shows as Stopped

**Solutions:**

```powershell
# Check service details
$ServiceName = "wuauserv"
Get-Service $ServiceName | Format-List *

# Start service
Start-Service $ServiceName

# Set to automatic
Set-Service $ServiceName -StartupType Automatic

# Check dependencies
Get-Service $ServiceName -DependentServices
Get-Service $ServiceName -RequiredServices
```

---

### Issue 3: High Event Log Errors

**Symptom:** >10 errors in System log

**Solutions:**

```powershell
# View recent errors
Get-WinEvent -FilterHashtable @{
    LogName='System'
    Level=1,2
    StartTime=(Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, ProviderName, Message |
    Format-Table -AutoSize

# Group by source to find patterns
Get-WinEvent -FilterHashtable @{
    LogName='System'
    Level=1,2
    StartTime=(Get-Date).AddHours(-24)
} | Group-Object ProviderName |
    Sort-Object Count -Descending |
    Format-Table Count, Name
```

---

### Issue 4: High CPU/Memory Usage

**Symptom:** CPU >80% or Memory >90%

**Solutions:**

```powershell
# Top CPU processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 |
    Format-Table Name, CPU, WS -AutoSize

# Top memory processes
Get-Process | Sort-Object WS -Descending | Select-Object -First 10 |
    Format-Table Name, @{L='MemoryMB';E={[math]::Round($_.WS/1MB,2)}} -AutoSize

# Check for runaway processes
# If found, consider:
Stop-Process -Name <ProcessName> -Force  # Last resort
```

---

### Issue 5: No Internet Connectivity

**Symptom:** Internet connectivity check fails

**Solutions:**

```powershell
# Check network adapters
Get-NetAdapter | Where-Object {$_.Status -eq "Up"}

# Check IP configuration
Get-NetIPAddress -AddressFamily IPv4

# Check default gateway
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0"

# Test connectivity steps
Test-Connection 127.0.0.1  # Loopback (should work)
Test-Connection 192.168.1.1  # Gateway (if known)
Test-Connection 8.8.8.8  # Internet
Resolve-DnsName www.google.com  # DNS

# Reset network if needed
netsh winsock reset
netsh int ip reset
ipconfig /release
ipconfig /renew
ipconfig /flushdns
```

---

## Best Practices

### 1. Run After Full Deployment

```
Deployment Order:
Phase 1-6: Configure system
Phase 7: Validate ← Run health check HERE
```

**Why:**
- System fully configured
- All changes applied
- Final validation before handoff
- Baseline health established

---

### 2. Review Reports Regularly

```
Immediate: After each deployment
Daily: First week of deployment
Weekly: Spot checks (10% of fleet)
Monthly: Full fleet health scan
```

---

### 3. Set Realistic Expectations

```
100% Health:    ✅ Excellent (rare)
95%+ Health:    ✅ Very Good
90%+ Health:    ✅ Good
85-89% Health:  ⚠️ Acceptable (investigate warnings)
<85% Health:    ❌ Needs attention
```

---

### 4. Prioritize Critical Issues

```
Priority 1 (Critical): Fix immediately
- Disk critically low (<20 GB C:\)
- Critical service stopped
- No network connectivity
- Hardware failure predicted

Priority 2 (Warning): Fix soon
- Disk space warning
- High event log errors
- Performance warnings

Priority 3 (Informational): Monitor
- Uptime
- Temperature (if normal)
```

---

## Summary

### What You Have

✅ **Comprehensive System Health Validation**
- 6 health categories
- 40+ individual checks
- Disk space monitoring
- Service validation (11 services)
- Event log scanning (24 hours)
- Performance metrics (CPU, memory, disk)
- Hardware health checks
- Network connectivity tests
- HTML health reports
- Health score calculation

### From Orchestration Config

```
Task: VAL-003 (System Health Check)
Categories: Disk, Services, Events, Performance
Report: HTML in C:\ProgramData\HealthReports\
Critical: NO (non-blocking)
```

### Benefits

**For Deployment:**
- ✅ Final quality check
- ✅ Validates system readiness
- ✅ Catches configuration issues
- ✅ Establishes baseline

**For Operations:**
- ✅ Health monitoring
- ✅ Proactive issue detection
- ✅ Trend analysis
- ✅ Performance tracking

**For Users:**
- ✅ Stable system
- ✅ Good performance
- ✅ Reliable services
- ✅ Network connectivity

### Current Status

🟢 **Enabled in orchestration** (VAL-003) - Ready  
🟢 **Production-ready** - 6 categories, 40+ checks  
🟢 **Non-critical task** - Won't block deployment  
🟢 **HTML reporting** - Professional health reports  
🟢 **Health scoring** - Percentage-based evaluation  
🟢 **Complete documentation** - Everything explained  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

**END OF DOCUMENTATION**
