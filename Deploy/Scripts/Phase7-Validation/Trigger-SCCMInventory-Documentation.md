# SCCM INVENTORY TRIGGER - DOCUMENTATION

## Overview

Comprehensive guide for **Trigger-SCCMInventory.ps1** — triggering SCCM/Configuration Manager inventory cycles for immediate data collection and reporting.

**Script Location:** `Phase7-Validation\Trigger-SCCMInventory.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## Quick Start

### Basic Usage

```powershell
# Trigger hardware and software inventory (default)
.\Trigger-SCCMInventory.ps1

# Trigger specific inventory types
.\Trigger-SCCMInventory.ps1 -TriggerHardware $true -TriggerSoftware $true

# Trigger and wait for completion
.\Trigger-SCCMInventory.ps1 -WaitForCompletion $true

# Trigger all inventory types
.\Trigger-SCCMInventory.ps1 -TriggerHardware $true -TriggerSoftware $true -TriggerDiscovery $true

# Test without triggering
.\Trigger-SCCMInventory.ps1 -DryRun
```

---

## What It Does

Triggers SCCM/Configuration Manager inventory cycles:

- ✅ **Hardware Inventory** - System specs, devices, configuration
- ✅ **Software Inventory** - Installed applications, files, versions
- ✅ **Discovery Data** - Network, AD, user information (optional)
- ✅ **Software Metering** - Application usage tracking (optional)
- ✅ **Policy Update** - Retrieves latest SCCM policies
- ✅ **Background Processing** - Inventory collected and sent to SCCM
- ✅ **Optional Wait** - Wait for inventory completion

---

## Configuration from Orchestration

```powershell
TaskID: VAL-005 (Trigger SCCM Inventory)
Parameters = @{
    TriggerHardware = $true
    TriggerSoftware = $true
    WaitForCompletion = $false
}
```

### What This Triggers

**1. Hardware Inventory**
```
Schedule ID: {00000000-0000-0000-0000-000000000001}

Collects:
- Computer manufacturer, model, serial number
- Processor (type, cores, speed)
- Memory (total, available)
- Disk drives (size, free space, type)
- Network adapters (MAC, IP, speed)
- Video cards
- BIOS version
- Operating system details
- Installed devices
- USB devices
- Printers

Why Important:
- Asset management
- Hardware inventory tracking
- Warranty management
- Capacity planning
- Support and troubleshooting

Update Frequency (Typical):
- Default: Every 7 days
- After deployment: Immediate
```

**2. Software Inventory**
```
Schedule ID: {00000000-0000-0000-0000-000000000002}

Collects:
- Installed applications (name, version, publisher)
- Windows updates/patches
- Software files (based on SCCM configuration)
- Application versions
- Installation dates

Why Important:
- Software license compliance
- Application deployment tracking
- Security patch verification
- Software audit trail
- License management

Update Frequency (Typical):
- Default: Every 7 days
- After deployment: Immediate
```

**3. Discovery Data Collection (Optional)**
```
Schedule ID: {00000000-0000-0000-0000-000000000003}

Collects:
- Active Directory information
- Domain membership
- User information
- Network configuration
- Site assignment

Why Important:
- AD synchronization
- Computer object updates
- User device relationships
- Network discovery

Update Frequency:
- Default: Every 24 hours
- Typically not needed after deployment
```

**4. Software Metering (Optional)**
```
Schedule ID: {00000000-0000-0000-0000-000000000010}

Collects:
- Application usage statistics
- Application launch counts
- Usage duration
- User usage patterns

Why Important:
- Software license optimization
- Application usage tracking
- Cost justification
- Removal of unused software

Update Frequency:
- Default: Every 7 days
- Only if metering configured
```

---

## SCCM Inventory Process

### How It Works

**Step 1: Trigger Inventory**
```
Script calls: TriggerSchedule() method
SCCM Client: Receives trigger command
Action: Starts inventory collection process
Duration: < 1 second to trigger
```

**Step 2: Data Collection (Background)**
```
SCCM Client: Scans system for data
Process: ccmexec.exe handles collection
Duration: 2-10 minutes (depends on system)
Location: Data stored in WMI (root\ccm)
```

**Step 3: Reporting to SCCM Server**
```
SCCM Client: Compiles inventory report
Transmission: Sends to Management Point
Process: Background, queued if offline
Duration: 5-15 minutes to reach server
```

**Step 4: SCCM Server Processing**
```
Management Point: Receives inventory data
Site Server: Processes and updates database
SCCM Console: Updated inventory visible
Duration: 5-30 minutes total from trigger
```

**Total Timeline:**
```
Trigger:     00:00 (instant)
Collection:  00:01 - 10:00 (background)
Upload:      10:00 - 20:00 (background)
Processing:  20:00 - 30:00 (server-side)
Visible:     30:00+ (SCCM console updated)
```

---

## Why Trigger Inventory After Deployment

### Immediate Benefits

**1. Asset Management**
```
Without Trigger:
- Wait 7 days for next scheduled inventory
- New PC not in SCCM inventory
- No visibility for 1 week

With Trigger:
- Inventory updated within 30 minutes
- New PC visible immediately
- Accurate asset tracking from day 1
```

**2. Software Compliance**
```
Without Trigger:
- Installed apps not reported
- License compliance delayed
- Audit gaps for 7 days

With Trigger:
- All apps reported immediately
- License compliance validated
- Complete audit trail
```

**3. Configuration Validation**
```
Without Trigger:
- Hardware specs unknown
- Configuration drift possible
- Support limitations

With Trigger:
- Full hardware specs known
- Configuration validated
- Support ready
```

**4. Collections & Targeting**
```
Without Trigger:
- Device not in collections
- Cannot target for updates
- Missed deployments possible

With Trigger:
- Device added to collections
- Update targeting active
- All deployments available
```

---

## Running the Script

### Method 1: Via SCCM (Production)

```
Step Type: Run PowerShell Script
Script: Trigger-SCCMInventory.ps1
Run as: SYSTEM
Success Codes: 0
Timeout: 300 seconds

Runs at end of task sequence (Phase 7)
```

---

### Method 2: Via PsExec (Manual)

```powershell
# Launch SYSTEM PowerShell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# Run inventory trigger
cd C:\DeploymentScripts\Phase7-Validation
.\Trigger-SCCMInventory.ps1

# Check SCCM client service
Get-Service CcmExec

# View last inventory dates
Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus"
```

---

### Method 3: As Admin (Testing)

```powershell
# Run as administrator
.\Trigger-SCCMInventory.ps1 -TriggerHardware $true -TriggerSoftware $true

# Check result in SCCM console after 15-30 minutes
```

---

## Configuration Options

### Standard Configuration (Recommended)

```powershell
TriggerHardware = $true      # Collect hardware inventory
TriggerSoftware = $true      # Collect software inventory
TriggerDiscovery = $false    # Not needed after deployment
TriggerSoftwareMetering = $false  # Only if metering enabled
WaitForCompletion = $false   # Don't wait (background)
```

**Why This Configuration:**
- Hardware and software are critical post-deployment
- Discovery runs automatically (not needed)
- Software metering only if configured
- No waiting (inventory completes in background)

---

### Wait for Completion (Slower but Verified)

```powershell
TriggerHardware = $true
TriggerSoftware = $true
WaitForCompletion = $true    # Wait for completion
CompletionTimeout = 180      # 3 minutes max wait
```

**When to Use:**
- Testing/validation scenarios
- Need confirmation of completion
- Troubleshooting inventory issues

**Trade-off:**
- Adds 3+ minutes to deployment time
- Inventory still completes in background even without waiting

---

### All Inventory Types (Comprehensive)

```powershell
TriggerHardware = $true
TriggerSoftware = $true
TriggerDiscovery = $true
TriggerSoftwareMetering = $true
```

**When to Use:**
- Initial deployment
- Major system changes
- Comprehensive data collection needed

---

## Verification

### Check Inventory Was Triggered

```powershell
# View last inventory dates
Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus" | 
    Select-Object InventoryActionID, 
                  @{Name="LastRun";Expression={[Management.ManagementDateTimeConverter]::ToDateTime($_.LastCycleStartedDate)}} |
    Format-Table -AutoSize

# Expected output:
# InventoryActionID                      LastRun
# -----------------                      -------
# {00000000-0000-0000-0000-000000000001} 2024-12-09 15:30:00  (Hardware)
# {00000000-0000-0000-0000-000000000002} 2024-12-09 15:30:15  (Software)
```

---

### Check SCCM Client Service

```powershell
# Check service status
Get-Service CcmExec | Format-List *

# Expected:
# Status: Running
# StartType: Automatic
```

---

### Check in SCCM Console (15-30 minutes later)

```
1. Open Configuration Manager Console
2. Navigate to: Assets and Compliance > Devices
3. Find computer by name
4. Right-click > Start > Hardware Inventory
5. View Properties > Hardware tab
6. Verify "Last Hardware Scan" shows recent timestamp
```

---

## Troubleshooting

### Issue 1: SCCM Client Not Installed

**Symptom:** "SCCM client not installed on this system"

**Cause:** ConfigMgr client not installed or service not running

**Solutions:**

```powershell
# Check for CCMExec service
Get-Service CcmExec -ErrorAction SilentlyContinue

# If not found, client not installed:
# Install SCCM client from:
\\SCCM-Server\SMS_XYZ\Client\ccmsetup.exe

# Or check with SCCM team
```

---

### Issue 2: SCCM Service Not Running

**Symptom:** Service exists but not running

**Solutions:**

```powershell
# Start service
Start-Service CcmExec

# Set to automatic
Set-Service CcmExec -StartupType Automatic

# Check status
Get-Service CcmExec
```

---

### Issue 3: Inventory Trigger Fails

**Symptom:** "Failed to trigger inventory (Return code: X)"

**Solutions:**

```powershell
# Check WMI
Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client"

# Repair WMI if needed
winmgmt /salvagerepository
winmgmt /resetrepository

# Restart SCCM service
Restart-Service CcmExec

# Retry inventory
.\Trigger-SCCMInventory.ps1
```

---

### Issue 4: Inventory Not Appearing in SCCM

**Symptom:** Inventory triggered but not showing in console after 30+ minutes

**Solutions:**

```powershell
# Check SCCM site assignment
Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority"

# Check management point connectivity
Test-Connection -ComputerName <ManagementPoint>

# Check pending inventory upload
Get-WmiObject -Namespace "root\ccm\invagt" -Class "InventoryActionStatus" |
    Select-Object InventoryActionID, LastReportDate, LastUpdateDate

# Force policy retrieval
Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" `
    -ArgumentList "{00000000-0000-0000-0000-000000000021}"

# Check client logs (if accessible):
# C:\Windows\CCM\Logs\InventoryAgent.log
# C:\Windows\CCM\Logs\DataTransferService.log
```

---

### Issue 5: Slow Inventory Collection

**Symptom:** WaitForCompletion times out

**Explanation:** This is normal!

```
Collection Time Varies:
- Fast system: 2-5 minutes
- Average system: 5-10 minutes  
- Slow/large system: 10-20 minutes

Timeout of 3 minutes may not be enough
```

**Solutions:**

```powershell
# Option 1: Increase timeout
.\Trigger-SCCMInventory.ps1 -WaitForCompletion $true -CompletionTimeout 600

# Option 2: Don't wait (recommended)
.\Trigger-SCCMInventory.ps1 -WaitForCompletion $false
# Inventory completes in background, no waiting needed
```

---

## Best Practices

### 1. Always Run After Deployment

```
Deployment Flow:
Phase 1-6: Configure system
Phase 7: Validate system
VAL-005: Trigger SCCM Inventory ← Run HERE

Why:
- All changes applied
- Configuration final
- Inventory reflects actual state
```

---

### 2. Don't Wait for Completion

```powershell
WaitForCompletion = $false  # Recommended
```

**Reasons:**
- Inventory completes in background reliably
- No delay in deployment completion
- 3-minute wait adds unnecessary time
- Result is the same (inventory reported to SCCM)

---

### 3. Trigger Hardware and Software Only

```powershell
TriggerHardware = $true
TriggerSoftware = $true
TriggerDiscovery = $false       # Runs automatically
TriggerSoftwareMetering = $false # Only if configured
```

**Reasons:**
- Hardware and software are post-deployment critical
- Discovery runs on schedule automatically
- Software metering only if organization uses it

---

### 4. Verify in SCCM Console

```
After Deployment:
1. Wait 30 minutes
2. Check SCCM console
3. Verify device appears
4. Check inventory timestamp
5. Validate hardware/software data
```

---

## Use Cases

### Use Case 1: Standard Deployment (Recommended)

**Scenario:** End of deployment, update SCCM inventory

```powershell
.\Trigger-SCCMInventory.ps1 `
    -TriggerHardware $true `
    -TriggerSoftware $true `
    -WaitForCompletion $false
```

**Result:**
- Hardware inventory triggered
- Software inventory triggered
- Script completes immediately
- Inventory reports in background
- SCCM updated in 15-30 minutes

---

### Use Case 2: Verification Deployment

**Scenario:** Need to verify inventory completed before finishing

```powershell
.\Trigger-SCCMInventory.ps1 `
    -TriggerHardware $true `
    -TriggerSoftware $true `
    -WaitForCompletion $true `
    -CompletionTimeout 300
```

**Result:**
- Inventories triggered
- Script waits up to 5 minutes
- Confirmation of collection
- Longer deployment time

---

### Use Case 3: Comprehensive Inventory

**Scenario:** Collect all available inventory data

```powershell
.\Trigger-SCCMInventory.ps1 `
    -TriggerHardware $true `
    -TriggerSoftware $true `
    -TriggerDiscovery $true `
    -TriggerSoftwareMetering $true
```

**Result:**
- All inventory types triggered
- Complete data collection
- Comprehensive SCCM update

---

## SCCM Schedule IDs Reference

### Standard Inventory

```
Hardware Inventory:
{00000000-0000-0000-0000-000000000001}
Default: Every 7 days

Software Inventory:
{00000000-0000-0000-0000-000000000002}
Default: Every 7 days

Discovery Data:
{00000000-0000-0000-0000-000000000003}
Default: Every 24 hours

Software Metering:
{00000000-0000-0000-0000-000000000010}
Default: Every 7 days (if enabled)
```

### Policy Cycles

```
Machine Policy Retrieval:
{00000000-0000-0000-0000-000000000021}
Retrieves latest policies from SCCM

Machine Policy Evaluation:
{00000000-0000-0000-0000-000000000022}
Applies retrieved policies
```

---

## Summary

### What You Have

✅ **SCCM Inventory Trigger**
- Hardware inventory collection
- Software inventory collection
- Discovery data (optional)
- Software metering (optional)
- Background processing
- Policy updates
- Optional completion wait
- Comprehensive verification

### From Orchestration Config

```
Task: VAL-005 (Trigger SCCM Inventory)
Hardware: Enabled (system specs)
Software: Enabled (applications)
Wait: Disabled (background processing)
```

### Benefits

**For SCCM Management:**
- ✅ Immediate inventory update
- ✅ Accurate asset tracking
- ✅ Current software inventory
- ✅ Collection membership updated
- ✅ Deployment targeting enabled

**For Compliance:**
- ✅ Software license tracking
- ✅ Hardware asset tracking
- ✅ Audit trail from day 1
- ✅ Configuration validation

**For Support:**
- ✅ Complete hardware specs
- ✅ Installed software list
- ✅ System configuration known
- ✅ Troubleshooting baseline

### Timeline

```
00:00 - Trigger inventory (instant)
00:01 - Collection starts (background)
10:00 - Collection complete
15:00 - Upload to SCCM (background)
30:00 - SCCM console updated ✓
```

### Current Status

🟢 **Enabled in orchestration** (VAL-005) - Ready  
🟢 **Production-ready** - 4 inventory types  
🟢 **Non-critical task** - Won't block deployment  
🟢 **Background processing** - No wait required  
🟢 **Policy updates** - Latest SCCM policies  
🟢 **Complete documentation** - Everything explained  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

**END OF DOCUMENTATION**
