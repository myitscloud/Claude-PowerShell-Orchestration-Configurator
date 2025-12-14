# TEMPORARY FILES CLEANUP - DOCUMENTATION

## Overview

Comprehensive guide for **Cleanup-TempFiles.ps1** — removing temporary files and deployment artifacts after Windows 11 deployment completion.

**Script Location:** `Phase7-Validation\Cleanup-TempFiles.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## Quick Start

### Basic Usage

```powershell
# Standard cleanup (safe defaults)
.\Cleanup-TempFiles.ps1

# Clean Windows temp and empty recycle bin
.\Cleanup-TempFiles.ps1 -CleanWindowsTemp $true -EmptyRecycleBin $true

# Include user temp files
.\Cleanup-TempFiles.ps1 -CleanUserTemp $true

# Aggressive cleanup (includes updates)
.\Cleanup-TempFiles.ps1 -CleanUpdateCache $true

# Remove old logs
.\Cleanup-TempFiles.ps1 -RemoveOldLogs $true -LogRetentionDays 7

# Test without removing
.\Cleanup-TempFiles.ps1 -DryRun
```

---

## What It Does

Removes temporary files and reclaims disk space:

- ✅ **Deployment Cache** - Removes deployment script cache
- ✅ **Windows Temp** - Cleans C:\Windows\Temp
- ✅ **User Temp** - Cleans user temporary files (optional)
- ✅ **Recycle Bin** - Empties recycle bin
- ✅ **Update Cache** - Cleans Windows Update downloads (optional)
- ✅ **Old Logs** - Removes logs older than X days (optional)
- ✅ **Safe Operation** - Never removes system/user files
- ✅ **Space Reporting** - Reports MB freed

---

## Configuration from Orchestration

```powershell
TaskID: VAL-006 (Clean Up Temporary Files - FINAL TASK!)
Parameters = @{
    RemoveLocalCache = $true
    CleanWindowsTemp = $true
    CleanUserTemp = $false      # Preserves user data
    EmptyRecycleBin = $true
}
```

### What Gets Cleaned

**1. Deployment Cache (Enabled)**
```
Path: C:\DeploymentCache\*
Content: Downloaded deployment files, installers
Size: Typically 500 MB - 2 GB
Safe: YES - no longer needed after deployment

Preserves:
- C:\DeploymentScripts\ (kept for troubleshooting)
- Orchestration logs (kept for audit trail)
```

**2. Windows Temporary Files (Enabled)**
```
Path: C:\Windows\Temp\*
Content: System temporary files, installation remnants
Size: Typically 100 MB - 1 GB
Safe: YES - Windows recreates as needed

Also Cleans:
- System temp directory
- Installation temp files
- Setup logs (temporary)
```

**3. User Temporary Files (Disabled by Default)**
```
Path: C:\Users\*\AppData\Local\Temp\*
Content: User application temp files
Size: Varies (50 MB - 500 MB per user)
Safe: YES but may remove user-specific temp data

Why Disabled:
- May remove user browser cache
- May remove application temp data
- User preferences may be affected
- Best left for user control

When to Enable:
- Shared workstations
- Kiosk mode
- Known temp file issues
```

**4. Recycle Bin (Enabled)**
```
Content: Deleted files in recycle bin
Size: Varies widely (0 MB - 10+ GB)
Safe: YES - files already deleted by user

Why Clean:
- Reclaims space from deleted items
- Standard post-deployment cleanup
- Users can delete before handoff if needed
```

**5. Windows Update Cache (Disabled by Default)**
```
Path: C:\Windows\SoftwareDistribution\Download\*
Content: Downloaded Windows updates
Size: 500 MB - 5 GB
Safe: YES but updates need re-download if needed

Why Disabled:
- Updates may need to be reinstalled
- Requires re-downloading updates
- Network bandwidth impact
- Only clean if space critical

When to Enable:
- Disk space critically low
- Updates fully installed and verified
- After major Windows update
```

**6. Old Logs (Disabled by Default)**
```
Path: C:\ProgramData\OrchestrationLogs\*.log
Content: Old orchestration logs
Size: 10 MB - 100 MB
Retention: 30 days (configurable)

Why Disabled:
- Logs useful for troubleshooting
- Minimal space usage
- Audit trail value
- Compliance may require retention

When to Enable:
- After deployment validation complete
- Logs archived elsewhere
- Space is critical
```

---

## Cleanup Categories

### Safe Cleanup (Default Configuration)

```powershell
RemoveLocalCache = $true     # Deployment files (not needed)
CleanWindowsTemp = $true     # Windows temp (safe)
CleanUserTemp = $false       # Preserve user data
EmptyRecycleBin = $true      # Already deleted files
CleanUpdateCache = $false    # Keep updates
RemoveOldLogs = $false       # Keep for troubleshooting
```

**Expected Space Freed:** 500 MB - 2 GB  
**Risk Level:** Low  
**User Impact:** None

---

### Aggressive Cleanup (Maximum Space)

```powershell
RemoveLocalCache = $true
CleanWindowsTemp = $true
CleanUserTemp = $true        # ⚠ User data
EmptyRecycleBin = $true
CleanUpdateCache = $true     # ⚠ Re-download needed
RemoveOldLogs = $true        # ⚠ Lose audit trail
LogRetentionDays = 7
```

**Expected Space Freed:** 2 GB - 10+ GB  
**Risk Level:** Medium  
**User Impact:** Possible (temp files, updates)

**When to Use:**
- Disk space critically low (<20 GB free)
- All deployment validation complete
- Logs archived elsewhere
- Users not yet on system

---

## Safety Features

### What Will NEVER Be Removed

```
✓ System files (Windows, Program Files)
✓ User documents (Desktop, Documents, Downloads, Pictures)
✓ Application data (AppData\Roaming, AppData\Local except Temp)
✓ Registry settings
✓ Installed applications
✓ Current orchestration logs (this run)
✓ Deployment scripts (C:\DeploymentScripts - kept for troubleshooting)
```

### Locked File Handling

```
If file is locked (in use):
→ Skip file gracefully
→ Log as debug message
→ Continue cleanup
→ No errors generated

Example:
- Chrome.exe using cache files → Skip
- Service using temp file → Skip
- User file open → Skip
```

---

## Typical Space Freed

### Fresh Deployment

```
Deployment Cache:         500 MB - 1.5 GB
Windows Temp:            100 MB - 500 MB
Recycle Bin:               0 MB - 100 MB
User Temp (optional):     50 MB - 200 MB per user
Update Cache (optional): 500 MB - 5 GB
Old Logs (optional):      10 MB - 50 MB
-------------------------------------------
Total (Standard):        600 MB - 2 GB
Total (Aggressive):      2 GB - 7+ GB
```

---

## Running the Script

### Method 1: Via SCCM (Production)

```
Step Type: Run PowerShell Script
Script: Cleanup-TempFiles.ps1
Run as: SYSTEM
Success Codes: 0
Timeout: 600 seconds

Runs as LAST task in deployment (VAL-006)
```

---

### Method 2: Via PsExec (Manual)

```powershell
# Launch SYSTEM PowerShell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# Run cleanup
cd C:\DeploymentScripts\Phase7-Validation
.\Cleanup-TempFiles.ps1

# Check space freed
$CDrive = Get-PSDrive C
Write-Host "C:\ Free: $([math]::Round($CDrive.Free/1GB,2)) GB"
```

---

### Method 3: As Admin (Testing)

```powershell
# Run as administrator
.\Cleanup-TempFiles.ps1

# Dry run first (recommended)
.\Cleanup-TempFiles.ps1 -DryRun
```

---

## Verification

### Before Cleanup

```powershell
# Check current space
Get-PSDrive C | Select-Object @{N='Free(GB)';E={[math]::Round($_.Free/1GB,2)}},
                             @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}

# Check folder sizes
Get-ChildItem C:\Windows\Temp | Measure-Object -Property Length -Sum
Get-ChildItem C:\DeploymentCache -Recurse -File -ErrorAction SilentlyContinue | 
    Measure-Object -Property Length -Sum
```

---

### After Cleanup

```powershell
# Verify space freed
Get-PSDrive C | Select-Object @{N='Free(GB)';E={[math]::Round($_.Free/1GB,2)}}

# Check cleanup log
Get-Content "C:\ProgramData\OrchestrationLogs\Cleanup-TempFiles_*.log" | 
    Select-String "Space Freed"

# Verify folders cleaned
Test-Path "C:\DeploymentCache\*"  # Should be minimal/empty
Test-Path "C:\Windows\Temp\*"     # Should have few items
```

---

## Troubleshooting

### Issue 1: Minimal Space Freed

**Symptom:** Cleanup reports <100 MB freed

**Cause:** Not much to clean (good!)

**Check:**

```powershell
# Check temp folder sizes
$WindowsTemp = Get-ChildItem C:\Windows\Temp -Recurse -File -ErrorAction SilentlyContinue | 
    Measure-Object -Property Length -Sum
Write-Host "Windows Temp: $([math]::Round($WindowsTemp.Sum/1MB,2)) MB"

$DeployCache = Get-ChildItem C:\DeploymentCache -Recurse -File -ErrorAction SilentlyContinue | 
    Measure-Object -Property Length -Sum
Write-Host "Deployment Cache: $([math]::Round($DeployCache.Sum/1MB,2)) MB"

# If both small, cleanup working correctly
```

---

### Issue 2: "Access Denied" Errors

**Symptom:** Cannot remove some files

**Cause:** Files locked by processes or permissions

**Solutions:**

```powershell
# Ensure running as SYSTEM or Administrator
whoami
# Expected: NT AUTHORITY\SYSTEM or BUILTIN\Administrator

# Check file locks (requires admin)
Get-SmbOpenFile | Where-Object Path -like "C:\Windows\Temp\*"

# Retry after reboot if needed
# (Files may be locked by services)
```

---

### Issue 3: Still Low Disk Space

**Symptom:** Still <20 GB free after cleanup

**Additional Actions:**

```powershell
# Run Windows Disk Cleanup utility
cleanmgr /d C: /verylowdisk

# Check large folders
Get-ChildItem C:\ -Directory | ForEach-Object {
    $Size = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | 
        Measure-Object -Property Length -Sum).Sum
    [PSCustomObject]@{
        Folder = $_.FullName
        SizeGB = [math]::Round($Size/1GB,2)
    }
} | Sort-Object SizeGB -Descending | Select-Object -First 10

# Consider:
# - Enabling CleanUpdateCache = $true
# - Enabling CleanUserTemp = $true
# - Manual review of large folders
# - Expanding C:\ drive
```

---

### Issue 4: Update Service Won't Start

**Symptom:** Windows Update service fails to start after cleanup

**Cause:** Update cache cleaned while service starting

**Solution:**

```powershell
# Stop service completely
Stop-Service wuauserv -Force
Start-Sleep -Seconds 5

# Start service
Start-Service wuauserv

# Verify
Get-Service wuauserv

# Reset Windows Update components if needed
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver

net start wuauserv
net start cryptSvc
net start bits
net start msiserver
```

---

## Best Practices

### 1. Run as Last Deployment Task

```
Deployment Order (Critical):
Phase 1-6: Configure system
Phase 7: Validate system
  - VAL-001: Security compliance ✓
  - VAL-002: Application validation ✓
  - VAL-003: System health ✓
  - VAL-004: Generate report ✓
  - VAL-005: Trigger SCCM inventory ✓
  - VAL-006: Cleanup temp files ← RUN LAST!

Why Last:
✓ All other tasks complete
✓ No more file creation
✓ Maximum cleanup possible
✓ Clean system handoff
```

---

### 2. Use Safe Defaults

```powershell
# Recommended configuration
RemoveLocalCache = $true     # Safe
CleanWindowsTemp = $true     # Safe
CleanUserTemp = $false       # Preserve user data (safe)
EmptyRecycleBin = $true      # Safe
CleanUpdateCache = $false    # Keep updates (safe)
RemoveOldLogs = $false       # Keep audit trail (safe)
```

**Benefits:**
- No user impact
- No re-downloads needed
- Audit trail preserved
- 500 MB - 2 GB space freed

---

### 3. Test with Dry Run First

```powershell
# Always test first
.\Cleanup-TempFiles.ps1 -DryRun

# Review output:
# - Shows what would be removed
# - Reports estimated space freed
# - No actual removal

# Then run for real
.\Cleanup-TempFiles.ps1
```

---

### 4. Keep Deployment Scripts

```
DO NOT REMOVE:
C:\DeploymentScripts\

Why:
- Troubleshooting reference
- Re-run validation scripts
- User support needs
- Audit and compliance

Remove manually after 30-90 days if desired
```

---

## Use Cases

### Use Case 1: Standard Post-Deployment Cleanup

**Scenario:** Normal deployment, reclaim deployment cache space

```powershell
.\Cleanup-TempFiles.ps1 `
    -RemoveLocalCache $true `
    -CleanWindowsTemp $true `
    -EmptyRecycleBin $true
```

**Result:**
- 500 MB - 2 GB freed
- Safe, no user impact
- Standard practice

---

### Use Case 2: Low Disk Space Emergency

**Scenario:** C:\ has <20 GB free, need more space

```powershell
.\Cleanup-TempFiles.ps1 `
    -RemoveLocalCache $true `
    -CleanWindowsTemp $true `
    -CleanUserTemp $true `
    -EmptyRecycleBin $true `
    -CleanUpdateCache $true
```

**Result:**
- 2 GB - 10+ GB freed
- Updates need re-download
- User temp files removed

---

### Use Case 3: Kiosk/Shared Workstation

**Scenario:** Shared PC, clean all user traces

```powershell
.\Cleanup-TempFiles.ps1 `
    -RemoveLocalCache $true `
    -CleanWindowsTemp $true `
    -CleanUserTemp $true `
    -EmptyRecycleBin $true `
    -RemoveOldLogs $true `
    -LogRetentionDays 7
```

**Result:**
- Maximum cleanup
- User data removed
- Fresh start for next user

---

## Summary

### What You Have

✅ **Temporary Files Cleanup**
- Deployment cache removal
- Windows temp cleanup
- User temp cleanup (optional)
- Recycle bin empty
- Update cache cleanup (optional)
- Old log removal (optional)
- Safe operation (never touches system/user files)
- Space reporting (MB freed)
- Dry run testing

### From Orchestration Config

```
Task: VAL-006 (Clean Up Temporary Files - FINAL TASK)
Deployment Cache: Enabled (remove cache)
Windows Temp: Enabled (clean temp)
User Temp: Disabled (preserve user data)
Recycle Bin: Enabled (empty)
Update Cache: Disabled (keep updates)
Old Logs: Disabled (keep audit trail)
```

### Benefits

**For Disk Space:**
- ✅ Reclaims 500 MB - 2 GB typically
- ✅ Removes deployment artifacts
- ✅ Cleans temporary files
- ✅ Empties recycle bin
- ✅ More space for user data

**For System Performance:**
- ✅ Cleaner file system
- ✅ Less clutter
- ✅ Faster disk operations
- ✅ Better search performance

**For Users:**
- ✅ Clean system handoff
- ✅ More available space
- ✅ No deployment artifacts visible
- ✅ Professional appearance

### Expected Results

```
Standard Cleanup:
Before: C:\ has 185 GB free
After:  C:\ has 187 GB free (+2 GB)
Files:  ~500 files removed
Time:   30-60 seconds

Aggressive Cleanup:
Before: C:\ has 185 GB free
After:  C:\ has 192 GB free (+7 GB)
Files:  ~2000 files removed
Time:   1-2 minutes
```

### Current Status

🟢 **Enabled in orchestration** (VAL-006) - **FINAL TASK!**  
🟢 **Production-ready** - Safe defaults  
🟢 **Non-critical task** - Won't block deployment  
🟢 **Safe operation** - Never removes system/user files  
🟢 **Space efficient** - Reclaims 500 MB - 2 GB  
🟢 **Complete documentation** - Everything explained  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

## 🎉 PHASE 7 COMPLETE!

**This is the FINAL task of the Windows 11 deployment!**

All Phase 7 validation tasks complete:
- ✅ VAL-001: Security Compliance Check
- ✅ VAL-002: Application Validation
- ✅ VAL-003: System Health Check
- ✅ VAL-004: Generate Deployment Report
- ✅ VAL-005: Trigger SCCM Inventory
- ✅ VAL-006: Clean Up Temporary Files ← YOU ARE HERE

**Deployment is now complete and ready for handoff!** 🚀

---

**END OF DOCUMENTATION**
