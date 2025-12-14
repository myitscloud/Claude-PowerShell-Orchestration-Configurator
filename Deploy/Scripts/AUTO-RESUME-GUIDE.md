# 🎯 Orchestration-Master.ps1 - Auto-Resume Guide

## 📋 **IMPORTANT DISCOVERY!**

Your "no-resume" file **ALREADY HAS FULL AUTO-RESUME CAPABILITY!** It was just misnamed. This is actually the production version with all resume features included.

---

## ✅ **What You Have:**

### **File: Orchestration-Master.ps1 (v2.1.0)**

**Full Auto-Resume Capability:**
- ✅ Scheduled task creation
- ✅ Checkpoint saving/loading
- ✅ Automatic resume after reboot
- ✅ Runs as SYSTEM
- ✅ No login required
- ✅ Self-cleanup on completion

---

## 🔧 **How Auto-Resume Works:**

### **Step 1: Initial Run**

When you start orchestration for the first time:

```powershell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe
cd C:\Deploy\Scripts
.\Orchestration-Master.ps1
```

**What happens:**
1. Script detects this is INITIAL RUN (not resume)
2. Creates scheduled task: "OrchestrationAutoResume"
   - **Trigger:** At system startup (before login!)
   - **User:** SYSTEM account
   - **Action:** Run `Orchestration-Master.ps1 -Resume`
3. Begins executing Phase 1

---

### **Step 2: Checkpoint Saved**

Before any reboot:

```
Phase 1 completes → Needs reboot
    ↓
Save-Checkpoint called:
    - Current phase: Phase1
    - Completed tasks: [list]
    - Reboot count: 1
    - Timestamp
    ↓
Checkpoint saved to: C:\ProgramData\OrchestrationLogs\Checkpoint.xml
    ↓
Reboot initiated
```

---

### **Step 3: Auto-Resume After Reboot**

System reboots and resumes **automatically**:

```
Windows boots
    ↓
System startup (before login screen)
    ↓
Scheduled task "OrchestrationAutoResume" triggers
    ↓
PowerShell.exe -File Orchestration-Master.ps1 -Resume
    ↓
Script detects -Resume parameter
    ↓
Load-Checkpoint reads saved state
    ↓
Continues from Phase 2 (NO LOGIN REQUIRED!)
```

---

### **Step 4: Completion**

When all phases complete:

```
Phase 7 finishes
    ↓
Unregister-AutoResumeTask called
    ↓
Scheduled task removed
    ↓
Checkpoint file deleted
    ↓
Orchestration complete!
```

---

## 🎯 **Why You Need to Login Currently:**

Based on our conversation, you said you still need to login after reboots. Here's why:

### **Possible Reason #1: Task Creation Failed**

```powershell
# Check if task was created:
Get-ScheduledTask -TaskName "OrchestrationAutoResume"

# If not found, task creation failed
# Common causes:
# - Not running as admin/SYSTEM
# - Permissions issue
# - Task was disabled
```

### **Possible Reason #2: Task Exists But Not Triggering**

```powershell
# Check task details:
$Task = Get-ScheduledTask -TaskName "OrchestrationAutoResume"
$Task.Triggers  # Should show: Trigger=Startup
$Task.Principal  # Should show: UserId=SYSTEM
$Task.State      # Should show: Ready (not Disabled)

# Check if task ran:
Get-ScheduledTask -TaskName "OrchestrationAutoResume" | Get-ScheduledTaskInfo
# Check LastRunTime and LastTaskResult
```

### **Possible Reason #3: Checkpoint Not Saving**

```powershell
# Check if checkpoint exists:
Test-Path "C:\ProgramData\OrchestrationLogs\Checkpoint.xml"

# View checkpoint:
[xml]$Checkpoint = Get-Content "C:\ProgramData\OrchestrationLogs\Checkpoint.xml"
$Checkpoint.Checkpoint

# Should show:
# - CompletedTasks
# - RebootCount
# - LastUpdate
```

---

## 🔍 **Troubleshooting Auto-Resume:**

### **Diagnostic Script:**

Run this to check auto-resume status:

```powershell
Write-Host "`n=== AUTO-RESUME DIAGNOSTIC ===" -ForegroundColor Cyan

# 1. Check scheduled task
Write-Host "`n1. Checking Scheduled Task..." -ForegroundColor Yellow
$Task = Get-ScheduledTask -TaskName "OrchestrationAutoResume" -ErrorAction SilentlyContinue

if ($Task) {
    Write-Host "   ✅ Task EXISTS" -ForegroundColor Green
    Write-Host "   State: $($Task.State)" -ForegroundColor Cyan
    Write-Host "   Trigger: $($Task.Triggers[0].CimClass.CimClassName)" -ForegroundColor Cyan
    Write-Host "   User: $($Task.Principal.UserId)" -ForegroundColor Cyan
    
    # Check if enabled
    if ($Task.State -eq "Ready") {
        Write-Host "   ✅ Task is ENABLED" -ForegroundColor Green
    }
    else {
        Write-Host "   ❌ Task is DISABLED - Enable it!" -ForegroundColor Red
    }
    
    # Check last run
    $TaskInfo = Get-ScheduledTaskInfo -TaskName "OrchestrationAutoResume"
    Write-Host "   Last Run: $($TaskInfo.LastRunTime)" -ForegroundColor Cyan
    Write-Host "   Last Result: $($TaskInfo.LastTaskResult)" -ForegroundColor Cyan
}
else {
    Write-Host "   ❌ Task NOT FOUND" -ForegroundColor Red
    Write-Host "   Solution: Run Orchestration-Master.ps1 as SYSTEM" -ForegroundColor Yellow
}

# 2. Check checkpoint file
Write-Host "`n2. Checking Checkpoint File..." -ForegroundColor Yellow
$CheckpointPath = "C:\ProgramData\OrchestrationLogs\Checkpoint.xml"

if (Test-Path $CheckpointPath) {
    Write-Host "   ✅ Checkpoint EXISTS" -ForegroundColor Green
    $Checkpoint = [xml](Get-Content $CheckpointPath)
    Write-Host "   Completed Tasks: $($Checkpoint.Checkpoint.CompletedTasks.Task.Count)" -ForegroundColor Cyan
    Write-Host "   Reboot Count: $($Checkpoint.Checkpoint.RebootCount)" -ForegroundColor Cyan
    Write-Host "   Last Update: $($Checkpoint.Checkpoint.LastUpdate)" -ForegroundColor Cyan
}
else {
    Write-Host "   ❌ Checkpoint NOT FOUND" -ForegroundColor Red
    Write-Host "   This is normal if orchestration hasn't started yet" -ForegroundColor Yellow
}

# 3. Check if running as SYSTEM
Write-Host "`n3. Checking Current User..." -ForegroundColor Yellow
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "   Current User: $CurrentUser" -ForegroundColor Cyan

if ($CurrentUser -eq "NT AUTHORITY\SYSTEM") {
    Write-Host "   ✅ Running as SYSTEM" -ForegroundColor Green
}
else {
    Write-Host "   ⚠️  NOT running as SYSTEM" -ForegroundColor Yellow
    Write-Host "   For best results, use PsExec64 to run as SYSTEM" -ForegroundColor Yellow
}

# 4. Check orchestration log
Write-Host "`n4. Checking Recent Logs..." -ForegroundColor Yellow
$LogPath = "C:\ProgramData\OrchestrationLogs"
$LatestLog = Get-ChildItem $LogPath -Filter "Orchestration_*.log" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1

if ($LatestLog) {
    Write-Host "   Latest log: $($LatestLog.Name)" -ForegroundColor Cyan
    Write-Host "   Last modified: $($LatestLog.LastWriteTime)" -ForegroundColor Cyan
    
    # Check for resume mentions
    $LogContent = Get-Content $LatestLog.FullName | Select-String -Pattern "resume|checkpoint|scheduled task" -CaseSensitive:$false
    if ($LogContent) {
        Write-Host "`n   Resume-related log entries:" -ForegroundColor Yellow
        $LogContent | Select-Object -First 5 | ForEach-Object {
            Write-Host "   $_" -ForegroundColor Gray
        }
    }
}
else {
    Write-Host "   ⚠️  No logs found" -ForegroundColor Yellow
}

Write-Host "`n=== END DIAGNOSTIC ===`n" -ForegroundColor Cyan
```

---

## ✅ **How to Enable Auto-Resume (If Not Working):**

### **Method 1: Run as SYSTEM (Recommended)**

```powershell
# Run PowerShell as SYSTEM
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# Verify you're SYSTEM
whoami
# Should show: nt authority\system

# Run orchestration
cd C:\Deploy\Scripts
.\Orchestration-Master.ps1

# Task will be created automatically!
```

---

### **Method 2: Manually Create Task (If Method 1 Fails)**

```powershell
# Run as Administrator (not SYSTEM)
$TaskName = "OrchestrationAutoResume"
$ScriptPath = "C:\Deploy\Scripts\Orchestration-Master.ps1"

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create action
$Action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -Resume"

# Create trigger (AT STARTUP - this is critical!)
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Create settings
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4)

# Create principal (RUN AS SYSTEM - this is critical!)
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Register task
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Description "Auto-resume orchestration after reboot" `
    -Force

Write-Host "`n✅ Scheduled task created!" -ForegroundColor Green
Write-Host "Task will run at STARTUP as SYSTEM" -ForegroundColor Cyan

# Verify task
Get-ScheduledTask -TaskName $TaskName | Format-List
```

---

### **Method 3: Enable Existing Task**

If task exists but is disabled:

```powershell
# Check task state
$Task = Get-ScheduledTask -TaskName "OrchestrationAutoResume"
Write-Host "Current State: $($Task.State)"

# Enable if disabled
if ($Task.State -ne "Ready") {
    Enable-ScheduledTask -TaskName "OrchestrationAutoResume"
    Write-Host "✅ Task enabled!" -ForegroundColor Green
}
```

---

## 🧪 **Testing Auto-Resume:**

### **Full Test Procedure:**

```powershell
# 1. Clean slate
Unregister-ScheduledTask -TaskName "OrchestrationAutoResume" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\OrchestrationLogs\Checkpoint.xml" -Force -ErrorAction SilentlyContinue

# 2. Start orchestration as SYSTEM
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe
cd C:\Deploy\Scripts
.\Orchestration-Master.ps1 -Phase Phase1

# 3. Wait for Phase 1 to complete and reboot

# 4. After reboot - DON'T LOGIN!
# Just wait at login screen for 1-2 minutes

# 5. Then login and check:
Get-Content "C:\ProgramData\OrchestrationLogs\Orchestration_*.log" -Tail 20

# Should see:
# [INFO] ORCHESTRATION ENGINE STARTED
# [INFO] Execution Mode: RESUME
# [INFO] Resumed with X completed tasks
# [INFO] Continuing from Phase2...
```

---

## 📊 **Expected vs. Actual Behavior:**

### **✅ Expected (Auto-Resume Working):**

```
Phase 1 → Reboot → Auto-resume Phase 2 → Reboot → Auto-resume Phase 3 → ... → Done
         ↑ NO LOGIN            ↑ NO LOGIN            ↑ NO LOGIN
```

### **❌ Current (Auto-Resume Not Working):**

```
Phase 1 → Reboot → LOGIN → Manually run Phase 2 → Reboot → LOGIN → Manually run Phase 3
         ↑ WAIT           ↑ MANUAL              ↑ WAIT           ↑ MANUAL
```

---

## 🎯 **Key Points:**

1. **Your file HAS auto-resume** - it's not missing the feature
2. **Task must run as SYSTEM** - not your user account
3. **Task must trigger at STARTUP** - not at logon
4. **PsExec64 is recommended** - ensures SYSTEM context
5. **Task creates automatically** - on first run (if running as SYSTEM)

---

## 📋 **Quick Checklist:**

- [ ] Run diagnostic script above
- [ ] Verify task exists: `Get-ScheduledTask -TaskName "OrchestrationAutoResume"`
- [ ] Verify task is enabled (State = "Ready")
- [ ] Verify task trigger is "AtStartup" (not "AtLogon")
- [ ] Verify task runs as "SYSTEM" (not your account)
- [ ] Run orchestration as SYSTEM via PsExec64
- [ ] Test reboot and check if auto-resume works
- [ ] Check logs after reboot for "RESUME" mode

---

## 🚀 **Production Deployment:**

### **For Technician-Free Deployment:**

```powershell
# One-time command (run as admin):
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# From SYSTEM prompt:
cd C:\Deploy\Scripts
.\Orchestration-Master.ps1

# Walk away! System will:
# 1. Execute Phase 1
# 2. Reboot automatically
# 3. Resume Phase 2 (no login!)
# 4. Continue through all 7 phases
# 5. Complete fully unattended
# 6. Clean up scheduled task
# 7. Display final report
```

---

## ❓ **Why Isn't It Working for You?**

Based on your symptoms ("I need to login after reboots"), the most likely cause is:

**The scheduled task is not triggering at startup.**

**Solutions:**
1. **Run as SYSTEM** via PsExec64 (Method 1 above)
2. **Manually create task** with correct triggers (Method 2 above)
3. **Enable task** if it exists but is disabled (Method 3 above)

---

## 📞 **Next Steps:**

1. **Run the diagnostic script** (copy from above)
2. **Share the output** - we can pinpoint the exact issue
3. **Apply appropriate fix** based on diagnostic results

---

**File Version:** 2.1.0-WITH-RESUME  
**Date:** 2024-12-11  
**Status:** Production Ready - Full Auto-Resume Capability ✅
