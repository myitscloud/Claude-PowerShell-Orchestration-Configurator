# Remove existing task
Unregister-ScheduledTask -TaskName "OrchestrationAutoResume" -Confirm:$false

# Create new task with STARTUP trigger (not LOGON)
$TaskName = "OrchestrationAutoResume"
$ScriptPath = "C:\Deploy\Scripts\Orchestration-Master.ps1"

# Action - Using pwsh.exe (PowerShell 7+)
$Action = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -Resume"

# STARTUP trigger (not LOGON) - This is the fix!
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Settings
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

# SYSTEM principal (not your user account)
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

Write-Host "`n✅ Task recreated with STARTUP trigger!" -ForegroundColor Green

# Verify
$NewTask = Get-ScheduledTask -TaskName $TaskName
Write-Host "`nVerification:" -ForegroundColor Cyan
Write-Host "  Trigger: $($NewTask.Triggers[0].CimClass.CimClassName)"
Write-Host "  User: $($NewTask.Principal.UserId)"