# Manual Auto-Resume Task Creator - Direct Method (No wrapper files)
# Run this as Administrator to create the auto-resume scheduled task
# This version calls pwsh.exe directly via cmd.exe with built-in delay

$TaskName = "OrchestrationAutoResume"
$ScriptPath = "C:\Training\Deploy\Scripts\Orchestration-Master.ps1"

Write-Host "`n=== Creating Auto-Resume Scheduled Task (Direct Method) ===" -ForegroundColor Cyan

# Remove existing task if present
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create scheduled task with direct cmd.exe call
Write-Host "Creating scheduled task..." -ForegroundColor Yellow

# Build command: timeout for 60 seconds, then run pwsh.exe with the script
# >nul 2>&1 suppresses timeout output
$Arguments = "/c timeout /t 60 /nobreak >nul 2>&1 && pwsh.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -Resume"

Write-Host "Command: cmd.exe $Arguments" -ForegroundColor Gray

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -Hidden

$Task = Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Automatic resume for Orchestration Engine after reboot" `
    -Force

if ($Task) {
    Write-Host "✓ Scheduled task created successfully!" -ForegroundColor Green
    Write-Host "`nTask Details:" -ForegroundColor Cyan
    Write-Host "  Task Name: $TaskName" -ForegroundColor Gray
    Write-Host "  Script Path: $ScriptPath" -ForegroundColor Gray
    Write-Host "  Trigger: At Startup" -ForegroundColor Gray
    Write-Host "  User: SYSTEM" -ForegroundColor Gray
    Write-Host "  Delay: 60 seconds (built into cmd)" -ForegroundColor Gray
    Write-Host "  Hidden: Yes" -ForegroundColor Gray

    Write-Host "`n✓ Auto-resume is now configured!" -ForegroundColor Green
    Write-Host "  After next reboot, the script will automatically resume." -ForegroundColor Gray
    Write-Host "  No wrapper files needed - calls pwsh.exe directly." -ForegroundColor Gray
}
else {
    Write-Host "✗ Failed to create scheduled task!" -ForegroundColor Red
    exit 1
}
