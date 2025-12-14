# Manual Auto-Resume Task Creator using VBScript wrapper
# Run this as Administrator to create the auto-resume scheduled task

$TaskName = "OrchestrationAutoResume"
$ScriptPath = "C:\Training\Deploy\Scripts\Orchestration-Master.ps1"
$WrapperDir = "C:\Deploy\Scripts"
$VBSFile = Join-Path $WrapperDir "OrchestrationResume.vbs"

Write-Host "`n=== Creating Auto-Resume Scheduled Task with VBScript Wrapper ===" -ForegroundColor Cyan

# Remove existing task if present
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create wrapper directory
if (-not (Test-Path $WrapperDir)) {
    Write-Host "Creating directory: $WrapperDir" -ForegroundColor Yellow
    New-Item -Path $WrapperDir -ItemType Directory -Force | Out-Null
}

# Create VBScript wrapper
Write-Host "Creating VBScript wrapper at: $VBSFile" -ForegroundColor Yellow

$VBSContent = @"
' Auto-Resume Orchestration Script
' This runs silently without any visible windows

Set WshShell = CreateObject("WScript.Shell")

' Wait 60 seconds for system to stabilize
WScript.Sleep 60000

' Run orchestration with pwsh.exe in hidden window
WshShell.Run "pwsh.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$ScriptPath"" -Resume", 0, False

' Exit
WScript.Quit
"@

$VBSContent | Out-File -FilePath $VBSFile -Encoding ASCII -Force

if (-not (Test-Path $VBSFile)) {
    Write-Host "✗ Failed to create VBScript file!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ VBScript wrapper created successfully" -ForegroundColor Green
Write-Host "  File size: $((Get-Item $VBSFile).Length) bytes" -ForegroundColor Gray

# Create scheduled task
Write-Host "`nCreating scheduled task..." -ForegroundColor Yellow

$Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$VBSFile`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

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
    Write-Host "  VBS File: $VBSFile" -ForegroundColor Gray
    Write-Host "  Script Path: $ScriptPath" -ForegroundColor Gray
    Write-Host "  Trigger: At Startup" -ForegroundColor Gray
    Write-Host "  User: SYSTEM" -ForegroundColor Gray
    Write-Host "  Delay: 60 seconds (built into VBS)" -ForegroundColor Gray

    Write-Host "`n✓ Auto-resume is now configured!" -ForegroundColor Green
    Write-Host "  After next reboot, the script will automatically resume." -ForegroundColor Gray
}
else {
    Write-Host "✗ Failed to create scheduled task!" -ForegroundColor Red
    exit 1
}
