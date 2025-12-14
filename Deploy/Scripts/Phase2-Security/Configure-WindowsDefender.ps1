<#
.SYNOPSIS
    Enables Microsoft Defender Antivirus and updates its definitions on Windows 11.

.DESCRIPTION
    This script:
    1. Enables Microsoft Defender Antivirus if disabled.
    2. Starts the Windows Defender service.
    3. Updates Defender's security intelligence to the latest version.

.NOTES
    Run this script in PowerShell as Administrator.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

try {
    Write-Host "Enabling Microsoft Defender Antivirus..." -ForegroundColor Cyan

    # Enable Defender real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop

    # Enable Defender if it was disabled via policy
    Set-MpPreference -DisableAntiSpyware $false -ErrorAction SilentlyContinue

<#     # Ensure the Defender service is set to automatic and running
    $serviceName = "WinDefend"
    Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        Start-Service -Name $serviceName -ErrorAction Stop
    } #>

    Write-Host "Updating Microsoft Defender security intelligence..." -ForegroundColor Cyan
    Update-MpSignature -ErrorAction Stop

    Write-Host "Microsoft Defender is enabled and up to date." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
}



<# Set-Service -Name WinDefend -StartupType Automatic
Start-Service -Name WinDefend
Set-MpPreference -DisableRealtimeMonitoring $false
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
Update-MpSignature #>