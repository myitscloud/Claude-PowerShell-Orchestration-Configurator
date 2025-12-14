<#
.SYNOPSIS
    Installs Adobe Acrobat Reader DC silently via EXE.
.DESCRIPTION
    This script installs the official Adobe Acrobat Reader DC EXE client
    silently with arguments optimized for enterprise deployment.
    It checks for file existence and verifies installation success via exit codes.
.NOTES
    REQUIRED: The installer file 'AcrobatReader.exe' must be present in the 
    'Installers' sub-directory relative to this script.
    Exits with code 0 on success or 1 on failure.
    Must be run as Administrator.
#>

Write-Host "    [Sub-Task] Starting Adobe Acrobat Reader DC Installation." -ForegroundColor Gray
Write-Host "    ------------------------------------------------------------------" -ForegroundColor DarkGray
$ExitCode = 0

# Get the directory where this script resides (e.g., C:\POWERSHELL_SCRIPTS)
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- 1. APPLICATION CONFIGURATION ---

# The name of the installer file (must be correct case)
# CHANGED: Switched from .msi to .exe
$InstallerFile = "AcroRdrDC.exe" 

# The full, expected path to the installer file
$InstallerPath = "Installers\Apps\AdobeReader\$InstallerFile"

# The command that will execute the installer. For EXEs, this is usually the installer path itself.
# CHANGED: Set the executable to the installer path itself.
$Executable = $InstallerPath

# The silent arguments for EXE installation.
# /sAll = Silent install for all users (most common for Adobe EXEs)
# Note: Acrobat EXE installers typically handle EULA implicitly in silent mode.
# CHANGED: Switched to the Adobe EXE silent switch.
$Arguments = "/sAll" 

# The exit code(s) that indicate successful installation.
# CHANGED: Removed 3010, as it's primarily an MSI/Windows Installer code.
$SuccessCodes = @(0)

# --- 2. PREREQUISITE CHECK: Installer File Existence ---

Write-Host "    [Action] Checking for installer file at: $InstallerPath" -ForegroundColor Cyan
if (-not (Test-Path $InstallerPath)) {
    Write-Host "    [Error] Installer not found! File expected: '$InstallerFile'." -ForegroundColor Red
    Write-Host "    [Action] Please verify the file is in the 'Installers' folder." -ForegroundColor Red
    $ExitCode = 1
}

# --- 3. EXECUTION ---

if ($ExitCode -eq 0) {
    Write-Host "    [Action] Executing command: $Executable $Arguments" -ForegroundColor Cyan

    try {
        # Start the installation process and wait for it to finish
        # IMPORTANT: We use the full path ($Executable) as the FilePath, which is the EXE itself.
        $Process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait -Passthru -ErrorAction Stop
        
        $FinalExitCode = $Process.ExitCode
        
        # --- 4. Result Check ---
        
        if ($SuccessCodes -contains $FinalExitCode) {
            Write-Host "    [Success] Adobe Acrobat Reader DC installation completed (Exit Code: $FinalExitCode)." -ForegroundColor Green
        } else {
            Write-Host "    [Error] Installation FAILED with unexpected exit code: $FinalExitCode." -ForegroundColor Red
            Write-Host "    Expected code(s): $($SuccessCodes -join ', ')." -ForegroundColor Red
            # Setting the exit code to 1 ensures the orchestrator (Start-PostOSD.ps1) knows this task failed.
            $ExitCode = 1 
        }

    } catch {
        Write-Host "    [Fatal Error] An exception occurred during execution: $($_.Exception.Message)" -ForegroundColor Red
        $ExitCode = 1
    }
}

# --- Final Check and Exit ---
Write-Host "    ------------------------------------------------------------------" -ForegroundColor DarkGray

if ($ExitCode -eq 0) {
    Write-Host "    [Sub-Task] Adobe Acrobat Reader DC Installation Complete." -ForegroundColor Green
    Exit 0
} else {
    Write-Host "    [Sub-Task] Adobe Acrobat Reader DC Installation FAILED." -ForegroundColor Red
    Exit 1
}