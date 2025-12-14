<#
.SYNOPSIS
    Downloads all required installers for orchestration deployment
    
.DESCRIPTION
    Helper script that downloads all application installers, .NET runtimes, and other
    required files into the proper folder structure for portable orchestration deployment.
    Creates a fully self-contained deployment package.
    
.PARAMETER DestinationPath
    Root path where Deploy folder structure will be created. Default: C:\Deploy
    
.PARAMETER SkipExisting
    Skip downloads if files already exist. Default: True
    
.PARAMETER VerifyHashes
    Verify file hashes after download (when available). Default: True
    
.PARAMETER DownloadOptional
    Download optional applications. Default: False
    
.PARAMETER CreateZip
    Create a ZIP file of the entire deployment after downloads complete. Default: False
    
.EXAMPLE
    .\Download-Installers.ps1
    Downloads all required installers to C:\Deploy\Installers
    
.EXAMPLE
    .\Download-Installers.ps1 -DestinationPath "E:\Deployment" -CreateZip
    Downloads to E:\Deployment and creates a ZIP archive
    
.NOTES
    Version: 1.0.0
    Author: IT Infrastructure Team
    Purpose: Prepare portable orchestration deployment package
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DestinationPath = "C:\Deploy",
    
    [Parameter(Mandatory=$false)]
    [bool]$SkipExisting = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$VerifyHashes = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DownloadOptional = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$CreateZip = $false
)

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Tracking
$Global:DownloadResults = @{
    TotalFiles = 0
    Downloaded = 0
    Skipped = 0
    Failed = 0
    TotalSizeGB = 0
}

#endregion

#region LOGGING
#==============================================================================

function Write-DownloadLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","PROGRESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    switch ($Level) {
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "PROGRESS" { Write-Host $LogMessage -ForegroundColor Cyan }
        default   { Write-Host $LogMessage -ForegroundColor White }
    }
}

#endregion

#region INSTALLER DEFINITIONS
#==============================================================================

# Define all installers to download
$InstallerDefinitions = @{
    
    # .NET Framework and Runtimes
    DotNet = @(
        @{
            Name = ".NET Framework 4.8"
            FileName = "ndp48-x86-x64-allos-enu.exe"
            URL = "https://go.microsoft.com/fwlink/?linkid=2088631"
            Folder = "DotNet"
            Required = $true
            SizeMB = 116
        }
        @{
            Name = ".NET 10 Runtime"
            FileName = "windowsdesktop-runtime-10.0.0-win-x64.exe"
            URL = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.0/windowsdesktop-runtime-10.0.0-win-x64.exe"
            Folder = "DotNet"
            Required = $true
            SizeMB = 28
        }
       
    )
    
    # Applications
    Applications = @(
        @{
            Name = "Google Chrome Enterprise (x64)"
            FileName = "GoogleChromeStandaloneEnterprise64.msi"
            URL = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
            Folder = "Apps\Chrome"
            Required = $true
            SizeMB = 95
        }
        @{
            Name = "Adobe Acrobat Reader DC"
            FileName = "AcroRdrDC.exe"
            URL = "https://ardownload2.adobe.com/pub/adobe/acrobat/win/AcrobatDC/2500120982/AcroRdrDCx642500120982_MUI.exe"
            Folder = "Apps\AdobeReader"
            Required = $true
            SizeMB = 280
        }
        @{
            Name = "7-Zip (x64)"
            FileName = "7z2408-x64.msi"
            URL = "https://www.7-zip.org/a/7z2408-x64.msi"
            Folder = "Apps\7Zip"
            Required = $true
            SizeMB = 1.5
        }
        @{
            Name = "Microsoft Teams (x64)"
            FileName = "Teams_windows_x64.exe"
            URL = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409&culture=en-us&country=us"
            Folder = "Apps\Teams"
            Required = $true
            SizeMB = 140
        }
        @{
            Name = "Mozilla Firefox ESR (x64)"
            FileName = "Firefox-Setup-ESR.exe"
            URL = "https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win64&lang=en-US"
            Folder = "Apps\Firefox"
            Required = $true
            SizeMB = 65
        }
        @{
            Name = "Notepad++ (x64)"
            FileName = "npp.8.6.9.Installer.x64.exe"
            URL = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.Installer.x64.exe"
            Folder = "Apps\Notepad++"
            Required = $true
            SizeMB = 4
        }
        @{
            Name = "VLC Media Player (x64)"
            FileName = "vlc-3.0.21-win64.exe"
            URL = "https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe"
            Folder = "Apps\VLC"
            Required = $true
            SizeMB = 42
        }
    )
}

#endregion

#region DOWNLOAD FUNCTIONS
#==============================================================================

function New-FolderStructure {
    <#
    .SYNOPSIS
        Creates the deployment folder structure
    #>
    
    Write-DownloadLog "Creating deployment folder structure..." -Level "INFO"
    
    $Folders = @(
        "$DestinationPath\Installers\DotNet"
        "$DestinationPath\Installers\Apps\Chrome"
        "$DestinationPath\Installers\Apps\Office"
        "$DestinationPath\Installers\Apps\AdobeReader"
        "$DestinationPath\Installers\Apps\7Zip"
        "$DestinationPath\Installers\Apps\Teams"
        "$DestinationPath\Installers\Apps\Firefox"
        "$DestinationPath\Installers\Apps\Notepad++"
        "$DestinationPath\Installers\Apps\VLC"
        "$DestinationPath\Installers\Drivers\Dell"
        "$DestinationPath\Installers\Drivers\HP"
        "$DestinationPath\Installers\Drivers\Lenovo"
        "$DestinationPath\Installers\Updates"
        "$DestinationPath\Scripts\Phase1-Critical"
        "$DestinationPath\Scripts\Phase2-Security"
        "$DestinationPath\Scripts\Phase3-Network"
        "$DestinationPath\Scripts\Phase4-Applications"
        "$DestinationPath\Scripts\Phase5-System"
        "$DestinationPath\Scripts\Phase6-UserExperience"
        "$DestinationPath\Scripts\Phase7-Validation"
        "$DestinationPath\Config"
        "$DestinationPath\Assets"
    )
    
    foreach ($Folder in $Folders) {
        if (-not (Test-Path $Folder)) {
            try {
                New-Item -Path $Folder -ItemType Directory -Force | Out-Null
                Write-DownloadLog "  Created: $Folder" -Level "SUCCESS"
            }
            catch {
                Write-DownloadLog "  Failed to create: $Folder - $_" -Level "ERROR"
            }
        }
        else {
            Write-DownloadLog "  Exists: $Folder" -Level "INFO"
        }
    }
    
    Write-DownloadLog "✓ Folder structure created" -Level "SUCCESS"
}

function Get-Installer {
    <#
    .SYNOPSIS
        Downloads a single installer
    #>
    param(
        [hashtable]$Installer
    )
    
    $DestFolder = Join-Path "$DestinationPath\Installers" $Installer.Folder
    $DestFile = Join-Path $DestFolder $Installer.FileName
    
    Write-DownloadLog "`nDownloading: $($Installer.Name)" -Level "PROGRESS"
    Write-DownloadLog "  File: $($Installer.FileName)" -Level "INFO"
    Write-DownloadLog "  Size: ~$($Installer.SizeMB) MB" -Level "INFO"
    
    # Check if already exists
    if ((Test-Path $DestFile) -and $SkipExisting) {
        $ExistingSize = (Get-Item $DestFile).Length / 1MB
        Write-DownloadLog "  ✓ Already exists ($([math]::Round($ExistingSize, 2)) MB) - skipping" -Level "SUCCESS"
        $Global:DownloadResults.Skipped++
        return $true
    }
    
    # Create folder if needed
    if (-not (Test-Path $DestFolder)) {
        New-Item -Path $DestFolder -ItemType Directory -Force | Out-Null
    }
    
    # Download
    try {
        Write-DownloadLog "  Downloading from: $($Installer.URL)" -Level "INFO"
        
        $ProgressPreference = 'SilentlyContinue'
        
        # Use WebClient for progress if possible
        $WebClient = New-Object System.Net.WebClient
        
        # Download with retry
        $MaxRetries = 3
        $RetryCount = 0
        $Downloaded = $false
        
        while ($RetryCount -lt $MaxRetries -and -not $Downloaded) {
            try {
                if ($RetryCount -gt 0) {
                    Write-DownloadLog "  Retry attempt $RetryCount of $MaxRetries..." -Level "WARNING"
                    Start-Sleep -Seconds 5
                }
                
                $WebClient.DownloadFile($Installer.URL, $DestFile)
                $Downloaded = $true
            }
            catch {
                $RetryCount++
                if ($RetryCount -ge $MaxRetries) {
                    throw
                }
            }
        }
        
        $WebClient.Dispose()
        $ProgressPreference = 'Continue'
        
        # Verify download
        if (Test-Path $DestFile) {
            $FileSize = (Get-Item $DestFile).Length / 1MB
            Write-DownloadLog "  ✓ Download complete: $([math]::Round($FileSize, 2)) MB" -Level "SUCCESS"
            
            $Global:DownloadResults.Downloaded++
            $Global:DownloadResults.TotalSizeGB += $FileSize / 1024
            
            # Basic size validation
            if ($FileSize -lt 0.1) {
                Write-DownloadLog "  ⚠ Warning: File is very small - may be incomplete" -Level "WARNING"
            }
            
            return $true
        }
        else {
            throw "File not found after download"
        }
    }
    catch {
        Write-DownloadLog "  ✗ Download failed: $_" -Level "ERROR"
        $Global:DownloadResults.Failed++
        return $false
    }
}

function Get-AllInstallers {
    <#
    .SYNOPSIS
        Downloads all defined installers
    #>
    
    Write-DownloadLog "`n========================================" -Level "INFO"
    Write-DownloadLog "DOWNLOADING INSTALLERS" -Level "INFO"
    Write-DownloadLog "========================================" -Level "INFO"
    
    # .NET Installers
    Write-DownloadLog "`n--- .NET Framework & Runtimes ---" -Level "INFO"
    foreach ($Installer in $InstallerDefinitions.DotNet) {
        if ($Installer.Required -or $DownloadOptional) {
            $Global:DownloadResults.TotalFiles++
            Get-Installer -Installer $Installer
        }
        else {
            Write-DownloadLog "Skipping optional: $($Installer.Name)" -Level "INFO"
        }
    }
    
    # Application Installers
    Write-DownloadLog "`n--- Applications ---" -Level "INFO"
    foreach ($Installer in $InstallerDefinitions.Applications) {
        if ($Installer.Required -or $DownloadOptional) {
            $Global:DownloadResults.TotalFiles++
            Get-Installer -Installer $Installer
        }
        else {
            Write-DownloadLog "Skipping optional: $($Installer.Name)" -Level "INFO"
        }
    }
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Test-AllDownloads {
    <#
    .SYNOPSIS
        Validates all downloaded files
    #>
    
    Write-DownloadLog "`n========================================" -Level "INFO"
    Write-DownloadLog "VALIDATING DOWNLOADS" -Level "INFO"
    Write-DownloadLog "========================================" -Level "INFO"
    
    $ValidationResults = @{
        Total = 0
        Valid = 0
        Missing = 0
        Suspicious = 0
    }
    
    # Check all defined installers
    $AllInstallers = $InstallerDefinitions.DotNet + $InstallerDefinitions.Applications
    
    foreach ($Installer in $AllInstallers) {
        if (-not $Installer.Required -and -not $DownloadOptional) {
            continue
        }
        
        $ValidationResults.Total++
        
        $FilePath = Join-Path "$DestinationPath\Installers" $Installer.Folder $Installer.FileName
        
        if (Test-Path $FilePath) {
            $FileSize = (Get-Item $FilePath).Length / 1MB
            
            if ($FileSize -lt 0.1) {
                Write-DownloadLog "⚠ $($Installer.Name): File too small ($([math]::Round($FileSize, 2)) MB)" -Level "WARNING"
                $ValidationResults.Suspicious++
            }
            else {
                Write-DownloadLog "✓ $($Installer.Name): $([math]::Round($FileSize, 2)) MB" -Level "SUCCESS"
                $ValidationResults.Valid++
            }
        }
        else {
            Write-DownloadLog "✗ $($Installer.Name): Missing" -Level "ERROR"
            $ValidationResults.Missing++
        }
    }
    
    Write-DownloadLog "`nValidation Summary:" -Level "INFO"
    Write-DownloadLog "  Total: $($ValidationResults.Total)" -Level "INFO"
    Write-DownloadLog "  Valid: $($ValidationResults.Valid)" -Level "SUCCESS"
    Write-DownloadLog "  Missing: $($ValidationResults.Missing)" -Level $(if($ValidationResults.Missing -gt 0){"ERROR"}else{"SUCCESS"})
    Write-DownloadLog "  Suspicious: $($ValidationResults.Suspicious)" -Level $(if($ValidationResults.Suspicious -gt 0){"WARNING"}else{"INFO"})
    
    return $ValidationResults
}

#endregion

#region PACKAGING FUNCTIONS
#==============================================================================

function New-DeploymentPackage {
    <#
    .SYNOPSIS
        Creates a ZIP archive of the deployment
    #>
    
    if (-not $CreateZip) {
        return
    }
    
    Write-DownloadLog "`n========================================" -Level "INFO"
    Write-DownloadLog "CREATING DEPLOYMENT PACKAGE" -Level "INFO"
    Write-DownloadLog "========================================" -Level "INFO"
    
    try {
        $ZipFileName = "OrchestrationDeployment_$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
        $ZipPath = Join-Path (Split-Path $DestinationPath -Parent) $ZipFileName
        
        Write-DownloadLog "Creating ZIP archive..." -Level "INFO"
        Write-DownloadLog "  Source: $DestinationPath" -Level "INFO"
        Write-DownloadLog "  Destination: $ZipPath" -Level "INFO"
        
        # Compress
        Compress-Archive -Path "$DestinationPath\*" -DestinationPath $ZipPath -CompressionLevel Optimal -Force
        
        if (Test-Path $ZipPath) {
            $ZipSize = (Get-Item $ZipPath).Length / 1GB
            Write-DownloadLog "✓ ZIP created: $([math]::Round($ZipSize, 2)) GB" -Level "SUCCESS"
            Write-DownloadLog "  Location: $ZipPath" -Level "SUCCESS"
        }
    }
    catch {
        Write-DownloadLog "Failed to create ZIP: $_" -Level "ERROR"
    }
}

function New-ReadmeFile {
    <#
    .SYNOPSIS
        Creates a README file in the deployment folder
    #>
    
    $ReadmePath = Join-Path $DestinationPath "README.txt"
    
    $ReadmeContent = @"
ORCHESTRATION DEPLOYMENT PACKAGE
=================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Version: $ScriptVersion

FOLDER STRUCTURE:
-----------------
Deploy\
  ├── Orchestration-Master.ps1          Master orchestration engine
  ├── Orchestration-Config.ps1          Configuration file
  ├── Scripts\                          Task scripts organized by phase
  ├── Installers\                       All application installers
  │   ├── DotNet\                       .NET Framework and runtimes
  │   ├── Apps\                         Application installers
  │   └── Drivers\                      Hardware drivers
  ├── Config\                           Configuration files (XML, etc.)
  └── Assets\                           Images, wallpapers

USAGE:
------
1. Copy entire Deploy folder to target location (C:\Deploy, USB drive, network share)
2. Run as Administrator: .\Orchestration-Master.ps1
3. Orchestration will automatically resume after reboots
4. Monitor logs in C:\ProgramData\OrchestrationLogs

DOWNLOADED INSTALLERS:
----------------------
Total Files: $($Global:DownloadResults.Downloaded)
Total Size: $([math]::Round($Global:DownloadResults.TotalSizeGB, 2)) GB

.NET FRAMEWORK & RUNTIMES:
$((Get-ChildItem "$DestinationPath\Installers\DotNet" -File -ErrorAction SilentlyContinue | ForEach-Object { "  - $($_.Name) ($([math]::Round($_.Length/1MB, 2)) MB)" }) -join "`n")

APPLICATIONS:
$((Get-ChildItem "$DestinationPath\Installers\Apps" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { "  - $($_.Name) ($([math]::Round($_.Length/1MB, 2)) MB)" }) -join "`n")

NOTES:
------
- This package is fully portable and offline-capable
- All installers are included locally
- No internet connection required for installation
- Auto-resume feature enabled for automatic orchestration continuation

For support, contact IT Infrastructure Team
"@
    
    try {
        $ReadmeContent | Out-File -FilePath $ReadmePath -Encoding UTF8 -Force
        Write-DownloadLog "✓ README.txt created" -Level "SUCCESS"
    }
    catch {
        Write-DownloadLog "Warning: Could not create README.txt: $_" -Level "WARNING"
    }
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    Clear-Host
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║              ORCHESTRATION DEPLOYMENT PACKAGE BUILDER                ║
║                                                                       ║
║              Downloads all required installers and creates           ║
║              a portable, self-contained deployment package           ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-DownloadLog "Destination: $DestinationPath" -Level "INFO"
    Write-DownloadLog "Skip Existing: $SkipExisting" -Level "INFO"
    Write-DownloadLog "Download Optional: $DownloadOptional" -Level "INFO"
    Write-DownloadLog "Create ZIP: $CreateZip`n" -Level "INFO"
    
    # Step 1: Create folder structure
    Write-DownloadLog "--- Step 1: Create Folder Structure ---" -Level "INFO"
    New-FolderStructure
    
    # Step 2: Download all installers
    Write-DownloadLog "`n--- Step 2: Download Installers ---" -Level "INFO"
    Get-AllInstallers
    
    # Step 3: Validate downloads
    Write-DownloadLog "`n--- Step 3: Validate Downloads ---" -Level "INFO"
    $ValidationResults = Test-AllDownloads
    
    # Step 4: Create README
    Write-DownloadLog "`n--- Step 4: Create Documentation ---" -Level "INFO"
    New-ReadmeFile
    
    # Step 5: Create ZIP if requested
    if ($CreateZip) {
        Write-DownloadLog "`n--- Step 5: Create Deployment Package ---" -Level "INFO"
        New-DeploymentPackage
    }
    
    # Final Summary
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalMinutes, 2)
    
    Write-DownloadLog "`n========================================" -Level "SUCCESS"
    Write-DownloadLog "DEPLOYMENT PACKAGE READY" -Level "SUCCESS"
    Write-DownloadLog "========================================" -Level "SUCCESS"
    Write-DownloadLog "Duration: $Duration minutes" -Level "INFO"
    Write-DownloadLog "Total Files: $($Global:DownloadResults.TotalFiles)" -Level "INFO"
    Write-DownloadLog "Downloaded: $($Global:DownloadResults.Downloaded)" -Level "SUCCESS"
    Write-DownloadLog "Skipped: $($Global:DownloadResults.Skipped)" -Level "INFO"
    Write-DownloadLog "Failed: $($Global:DownloadResults.Failed)" -Level $(if($Global:DownloadResults.Failed -gt 0){"ERROR"}else{"SUCCESS"})
    Write-DownloadLog "Total Size: $([math]::Round($Global:DownloadResults.TotalSizeGB, 2)) GB" -Level "INFO"
    Write-DownloadLog "`nDeployment Location: $DestinationPath" -Level "SUCCESS"
    
    if ($ValidationResults.Missing -gt 0) {
        Write-DownloadLog "`n⚠ WARNING: $($ValidationResults.Missing) file(s) missing - review errors above" -Level "WARNING"
    }
    
    Write-DownloadLog "`n✓ Ready for deployment!" -Level "SUCCESS"
    Write-DownloadLog "Copy the entire '$DestinationPath' folder to your deployment media" -Level "INFO"
    
}
catch {
    Write-DownloadLog "`nFATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-DownloadLog "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

#endregion