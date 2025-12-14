<#
.SYNOPSIS
    Installs required .NET Framework versions
    
.DESCRIPTION
    Task script for orchestration engine that installs .NET Framework versions.
    Supports .NET Framework 3.5, 4.8, and modern .NET (Core) 6.0/8.0/9.0.
    Includes detection logic to skip if already installed with proper validation.
    
.PARAMETER Versions
    Comma-separated list of .NET versions to install. 
    Default: ".NET 4.8,.NET 6.0,.NET 8.0"
    Options: .NET 3.5, .NET 4.8, .NET 6.0, .NET 8.0, .NET 9.0
    
.PARAMETER InstallPath
    Path to .NET installers. If not provided, will download from Microsoft.
    
.PARAMETER Enable35ViaFeature
    Enable .NET 3.5 via Windows Feature instead of installer. Default: True
    
.PARAMETER AutoDownload
    Automatically download installers if not found locally. Default: True
    
.PARAMETER DownloadPath
    Path to download installers. Default: C:\Temp\DotNetInstallers
    
.PARAMETER VerifyInstallation
    Verify installation after completion. Default: True
    
.PARAMETER CleanupInstallers
    Remove downloaded installers after successful installation. Default: True
    
.PARAMETER AcceptLicense
    Automatically accept license agreements. Default: True
    
.PARAMETER InstallASPNETCore
    Install ASP.NET Core runtime with modern .NET. Default: True
    
.PARAMETER InstallDesktopRuntime
    Install .NET Desktop runtime with modern .NET. Default: True
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\Install-DotNetFramework.ps1 -Versions ".NET 4.8,.NET 8.0"
    
.EXAMPLE
    .\Install-DotNetFramework.ps1 -InstallPath "\\FileServer\Software\DotNet"
    
.NOTES
    Task ID: CRIT-004
    Version: 1.0.1
    Author: IT Infrastructure Team
    Requires: Administrator privileges
    
.OUTPUTS
    Returns exit code:
    0 = Success (installed)
    1 = Failed (installation error)
    2 = Already compliant (already installed)
    3 = Download failed
    4 = Installation failed
    5 = Reboot required
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Versions = ".NET 4.8,.NET 6.0,.NET 8.0",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "",
    
    [Parameter(Mandatory=$false)]
    [bool]$Enable35ViaFeature = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AutoDownload = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$DownloadPath = "C:\Temp\DotNetInstallers",
    
    [Parameter(Mandatory=$false)]
    [bool]$VerifyInstallation = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanupInstallers = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AcceptLicense = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$InstallASPNETCore = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$InstallDesktopRuntime = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.1"
$TaskID = "CRIT-004"
$TaskName = "Install .NET Framework"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "Install-DotNetFramework_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Exit codes
$ExitCode_Success = 0
$ExitCode_Failed = 1
$ExitCode_AlreadyCompliant = 2
$ExitCode_DownloadFailed = 3
$ExitCode_InstallFailed = 4
$ExitCode_RebootRequired = 5

# Installation tracking
$Global:DotNetResults = @{
    VersionsRequested = @()
    VersionsAlreadyInstalled = @()
    VersionsInstalled = @()
    VersionsFailed = @()
    RebootRequired = $false
}

# Parse versions
$RequestedVersions = $Versions -split ',' | ForEach-Object { $_.Trim() }
$Global:DotNetResults.VersionsRequested = $RequestedVersions

# Download URLs for .NET installers (using single quotes to avoid variable parsing issues)
$Script:DownloadURLs = @{
    '.NET 4.8' = 'https://go.microsoft.com/fwlink/?linkid=2088631'
    '.NET 6.0' = 'https://download.visualstudio.microsoft.com/download/pr/5681bdf9-0a48-45ac-b7bf-21b7b61657aa/bbdc43bc7bf0d15b97c1a98ae2e82ec0/dotnet-runtime-6.0.36-win-x64.exe'
    '.NET 8.0' = 'https://download.visualstudio.microsoft.com/download/pr/b395fa18-c53b-4f7f-bf91-6b2d3c43fedb/d3e8c363d5f0bd5dcd21836de0f3a1d9/dotnet-runtime-8.0.11-win-x64.exe'
    '.NET 9.0' = 'https://download.visualstudio.microsoft.com/download/pr/0c0c01cc-84c6-4301-a783-32d4df3b0df6/d85f8d4f50e38e8f21eecc71a7d7c058/dotnet-runtime-9.0.0-win-x64.exe'
}

# ASP.NET Core URLs (using single quotes)
$Script:ASPNETCoreURLs = @{
    '.NET 6.0' = 'https://download.visualstudio.microsoft.com/download/pr/c1ea0601-abe4-4c6d-96ed-131764bf5129/1f3f78d3acc9d1e4d58ef7e417c50a6d/aspnetcore-runtime-6.0.36-win-x64.exe'
    '.NET 8.0' = 'https://download.visualstudio.microsoft.com/download/pr/a5a29e28-a49c-4a59-9cce-aae24bbff181/24f14a7d4c3354521f10c9b641e0ea8b/aspnetcore-runtime-8.0.11-win-x64.exe'
    '.NET 9.0' = 'https://download.visualstudio.microsoft.com/download/pr/6b8e1d9d-64b8-4f8c-8dbb-3e84b8c8b92d/5129e05cf96f7b6ab18cee76d63a9b16/aspnetcore-runtime-9.0.0-win-x64.exe'
}

# Desktop Runtime URLs (using single quotes)
$Script:DesktopRuntimeURLs = @{
    '.NET 6.0' = 'https://download.visualstudio.microsoft.com/download/pr/6f25d2b6-1394-4b39-adef-c8934af07b98/c46bc55f3a55fb1bc3fd60b29b2acd5e/windowsdesktop-runtime-6.0.36-win-x64.exe'
    '.NET 8.0' = 'https://download.visualstudio.microsoft.com/download/pr/4a5c9b3c-d8e6-401a-b3af-40e9f5b8cd91/d9e981d6a4dc9cac5afe8607d2eb4007/windowsdesktop-runtime-8.0.11-win-x64.exe'
    '.NET 9.0' = 'https://download.visualstudio.microsoft.com/download/pr/cfa86447-9ea2-4b1e-854c-351c3de52f66/2ca6c62f2ce0e4eee0f86b1303a7cc5b/windowsdesktop-runtime-9.0.0-win-x64.exe'
}

# Check for local installer repository first
if (-not $InstallPath) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $PossiblePaths = @(
        (Join-Path $ScriptDir "..\..\..\Installers\DotNet"),  # From Scripts\Phase1-Critical
        (Join-Path $ScriptDir "..\..\Installers\DotNet"),     # From Scripts
        (Join-Path $ScriptDir "..\Installers\DotNet"),        # From Deploy
        "C:\Deploy\Installers\DotNet"                          # Fallback
    )
    
    foreach ($Path in $PossiblePaths) {
        if (Test-Path $Path) {
            $InstallPath = $Path
            break
        }
    }
}

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-TaskLog {
    <#
    .SYNOPSIS
        Writes to task-specific log file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $LogMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Write to console with color
    switch ($Level) {
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "DEBUG"   { Write-Host $LogMessage -ForegroundColor Cyan }
        default   { Write-Host $LogMessage -ForegroundColor White }
    }
}

#endregion

#region DETECTION FUNCTIONS
#==============================================================================

function Test-DotNetFramework35Installed {
    <#
    .SYNOPSIS
        Checks if .NET Framework 3.5 is installed
    #>
    
    Write-TaskLog "Checking .NET Framework 3.5 installation..." -Level "DEBUG"
    
    try {
        # Check Windows Feature
        $Feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
        
        if ($Feature -and $Feature.State -eq "Enabled") {
            Write-TaskLog "✓ .NET Framework 3.5 is installed" -Level "SUCCESS"
            return $true
        }
        
        # Fallback: Check registry
        $RegPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
        if (Test-Path $RegPath) {
            $Install = (Get-ItemProperty -Path $RegPath -Name "Install" -ErrorAction SilentlyContinue).Install
            if ($Install -eq 1) {
                Write-TaskLog "✓ .NET Framework 3.5 is installed (registry)" -Level "SUCCESS"
                return $true
            }
        }
        
        Write-TaskLog ".NET Framework 3.5 is not installed" -Level "INFO"
        return $false
    }
    catch {
        Write-TaskLog "Error checking .NET Framework 3.5: $_" -Level "DEBUG"
        return $false
    }
}

function Test-DotNetFramework48Installed {
    <#
    .SYNOPSIS
        Checks if .NET Framework 4.8 is installed
    #>
    
    Write-TaskLog "Checking .NET Framework 4.8 installation..." -Level "DEBUG"
    
    try {
        # Check registry for .NET 4.8 (release number 528040 or higher)
        $RegPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        
        if (Test-Path $RegPath) {
            $Release = (Get-ItemProperty -Path $RegPath -Name "Release" -ErrorAction SilentlyContinue).Release
            
            # .NET 4.8 = 528040, 4.8.1 = 533320
            if ($Release -ge 528040) {
                $Version = switch ($Release) {
                    { $_ -ge 533320 } { "4.8.1" }
                    { $_ -ge 528040 } { "4.8" }
                    default { "Unknown" }
                }
                
                Write-TaskLog "✓ .NET Framework $Version is installed (Release: $Release)" -Level "SUCCESS"
                return $true
            }
            else {
                Write-TaskLog ".NET Framework 4.8 is not installed (Release: $Release)" -Level "INFO"
                return $false
            }
        }
        
        Write-TaskLog ".NET Framework 4.x registry key not found" -Level "INFO"
        return $false
    }
    catch {
        Write-TaskLog "Error checking .NET Framework 4.8: $_" -Level "DEBUG"
        return $false
    }
}

function Test-DotNetCoreInstalled {
    <#
    .SYNOPSIS
        Checks if modern .NET (Core/5+) is installed
    #>
    param([string]$Version)
    
    Write-TaskLog "Checking .NET $Version installation..." -Level "DEBUG"
    
    try {
        # Extract major version (6.0, 8.0, 9.0)
        $MajorVersion = $Version -replace '\.NET ', ''
        
        # Check using dotnet --list-runtimes
        $DotNetExe = Get-Command dotnet -ErrorAction SilentlyContinue
        
        if ($DotNetExe) {
            $Runtimes = & dotnet --list-runtimes 2>&1
            
            if ($Runtimes) {
                # Check for runtime
                $RuntimeInstalled = $Runtimes | Where-Object { $_ -match "Microsoft\.NETCore\.App $MajorVersion\." }
                
                if ($RuntimeInstalled) {
                    Write-TaskLog "✓ .NET $MajorVersion runtime is installed" -Level "SUCCESS"
                    Write-TaskLog "  $($RuntimeInstalled[0])" -Level "DEBUG"
                    return $true
                }
            }
        }
        
        # Fallback: Check common installation paths
        $RuntimePaths = @(
            "$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App",
            "${env:ProgramFiles(x86)}\dotnet\shared\Microsoft.NETCore.App"
        )
        
        foreach ($Path in $RuntimePaths) {
            if (Test-Path $Path) {
                $Versions = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -like "$MajorVersion.*" }
                
                if ($Versions) {
                    Write-TaskLog "✓ .NET $MajorVersion is installed (found in $Path)" -Level "SUCCESS"
                    return $true
                }
            }
        }
        
        Write-TaskLog ".NET $MajorVersion is not installed" -Level "INFO"
        return $false
    }
    catch {
        Write-TaskLog "Error checking .NET $Version: $_" -Level "DEBUG"
        return $false
    }
}

function Test-DotNetVersionInstalled {
    <#
    .SYNOPSIS
        Main detection function for any .NET version
    #>
    param([string]$Version)
    
    switch ($Version) {
        ".NET 3.5" { return Test-DotNetFramework35Installed }
        ".NET 4.8" { return Test-DotNetFramework48Installed }
        { $_ -match "\.NET (6|8|9)\.0" } { return Test-DotNetCoreInstalled -Version $Version }
        default {
            Write-TaskLog "Unknown .NET version: $Version" -Level "WARNING"
            return $false
        }
    }
}

#endregion

#region DOWNLOAD FUNCTIONS
#==============================================================================

function Get-DotNetInstaller {
    <#
    .SYNOPSIS
        Downloads .NET installer
    #>
    param(
        [string]$Version,
        [string]$URL,
        [string]$OutputPath
    )
    
    Write-TaskLog "Downloading $Version installer..." -Level "INFO"
    Write-TaskLog "URL: $URL" -Level "DEBUG"
    Write-TaskLog "Destination: $OutputPath" -Level "DEBUG"
    
    try {
        # Create download directory
        $DownloadDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $DownloadDir)) {
            New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null
        }
        
        # Download with progress
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $URL -OutFile $OutputPath -UseBasicParsing -ErrorAction Stop
        $ProgressPreference = 'Continue'
        
        # Verify download
        if (Test-Path $OutputPath) {
            $FileSize = (Get-Item $OutputPath).Length / 1MB
            Write-TaskLog "✓ Download completed: $([math]::Round($FileSize, 2)) MB" -Level "SUCCESS"
            return $true
        }
        else {
            Write-TaskLog "✗ Download failed - file not found" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-TaskLog "✗ Download failed: $_" -Level "ERROR"
        return $false
    }
}

function Get-InstallerPath {
    <#
    .SYNOPSIS
        Gets or downloads installer path
    #>
    param(
        [string]$Version,
        [string]$RuntimeType = "Runtime"  # Runtime, ASPNETCore, Desktop
    )
    
    # Determine filename
    $FileName = switch ($Version) {
        ".NET 3.5" { "" }  # Not used - installed via Windows Feature
        ".NET 4.8" { "ndp48-x86-x64-allos-enu.exe" }
        { $_ -match "\.NET (6|8|9)\.0" } {
            $Major = $_ -replace '\.NET ', '' -replace '\.0', ''
            switch ($RuntimeType) {
                "ASPNETCore" { "aspnetcore-runtime-$Major-win-x64.exe" }
                "Desktop" { "windowsdesktop-runtime-$Major-win-x64.exe" }
                default { "dotnet-runtime-$Major-win-x64.exe" }
            }
        }
        default { "" }
    }
    
    if (-not $FileName) {
        return $null
    }
    
    # Check if installer exists in InstallPath
    if ($InstallPath) {
        $LocalPath = Join-Path $InstallPath $FileName
        if (Test-Path $LocalPath) {
            Write-TaskLog "Found local installer: $LocalPath" -Level "SUCCESS"
            return $LocalPath
        }
        else {
            Write-TaskLog "Installer not found in $InstallPath" -Level "DEBUG"
        }
    }
    
    # Download if AutoDownload enabled
    if ($AutoDownload) {
        $DownloadFile = Join-Path $DownloadPath $FileName
        
        # Check if already downloaded
        if (Test-Path $DownloadFile) {
            Write-TaskLog "Using previously downloaded installer: $DownloadFile" -Level "INFO"
            return $DownloadFile
        }
        
        # Get download URL
        $URL = switch ($RuntimeType) {
            "ASPNETCore" { $Script:ASPNETCoreURLs[$Version] }
            "Desktop" { $Script:DesktopRuntimeURLs[$Version] }
            default { $Script:DownloadURLs[$Version] }
        }
        
        if (-not $URL) {
            Write-TaskLog "No download URL configured for $Version ($RuntimeType)" -Level "WARNING"
            return $null
        }
        
        # Download
        if (Get-DotNetInstaller -Version "$Version ($RuntimeType)" -URL $URL -OutputPath $DownloadFile) {
            return $DownloadFile
        }
    }
    
    Write-TaskLog "Could not obtain installer for $Version ($RuntimeType)" -Level "WARNING"
    return $null
}

#endregion

#region INSTALLATION FUNCTIONS
#==============================================================================

function Install-DotNetFramework35 {
    <#
    .SYNOPSIS
        Installs .NET Framework 3.5 via Windows Feature
    #>
    
    Write-TaskLog "`n=== Installing .NET Framework 3.5 ===" -Level "INFO"
    
    try {
        if ($Enable35ViaFeature) {
            Write-TaskLog "Enabling .NET Framework 3.5 via Windows Feature..." -Level "INFO"
            
            $Result = Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -ErrorAction Stop
            
            if ($Result.RestartNeeded) {
                Write-TaskLog "⚠ Reboot required after .NET 3.5 installation" -Level "WARNING"
                $Global:DotNetResults.RebootRequired = $true
            }
            
            Write-TaskLog "✓ .NET Framework 3.5 enabled successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-TaskLog ".NET Framework 3.5 installation via feature disabled" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-TaskLog "✗ Failed to enable .NET Framework 3.5: $_" -Level "ERROR"
        return $false
    }
}

function Install-DotNetFramework48 {
    <#
    .SYNOPSIS
        Installs .NET Framework 4.8
    #>
    
    Write-TaskLog "`n=== Installing .NET Framework 4.8 ===" -Level "INFO"
    
    try {
        $InstallerPath = Get-InstallerPath -Version ".NET 4.8"
        
        if (-not $InstallerPath) {
            Write-TaskLog "✗ Installer not available for .NET Framework 4.8" -Level "ERROR"
            return $false
        }
        
        Write-TaskLog "Starting installation..." -Level "INFO"
        Write-TaskLog "Installer: $InstallerPath" -Level "DEBUG"
        
        # Build arguments
        $Arguments = @("/q", "/norestart")
        
        if ($AcceptLicense) {
            $Arguments += "/passive"
        }
        
        # Execute installer
        $Process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        
        $ExitCode = $Process.ExitCode
        
        # Check exit codes
        # 0 = Success
        # 1641 = Success, reboot initiated
        # 3010 = Success, reboot required
        # 5100 = System requirements not met
        
        if ($ExitCode -eq 0 -or $ExitCode -eq 1641 -or $ExitCode -eq 3010) {
            Write-TaskLog "✓ .NET Framework 4.8 installed successfully (Exit Code: $ExitCode)" -Level "SUCCESS"
            
            if ($ExitCode -eq 3010 -or $ExitCode -eq 1641) {
                Write-TaskLog "⚠ Reboot required to complete installation" -Level "WARNING"
                $Global:DotNetResults.RebootRequired = $true
            }
            
            return $true
        }
        else {
            Write-TaskLog "✗ Installation failed with exit code: $ExitCode" -Level "ERROR"
            
            if ($ExitCode -eq 5100) {
                Write-TaskLog "System does not meet requirements for .NET Framework 4.8" -Level "ERROR"
            }
            
            return $false
        }
    }
    catch {
        Write-TaskLog "✗ Error installing .NET Framework 4.8: $_" -Level "ERROR"
        return $false
    }
}

function Install-DotNetModern {
    <#
    .SYNOPSIS
        Installs modern .NET (6.0, 8.0, 9.0)
    #>
    param([string]$Version)
    
    Write-TaskLog "`n=== Installing .NET $Version ===" -Level "INFO"
    
    $InstallSuccess = $true
    
    # Install main runtime
    Write-TaskLog "Installing .NET $Version Runtime..." -Level "INFO"
    $RuntimePath = Get-InstallerPath -Version $Version -RuntimeType "Runtime"
    
    if ($RuntimePath) {
        if (-not (Install-DotNetRuntime -InstallerPath $RuntimePath -RuntimeName "Runtime")) {
            $InstallSuccess = $false
        }
    }
    else {
        Write-TaskLog "✗ Runtime installer not available" -Level "ERROR"
        return $false
    }
    
    # Install ASP.NET Core if requested
    if ($InstallASPNETCore) {
        Write-TaskLog "`nInstalling ASP.NET Core Runtime..." -Level "INFO"
        $ASPNETPath = Get-InstallerPath -Version $Version -RuntimeType "ASPNETCore"
        
        if ($ASPNETPath) {
            if (-not (Install-DotNetRuntime -InstallerPath $ASPNETPath -RuntimeName "ASP.NET Core")) {
                Write-TaskLog "⚠ ASP.NET Core installation failed but continuing" -Level "WARNING"
            }
        }
        else {
            Write-TaskLog "⚠ ASP.NET Core installer not available" -Level "WARNING"
        }
    }
    
    # Install Desktop Runtime if requested
    if ($InstallDesktopRuntime) {
        Write-TaskLog "`nInstalling .NET Desktop Runtime..." -Level "INFO"
        $DesktopPath = Get-InstallerPath -Version $Version -RuntimeType "Desktop"
        
        if ($DesktopPath) {
            if (-not (Install-DotNetRuntime -InstallerPath $DesktopPath -RuntimeName "Desktop")) {
                Write-TaskLog "⚠ Desktop Runtime installation failed but continuing" -Level "WARNING"
            }
        }
        else {
            Write-TaskLog "⚠ Desktop Runtime installer not available" -Level "WARNING"
        }
    }
    
    return $InstallSuccess
}

function Install-DotNetRuntime {
    <#
    .SYNOPSIS
        Installs a .NET runtime component
    #>
    param(
        [string]$InstallerPath,
        [string]$RuntimeName
    )
    
    try {
        Write-TaskLog "Installing $RuntimeName from: $InstallerPath" -Level "DEBUG"
        
        # Arguments for modern .NET installers
        $Arguments = @("/install", "/quiet", "/norestart")
        
        # Execute installer
        $Process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        
        $ExitCode = $Process.ExitCode
        
        # Modern .NET installer exit codes
        # 0 = Success
        # 1641 = Success, reboot initiated
        # 3010 = Success, reboot required
        # 1602 = User cancelled
        # 1618 = Another installation in progress
        
        if ($ExitCode -eq 0 -or $ExitCode -eq 1641 -or $ExitCode -eq 3010) {
            Write-TaskLog "✓ $RuntimeName installed successfully (Exit Code: $ExitCode)" -Level "SUCCESS"
            
            if ($ExitCode -eq 3010 -or $ExitCode -eq 1641) {
                Write-TaskLog "⚠ Reboot required" -Level "WARNING"
                $Global:DotNetResults.RebootRequired = $true
            }
            
            return $true
        }
        else {
            Write-TaskLog "✗ $RuntimeName installation failed (Exit Code: $ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-TaskLog "✗ Error installing $RuntimeName: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Test-AllVersionsInstalled {
    <#
    .SYNOPSIS
        Checks if all requested versions are installed
    #>
    
    Write-TaskLog "Validating all requested .NET versions..." -Level "INFO"
    
    $AllInstalled = $true
    
    foreach ($Version in $RequestedVersions) {
        $Installed = Test-DotNetVersionInstalled -Version $Version
        
        if (-not $Installed) {
            Write-TaskLog "✗ $Version is not installed" -Level "WARNING"
            $AllInstalled = $false
        }
    }
    
    if ($AllInstalled) {
        Write-TaskLog "✓ All requested .NET versions are installed" -Level "SUCCESS"
    }
    
    return $AllInstalled
}

function Write-DotNetSummary {
    <#
    .SYNOPSIS
        Displays installation summary
    #>
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog ".NET INSTALLATION SUMMARY" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    Write-TaskLog "Versions Requested: $($Global:DotNetResults.VersionsRequested.Count)" -Level "INFO"
    Write-TaskLog "Already Installed: $($Global:DotNetResults.VersionsAlreadyInstalled.Count)" -Level $(if($Global:DotNetResults.VersionsAlreadyInstalled.Count -gt 0){"SUCCESS"}else{"INFO"})
    Write-TaskLog "Newly Installed: $($Global:DotNetResults.VersionsInstalled.Count)" -Level $(if($Global:DotNetResults.VersionsInstalled.Count -gt 0){"SUCCESS"}else{"INFO"})
    Write-TaskLog "Failed: $($Global:DotNetResults.VersionsFailed.Count)" -Level $(if($Global:DotNetResults.VersionsFailed.Count -gt 0){"ERROR"}else{"INFO"})
    Write-TaskLog "Reboot Required: $($Global:DotNetResults.RebootRequired)" -Level $(if($Global:DotNetResults.RebootRequired){"WARNING"}else{"INFO"})
    
    if ($Global:DotNetResults.VersionsAlreadyInstalled.Count -gt 0) {
        Write-TaskLog "`nAlready Installed:" -Level "INFO"
        foreach ($Ver in $Global:DotNetResults.VersionsAlreadyInstalled) {
            Write-TaskLog "  ✓ $Ver" -Level "SUCCESS"
        }
    }
    
    if ($Global:DotNetResults.VersionsInstalled.Count -gt 0) {
        Write-TaskLog "`nNewly Installed:" -Level "INFO"
        foreach ($Ver in $Global:DotNetResults.VersionsInstalled) {
            Write-TaskLog "  ✓ $Ver" -Level "SUCCESS"
        }
    }
    
    if ($Global:DotNetResults.VersionsFailed.Count -gt 0) {
        Write-TaskLog "`nFailed Installations:" -Level "ERROR"
        foreach ($Ver in $Global:DotNetResults.VersionsFailed) {
            Write-TaskLog "  ✗ $Ver" -Level "ERROR"
        }
    }
    
    Write-TaskLog "========================================`n" -Level "INFO"
}

function Get-InstalledDotNetVersions {
    <#
    .SYNOPSIS
        Lists all installed .NET versions for reporting
    #>
    
    Write-TaskLog "`nDetecting all installed .NET versions..." -Level "INFO"
    
    $InstalledVersions = @()
    
    # Check .NET Framework 3.5
    if (Test-DotNetFramework35Installed) {
        $InstalledVersions += ".NET Framework 3.5"
    }
    
    # Check .NET Framework 4.x
    if (Test-DotNetFramework48Installed) {
        $RegPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        $Release = (Get-ItemProperty -Path $RegPath -Name "Release" -ErrorAction SilentlyContinue).Release
        
        $FrameworkVersion = switch ($Release) {
            { $_ -ge 533320 } { ".NET Framework 4.8.1" }
            { $_ -ge 528040 } { ".NET Framework 4.8" }
            { $_ -ge 461808 } { ".NET Framework 4.7.2" }
            { $_ -ge 461308 } { ".NET Framework 4.7.1" }
            { $_ -ge 460798 } { ".NET Framework 4.7" }
            default { ".NET Framework 4.x" }
        }
        
        $InstalledVersions += $FrameworkVersion
    }
    
    # Check modern .NET versions
    try {
        $DotNetExe = Get-Command dotnet -ErrorAction SilentlyContinue
        
        if ($DotNetExe) {
            $Runtimes = & dotnet --list-runtimes 2>&1
            
            if ($Runtimes) {
                foreach ($Runtime in $Runtimes) {
                    $InstalledVersions += $Runtime.Trim()
                }
            }
        }
    }
    catch {
        Write-TaskLog "Could not enumerate .NET Core runtimes" -Level "DEBUG"
    }
    
    if ($InstalledVersions.Count -gt 0) {
        Write-TaskLog "Installed .NET Versions:" -Level "INFO"
        foreach ($Ver in $InstalledVersions) {
            Write-TaskLog "  - $Ver" -Level "INFO"
        }
    }
    else {
        Write-TaskLog "No .NET versions detected" -Level "WARNING"
    }
}

#endregion

#region CLEANUP FUNCTIONS
#==============================================================================

function Remove-DownloadedInstallers {
    <#
    .SYNOPSIS
        Removes downloaded installers after successful installation
    #>
    
    if (-not $CleanupInstallers) {
        Write-TaskLog "Installer cleanup disabled - keeping downloaded files" -Level "INFO"
        return
    }
    
    Write-TaskLog "Cleaning up downloaded installers..." -Level "INFO"
    
    try {
        if (Test-Path $DownloadPath) {
            $Files = Get-ChildItem -Path $DownloadPath -Filter "*.exe" -ErrorAction SilentlyContinue
            
            foreach ($File in $Files) {
                try {
                    Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                    Write-TaskLog "Removed: $($File.Name)" -Level "DEBUG"
                }
                catch {
                    Write-TaskLog "Could not remove $($File.Name): $_" -Level "DEBUG"
                }
            }
            
            # Remove download directory if empty
            $RemainingFiles = Get-ChildItem -Path $DownloadPath -ErrorAction SilentlyContinue
            if (-not $RemainingFiles) {
                Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue
                Write-TaskLog "✓ Download directory removed" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-TaskLog "Error during cleanup: $_" -Level "DEBUG"
    }
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "TASK: $TaskID - $TaskName" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "Script Version: $ScriptVersion" -Level "INFO"
    Write-TaskLog "Requested Versions: $Versions" -Level "INFO"
    Write-TaskLog "Install Path: $(if($InstallPath){$InstallPath}else{'Auto-download'})" -Level "INFO"
    Write-TaskLog "Auto Download: $AutoDownload" -Level "INFO"
    Write-TaskLog "Install ASP.NET Core: $InstallASPNETCore" -Level "INFO"
    Write-TaskLog "Install Desktop Runtime: $InstallDesktopRuntime" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    
    # Step 1: Validate requested versions
    Write-TaskLog "`n--- Step 1: Validate Requested Versions ---" -Level "INFO"
    
    if ($RequestedVersions.Count -eq 0) {
        Write-TaskLog "No .NET versions requested" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    Write-TaskLog "Will process $($RequestedVersions.Count) version(s):" -Level "INFO"
    foreach ($Ver in $RequestedVersions) {
        Write-TaskLog "  - $Ver" -Level "INFO"
    }
    
    # Step 2: Check which versions are already installed
    Write-TaskLog "`n--- Step 2: Check Installation Status ---" -Level "INFO"
    
    $NeedsInstallation = @()
    
    foreach ($Version in $RequestedVersions) {
        $IsInstalled = Test-DotNetVersionInstalled -Version $Version
        
        if ($IsInstalled) {
            Write-TaskLog "✓ $Version is already installed" -Level "SUCCESS"
            $Global:DotNetResults.VersionsAlreadyInstalled += $Version
        }
        else {
            Write-TaskLog "✗ $Version needs to be installed" -Level "INFO"
            $NeedsInstallation += $Version
        }
    }
    
    # If all versions already installed, exit
    if ($NeedsInstallation.Count -eq 0) {
        Write-TaskLog "`nAll requested .NET versions are already installed - no action needed" -Level "SUCCESS"
        Get-InstalledDotNetVersions
        Write-TaskLog "Task completed in $([math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)) seconds" -Level "INFO"
        exit $ExitCode_AlreadyCompliant
    }
    
    Write-TaskLog "`n$($NeedsInstallation.Count) version(s) need to be installed" -Level "INFO"
    
    # Step 3: Install each required version
    Write-TaskLog "`n--- Step 3: Install .NET Versions ---" -Level "INFO"
    
    foreach ($Version in $NeedsInstallation) {
        Write-TaskLog "`nProcessing: $Version" -Level "INFO"
        
        $InstallSuccess = $false
        
        try {
            switch ($Version) {
                ".NET 3.5" {
                    $InstallSuccess = Install-DotNetFramework35
                }
                ".NET 4.8" {
                    $InstallSuccess = Install-DotNetFramework48
                }
                { $_ -match "\.NET (6|8|9)\.0" } {
                    $InstallSuccess = Install-DotNetModern -Version $Version
                }
                default {
                    Write-TaskLog "✗ Unknown version: $Version" -Level "ERROR"
                    $InstallSuccess = $false
                }
            }
            
            if ($InstallSuccess) {
                $Global:DotNetResults.VersionsInstalled += $Version
                Write-TaskLog "✓ $Version installation completed" -Level "SUCCESS"
            }
            else {
                $Global:DotNetResults.VersionsFailed += $Version
                Write-TaskLog "✗ $Version installation failed" -Level "ERROR"
            }
        }
        catch {
            Write-TaskLog "✗ Exception during $Version installation: $_" -Level "ERROR"
            $Global:DotNetResults.VersionsFailed += $Version
        }
    }
    
    # Step 4: Verify installations
    if ($VerifyInstallation) {
        Write-TaskLog "`n--- Step 4: Verify Installations ---" -Level "INFO"
        
        # Wait a moment for installations to finalize
        Start-Sleep -Seconds 3
        
        foreach ($Version in $Global:DotNetResults.VersionsInstalled) {
            $Verified = Test-DotNetVersionInstalled -Version $Version
            
            if ($Verified) {
                Write-TaskLog "✓ Verified: $Version" -Level "SUCCESS"
            }
            else {
                Write-TaskLog "⚠ Could not verify: $Version (may require reboot)" -Level "WARNING"
            }
        }
    }
    
    # Step 5: Cleanup
    Write-TaskLog "`n--- Step 5: Cleanup ---" -Level "INFO"
    
    if ($Global:DotNetResults.VersionsInstalled.Count -gt 0) {
        Remove-DownloadedInstallers
    }
    
    # Step 6: Summary
    Write-TaskLog "`n--- Step 6: Summary ---" -Level "INFO"
    
    Write-DotNetSummary
    Get-InstalledDotNetVersions
    
    # Determine exit code
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)
    
    if ($Global:DotNetResults.VersionsFailed.Count -gt 0) {
        Write-TaskLog "`n========================================" -Level "ERROR"
        Write-TaskLog "TASK COMPLETED WITH ERRORS" -Level "ERROR"
        Write-TaskLog "Duration: $Duration seconds" -Level "ERROR"
        Write-TaskLog "Installed: $($Global:DotNetResults.VersionsInstalled.Count)" -Level "SUCCESS"
        Write-TaskLog "Failed: $($Global:DotNetResults.VersionsFailed.Count)" -Level "ERROR"
        Write-TaskLog "========================================" -Level "ERROR"
        
        # If some succeeded, consider it partial success
        if ($Global:DotNetResults.VersionsInstalled.Count -gt 0) {
            exit $ExitCode_Success
        }
        else {
            exit $ExitCode_InstallFailed
        }
    }
    elseif ($Global:DotNetResults.RebootRequired) {
        Write-TaskLog "`n========================================" -Level "WARNING"
        Write-TaskLog "TASK COMPLETED - REBOOT REQUIRED" -Level "WARNING"
        Write-TaskLog "Duration: $Duration seconds" -Level "WARNING"
        Write-TaskLog "Installed $($Global:DotNetResults.VersionsInstalled.Count) version(s)" -Level "SUCCESS"
        Write-TaskLog "⚠ REBOOT REQUIRED to complete installation" -Level "WARNING"
        Write-TaskLog "========================================" -Level "WARNING"
        exit $ExitCode_RebootRequired
    }
    else {
        Write-TaskLog "`n========================================" -Level "SUCCESS"
        Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
        Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
        Write-TaskLog "Installed $($Global:DotNetResults.VersionsInstalled.Count) version(s)" -Level "SUCCESS"
        Write-TaskLog "Already Installed: $($Global:DotNetResults.VersionsAlreadyInstalled.Count)" -Level "INFO"
        Write-TaskLog "========================================" -Level "SUCCESS"
        exit $ExitCode_Success
    }
}
catch {
    Write-TaskLog "`n========================================" -Level "ERROR"
    Write-TaskLog "TASK FAILED WITH EXCEPTION" -Level "ERROR"
    Write-TaskLog "Error: $($_.Exception.Message)" -Level "ERROR"
    Write-TaskLog "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-TaskLog "========================================" -Level "ERROR"
    
    # Display summary even on failure
    Write-DotNetSummary
    
    exit $ExitCode_Failed
}

#endregion