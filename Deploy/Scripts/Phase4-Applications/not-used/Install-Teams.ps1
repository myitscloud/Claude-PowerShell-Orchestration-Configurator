<#
.SYNOPSIS
    Universal Application Installer Template for Orchestration Engine
    
.DESCRIPTION
    A flexible, parameter-driven application installer that can handle most
    standard application installations without requiring custom scripts.
    
    Supports:
    - MSI, EXE, MSIX, APPX installer types
    - Multiple detection methods (Registry, File, AppX, Get-Package)
    - Pre/post installation validation
    - Automatic installer location discovery
    - Comprehensive logging and error handling
    - Standard exit codes for orchestration integration
    
.PARAMETER AppName
    Display name of the application being installed
    
.PARAMETER InstallerFileName
    Name of the installer file (will be located automatically in configured paths)
    
.PARAMETER InstallerType
    Type of installer: MSI, EXE, MSIX, APPX, or AUTO (auto-detect from extension)
    
.PARAMETER InstallArguments
    Silent installation arguments (e.g., "/quiet /norestart" or "/S")
    
.PARAMETER DetectionMethod
    How to detect if app is already installed: Registry, File, AppX, Package, Custom
    
.PARAMETER DetectionPath
    Path to check for detection (registry key, file path, package name, etc.)
    
.PARAMETER DetectionValue
    Optional: Specific registry value to check or version to compare
    
.PARAMETER DetectionScript
    Optional: Custom PowerShell script block for complex detection logic
    
.PARAMETER RequiredVersion
    Optional: Minimum version required (used with version comparison)
    
.PARAMETER PreInstallScript
    Optional: Script block to run before installation
    
.PARAMETER PostInstallScript
    Optional: Script block to run after installation
    
.PARAMETER ValidateInstall
    Optional: Perform post-install validation (default: $true)
    
.PARAMETER TimeoutSeconds
    Maximum time to wait for installation to complete (default: 1800)
    
.PARAMETER LogPath
    Path where logs should be written (default: C:\ProgramData\OrchestrationLogs\Apps)
    
.EXAMPLE
    .\Universal-AppInstaller.ps1 -AppName "7-Zip" `
        -InstallerFileName "7z2408-x64.msi" `
        -InstallerType "MSI" `
        -InstallArguments "/quiet /norestart" `
        -DetectionMethod "Registry" `
        -DetectionPath "HKLM:\SOFTWARE\7-Zip" `
        -DetectionValue "Path"
    
.EXAMPLE
    .\Universal-AppInstaller.ps1 -AppName "Notepad++" `
        -InstallerFileName "npp.8.6.9.Installer.x64.exe" `
        -InstallerType "EXE" `
        -InstallArguments "/S" `
        -DetectionMethod "File" `
        -DetectionPath "C:\Program Files\Notepad++\notepad++.exe"
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Universal app installer for orchestration framework
    
    EXIT CODES:
    0   = Success (app installed or already present)
    1   = General failure
    2   = Installer not found
    3   = Detection method failed
    4   = Installation failed
    5   = Validation failed after install
    10  = App already installed (success, no action needed)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$AppName,
    
    [Parameter(Mandatory=$true)]
    [string]$InstallerFileName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("MSI", "EXE", "MSIX", "APPX", "AUTO")]
    [string]$InstallerType = "AUTO",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallArguments = "",
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Registry", "File", "AppX", "Package", "Custom", "None")]
    [string]$DetectionMethod,
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionValue = "",
    
    [Parameter(Mandatory=$false)]
    [scriptblock]$DetectionScript = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$RequiredVersion = "",
    
    [Parameter(Mandatory=$false)]
    [scriptblock]$PreInstallScript = $null,
    
    [Parameter(Mandatory=$false)]
    [scriptblock]$PostInstallScript = $null,
    
    [Parameter(Mandatory=$false)]
    [bool]$ValidateInstall = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 1800,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Apps"
)

#region INITIALIZATION
#==============================================================================

# Script metadata
$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Initialize logging
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Install-{0}_{1}.log" -f ($AppName -replace '[^\w\-]', '_'), (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Standard installer search paths
$InstallerSearchPaths = @(
    ".\Installers\Apps",
    "C:\Deploy\Apps",
    "C:\Installers\Apps",
    "$PSScriptRoot\..\Installers\Apps",
    "\\FileServer\Deployment\Apps",
    $env:TEMP
)

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes log messages to file and console
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $Global:LogFile -Value $LogMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log: $_"
    }
    
    # Write to console with color
    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "DEBUG"   { "Cyan" }
        default   { "White" }
    }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Write-LogHeader {
    <#
    .SYNOPSIS
        Writes a formatted header to the log
    #>
    param([string]$Title)
    
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region DETECTION FUNCTIONS
#==============================================================================

function Test-AppInstalled {
    <#
    .SYNOPSIS
        Tests if the application is already installed using specified detection method
    #>
    [CmdletBinding()]
    param()
    
    Write-Log "Checking if $AppName is already installed..." -Level "INFO"
    Write-Log "Detection Method: $DetectionMethod" -Level "DEBUG"
    
    try {
        switch ($DetectionMethod) {
            "Registry" {
                return Test-RegistryDetection
            }
            "File" {
                return Test-FileDetection
            }
            "AppX" {
                return Test-AppXDetection
            }
            "Package" {
                return Test-PackageDetection
            }
            "Custom" {
                return Test-CustomDetection
            }
            "None" {
                Write-Log "Detection method set to None - assuming not installed" -Level "DEBUG"
                return $false
            }
            default {
                Write-Log "Unknown detection method: $DetectionMethod" -Level "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-Log "Error during detection: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-RegistryDetection {
    <#
    .SYNOPSIS
        Detects application via registry key/value
    #>
    
    if ([string]::IsNullOrWhiteSpace($DetectionPath)) {
        Write-Log "Registry detection requires DetectionPath parameter" -Level "ERROR"
        return $false
    }
    
    Write-Log "Checking registry path: $DetectionPath" -Level "DEBUG"
    
    # Test if registry key exists
    if (Test-Path $DetectionPath) {
        Write-Log "Registry key found: $DetectionPath" -Level "DEBUG"
        
        # If specific value specified, check it
        if (-not [string]::IsNullOrWhiteSpace($DetectionValue)) {
            try {
                $RegValue = Get-ItemProperty -Path $DetectionPath -Name $DetectionValue -ErrorAction Stop
                Write-Log "Registry value '$DetectionValue' found: $($RegValue.$DetectionValue)" -Level "DEBUG"
                
                # If version check required
                if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
                    $InstalledVersion = $RegValue.$DetectionValue
                    if (Compare-Version -Installed $InstalledVersion -Required $RequiredVersion) {
                        Write-Log "Version check passed: $InstalledVersion >= $RequiredVersion" -Level "SUCCESS"
                        return $true
                    }
                    else {
                        Write-Log "Version check failed: $InstalledVersion < $RequiredVersion" -Level "WARNING"
                        return $false
                    }
                }
                
                return $true
            }
            catch {
                Write-Log "Registry value '$DetectionValue' not found" -Level "DEBUG"
                return $false
            }
        }
        
        return $true
    }
    else {
        Write-Log "Registry key not found: $DetectionPath" -Level "DEBUG"
        return $false
    }
}

function Test-FileDetection {
    <#
    .SYNOPSIS
        Detects application via file existence
    #>
    
    if ([string]::IsNullOrWhiteSpace($DetectionPath)) {
        Write-Log "File detection requires DetectionPath parameter" -Level "ERROR"
        return $false
    }
    
    Write-Log "Checking file path: $DetectionPath" -Level "DEBUG"
    
    if (Test-Path $DetectionPath -PathType Leaf) {
        Write-Log "File found: $DetectionPath" -Level "DEBUG"
        
        # If version check required
        if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
            try {
                $FileVersion = (Get-Item $DetectionPath).VersionInfo.FileVersion
                Write-Log "File version: $FileVersion" -Level "DEBUG"
                
                if (Compare-Version -Installed $FileVersion -Required $RequiredVersion) {
                    Write-Log "Version check passed: $FileVersion >= $RequiredVersion" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Version check failed: $FileVersion < $RequiredVersion" -Level "WARNING"
                    return $false
                }
            }
            catch {
                Write-Log "Could not retrieve file version information" -Level "WARNING"
                return $true  # File exists, assume installed
            }
        }
        
        return $true
    }
    else {
        Write-Log "File not found: $DetectionPath" -Level "DEBUG"
        return $false
    }
}

function Test-AppXDetection {
    <#
    .SYNOPSIS
        Detects modern AppX/MSIX application
    #>
    
    if ([string]::IsNullOrWhiteSpace($DetectionPath)) {
        Write-Log "AppX detection requires DetectionPath (package name) parameter" -Level "ERROR"
        return $false
    }
    
    Write-Log "Checking for AppX package: $DetectionPath" -Level "DEBUG"
    
    try {
        $Package = Get-AppxPackage -Name $DetectionPath -ErrorAction SilentlyContinue
        if ($Package) {
            Write-Log "AppX package found: $($Package.Name) version $($Package.Version)" -Level "DEBUG"
            
            # Version check if required
            if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
                if (Compare-Version -Installed $Package.Version -Required $RequiredVersion) {
                    Write-Log "Version check passed: $($Package.Version) >= $RequiredVersion" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Version check failed: $($Package.Version) < $RequiredVersion" -Level "WARNING"
                    return $false
                }
            }
            
            return $true
        }
        else {
            Write-Log "AppX package not found: $DetectionPath" -Level "DEBUG"
            return $false
        }
    }
    catch {
        Write-Log "Error checking AppX package: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-PackageDetection {
    <#
    .SYNOPSIS
        Detects application via Get-Package (Windows Package Manager)
    #>
    
    if ([string]::IsNullOrWhiteSpace($DetectionPath)) {
        Write-Log "Package detection requires DetectionPath (package name) parameter" -Level "ERROR"
        return $false
    }
    
    Write-Log "Checking for installed package: $DetectionPath" -Level "DEBUG"
    
    try {
        $Package = Get-Package -Name $DetectionPath -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($Package) {
            Write-Log "Package found: $($Package.Name) version $($Package.Version)" -Level "DEBUG"
            
            # Version check if required
            if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
                if (Compare-Version -Installed $Package.Version -Required $RequiredVersion) {
                    Write-Log "Version check passed: $($Package.Version) >= $RequiredVersion" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Version check failed: $($Package.Version) < $RequiredVersion" -Level "WARNING"
                    return $false
                }
            }
            
            return $true
        }
        else {
            Write-Log "Package not found: $DetectionPath" -Level "DEBUG"
            return $false
        }
    }
    catch {
        Write-Log "Error checking package: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-CustomDetection {
    <#
    .SYNOPSIS
        Executes custom detection script block
    #>
    
    if ($null -eq $DetectionScript) {
        Write-Log "Custom detection requires DetectionScript parameter" -Level "ERROR"
        return $false
    }
    
    Write-Log "Executing custom detection script..." -Level "DEBUG"
    
    try {
        $Result = & $DetectionScript
        Write-Log "Custom detection result: $Result" -Level "DEBUG"
        return [bool]$Result
    }
    catch {
        Write-Log "Error executing custom detection script: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Compare-Version {
    <#
    .SYNOPSIS
        Compares two version strings
    #>
    param(
        [string]$Installed,
        [string]$Required
    )
    
    try {
        $InstalledVer = [version]$Installed
        $RequiredVer = [version]$Required
        return $InstalledVer -ge $RequiredVer
    }
    catch {
        # If version comparison fails, try string comparison
        Write-Log "Version comparison failed, using string comparison" -Level "DEBUG"
        return $Installed -ge $Required
    }
}

#endregion

#region INSTALLER FUNCTIONS
#==============================================================================

function Find-Installer {
    <#
    .SYNOPSIS
        Locates the installer file in configured search paths
    #>
    
    Write-Log "Searching for installer: $InstallerFileName" -Level "INFO"
    
    foreach ($SearchPath in $InstallerSearchPaths) {
        $FullPath = Join-Path $SearchPath $InstallerFileName
        Write-Log "Checking: $FullPath" -Level "DEBUG"
        
        if (Test-Path $FullPath -PathType Leaf) {
            Write-Log "Installer found: $FullPath" -Level "SUCCESS"
            return $FullPath
        }
    }
    
    # Try current directory as last resort
    if (Test-Path $InstallerFileName -PathType Leaf) {
        Write-Log "Installer found in current directory: $InstallerFileName" -Level "SUCCESS"
        return (Resolve-Path $InstallerFileName).Path
    }
    
    Write-Log "Installer not found in any search path" -Level "ERROR"
    return $null
}

function Get-InstallerType {
    <#
    .SYNOPSIS
        Determines installer type from file extension if AUTO
    #>
    param([string]$FilePath)
    
    if ($InstallerType -ne "AUTO") {
        return $InstallerType
    }
    
    $Extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($Extension) {
        ".msi"  { return "MSI" }
        ".exe"  { return "EXE" }
        ".msix" { return "MSIX" }
        ".appx" { return "APPX" }
        default {
            Write-Log "Unknown installer extension: $Extension - defaulting to EXE" -Level "WARNING"
            return "EXE"
        }
    }
}

function Install-Application {
    <#
    .SYNOPSIS
        Performs the actual installation
    #>
    param([string]$InstallerPath)
    
    $ActualInstallerType = Get-InstallerType -FilePath $InstallerPath
    
    Write-Log "Installing $AppName using $ActualInstallerType installer..." -Level "INFO"
    Write-Log "Installer: $InstallerPath" -Level "INFO"
    Write-Log "Arguments: $InstallArguments" -Level "INFO"
    Write-Log "Timeout: $TimeoutSeconds seconds" -Level "INFO"
    
    try {
        switch ($ActualInstallerType) {
            "MSI" {
                return Install-MSI -InstallerPath $InstallerPath
            }
            "EXE" {
                return Install-EXE -InstallerPath $InstallerPath
            }
            "MSIX" {
                return Install-MSIX -InstallerPath $InstallerPath
            }
            "APPX" {
                return Install-APPX -InstallerPath $InstallerPath
            }
            default {
                Write-Log "Unsupported installer type: $ActualInstallerType" -Level "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-Log "Installation failed with error: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "DEBUG"
        return $false
    }
}

function Install-MSI {
    <#
    .SYNOPSIS
        Installs MSI package
    #>
    param([string]$InstallerPath)
    
    # Build msiexec arguments
    $MSIArgs = "/i `"$InstallerPath`" $InstallArguments /qn /norestart /l*v `"$LogPath\$($AppName)_msi_install.log`""
    
    Write-Log "Executing: msiexec.exe $MSIArgs" -Level "DEBUG"
    
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MSIArgs -Wait -PassThru -NoNewWindow
    
    Write-Log "MSI installation completed with exit code: $($Process.ExitCode)" -Level "INFO"
    
    # MSI exit codes: 0 = success, 3010 = success with reboot required, 1641 = success with immediate reboot
    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010 -or $Process.ExitCode -eq 1641) {
        Write-Log "MSI installation successful" -Level "SUCCESS"
        return $true
    }
    else {
        Write-Log "MSI installation failed with exit code: $($Process.ExitCode)" -Level "ERROR"
        return $false
    }
}

function Install-EXE {
    <#
    .SYNOPSIS
        Installs EXE package
    #>
    param([string]$InstallerPath)
    
    Write-Log "Executing: `"$InstallerPath`" $InstallArguments" -Level "DEBUG"
    
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $InstallerPath
    $ProcessInfo.Arguments = $InstallArguments
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.CreateNoWindow = $true
    
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    
    [void]$Process.Start()
    
    # Wait with timeout
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        Write-Log "Installation timed out after $TimeoutSeconds seconds" -Level "ERROR"
        try {
            $Process.Kill()
        }
        catch {
            Write-Log "Failed to kill process: $_" -Level "WARNING"
        }
        return $false
    }
    
    $ExitCode = $Process.ExitCode
    $StdOut = $Process.StandardOutput.ReadToEnd()
    $StdErr = $Process.StandardError.ReadToEnd()
    
    Write-Log "EXE installation completed with exit code: $ExitCode" -Level "INFO"
    
    if ($StdOut) {
        Write-Log "Standard Output: $StdOut" -Level "DEBUG"
    }
    if ($StdErr) {
        Write-Log "Standard Error: $StdErr" -Level "DEBUG"
    }
    
    # Most silent installers return 0 for success
    if ($ExitCode -eq 0) {
        Write-Log "EXE installation successful" -Level "SUCCESS"
        return $true
    }
    else {
        Write-Log "EXE installation may have failed with exit code: $ExitCode" -Level "WARNING"
        # Some installers return non-zero even on success, so we'll validate later
        return $true
    }
}

function Install-MSIX {
    <#
    .SYNOPSIS
        Installs MSIX package
    #>
    param([string]$InstallerPath)
    
    Write-Log "Installing MSIX package: $InstallerPath" -Level "DEBUG"
    
    try {
        Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
        Write-Log "MSIX installation successful" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "MSIX installation failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Install-APPX {
    <#
    .SYNOPSIS
        Installs APPX package (same as MSIX)
    #>
    param([string]$InstallerPath)
    
    return Install-MSIX -InstallerPath $InstallerPath
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Test-InstallationSuccess {
    <#
    .SYNOPSIS
        Validates that installation was successful
    #>
    
    if (-not $ValidateInstall) {
        Write-Log "Post-install validation disabled" -Level "INFO"
        return $true
    }
    
    Write-Log "Validating installation..." -Level "INFO"
    
    # Wait a moment for installation to settle
    Start-Sleep -Seconds 3
    
    # Re-run detection
    $IsInstalled = Test-AppInstalled
    
    if ($IsInstalled) {
        Write-Log "Validation successful - $AppName is now installed" -Level "SUCCESS"
        return $true
    }
    else {
        Write-Log "Validation failed - $AppName could not be detected after installation" -Level "ERROR"
        return $false
    }
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    # Write header
    Write-LogHeader "UNIVERSAL APP INSTALLER v$ScriptVersion"
    
    Write-Log "Application: $AppName" -Level "INFO"
    Write-Log "Installer File: $InstallerFileName" -Level "INFO"
    Write-Log "Installer Type: $InstallerType" -Level "INFO"
    Write-Log "Detection Method: $DetectionMethod" -Level "INFO"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Start Time: $ScriptStartTime" -Level "INFO"
    
    # Pre-flight checks
    Write-Log " " -Level "INFO"
    Write-LogHeader "PRE-FLIGHT CHECKS"
    
    # Check if already installed
    if (Test-AppInstalled) {
        Write-Log "$AppName is already installed - no action needed" -Level "SUCCESS"
        Write-Log "Installation skipped" -Level "INFO"
        
        $EndTime = Get-Date
        $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
        Write-Log "Total execution time: $Duration seconds" -Level "INFO"
        Write-Log "Exit Code: 10 (Already Installed)" -Level "INFO"
        
        exit 10
    }
    
    Write-Log "$AppName is not currently installed" -Level "INFO"
    
    # Find installer
    Write-Log " " -Level "INFO"
    Write-LogHeader "LOCATING INSTALLER"
    
    $InstallerPath = Find-Installer
    if (-not $InstallerPath) {
        Write-Log "FATAL: Installer file not found: $InstallerFileName" -Level "ERROR"
        Write-Log "Searched paths:" -Level "ERROR"
        foreach ($Path in $InstallerSearchPaths) {
            Write-Log "  - $Path" -Level "ERROR"
        }
        exit 2
    }
    
    # Execute pre-install script if provided
    if ($null -ne $PreInstallScript) {
        Write-Log " " -Level "INFO"
        Write-LogHeader "PRE-INSTALL SCRIPT"
        
        try {
            Write-Log "Executing pre-install script..." -Level "INFO"
            & $PreInstallScript
            Write-Log "Pre-install script completed successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Pre-install script failed: $($_.Exception.Message)" -Level "ERROR"
            Write-Log "Continuing with installation anyway..." -Level "WARNING"
        }
    }
    
    # Perform installation
    Write-Log " " -Level "INFO"
    Write-LogHeader "INSTALLATION"
    
    $InstallSuccess = Install-Application -InstallerPath $InstallerPath
    
    if (-not $InstallSuccess) {
        Write-Log "Installation failed" -Level "ERROR"
        exit 4
    }
    
    # Execute post-install script if provided
    if ($null -ne $PostInstallScript) {
        Write-Log " " -Level "INFO"
        Write-LogHeader "POST-INSTALL SCRIPT"
        
        try {
            Write-Log "Executing post-install script..." -Level "INFO"
            & $PostInstallScript
            Write-Log "Post-install script completed successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Post-install script failed: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Continuing with validation..." -Level "INFO"
        }
    }
    
    # Validate installation
    Write-Log " " -Level "INFO"
    Write-LogHeader "POST-INSTALL VALIDATION"
    
    $ValidationSuccess = Test-InstallationSuccess
    
    if (-not $ValidationSuccess) {
        Write-Log "Validation failed - application may not have installed correctly" -Level "ERROR"
        exit 5
    }
    
    # Success!
    Write-Log " " -Level "INFO"
    Write-LogHeader "INSTALLATION COMPLETE"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Application: $AppName" -Level "SUCCESS"
    Write-Log "Status: Successfully Installed" -Level "SUCCESS"
    Write-Log "Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "End Time: $EndTime" -Level "INFO"
    Write-Log "Duration: $Duration seconds" -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
    Write-Log "Exit Code: 0 (Success)" -Level "SUCCESS"
    
    exit 0
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    Write-Log "Total execution time: $Duration seconds" -Level "INFO"
    Write-Log "Exit Code: 1 (General Failure)" -Level "ERROR"
    
    exit 1
}

#endregion
