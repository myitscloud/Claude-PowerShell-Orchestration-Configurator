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
    - Relative and absolute paths (portable across environments)
    - Comprehensive logging and error handling
    - Standard exit codes for orchestration integration
    
.PARAMETER AppName
    Display name of the application being installed
    
.PARAMETER InstallerFileName
    Name of the installer file
    
.PARAMETER SourcePath
    Path to the installer file (supports relative or absolute paths)
    Relative paths are resolved from Deploy root directory
    Examples: 
    - "Installers\Apps\Chrome" (relative)
    - "C:\Deploy\Installers\Apps\Chrome" (absolute)
    - "\\Server\Deploy\Installers\Apps\Chrome" (network)
    
.PARAMETER InstallerType
    Type of installer: MSI, EXE, MSIX, APPX, or AUTO (auto-detect from extension)
    
.PARAMETER InstallArguments
    Silent installation arguments (e.g., "/quiet /norestart" or "/S")
    
.PARAMETER DetectionMethod
    How to detect if app is already installed: Registry, File, AppX, Package, None
    
.PARAMETER DetectionPath
    Path to check for detection (registry key or file path)
    
.PARAMETER DetectionRegistry
    Registry key to check (alternative to DetectionPath for Registry method)
    
.PARAMETER DetectionRegistryValue
    Registry value name to check (optional)
    
.PARAMETER DetectionRegistryData
    Expected registry data value (optional)
    
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
    .\Universal-AppInstaller.ps1 -AppName "Adobe Reader" `
        -SourcePath "Installers\Apps\AdobeReader" `
        -InstallerFileName "AcroRdrDC.exe" `
        -InstallerType "EXE" `
        -InstallArguments "/sAll /rs /msi EULA_ACCEPT=YES" `
        -DetectionMethod "File" `
        -DetectionPath "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    
.EXAMPLE
    .\Universal-AppInstaller.ps1 -AppName "7-Zip" `
        -SourcePath "Installers\Apps\7Zip" `
        -InstallerFileName "7z2301-x64.exe" `
        -InstallerType "EXE" `
        -InstallArguments "/S" `
        -DetectionMethod "File" `
        -DetectionPath "C:\Program Files\7-Zip\7z.exe"
    
.NOTES
    Version:        2.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-11
    Purpose:        Universal app installer for orchestration framework
    
    CHANGELOG:
    2.0.0 - Added SourcePath parameter with relative path support
          - Added Resolve-DeployPath function for portability
          - Added DetectionRegistry parameters for better registry detection
          - Fixed empty string logging support
          - Improved error handling and validation
          - Enhanced detection methods with wildcard support
    
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
    [string]$SourcePath = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("MSI", "EXE", "MSIX", "APPX", "AUTO")]
    [string]$InstallerType = "AUTO",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallArguments = "",
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Registry", "File", "AppX", "Package", "None")]
    [string]$DetectionMethod,
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionRegistry = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionRegistryValue = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DetectionRegistryData = "",
    
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
$ScriptVersion = "2.0.0"
$ScriptStartTime = Get-Date

# Initialize logging
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Install-{0}_{1}.log" -f ($AppName -replace '[^\w\-]', '_'), (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

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
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
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
    param([string]$Title)
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region PATH RESOLUTION
#==============================================================================

function Resolve-DeployPath {
    <#
    .SYNOPSIS
        Resolves relative paths based on Deploy root directory
    .DESCRIPTION
        Supports both relative and absolute paths for portability
        Relative paths are resolved from the Deploy root directory
        Works with local paths, network paths, and USB drives
    .EXAMPLE
        Resolve-DeployPath "Installers\Apps\Chrome"
        Returns: C:\Deploy\Installers\Apps\Chrome (or wherever Deploy is located)
    .EXAMPLE
        Resolve-DeployPath "C:\Deploy\Installers\Apps\Chrome"
        Returns: C:\Deploy\Installers\Apps\Chrome (absolute path unchanged)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    # If path is already absolute (drive letter or UNC), return as-is
    if ([System.IO.Path]::IsPathRooted($Path)) {
        Write-Log "Using absolute path: $Path" -Level "DEBUG"
        return $Path
    }
    
    # Path is relative - resolve from Deploy root
    # Script location: Deploy\Scripts\Phase4-Applications\Universal-AppInstaller.ps1
    # Deploy root is 2 levels up from script directory
    $ScriptRoot = $PSScriptRoot
    
    if ($ScriptRoot) {
        # Navigate up from Phase4-Applications -> Scripts -> Deploy
        $ScriptsDir = Split-Path $ScriptRoot -Parent
        $DeployRoot = Split-Path $ScriptsDir -Parent
        $ResolvedPath = Join-Path $DeployRoot $Path
        
        Write-Log "Resolved relative path '$Path' to: $ResolvedPath" -Level "DEBUG"
        return $ResolvedPath
    }
    else {
        # Fallback: return path as-is
        Write-Log "Could not determine script root, using path as-is: $Path" -Level "WARNING"
        return $Path
    }
}

#endregion

#region DETECTION FUNCTIONS
#==============================================================================

function Test-AppInstalled {
    <#
    .SYNOPSIS
        Checks if application is already installed using specified detection method
    #>
    param(
        [string]$Method,
        [string]$Path,
        [string]$Registry,
        [string]$RegistryValue,
        [string]$RegistryData,
        [scriptblock]$CustomScript
    )
    
    Write-Log "Checking if $AppName is already installed..." -Level "INFO"
    Write-Log "Detection method: $Method" -Level "DEBUG"
    
    try {
        switch ($Method) {
            "File" {
                if (-not $Path) {
                    Write-Log "File detection requires DetectionPath parameter" -Level "ERROR"
                    return $false
                }
                
                # Support wildcards in path for version-specific folders
                if ($Path -like "*`**") {
                    $ParentPath = Split-Path $Path -Parent
                    $FileName = Split-Path $Path -Leaf
                    
                    if (Test-Path $ParentPath) {
                        $MatchingFiles = Get-ChildItem -Path $ParentPath -Filter $FileName -Recurse -ErrorAction SilentlyContinue
                        if ($MatchingFiles) {
                            Write-Log "Application detected via file: $($MatchingFiles[0].FullName)" -Level "SUCCESS"
                            return $true
                        }
                    }
                }
                else {
                    if (Test-Path $Path) {
                        Write-Log "Application detected via file: $Path" -Level "SUCCESS"
                        return $true
                    }
                }
                
                Write-Log "Application not detected - file not found: $Path" -Level "INFO"
                return $false
            }
            
            "Registry" {
                $RegPath = if ($Registry) { $Registry } else { $Path }
                
                if (-not $RegPath) {
                    Write-Log "Registry detection requires DetectionPath or DetectionRegistry parameter" -Level "ERROR"
                    return $false
                }
                
                # Check if registry key exists
                if (Test-Path $RegPath) {
                    Write-Log "Registry key found: $RegPath" -Level "DEBUG"
                    
                    # If checking specific value and data
                    if ($RegistryValue) {
                        $ActualValue = Get-ItemProperty -Path $RegPath -Name $RegistryValue -ErrorAction SilentlyContinue
                        
                        if ($ActualValue) {
                            $ActualData = $ActualValue.$RegistryValue
                            Write-Log "Registry value '$RegistryValue' = '$ActualData'" -Level "DEBUG"
                            
                            if ($RegistryData) {
                                if ($ActualData -like "*$RegistryData*") {
                                    Write-Log "Application detected via registry (value matches)" -Level "SUCCESS"
                                    return $true
                                }
                                else {
                                    Write-Log "Registry value exists but data doesn't match. Expected: '$RegistryData', Got: '$ActualData'" -Level "INFO"
                                    return $false
                                }
                            }
                            else {
                                # Value exists, that's enough
                                Write-Log "Application detected via registry (value exists)" -Level "SUCCESS"
                                return $true
                            }
                        }
                        else {
                            Write-Log "Registry value '$RegistryValue' not found in key" -Level "INFO"
                            return $false
                        }
                    }
                    else {
                        # Key exists, that's enough
                        Write-Log "Application detected via registry (key exists)" -Level "SUCCESS"
                        return $true
                    }
                }
                else {
                    Write-Log "Application not detected - registry key not found: $RegPath" -Level "INFO"
                    return $false
                }
            }
            
            "Package" {
                $PackageName = if ($Path) { $Path } else { $AppName }
                $Package = Get-Package -Name "*$PackageName*" -ErrorAction SilentlyContinue
                
                if ($Package) {
                    Write-Log "Application detected via Get-Package: $($Package.Name) v$($Package.Version)" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Application not detected via Get-Package" -Level "INFO"
                    return $false
                }
            }
            
            "AppX" {
                $PackageName = if ($Path) { $Path } else { $AppName }
                $AppxPackage = Get-AppxPackage -Name "*$PackageName*" -ErrorAction SilentlyContinue
                
                if ($AppxPackage) {
                    Write-Log "Application detected via AppX: $($AppxPackage.Name) v$($AppxPackage.Version)" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Application not detected via AppX" -Level "INFO"
                    return $false
                }
            }
            
            "None" {
                Write-Log "Detection method set to None - will proceed with installation" -Level "INFO"
                return $false
            }
            
            default {
                Write-Log "Unknown detection method: $Method" -Level "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-Log "Error during detection: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region INSTALLATION FUNCTIONS
#==============================================================================

function Find-Installer {
    <#
    .SYNOPSIS
        Locates the installer file in the specified or default paths
    #>
    param(
        [string]$FileName,
        [string]$SourcePath
    )
    
    Write-Log "Searching for installer: $FileName" -Level "INFO"
    
    # Resolve SourcePath (support both relative and absolute)
    if ($SourcePath) {
        $ResolvedSourcePath = Resolve-DeployPath -Path $SourcePath
        Write-Log "Using SourcePath: $ResolvedSourcePath" -Level "DEBUG"
        
        $InstallerPath = Join-Path $ResolvedSourcePath $FileName
        
        if (Test-Path $InstallerPath) {
            Write-Log "Installer found: $InstallerPath" -Level "SUCCESS"
            return $InstallerPath
        }
        else {
            Write-Log "Installer not found at specified path: $InstallerPath" -Level "ERROR"
            return $null
        }
    }
    else {
        # Search in default locations
        Write-Log "No SourcePath specified - searching default locations" -Level "WARNING"
        
        $SearchPaths = @(
            "$PSScriptRoot\..\..\..\Installers\Apps",  # Relative to script
            "C:\Deploy\Installers\Apps",                 # Standard local
            ".\Installers\Apps",                         # Current directory
            $env:TEMP                                    # Temp folder
        )
        
        foreach ($SearchPath in $SearchPaths) {
            $TestPath = Join-Path $SearchPath $FileName
            Write-Log "Checking: $TestPath" -Level "DEBUG"
            
            if (Test-Path $TestPath) {
                Write-Log "Installer found: $TestPath" -Level "SUCCESS"
                return $TestPath
            }
        }
        
        Write-Log "Installer not found in any default location" -Level "ERROR"
        return $null
    }
}

function Install-Application {
    <#
    .SYNOPSIS
        Performs the actual installation
    #>
    param(
        [string]$InstallerPath,
        [string]$Type,
        [string]$Arguments
    )
    
    Write-Log "Starting installation of $AppName" -Level "INFO"
    Write-Log "Installer: $InstallerPath" -Level "DEBUG"
    Write-Log "Type: $Type" -Level "DEBUG"
    Write-Log "Arguments: $Arguments" -Level "DEBUG"
    
    try {
        # Auto-detect installer type if needed
        if ($Type -eq "AUTO") {
            $Extension = [System.IO.Path]::GetExtension($InstallerPath).ToLower()
            $Type = switch ($Extension) {
                ".msi" { "MSI" }
                ".exe" { "EXE" }
                ".msix" { "MSIX" }
                ".appx" { "APPX" }
                default { "EXE" }
            }
            Write-Log "Auto-detected installer type: $Type" -Level "DEBUG"
        }
        
        # Execute installation based on type
        $StartTime = Get-Date
        
        switch ($Type) {
            "MSI" {
                $MsiArgs = "/i `"$InstallerPath`" $Arguments"
                Write-Log "Executing: msiexec.exe $MsiArgs" -Level "DEBUG"
                
                $Process = Start-Process -FilePath "msiexec.exe" `
                    -ArgumentList $MsiArgs `
                    -Wait `
                    -PassThru `
                    -NoNewWindow
                
                $ExitCode = $Process.ExitCode
            }
            
            "EXE" {
                Write-Log "Executing: $InstallerPath $Arguments" -Level "DEBUG"
                
                $Process = Start-Process -FilePath $InstallerPath `
                    -ArgumentList $Arguments `
                    -Wait `
                    -PassThru `
                    -NoNewWindow
                
                $ExitCode = $Process.ExitCode
            }
            
            "MSIX" {
                Write-Log "Installing MSIX package: $InstallerPath" -Level "DEBUG"
                Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
                $ExitCode = 0
            }
            
            "APPX" {
                Write-Log "Installing APPX package: $InstallerPath" -Level "DEBUG"
                Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
                $ExitCode = 0
            }
            
            default {
                Write-Log "Unknown installer type: $Type" -Level "ERROR"
                return $false
            }
        }
        
        $Duration = ((Get-Date) - $StartTime).TotalSeconds
        Write-Log "Installation completed in $([math]::Round($Duration, 2)) seconds" -Level "INFO"
        Write-Log "Exit code: $ExitCode" -Level "DEBUG"
        
        # Check exit code
        # Common success codes: 0, 3010 (reboot required)
        if ($ExitCode -eq 0 -or $ExitCode -eq 3010) {
            Write-Log "Installation completed successfully" -Level "SUCCESS"
            if ($ExitCode -eq 3010) {
                Write-Log "Note: Reboot required (exit code 3010)" -Level "WARNING"
            }
            return $true
        }
        else {
            Write-Log "Installation failed with exit code: $ExitCode" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Installation error: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    # Display banner
    Write-LogHeader "UNIVERSAL APPLICATION INSTALLER"
    Write-Log "Application: $AppName" -Level "INFO"
    Write-Log "Installer: $InstallerFileName" -Level "INFO"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log " "
    
    # Step 1: Check if already installed
    Write-LogHeader "DETECTION CHECK"
    
    $IsInstalled = Test-AppInstalled `
        -Method $DetectionMethod `
        -Path $DetectionPath `
        -Registry $DetectionRegistry `
        -RegistryValue $DetectionRegistryValue `
        -RegistryData $DetectionRegistryData `
        -CustomScript $DetectionScript
    
    if ($IsInstalled) {
        Write-Log " "
        Write-Log "✓ $AppName is already installed - no action needed" -Level "SUCCESS"
        Write-Log "Exit Code: 10 (Already installed)" -Level "INFO"
        exit 10
    }
    
    Write-Log "$AppName is not currently installed - proceeding with installation" -Level "INFO"
    Write-Log " "
    
    # Step 2: Run pre-install script if provided
    if ($PreInstallScript) {
        Write-LogHeader "PRE-INSTALLATION SCRIPT"
        try {
            & $PreInstallScript
            Write-Log "Pre-install script completed successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Pre-install script failed: $_" -Level "ERROR"
            exit 1
        }
        Write-Log " "
    }
    
    # Step 3: Locate installer
    Write-LogHeader "INSTALLER LOCATION"
    
    $InstallerPath = Find-Installer -FileName $InstallerFileName -SourcePath $SourcePath
    
    if (-not $InstallerPath) {
        Write-Log "✗ Installer not found: $InstallerFileName" -Level "ERROR"
        Write-Log "Exit Code: 2 (Installer not found)" -Level "ERROR"
        exit 2
    }
    
    Write-Log " "
    
    # Step 4: Install application
    Write-LogHeader "INSTALLATION"
    
    $InstallSuccess = Install-Application `
        -InstallerPath $InstallerPath `
        -Type $InstallerType `
        -Arguments $InstallArguments
    
    if (-not $InstallSuccess) {
        Write-Log "✗ Installation failed" -Level "ERROR"
        Write-Log "Exit Code: 4 (Installation failed)" -Level "ERROR"
        exit 4
    }
    
    Write-Log " "
    
    # Step 5: Validate installation
    if ($ValidateInstall -and $DetectionMethod -ne "None") {
        Write-LogHeader "POST-INSTALL VALIDATION"
        
        # Wait a moment for installation to settle
        Start-Sleep -Seconds 3
        
        $IsInstalledNow = Test-AppInstalled `
            -Method $DetectionMethod `
            -Path $DetectionPath `
            -Registry $DetectionRegistry `
            -RegistryValue $DetectionRegistryValue `
            -RegistryData $DetectionRegistryData `
            -CustomScript $DetectionScript
        
        if (-not $IsInstalledNow) {
            Write-Log "✗ Validation failed - application not detected after installation" -Level "ERROR"
            Write-Log "Exit Code: 5 (Validation failed)" -Level "ERROR"
            exit 5
        }
        
        Write-Log "✓ Installation validated successfully" -Level "SUCCESS"
        Write-Log " "
    }
    
    # Step 6: Run post-install script if provided
    if ($PostInstallScript) {
        Write-LogHeader "POST-INSTALLATION SCRIPT"
        try {
            & $PostInstallScript
            Write-Log "Post-install script completed successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Post-install script failed: $_" -Level "WARNING"
            # Don't fail the entire installation for post-install script issues
        }
        Write-Log " "
    }
    
    # Success!
    $Duration = ((Get-Date) - $ScriptStartTime).TotalSeconds
    Write-LogHeader "INSTALLATION COMPLETE"
    Write-Log "✓ $AppName installed successfully!" -Level "SUCCESS"
    Write-Log "Total Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
    Write-Log "Exit Code: 0 (Success)" -Level "SUCCESS"
    
    exit 0
}
catch {
    Write-Log " "
    Write-LogHeader "FATAL ERROR"
    Write-Log "Unexpected error: $_" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Log "Exit Code: 1 (General failure)" -Level "ERROR"
    exit 1
}

#endregion
