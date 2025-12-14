<#
.SYNOPSIS
    Installs hardware drivers for the system
    
.DESCRIPTION
    Task script for orchestration engine that installs hardware-specific drivers.
    Supports automatic driver detection via Windows Update, manufacturer-specific
    driver packages, and PnP driver installation from repositories.
    
.PARAMETER DriverSource
    Path to driver repository. Can be network share or local path.
    
.PARAMETER AutoDetectHardware
    Automatically detect hardware and install appropriate drivers. Default: True
    
.PARAMETER UseWindowsUpdate
    Use Windows Update to find and install drivers. Default: True
    
.PARAMETER Manufacturer
    Force specific manufacturer (Dell, HP, Lenovo, etc.). Default: Auto-detect
    
.PARAMETER Model
    Force specific model. Default: Auto-detect
    
.PARAMETER DriverCategories
    Categories of drivers to install. Default: All
    Options: Network, Display, Chipset, Audio, Storage, All
    
.PARAMETER InstallOEMDrivers
    Install OEM/manufacturer-specific drivers. Default: True
    
.PARAMETER RecurseDriverPath
    Recursively search driver path for .inf files. Default: True
    
.PARAMETER ForceReinstall
    Force reinstall of drivers even if already installed. Default: False
    
.PARAMETER SkipSignatureCheck
    Skip driver signature verification (not recommended). Default: False
    
.PARAMETER MaxDriverInstallTimeMins
    Maximum time to wait for driver installation in minutes. Default: 30
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\Install-Drivers.ps1 -DriverSource "\\FileServer\Drivers" -AutoDetectHardware $true
    
.EXAMPLE
    .\Install-Drivers.ps1 -UseWindowsUpdate $true -DriverCategories "Network,Display"
    
.NOTES
    Task ID: CRIT-003
    Version: 1.0.0
    Author: IT Infrastructure Team
    Requires: Administrator privileges
    
.OUTPUTS
    Returns exit code:
    0 = Success (drivers installed)
    1 = Failed (driver installation error)
    2 = Already compliant (all drivers current)
    3 = Driver source not found
    4 = No compatible drivers found
    5 = Hardware detection failed
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DriverSource = "",
    
    [Parameter(Mandatory=$false)]
    [bool]$AutoDetectHardware = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$UseWindowsUpdate = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$Manufacturer = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Model = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DriverCategories = "All",
    
    [Parameter(Mandatory=$false)]
    [bool]$InstallOEMDrivers = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$RecurseDriverPath = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ForceReinstall = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$SkipSignatureCheck = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDriverInstallTimeMins = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.0"
$TaskID = "CRIT-003"
$TaskName = "Install Hardware Drivers"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "Install-Drivers_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Exit codes
$ExitCode_Success = 0
$ExitCode_Failed = 1
$ExitCode_AlreadyCompliant = 2
$ExitCode_DriverSourceNotFound = 3
$ExitCode_NoCompatibleDrivers = 4
$ExitCode_RebootRequired = 5
$ExitCode_HardwareDetectionFailed = 6

# Driver tracking
$Global:DriverResults = @{
    TotalDevicesFound = 0
    TotalDriversInstalled = 0
    TotalDriversFailed = 0
    DevicesWithoutDrivers = @()
    InstalledDrivers = @()
    FailedDrivers = @()
    RebootRequired = $false
}

# Hardware information
$Global:HardwareInfo = @{
    Manufacturer = ""
    Model = ""
    SerialNumber = ""
    BIOSVersion = ""
    SystemSKU = ""
}

# Parse driver categories
$Categories = $DriverCategories -split ',' | ForEach-Object { $_.Trim() }

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

#region HARDWARE DETECTION FUNCTIONS
#==============================================================================

function Get-SystemHardwareInfo {
    <#
    .SYNOPSIS
        Detects system manufacturer and model
    #>
    
    Write-TaskLog "Detecting system hardware information..." -Level "INFO"
    
    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $BaseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
        
        $Global:HardwareInfo.Manufacturer = $ComputerSystem.Manufacturer
        $Global:HardwareInfo.Model = $ComputerSystem.Model
        $Global:HardwareInfo.SerialNumber = $BIOS.SerialNumber
        $Global:HardwareInfo.BIOSVersion = $BIOS.SMBIOSBIOSVersion
        $Global:HardwareInfo.SystemSKU = $ComputerSystem.SystemSKUNumber
        
        # Clean up manufacturer name
        $Global:HardwareInfo.Manufacturer = $Global:HardwareInfo.Manufacturer.Trim()
        
        Write-TaskLog "System Information:" -Level "INFO"
        Write-TaskLog "  Manufacturer: $($Global:HardwareInfo.Manufacturer)" -Level "INFO"
        Write-TaskLog "  Model: $($Global:HardwareInfo.Model)" -Level "INFO"
        Write-TaskLog "  Serial Number: $($Global:HardwareInfo.SerialNumber)" -Level "INFO"
        Write-TaskLog "  BIOS Version: $($Global:HardwareInfo.BIOSVersion)" -Level "INFO"
        
        if ($Global:HardwareInfo.SystemSKU) {
            Write-TaskLog "  System SKU: $($Global:HardwareInfo.SystemSKU)" -Level "DEBUG"
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error detecting hardware information: $_" -Level "ERROR"
        return $false
    }
}

function Get-MissingDriverDevices {
    <#
    .SYNOPSIS
        Finds devices with missing or problematic drivers
    #>
    
    Write-TaskLog "Scanning for devices with missing drivers..." -Level "INFO"
    
    try {
        # Get all PnP devices
        $AllDevices = Get-PnpDevice -ErrorAction Stop
        
        # Find devices with problems
        $ProblematicDevices = $AllDevices | Where-Object { 
            $_.Status -ne "OK" -or 
            $_.Problem -ne 0 -or
            $_.ConfigManagerErrorCode -ne 0
        }
        
        Write-TaskLog "Total devices found: $($AllDevices.Count)" -Level "INFO"
        Write-TaskLog "Devices with issues: $($ProblematicDevices.Count)" -Level "INFO"
        
        if ($ProblematicDevices.Count -gt 0) {
            Write-TaskLog "`nDevices requiring attention:" -Level "INFO"
            
            foreach ($Device in $ProblematicDevices) {
                $DeviceInfo = @{
                    FriendlyName = $Device.FriendlyName
                    InstanceId = $Device.InstanceId
                    Status = $Device.Status
                    Problem = $Device.Problem
                    Class = $Device.Class
                    DeviceID = $Device.DeviceID
                }
                
                $Global:DriverResults.DevicesWithoutDrivers += $DeviceInfo
                $Global:DriverResults.TotalDevicesFound++
                
                $ProblemText = switch ($Device.Problem) {
                    0 { "No Problem" }
                    1 { "Not Configured" }
                    10 { "Device Cannot Start" }
                    12 { "Not Enough Resources" }
                    18 { "Reinstall Driver" }
                    22 { "Device Disabled" }
                    24 { "Device Not Present" }
                    28 { "Driver Not Installed" }
                    default { "Error Code $($Device.Problem)" }
                }
                
                Write-TaskLog "  - $($Device.FriendlyName) [$($Device.Class)]" -Level "WARNING"
                Write-TaskLog "    Status: $($Device.Status) | Problem: $ProblemText" -Level "DEBUG"
                Write-TaskLog "    Instance ID: $($Device.InstanceId)" -Level "DEBUG"
            }
        }
        else {
            Write-TaskLog "✓ All devices appear to have working drivers" -Level "SUCCESS"
        }
        
        return $ProblematicDevices
    }
    catch {
        Write-TaskLog "Error scanning for missing drivers: $_" -Level "ERROR"
        return @()
    }
}

function Get-DevicesByCategory {
    <#
    .SYNOPSIS
        Gets devices filtered by category
    #>
    
    if ($Categories -contains "All") {
        Write-TaskLog "Processing all device categories" -Level "INFO"
        return Get-PnpDevice -ErrorAction SilentlyContinue
    }
    
    Write-TaskLog "Filtering devices by categories: $($Categories -join ', ')" -Level "INFO"
    
    $FilteredDevices = @()
    
    # Map friendly category names to PnP class names
    $CategoryMap = @{
        "Network" = @("Net", "Network")
        "Display" = @("Display", "Monitor")
        "Chipset" = @("System", "HDC")
        "Audio" = @("Media", "MEDIA", "AudioEndpoint")
        "Storage" = @("SCSIAdapter", "HDC", "DiskDrive")
    }
    
    foreach ($Category in $Categories) {
        if ($CategoryMap.ContainsKey($Category)) {
            $ClassNames = $CategoryMap[$Category]
            foreach ($ClassName in $ClassNames) {
                $Devices = Get-PnpDevice -Class $ClassName -ErrorAction SilentlyContinue
                if ($Devices) {
                    $FilteredDevices += $Devices
                }
            }
        }
    }
    
    Write-TaskLog "Found $($FilteredDevices.Count) device(s) in specified categories" -Level "INFO"
    
    return $FilteredDevices
}

#endregion

#region DRIVER SOURCE FUNCTIONS
#==============================================================================

function Test-DriverSourceAvailability {
    <#
    .SYNOPSIS
        Verifies driver source is accessible
    #>
    
    if (-not $DriverSource) {
        Write-TaskLog "No driver source path specified" -Level "INFO"
        return $false
    }
    
    Write-TaskLog "Checking driver source accessibility..." -Level "INFO"
    Write-TaskLog "Driver Source: $DriverSource" -Level "DEBUG"
    
    try {
        if (Test-Path $DriverSource) {
            Write-TaskLog "✓ Driver source is accessible" -Level "SUCCESS"
            
            # Check for drivers in the path
            $INFFiles = Get-ChildItem -Path $DriverSource -Filter "*.inf" -Recurse:$RecurseDriverPath -ErrorAction SilentlyContinue
            
            if ($INFFiles) {
                Write-TaskLog "Found $($INFFiles.Count) driver package(s) (.inf files)" -Level "INFO"
                return $true
            }
            else {
                Write-TaskLog "⚠ No driver packages (.inf files) found in source" -Level "WARNING"
                return $false
            }
        }
        else {
            Write-TaskLog "✗ Driver source path not accessible: $DriverSource" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-TaskLog "Error accessing driver source: $_" -Level "ERROR"
        return $false
    }
}

function Get-ManufacturerDriverPath {
    <#
    .SYNOPSIS
        Determines manufacturer-specific driver path
    #>
    
    if (-not $DriverSource) {
        return $null
    }
    
    $ManufacturerName = if ($Manufacturer) { $Manufacturer } else { $Global:HardwareInfo.Manufacturer }
    $ModelName = if ($Model) { $Model } else { $Global:HardwareInfo.Model }
    
    Write-TaskLog "Looking for manufacturer-specific driver path..." -Level "DEBUG"
    
    # Common manufacturer folder name variations
    $ManufacturerVariations = @(
        $ManufacturerName,
        $ManufacturerName.Replace(" ", ""),
        $ManufacturerName.Replace(" ", "_")
    )
    
    # Check for manufacturer-specific paths
    foreach ($MfgName in $ManufacturerVariations) {
        $PossiblePaths = @(
            (Join-Path $DriverSource $MfgName),
            (Join-Path $DriverSource "$MfgName\$ModelName"),
            (Join-Path $DriverSource "$MfgName\$($Global:HardwareInfo.SystemSKU)")
        )
        
        foreach ($Path in $PossiblePaths) {
            if (Test-Path $Path) {
                Write-TaskLog "✓ Found manufacturer path: $Path" -Level "SUCCESS"
                return $Path
            }
        }
    }
    
    Write-TaskLog "No manufacturer-specific path found - using root driver source" -Level "INFO"
    return $DriverSource
}

#endregion

#region DRIVER INSTALLATION FUNCTIONS
#==============================================================================

function Install-DriversFromWindowsUpdate {
    <#
    .SYNOPSIS
        Installs drivers from Windows Update
    #>
    
    Write-TaskLog "`n=== Installing Drivers from Windows Update ===" -Level "INFO"
    
    try {
        # Check if PSWindowsUpdate module is available
        $PSWUModule = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue
        
        if (-not $PSWUModule) {
            Write-TaskLog "PSWindowsUpdate module not available - attempting to install..." -Level "INFO"
            
            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -ErrorAction Stop
                Import-Module PSWindowsUpdate -Force
                Write-TaskLog "✓ PSWindowsUpdate module installed" -Level "SUCCESS"
            }
            catch {
                Write-TaskLog "Could not install PSWindowsUpdate module - using alternative method" -Level "WARNING"
                return Install-DriversFromWU_Native
            }
        }
        else {
            Import-Module PSWindowsUpdate -Force
        }
        
        # Search for driver updates
        Write-TaskLog "Searching for driver updates from Windows Update..." -Level "INFO"
        
        $DriverUpdates = Get-WindowsUpdate -MicrosoftUpdate -Category "Drivers" -ErrorAction Stop
        
        if (-not $DriverUpdates -or $DriverUpdates.Count -eq 0) {
            Write-TaskLog "No driver updates available from Windows Update" -Level "INFO"
            return $false
        }
        
        Write-TaskLog "Found $($DriverUpdates.Count) driver update(s)" -Level "INFO"
        
        # Display available drivers
        foreach ($Update in $DriverUpdates) {
            Write-TaskLog "  - $($Update.Title)" -Level "INFO"
        }
        
        # Install driver updates
        Write-TaskLog "`nInstalling driver updates..." -Level "INFO"
        
        $InstallResults = Install-WindowsUpdate -MicrosoftUpdate -Category "Drivers" -AcceptAll -IgnoreReboot -ErrorAction Stop
        
        # Process results
        foreach ($Result in $InstallResults) {
            if ($Result.Result -eq "Installed" -or $Result.Result -eq "Succeeded") {
                Write-TaskLog "✓ Installed: $($Result.Title)" -Level "SUCCESS"
                
                $Global:DriverResults.InstalledDrivers += @{
                    Name = $Result.Title
                    KB = $Result.KB
                    Source = "Windows Update"
                    Status = "Installed"
                }
                
                $Global:DriverResults.TotalDriversInstalled++
            }
            else {
                Write-TaskLog "✗ Failed: $($Result.Title)" -Level "ERROR"
                
                $Global:DriverResults.FailedDrivers += @{
                    Name = $Result.Title
                    KB = $Result.KB
                    Source = "Windows Update"
                    Error = $Result.Result
                }
                
                $Global:DriverResults.TotalDriversFailed++
            }
            
            if ($Result.RebootRequired) {
                $Global:DriverResults.RebootRequired = $true
            }
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error installing drivers from Windows Update: $_" -Level "ERROR"
        return $false
    }
}

function Install-DriversFromWU_Native {
    <#
    .SYNOPSIS
        Installs drivers using native Windows Update API
    #>
    
    Write-TaskLog "Using native Windows Update API for drivers..." -Level "INFO"
    
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        
        # Search specifically for driver updates
        Write-TaskLog "Searching for driver updates..." -Level "INFO"
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Driver'")
        
        if ($SearchResult.Updates.Count -eq 0) {
            Write-TaskLog "No driver updates found" -Level "INFO"
            return $false
        }
        
        Write-TaskLog "Found $($SearchResult.Updates.Count) driver update(s)" -Level "INFO"
        
        # Create collection of updates to install
        $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        
        foreach ($Update in $SearchResult.Updates) {
            Write-TaskLog "  - $($Update.Title)" -Level "INFO"
            $Update.AcceptEula()
            $UpdatesToInstall.Add($Update) | Out-Null
        }
        
        # Download drivers
        Write-TaskLog "`nDownloading driver updates..." -Level "INFO"
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToInstall
        $DownloadResult = $Downloader.Download()
        
        if ($DownloadResult.ResultCode -ne 2) {
            Write-TaskLog "Driver download failed" -Level "ERROR"
            return $false
        }
        
        Write-TaskLog "✓ Driver download completed" -Level "SUCCESS"
        
        # Install drivers
        Write-TaskLog "`nInstalling driver updates..." -Level "INFO"
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallResult = $Installer.Install()
        
        # Process results
        for ($i = 0; $i -lt $UpdatesToInstall.Count; $i++) {
            $Update = $UpdatesToInstall.Item($i)
            $Result = $InstallResult.GetUpdateResult($i)
            
            if ($Result.ResultCode -eq 2) {
                Write-TaskLog "✓ Installed: $($Update.Title)" -Level "SUCCESS"
                
                $Global:DriverResults.InstalledDrivers += @{
                    Name = $Update.Title
                    Source = "Windows Update"
                    Status = "Installed"
                }
                
                $Global:DriverResults.TotalDriversInstalled++
            }
            else {
                Write-TaskLog "✗ Failed: $($Update.Title) (Code: $($Result.ResultCode))" -Level "ERROR"
                
                $Global:DriverResults.FailedDrivers += @{
                    Name = $Update.Title
                    Source = "Windows Update"
                    Error = "Result Code $($Result.ResultCode)"
                }
                
                $Global:DriverResults.TotalDriversFailed++
            }
            
            if ($Result.RebootRequired) {
                $Global:DriverResults.RebootRequired = $true
            }
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error with native Windows Update API: $_" -Level "ERROR"
        return $false
    }
}

function Install-DriversFromRepository {
    <#
    .SYNOPSIS
        Installs drivers from local/network repository
    #>
    param([string]$DriverPath)
    
    Write-TaskLog "`n=== Installing Drivers from Repository ===" -Level "INFO"
    Write-TaskLog "Driver Path: $DriverPath" -Level "INFO"
    
    try {
        # Get all .inf files
        $INFFiles = Get-ChildItem -Path $DriverPath -Filter "*.inf" -Recurse:$RecurseDriverPath -ErrorAction Stop
        
        if ($INFFiles.Count -eq 0) {
            Write-TaskLog "No driver packages (.inf files) found in path" -Level "WARNING"
            return $false
        }
        
        Write-TaskLog "Found $($INFFiles.Count) driver package(s)" -Level "INFO"
        
        # Install each driver package
        $InstalledCount = 0
        $FailedCount = 0
        
        foreach ($INFFile in $INFFiles) {
            Write-TaskLog "`nProcessing: $($INFFile.Name)" -Level "INFO"
            Write-TaskLog "Path: $($INFFile.FullName)" -Level "DEBUG"
            
            try {
                # Use pnputil to add and install driver
                $PnpUtilArgs = @("/add-driver", "`"$($INFFile.FullName)`"", "/install")
                
                Write-TaskLog "Executing: pnputil.exe $($PnpUtilArgs -join ' ')" -Level "DEBUG"
                
                $Process = Start-Process -FilePath "pnputil.exe" -ArgumentList $PnpUtilArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\pnputil_out.txt" -RedirectStandardError "$env:TEMP\pnputil_err.txt"
                
                $ExitCode = $Process.ExitCode
                
                # Read output
                $Output = Get-Content "$env:TEMP\pnputil_out.txt" -ErrorAction SilentlyContinue
                $ErrorOutput = Get-Content "$env:TEMP\pnputil_err.txt" -ErrorAction SilentlyContinue
                
                if ($ExitCode -eq 0) {
                    Write-TaskLog "✓ Driver installed: $($INFFile.Name)" -Level "SUCCESS"
                    
                    $Global:DriverResults.InstalledDrivers += @{
                        Name = $INFFile.Name
                        Path = $INFFile.FullName
                        Source = "Repository"
                        Status = "Installed"
                    }
                    
                    $InstalledCount++
                    $Global:DriverResults.TotalDriversInstalled++
                }
                elseif ($ExitCode -eq 259) {
                    Write-TaskLog "⚠ Driver already installed: $($INFFile.Name)" -Level "INFO"
                }
                else {
                    Write-TaskLog "✗ Driver installation failed: $($INFFile.Name) (Exit Code: $ExitCode)" -Level "WARNING"
                    
                    if ($ErrorOutput) {
                        Write-TaskLog "Error: $($ErrorOutput -join ' ')" -Level "DEBUG"
                    }
                    
                    $FailedCount++
                    $Global:DriverResults.TotalDriversFailed++
                }
                
                # Clean up temp files
                Remove-Item "$env:TEMP\pnputil_out.txt" -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\pnputil_err.txt" -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-TaskLog "✗ Error installing driver $($INFFile.Name): $_" -Level "ERROR"
                $FailedCount++
                $Global:DriverResults.TotalDriversFailed++
            }
        }
        
        Write-TaskLog "`nRepository Installation Summary:" -Level "INFO"
        Write-TaskLog "  Installed: $InstalledCount" -Level "SUCCESS"
        Write-TaskLog "  Failed: $FailedCount" -Level $(if($FailedCount -gt 0){"WARNING"}else{"INFO"})
        
        return ($InstalledCount -gt 0)
    }
    catch {
        Write-TaskLog "Error installing drivers from repository: $_" -Level "ERROR"
        return $false
    }
}

function Update-DriverForDevice {
    <#
    .SYNOPSIS
        Updates driver for a specific device
    #>
    param([object]$Device)
    
    Write-TaskLog "Attempting to update driver for: $($Device.FriendlyName)" -Level "INFO"
    
    try {
        # Try to update the device driver
        $Result = Update-PnpDevice -InstanceId $Device.InstanceId -Confirm:$false -ErrorAction Stop
        
        Write-TaskLog "✓ Driver updated for: $($Device.FriendlyName)" -Level "SUCCESS"
        
        $Global:DriverResults.InstalledDrivers += @{
            Name = $Device.FriendlyName
            InstanceId = $Device.InstanceId
            Source = "PnP Update"
            Status = "Updated"
        }
        
        $Global:DriverResults.TotalDriversInstalled++
        
        return $true
    }
    catch {
        Write-TaskLog "Could not update driver for $($Device.FriendlyName): $_" -Level "DEBUG"
        return $false
    }
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Test-DriversCompliant {
    <#
    .SYNOPSIS
        Checks if all devices have working drivers
    #>
    
    Write-TaskLog "Checking driver compliance..." -Level "INFO"
    
    $ProblematicDevices = Get-MissingDriverDevices
    
    if ($ProblematicDevices.Count -eq 0) {
        Write-TaskLog "✓ All devices have working drivers" -Level "SUCCESS"
        return $true
    }
    else {
        Write-TaskLog "$($ProblematicDevices.Count) device(s) need attention" -Level "INFO"
        return $false
    }
}

function Write-DriverSummary {
    <#
    .SYNOPSIS
        Displays final driver installation summary
    #>
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog "DRIVER INSTALLATION SUMMARY" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    Write-TaskLog "Devices Scanned: $($Global:DriverResults.TotalDevicesFound)" -Level "INFO"
    Write-TaskLog "Drivers Installed: $($Global:DriverResults.TotalDriversInstalled)" -Level $(if($Global:DriverResults.TotalDriversInstalled -gt 0){"SUCCESS"}else{"INFO"})
    Write-TaskLog "Drivers Failed: $($Global:DriverResults.TotalDriversFailed)" -Level $(if($Global:DriverResults.TotalDriversFailed -gt 0){"ERROR"}else{"INFO"})
    Write-TaskLog "Reboot Required: $($Global:DriverResults.RebootRequired)" -Level $(if($Global:DriverResults.RebootRequired){"WARNING"}else{"INFO"})
    
    if ($Global:DriverResults.InstalledDrivers.Count -gt 0) {
        Write-TaskLog "`nSuccessfully Installed Drivers:" -Level "INFO"
        foreach ($Driver in $Global:DriverResults.InstalledDrivers) {
            Write-TaskLog "  ✓ $($Driver.Name) [Source: $($Driver.Source)]" -Level "SUCCESS"
        }
    }
    
    if ($Global:DriverResults.FailedDrivers.Count -gt 0) {
        Write-TaskLog "`nFailed Driver Installations:" -Level "WARNING"
        foreach ($Driver in $Global:DriverResults.FailedDrivers) {
            Write-TaskLog "  ✗ $($Driver.Name) - $($Driver.Error)" -Level "ERROR"
        }
    }
    
    if ($Global:DriverResults.DevicesWithoutDrivers.Count -gt 0) {
        Write-TaskLog "`nDevices Still Requiring Attention:" -Level "WARNING"
        foreach ($Device in $Global:DriverResults.DevicesWithoutDrivers) {
            Write-TaskLog "  - $($Device.FriendlyName) [$($Device.Class)]" -Level "WARNING"
        }
    }
    
    Write-TaskLog "========================================`n" -Level "INFO"
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "TASK: $TaskID - $TaskName" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    Write-TaskLog "Script Version: $ScriptVersion" -Level "INFO"
    Write-TaskLog "Driver Source: $(if($DriverSource){$DriverSource}else{'Not specified'})" -Level "INFO"
    Write-TaskLog "Auto Detect Hardware: $AutoDetectHardware" -Level "INFO"
    Write-TaskLog "Use Windows Update: $UseWindowsUpdate" -Level "INFO"
    Write-TaskLog "Driver Categories: $DriverCategories" -Level "INFO"
    Write-TaskLog "Install OEM Drivers: $InstallOEMDrivers" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    
    # Step 1: Detect hardware
    Write-TaskLog "`n--- Step 1: Hardware Detection ---" -Level "INFO"
    
    if (-not (Get-SystemHardwareInfo)) {
        Write-TaskLog "Failed to detect hardware information" -Level "ERROR"
        exit $ExitCode_HardwareDetectionFailed
    }
    
    # Apply manual overrides if specified
    if ($Manufacturer) {
        Write-TaskLog "Manufacturer override: $Manufacturer" -Level "INFO"
        $Global:HardwareInfo.Manufacturer = $Manufacturer
    }
    
    if ($Model) {
        Write-TaskLog "Model override: $Model" -Level "INFO"
        $Global:HardwareInfo.Model = $Model
    }
    
    # Step 2: Check current driver status
    Write-TaskLog "`n--- Step 2: Driver Status Assessment ---" -Level "INFO"
    
    if (-not $ForceReinstall) {
        if (Test-DriversCompliant) {
            Write-TaskLog "All drivers are current and working - no action needed" -Level "SUCCESS"
            Write-TaskLog "Task completed in $([math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)) seconds" -Level "INFO"
            exit $ExitCode_AlreadyCompliant
        }
    }
    else {
        Write-TaskLog "Force reinstall enabled - proceeding with driver installation" -Level "INFO"
        Get-MissingDriverDevices | Out-Null
    }
    
    # Step 3: Determine driver sources
    Write-TaskLog "`n--- Step 3: Driver Source Validation ---" -Level "INFO"
    
    $UseRepository = $false
    $RepositoryPath = $null
    
    if ($DriverSource) {
        $SourceAvailable = Test-DriverSourceAvailability
        
        if ($SourceAvailable) {
            $UseRepository = $true
            
            # Get manufacturer-specific path if available
            if ($InstallOEMDrivers) {
                $RepositoryPath = Get-ManufacturerDriverPath
            }
            else {
                $RepositoryPath = $DriverSource
            }
            
            Write-TaskLog "Will use driver repository: $RepositoryPath" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "Driver repository not available or contains no drivers" -Level "WARNING"
            
            if (-not $UseWindowsUpdate) {
                Write-TaskLog "No driver sources available - cannot proceed" -Level "ERROR"
                exit $ExitCode_DriverSourceNotFound
            }
        }
    }
    else {
        Write-TaskLog "No driver repository specified" -Level "INFO"
    }
    
    if (-not $UseRepository -and -not $UseWindowsUpdate) {
        Write-TaskLog "No driver installation methods enabled" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    # Step 4: Install drivers from repository
    if ($UseRepository -and $RepositoryPath) {
        Write-TaskLog "`n--- Step 4: Repository Driver Installation ---" -Level "INFO"
        
        $RepositorySuccess = Install-DriversFromRepository -DriverPath $RepositoryPath
        
        if ($RepositorySuccess) {
            Write-TaskLog "✓ Repository driver installation completed" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "⚠ Repository driver installation had no new drivers to install" -Level "WARNING"
        }
    }
    else {
        Write-TaskLog "`n--- Step 4: Repository Driver Installation ---" -Level "INFO"
        Write-TaskLog "Skipping repository installation (not available or not enabled)" -Level "INFO"
    }
    
    # Step 5: Install drivers from Windows Update
    if ($UseWindowsUpdate) {
        Write-TaskLog "`n--- Step 5: Windows Update Driver Installation ---" -Level "INFO"
        
        $WUSuccess = Install-DriversFromWindowsUpdate
        
        if ($WUSuccess) {
            Write-TaskLog "✓ Windows Update driver installation completed" -Level "SUCCESS"
        }
        else {
            Write-TaskLog "No drivers available from Windows Update or installation failed" -Level "INFO"
        }
    }
    else {
        Write-TaskLog "`n--- Step 5: Windows Update Driver Installation ---" -Level "INFO"
        Write-TaskLog "Skipping Windows Update (disabled)" -Level "INFO"
    }
    
    # Step 6: Attempt to update problematic devices
    Write-TaskLog "`n--- Step 6: Device Driver Updates ---" -Level "INFO"
    
    $RemainingProblems = Get-MissingDriverDevices
    
    if ($RemainingProblems.Count -gt 0) {
        Write-TaskLog "Attempting to update drivers for $($RemainingProblems.Count) problematic device(s)..." -Level "INFO"
        
        foreach ($Device in $RemainingProblems) {
            Update-DriverForDevice -Device $Device | Out-Null
        }
    }
    else {
        Write-TaskLog "No problematic devices remaining" -Level "SUCCESS"
    }
    
    # Step 7: Final validation
    Write-TaskLog "`n--- Step 7: Final Validation ---" -Level "INFO"
    
    # Re-check for remaining issues
    $FinalProblems = Get-MissingDriverDevices
    
    if ($FinalProblems.Count -gt 0) {
        Write-TaskLog "⚠ $($FinalProblems.Count) device(s) still have driver issues" -Level "WARNING"
        Write-TaskLog "Some devices may require manufacturer-specific drivers not available via Windows Update" -Level "INFO"
    }
    else {
        Write-TaskLog "✓ All devices now have working drivers" -Level "SUCCESS"
    }
    
    # Step 8: Generate summary
    Write-TaskLog "`n--- Step 8: Summary ---" -Level "INFO"
    
    Write-DriverSummary
    
    # Determine exit code
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)
    
    if ($Global:DriverResults.TotalDriversInstalled -eq 0 -and $Global:DriverResults.TotalDriversFailed -eq 0) {
        # No drivers were installed, but check if that's because everything was already OK
        if (Test-DriversCompliant) {
            Write-TaskLog "`n========================================" -Level "SUCCESS"
            Write-TaskLog "TASK COMPLETED - NO DRIVERS NEEDED" -Level "SUCCESS"
            Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
            Write-TaskLog "All drivers are current" -Level "SUCCESS"
            Write-TaskLog "========================================" -Level "SUCCESS"
            exit $ExitCode_AlreadyCompliant
        }
        else {
            Write-TaskLog "`n========================================" -Level "WARNING"
            Write-TaskLog "TASK COMPLETED - NO COMPATIBLE DRIVERS" -Level "WARNING"
            Write-TaskLog "Duration: $Duration seconds" -Level "WARNING"
            Write-TaskLog "Some devices still need drivers but none were found" -Level "WARNING"
            Write-TaskLog "========================================" -Level "WARNING"
            exit $ExitCode_NoCompatibleDrivers
        }
    }
    elseif ($Global:DriverResults.TotalDriversFailed -gt 0) {
        Write-TaskLog "`n========================================" -Level "WARNING"
        Write-TaskLog "TASK COMPLETED WITH ERRORS" -Level "WARNING"
        Write-TaskLog "Duration: $Duration seconds" -Level "WARNING"
        Write-TaskLog "Installed: $($Global:DriverResults.TotalDriversInstalled)" -Level "SUCCESS"
        Write-TaskLog "Failed: $($Global:DriverResults.TotalDriversFailed)" -Level "ERROR"
        Write-TaskLog "========================================" -Level "WARNING"
        
        # Still consider it a success if some drivers were installed
        if ($Global:DriverResults.TotalDriversInstalled -gt 0) {
            exit $ExitCode_Success
        }
        else {
            exit $ExitCode_Failed
        }
    }
    else {
        Write-TaskLog "`n========================================" -Level "SUCCESS"
        Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
        Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
        Write-TaskLog "Installed $($Global:DriverResults.TotalDriversInstalled) driver(s)" -Level "SUCCESS"

        if ($Global:DriverResults.RebootRequired) {
            Write-TaskLog "⚠ REBOOT REQUIRED to complete driver installation" -Level "WARNING"
            Write-TaskLog "========================================" -Level "WARNING"
            exit $ExitCode_RebootRequired
        }

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
    Write-DriverSummary
    
    exit $ExitCode_Failed
}

#endregion