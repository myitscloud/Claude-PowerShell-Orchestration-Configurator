<#
.SYNOPSIS
    Installs all available Windows updates
    
.DESCRIPTION
    Task script for orchestration engine that installs ALL available Windows updates
    including optional, recommended, feature packs, and cumulative updates.
    This is the comprehensive update task that runs after critical updates,
    drivers, and prerequisites are installed to ensure 100% patch compliance.
    
.PARAMETER UpdateCategories
    Categories of updates to install. Default: All
    Options: Critical, Security, Definition, Driver, FeaturePack, ServicePack, Tool, UpdateRollup, Update, All
    
.PARAMETER MaxUpdateRounds
    Maximum number of update check/install rounds. Default: 5
    
.PARAMETER AutoReboot
    Automatically reboot if required by updates. Default: False
    
.PARAMETER RebootTimeout
    Timeout in seconds before forcing reboot. Default: 300
    
.PARAMETER IncludeDrivers
    Include driver updates. Default: False (already handled by Install-Drivers.ps1)
    
.PARAMETER IncludeOptional
    Include optional updates. Default: True
    
.PARAMETER IncludeRecommended
    Include recommended updates. Default: True
    
.PARAMETER AcceptEULA
    Accept all EULAs automatically. Default: True
    
.PARAMETER MaxDownloadTimeMins
    Maximum time to wait for downloads in minutes. Default: 90
    
.PARAMETER MaxInstallTimeMins
    Maximum time to wait for installation in minutes. Default: 180
    
.PARAMETER IgnoreRebootsUntilEnd
    Suppress reboots until all rounds complete. Default: True
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\WindowsUpdate-All.ps1 -MaxUpdateRounds 5 -IncludeOptional $true
    
.NOTES
    Task ID: CRIT-005
    Version: 1.0.0
    Author: IT Infrastructure Team
    Requires: Administrator privileges
    Should run AFTER critical updates, drivers, and .NET installation
    
.OUTPUTS
    Returns exit code:
    0 = Success (updates installed or no updates needed)
    1 = Failed
    2 = Already compliant (no updates available)
    3 = Download failed
    4 = Installation failed
    5 = Reboot required (pending)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UpdateCategories = "All",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxUpdateRounds = 5,
    
    [Parameter(Mandatory=$false)]
    [bool]$AutoReboot = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$RebootTimeout = 300,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeDrivers = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeOptional = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeRecommended = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AcceptEULA = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDownloadTimeMins = 90,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxInstallTimeMins = 180,
    
    [Parameter(Mandatory=$false)]
    [bool]$IgnoreRebootsUntilEnd = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.0"
$TaskID = "CRIT-005"
$TaskName = "Windows Update - All Updates"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "WindowsUpdate-All_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Exit codes
$ExitCode_Success = 0
$ExitCode_Failed = 1
$ExitCode_AlreadyCompliant = 2
$ExitCode_DownloadFailed = 3
$ExitCode_InstallFailed = 4
$ExitCode_RebootRequired = 5

# Update tracking
$Global:UpdateResults = @{
    TotalUpdatesFound = 0
    TotalUpdatesInstalled = 0
    TotalUpdatesFailed = 0
    TotalUpdatesSkipped = 0
    UpdateHistory = @()
    RebootRequired = $false
    RoundsCompleted = 0
}

# Parse categories
$Categories = $UpdateCategories -split ',' | ForEach-Object { $_.Trim() }

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

#region MODULE MANAGEMENT
#==============================================================================

function Install-PSWindowsUpdateModule {
    <#
    .SYNOPSIS
        Installs PSWindowsUpdate module if not present
    #>
    
    Write-TaskLog "Checking for PSWindowsUpdate module..." -Level "INFO"
    
    try {
        $Module = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue
        
        if ($Module) {
            Write-TaskLog "✓ PSWindowsUpdate module found: Version $($Module.Version)" -Level "SUCCESS"
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            return $true
        }
        
        Write-TaskLog "PSWindowsUpdate module not found - attempting to install..." -Level "WARNING"
        
        # Check if NuGet provider is installed
        $NuGetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $NuGetProvider) {
            Write-TaskLog "Installing NuGet provider..." -Level "INFO"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }
        
        # Set PSGallery as trusted (temporarily)
        $PSGalleryTrusted = (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -eq 'Trusted'
        if (-not $PSGalleryTrusted) {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
        
        # Install PSWindowsUpdate module
        Write-TaskLog "Installing PSWindowsUpdate module from PSGallery..." -Level "INFO"
        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -ErrorAction Stop
        
        # Restore PSGallery trust setting
        if (-not $PSGalleryTrusted) {
            Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted -ErrorAction SilentlyContinue
        }
        
        # Import the module
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        
        Write-TaskLog "✓ PSWindowsUpdate module installed successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Failed to install PSWindowsUpdate module: $_" -Level "ERROR"
        Write-TaskLog "Will attempt to use native Windows Update API" -Level "WARNING"
        return $false
    }
}

#endregion

#region DETECTION FUNCTIONS
#==============================================================================

function Test-PendingUpdates {
    <#
    .SYNOPSIS
        Checks if updates are available
    #>
    
    Write-TaskLog "Checking for available updates..." -Level "INFO"
    
    try {
        # Try using PSWindowsUpdate module first
        $ModuleAvailable = Get-Module -Name PSWindowsUpdate -ListAvailable
        
        if ($ModuleAvailable) {
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            
            # Build parameters for Get-WindowsUpdate
            $Params = @{
                MicrosoftUpdate = $true
                ErrorAction = 'Stop'
            }
            
            # Category filter
            if ($UpdateCategories -ne "All") {
                $Params.Category = $Categories
            }
            
            if (-not $IncludeDrivers) {
                $Params.NotCategory = "Drivers"
            }
            
            $AvailableUpdates = Get-WindowsUpdate @Params
            
            if ($AvailableUpdates) {
                Write-TaskLog "Found $($AvailableUpdates.Count) available update(s)" -Level "INFO"
                
                # Log first 10 updates
                $DisplayCount = [Math]::Min(10, $AvailableUpdates.Count)
                for ($i = 0; $i -lt $DisplayCount; $i++) {
                    Write-TaskLog "  - $($AvailableUpdates[$i].Title)" -Level "DEBUG"
                }
                
                if ($AvailableUpdates.Count -gt 10) {
                    Write-TaskLog "  ... and $($AvailableUpdates.Count - 10) more" -Level "DEBUG"
                }
                
                return $true
            }
            else {
                Write-TaskLog "No updates available" -Level "INFO"
                return $false
            }
        }
        else {
            # Fallback to COM-based Windows Update API
            Write-TaskLog "Using native Windows Update API..." -Level "DEBUG"
            
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            
            # Build search criteria
            $SearchCriteria = "IsInstalled=0"
            
            Write-TaskLog "Searching for updates with criteria: $SearchCriteria" -Level "DEBUG"
            
            $SearchResult = $UpdateSearcher.Search($SearchCriteria)
            
            if ($SearchResult.Updates.Count -gt 0) {
                Write-TaskLog "Found $($SearchResult.Updates.Count) available update(s)" -Level "INFO"
                
                # Log first 10
                $DisplayCount = [Math]::Min(10, $SearchResult.Updates.Count)
                for ($i = 0; $i -lt $DisplayCount; $i++) {
                    Write-TaskLog "  - $($SearchResult.Updates.Item($i).Title)" -Level "DEBUG"
                }
                
                if ($SearchResult.Updates.Count -gt 10) {
                    Write-TaskLog "  ... and $($SearchResult.Updates.Count - 10) more" -Level "DEBUG"
                }
                
                return $true
            }
            else {
                Write-TaskLog "No updates available" -Level "INFO"
                return $false
            }
        }
    }
    catch {
        Write-TaskLog "Error checking for updates: $_" -Level "WARNING"
        # If we can't check, assume updates might be needed
        return $true
    }
}

function Test-WindowsUpdateService {
    <#
    .SYNOPSIS
        Verifies Windows Update service is running
    #>
    
    Write-TaskLog "Checking Windows Update service status..." -Level "INFO"
    
    try {
        $WUService = Get-Service -Name wuauserv -ErrorAction Stop
        
        if ($WUService.Status -ne "Running") {
            Write-TaskLog "Windows Update service is not running - starting..." -Level "WARNING"
            Start-Service -Name wuauserv -ErrorAction Stop
            Start-Sleep -Seconds 5
            
            $WUService = Get-Service -Name wuauserv -ErrorAction Stop
            if ($WUService.Status -eq "Running") {
                Write-TaskLog "✓ Windows Update service started" -Level "SUCCESS"
                return $true
            }
            else {
                Write-TaskLog "✗ Failed to start Windows Update service" -Level "ERROR"
                return $false
            }
        }
        else {
            Write-TaskLog "✓ Windows Update service is running" -Level "SUCCESS"
            return $true
        }
    }
    catch {
        Write-TaskLog "Error checking Windows Update service: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region UPDATE INSTALLATION FUNCTIONS
#==============================================================================

function Install-UpdatesWithPSModule {
    <#
    .SYNOPSIS
        Installs updates using PSWindowsUpdate module
    #>
    param([int]$RoundNumber)
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog "UPDATE ROUND $RoundNumber of $MaxUpdateRounds" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    try {
        # Build parameters
        $Params = @{
            MicrosoftUpdate = $true
            AcceptAll = $AcceptEULA
            Install = $true
            IgnoreReboot = $IgnoreRebootsUntilEnd
            Verbose = $false
            ErrorAction = 'Stop'
        }
        
        # Category filter
        if ($UpdateCategories -ne "All") {
            $Params.Category = $Categories
        }
        
        if (-not $IncludeDrivers) {
            $Params.NotCategory = "Drivers"
        }
        
        Write-TaskLog "Starting comprehensive update installation..." -Level "INFO"
        Write-TaskLog "Categories: $(if($UpdateCategories -eq 'All'){'All'}else{$Categories -join ', '})" -Level "INFO"
        Write-TaskLog "Include Drivers: $IncludeDrivers" -Level "INFO"
        Write-TaskLog "Include Optional: $IncludeOptional" -Level "INFO"
        
        # Install updates
        $RoundStartTime = Get-Date
        $Results = Get-WindowsUpdate @Params
        $RoundDuration = ((Get-Date) - $RoundStartTime).TotalMinutes
        
        if ($Results) {
            $RoundInstalled = 0
            $RoundFailed = 0
            
            foreach ($Result in $Results) {
                $UpdateInfo = @{
                    Title = $Result.Title
                    KB = $Result.KB
                    Size = $Result.Size
                    Status = $Result.Result
                    Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Round = $RoundNumber
                }
                
                $Global:UpdateResults.UpdateHistory += $UpdateInfo
                $Global:UpdateResults.TotalUpdatesFound++
                
                if ($Result.Result -eq "Installed" -or $Result.Result -eq "Succeeded") {
                    Write-TaskLog "✓ Installed: $($Result.Title) (KB$($Result.KB))" -Level "SUCCESS"
                    $Global:UpdateResults.TotalUpdatesInstalled++
                    $RoundInstalled++
                }
                elseif ($Result.Result -eq "Failed") {
                    Write-TaskLog "✗ Failed: $($Result.Title) (KB$($Result.KB))" -Level "ERROR"
                    $Global:UpdateResults.TotalUpdatesFailed++
                    $RoundFailed++
                }
                elseif ($Result.Result -eq "Downloaded") {
                    Write-TaskLog "⚠ Downloaded but not installed: $($Result.Title)" -Level "WARNING"
                    $Global:UpdateResults.TotalUpdatesSkipped++
                }
                else {
                    Write-TaskLog "⚠ $($Result.Result): $($Result.Title) (KB$($Result.KB))" -Level "WARNING"
                }
            }
            
            # Check if reboot is required
            try {
                $RebootRequired = Get-WURebootStatus -Silent
                if ($RebootRequired) {
                    Write-TaskLog "⚠ Reboot required after this round" -Level "WARNING"
                    $Global:UpdateResults.RebootRequired = $true
                }
            }
            catch {
                Write-TaskLog "Could not check reboot status" -Level "DEBUG"
            }
            
            Write-TaskLog "`nRound $RoundNumber Summary:" -Level "INFO"
            Write-TaskLog "  Duration: $([math]::Round($RoundDuration, 2)) minutes" -Level "INFO"
            Write-TaskLog "  Installed: $RoundInstalled" -Level "SUCCESS"
            Write-TaskLog "  Failed: $RoundFailed" -Level $(if($RoundFailed -gt 0){"ERROR"}else{"INFO"})
            
            return ($RoundInstalled -gt 0)
        }
        else {
            Write-TaskLog "No updates installed in this round" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-TaskLog "Error during update installation: $_" -Level "ERROR"
        return $false
    }
}

function Install-UpdatesWithNativeAPI {
    <#
    .SYNOPSIS
        Installs updates using native Windows Update COM API
    #>
    param([int]$RoundNumber)
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog "UPDATE ROUND $RoundNumber of $MaxUpdateRounds (Native API)" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        
        # Search for updates
        Write-TaskLog "Searching for updates..." -Level "INFO"
        $SearchCriteria = "IsInstalled=0"
        $SearchResult = $UpdateSearcher.Search($SearchCriteria)
        
        if ($SearchResult.Updates.Count -eq 0) {
            Write-TaskLog "No updates found" -Level "INFO"
            return $false
        }
        
        Write-TaskLog "Found $($SearchResult.Updates.Count) update(s)" -Level "INFO"
        
        # Create update collection
        $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        
        foreach ($Update in $SearchResult.Updates) {
            # Skip drivers if requested
            if (-not $IncludeDrivers) {
                $IsDriver = $false
                foreach ($Category in $Update.Categories) {
                    if ($Category.Name -eq "Drivers") {
                        $IsDriver = $true
                        break
                    }
                }
                if ($IsDriver) {
                    Write-TaskLog "Skipping driver update: $($Update.Title)" -Level "DEBUG"
                    continue
                }
            }
            
            # Accept EULA if needed
            if ($Update.EulaAccepted -eq $false -and $AcceptEULA) {
                $Update.AcceptEula()
            }
            
            $UpdatesToInstall.Add($Update) | Out-Null
            Write-TaskLog "Queued: $($Update.Title)" -Level "INFO"
            $Global:UpdateResults.TotalUpdatesFound++
        }
        
        if ($UpdatesToInstall.Count -eq 0) {
            Write-TaskLog "No updates match specified criteria" -Level "INFO"
            return $false
        }
        
        # Download updates
        Write-TaskLog "`nDownloading $($UpdatesToInstall.Count) update(s)..." -Level "INFO"
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToInstall
        $DownloadResult = $Downloader.Download()
        
        if ($DownloadResult.ResultCode -ne 2) {
            Write-TaskLog "Download failed with result code: $($DownloadResult.ResultCode)" -Level "ERROR"
            return $false
        }
        
        Write-TaskLog "✓ Download completed successfully" -Level "SUCCESS"
        
        # Install updates
        Write-TaskLog "`nInstalling updates..." -Level "INFO"
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallResult = $Installer.Install()
        
        # Process results
        $RoundInstalled = 0
        $RoundFailed = 0
        
        for ($i = 0; $i -lt $UpdatesToInstall.Count; $i++) {
            $Update = $UpdatesToInstall.Item($i)
            $Result = $InstallResult.GetUpdateResult($i)
            
            $UpdateInfo = @{
                Title = $Update.Title
                KB = ($Update.KBArticleIDs | Select-Object -First 1)
                Status = $Result.ResultCode
                Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Round = $RoundNumber
            }
            
            $Global:UpdateResults.UpdateHistory += $UpdateInfo
            
            # Result codes: 2=Succeeded, 3=Succeeded with errors, 4=Failed, 5=Aborted
            if ($Result.ResultCode -eq 2) {
                Write-TaskLog "✓ Installed: $($Update.Title)" -Level "SUCCESS"
                $Global:UpdateResults.TotalUpdatesInstalled++
                $RoundInstalled++
            }
            elseif ($Result.ResultCode -eq 3) {
                Write-TaskLog "⚠ Installed with errors: $($Update.Title)" -Level "WARNING"
                $Global:UpdateResults.TotalUpdatesInstalled++
                $RoundInstalled++
            }
            else {
                Write-TaskLog "✗ Failed: $($Update.Title) (Result: $($Result.ResultCode))" -Level "ERROR"
                $Global:UpdateResults.TotalUpdatesFailed++
                $RoundFailed++
            }
            
            if ($Result.RebootRequired) {
                $Global:UpdateResults.RebootRequired = $true
            }
        }
        
        if ($InstallResult.RebootRequired) {
            Write-TaskLog "⚠ Reboot required after this round" -Level "WARNING"
            $Global:UpdateResults.RebootRequired = $true
        }
        
        Write-TaskLog "`nRound $RoundNumber Summary:" -Level "INFO"
        Write-TaskLog "  Installed: $RoundInstalled" -Level "SUCCESS"
        Write-TaskLog "  Failed: $RoundFailed" -Level $(if($RoundFailed -gt 0){"ERROR"}else{"INFO"})
        
        return ($RoundInstalled -gt 0)
    }
    catch {
        Write-TaskLog "Error during native API update installation: $_" -Level "ERROR"
        return $false
    }
}

function Invoke-UpdateRounds {
    <#
    .SYNOPSIS
        Performs multiple rounds of update checks and installations
    #>
    
    $ModuleAvailable = Get-Module -Name PSWindowsUpdate -ListAvailable
    
    for ($Round = 1; $Round -le $MaxUpdateRounds; $Round++) {
        $Global:UpdateResults.RoundsCompleted = $Round
        
        # Check if updates are available
        $UpdatesAvailable = Test-PendingUpdates
        
        if (-not $UpdatesAvailable) {
            Write-TaskLog "`n✓ No more updates available - stopping update rounds" -Level "SUCCESS"
            break
        }
        
        # Install updates
        $Success = if ($ModuleAvailable) {
            Install-UpdatesWithPSModule -RoundNumber $Round
        }
        else {
            Install-UpdatesWithNativeAPI -RoundNumber $Round
        }
        
        if (-not $Success) {
            Write-TaskLog "No updates installed in round $Round - may be complete" -Level "INFO"
            
            # Double-check if more updates available
            Start-Sleep -Seconds 5
            $StillAvailable = Test-PendingUpdates
            
            if (-not $StillAvailable) {
                Write-TaskLog "✓ Confirmed: No more updates available" -Level "SUCCESS"
                break
            }
        }
        
        # Brief pause between rounds
        if ($Round -lt $MaxUpdateRounds) {
            Write-TaskLog "`nWaiting 15 seconds before next round..." -Level "INFO"
            Start-Sleep -Seconds 15
        }
    }
    
    if ($Global:UpdateResults.RoundsCompleted -eq $MaxUpdateRounds) {
        Write-TaskLog "`n⚠ Maximum update rounds ($MaxUpdateRounds) reached" -Level "WARNING"
        Write-TaskLog "More updates may be available - consider running again" -Level "INFO"
    }
}

#endregion

#region REBOOT FUNCTIONS
#==============================================================================

function Invoke-SystemReboot {
    <#
    .SYNOPSIS
        Initiates system reboot with notification
    #>
    
    Write-TaskLog "`n=== INITIATING SYSTEM REBOOT ===" -Level "WARNING"
    Write-TaskLog "Reboot will occur in $RebootTimeout seconds" -Level "WARNING"
    
    try {
        # Display notification to user
        $Message = "All Windows updates have been installed. Your computer will restart in $($RebootTimeout / 60) minutes. Please save your work."
        
        # Try to show toast notification
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $notification = New-Object System.Windows.Forms.NotifyIcon
            $notification.Icon = [System.Drawing.SystemIcons]::Information
            $notification.BalloonTipTitle = "System Restart Required"
            $notification.BalloonTipText = $Message
            $notification.Visible = $True
            $notification.ShowBalloonTip(30000)
        }
        catch {
            Write-TaskLog "Could not display user notification: $_" -Level "DEBUG"
        }
        
        # Initiate shutdown
        Write-TaskLog "Executing shutdown command..." -Level "INFO"
        shutdown /r /t $RebootTimeout /c $Message /d p:2:17
        
        Write-TaskLog "Reboot scheduled successfully" -Level "SUCCESS"
    }
    catch {
        Write-TaskLog "Error initiating reboot: $_" -Level "ERROR"
    }
}

#endregion

#region VALIDATION FUNCTIONS
#==============================================================================

function Write-UpdateSummary {
    <#
    .SYNOPSIS
        Displays final update summary
    #>
    
    Write-TaskLog "`n========================================" -Level "INFO"
    Write-TaskLog "WINDOWS UPDATE SUMMARY - ALL UPDATES" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    Write-TaskLog "Rounds Completed: $($Global:UpdateResults.RoundsCompleted) of $MaxUpdateRounds" -Level "INFO"
    Write-TaskLog "Updates Found: $($Global:UpdateResults.TotalUpdatesFound)" -Level "INFO"
    Write-TaskLog "Updates Installed: $($Global:UpdateResults.TotalUpdatesInstalled)" -Level $(if($Global:UpdateResults.TotalUpdatesInstalled -gt 0){"SUCCESS"}else{"INFO"})
    Write-TaskLog "Updates Failed: $($Global:UpdateResults.TotalUpdatesFailed)" -Level $(if($Global:UpdateResults.TotalUpdatesFailed -gt 0){"ERROR"}else{"INFO"})
    Write-TaskLog "Updates Skipped: $($Global:UpdateResults.TotalUpdatesSkipped)" -Level $(if($Global:UpdateResults.TotalUpdatesSkipped -gt 0){"WARNING"}else{"INFO"})
    Write-TaskLog "Reboot Required: $($Global:UpdateResults.RebootRequired)" -Level $(if($Global:UpdateResults.RebootRequired){"WARNING"}else{"INFO"})
    
    if ($Global:UpdateResults.UpdateHistory.Count -gt 0) {
        Write-TaskLog "`nUpdate Installation Details:" -Level "INFO"
        
        # Group by round
        for ($i = 1; $i -le $Global:UpdateResults.RoundsCompleted; $i++) {
            $RoundUpdates = $Global:UpdateResults.UpdateHistory | Where-Object { $_.Round -eq $i }
            
            if ($RoundUpdates) {
                Write-TaskLog "`n  Round $i ($($RoundUpdates.Count) update(s)):" -Level "INFO"
                
                foreach ($Update in $RoundUpdates | Select-Object -First 20) {
                    $KB = if ($Update.KB) { "KB$($Update.KB)" } else { "N/A" }
                    $StatusSymbol = switch ($Update.Status) {
                        "Installed" { "✓" }
                        "Succeeded" { "✓" }
                        2 { "✓" }
                        "Failed" { "✗" }
                        4 { "✗" }
                        default { "⚠" }
                    }
                    Write-TaskLog "    $StatusSymbol $($Update.Title) [$KB]" -Level "DEBUG"
                }
                
                if ($RoundUpdates.Count -gt 20) {
                    Write-TaskLog "    ... and $($RoundUpdates.Count - 20) more" -Level "DEBUG"
                }
            }
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
    Write-TaskLog "Update Categories: $UpdateCategories" -Level "INFO"
    Write-TaskLog "Max Update Rounds: $MaxUpdateRounds" -Level "INFO"
    Write-TaskLog "Auto Reboot: $AutoReboot" -Level "INFO"
    Write-TaskLog "Include Drivers: $IncludeDrivers" -Level "INFO"
    Write-TaskLog "Include Optional: $IncludeOptional" -Level "INFO"
    Write-TaskLog "Include Recommended: $IncludeRecommended" -Level "INFO"
    Write-TaskLog "Ignore Reboots Until End: $IgnoreRebootsUntilEnd" -Level "INFO"
    Write-TaskLog "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-TaskLog "User: $env:USERNAME" -Level "INFO"
    
    # Step 1: Verify Windows Update service
    Write-TaskLog "`n--- Step 1: Service Verification ---" -Level "INFO"
    
    if (-not (Test-WindowsUpdateService)) {
        Write-TaskLog "Windows Update service is not available" -Level "ERROR"
        exit $ExitCode_Failed
    }
    
    # Step 2: Install/Check PSWindowsUpdate module
    Write-TaskLog "`n--- Step 2: Module Management ---" -Level "INFO"
    
    $ModuleInstalled = Install-PSWindowsUpdateModule
    if ($ModuleInstalled) {
        Write-TaskLog "Will use PSWindowsUpdate module for updates" -Level "SUCCESS"
    }
    else {
        Write-TaskLog "Will use native Windows Update API" -Level "WARNING"
    }
    
    # Step 3: Check for available updates
    Write-TaskLog "`n--- Step 3: Update Detection ---" -Level "INFO"
    
    $UpdatesAvailable = Test-PendingUpdates
    
    if (-not $UpdatesAvailable) {
        Write-TaskLog "No updates available - system is fully up to date" -Level "SUCCESS"
        Write-TaskLog "Task completed in $([math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)) seconds" -Level "INFO"
        exit $ExitCode_AlreadyCompliant
    }
    
    Write-TaskLog "Updates are available - proceeding with installation" -Level "INFO"
    
    # Step 4: Install updates (multiple rounds)
    Write-TaskLog "`n--- Step 4: Comprehensive Update Installation ---" -Level "INFO"
    Write-TaskLog "This may take a significant amount of time (30-120 minutes)" -Level "INFO"
    Write-TaskLog "Progress will be logged for each round and update" -Level "INFO"
    
    Invoke-UpdateRounds
    
    # Step 5: Display summary
    Write-TaskLog "`n--- Step 5: Summary ---" -Level "INFO"
    
    Write-UpdateSummary
    
    # Step 6: Handle reboot if required
    if ($Global:UpdateResults.RebootRequired) {
        Write-TaskLog "`n--- Step 6: Reboot Management ---" -Level "INFO"
        
        if ($AutoReboot) {
            Invoke-SystemReboot
        }
        else {
            Write-TaskLog "Reboot required but AutoReboot is disabled" -Level "WARNING"
            Write-TaskLog "Please reboot the system manually to complete update installation" -Level "WARNING"
        }
    }
    else {
        Write-TaskLog "`n--- Step 6: Reboot Management ---" -Level "INFO"
        Write-TaskLog "No reboot required" -Level "SUCCESS"
    }
    
    # Determine exit code
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalMinutes, 2)
    
    if ($Global:UpdateResults.TotalUpdatesFailed -gt 0) {
        Write-TaskLog "`n========================================" -Level "ERROR"
        Write-TaskLog "TASK COMPLETED WITH ERRORS" -Level "ERROR"
        Write-TaskLog "Duration: $Duration minutes" -Level "ERROR"
        Write-TaskLog "Installed: $($Global:UpdateResults.TotalUpdatesInstalled)" -Level "SUCCESS"
        Write-TaskLog "Failed: $($Global:UpdateResults.TotalUpdatesFailed)" -Level "ERROR"
        Write-TaskLog "========================================" -Level "ERROR"
        
        # Still consider it a success if some updates were installed
        if ($Global:UpdateResults.TotalUpdatesInstalled -gt 0) {
            Write-TaskLog "Partial success - some updates installed despite failures" -Level "WARNING"
            exit $ExitCode_Success
        }
        else {
            exit $ExitCode_InstallFailed
        }
    }
    elseif ($Global:UpdateResults.RebootRequired) {
        Write-TaskLog "`n========================================" -Level "WARNING"
        Write-TaskLog "TASK COMPLETED - REBOOT REQUIRED" -Level "WARNING"
        Write-TaskLog "Duration: $Duration minutes" -Level "WARNING"
        Write-TaskLog "Rounds Completed: $($Global:UpdateResults.RoundsCompleted)" -Level "INFO"
        Write-TaskLog "Updates Installed: $($Global:UpdateResults.TotalUpdatesInstalled)" -Level "SUCCESS"
        Write-TaskLog "⚠ REBOOT REQUIRED to complete installation" -Level "WARNING"
        Write-TaskLog "========================================" -Level "WARNING"
        exit $ExitCode_RebootRequired
    }
    else {
        Write-TaskLog "`n========================================" -Level "SUCCESS"
        Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
        Write-TaskLog "Duration: $Duration minutes" -Level "SUCCESS"
        Write-TaskLog "Rounds Completed: $($Global:UpdateResults.RoundsCompleted)" -Level "INFO"
        Write-TaskLog "Updates Installed: $($Global:UpdateResults.TotalUpdatesInstalled)" -Level "SUCCESS"
        Write-TaskLog "System is now fully up to date" -Level "SUCCESS"
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
    Write-UpdateSummary
    
    exit $ExitCode_Failed
}

#endregion