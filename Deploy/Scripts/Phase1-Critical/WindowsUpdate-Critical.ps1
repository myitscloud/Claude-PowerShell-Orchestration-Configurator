<#
.SYNOPSIS
    Installs critical and security Windows updates
    
.DESCRIPTION
    Task script for orchestration engine that installs critical and security
    Windows updates. Uses PSWindowsUpdate module with fallback to native methods.
    Includes detection logic to skip if already up-to-date with progress tracking.
    
.PARAMETER UpdateCategories
    Categories of updates to install. Default: Critical,Security
    Options: Critical, Security, Definition, Driver, FeaturePack, ServicePack, Tool, UpdateRollup, Update
    
.PARAMETER MaxUpdateRounds
    Maximum number of update check/install rounds. Default: 3
    
.PARAMETER AutoReboot
    Automatically reboot if required by updates. Default: False
    
.PARAMETER RebootTimeout
    Timeout in seconds before forcing reboot. Default: 300
    
.PARAMETER SkipDriverUpdates
    Skip driver updates. Default: True
    
.PARAMETER AcceptEULA
    Accept all EULAs automatically. Default: True
    
.PARAMETER IncludeRecommended
    Include recommended updates. Default: False
    
.PARAMETER MaxDownloadTimeMins
    Maximum time to wait for downloads in minutes. Default: 60
    
.PARAMETER MaxInstallTimeMins
    Maximum time to wait for installation in minutes. Default: 120
    
.PARAMETER ForceInstall
    Force installation even if updates already installed. Default: False
    
.PARAMETER LogPath
    Path for task-specific log file. Default: C:\ProgramData\OrchestrationLogs\Tasks
    
.EXAMPLE
    .\WindowsUpdate-Critical.ps1 -UpdateCategories "Critical,Security" -MaxUpdateRounds 3
    
.NOTES
    Task ID: CRIT-002
    Version: 1.0.0
    Author: IT Infrastructure Team
    Requires: Administrator privileges
    
.OUTPUTS
    Returns exit code:
    0 = Success (updates installed or no updates needed)
    1 = Failed (update installation error)
    2 = Already compliant (no updates available)
    3 = Download failed
    4 = Installation failed
    5 = Reboot required (pending)
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UpdateCategories = "Critical,Security",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxUpdateRounds = 3,
    
    [Parameter(Mandatory=$false)]
    [bool]$AutoReboot = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$RebootTimeout = 300,
    
    [Parameter(Mandatory=$false)]
    [bool]$SkipDriverUpdates = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AcceptEULA = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeRecommended = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDownloadTimeMins = 60,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxInstallTimeMins = 120,
    
    [Parameter(Mandatory=$false)]
    [bool]$ForceInstall = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs\Tasks"
)

#region INITIALIZATION
#==============================================================================

# Script variables
$ScriptVersion = "1.0.0"
$TaskID = "CRIT-002"
$TaskName = "Windows Update - Critical"
$ScriptStartTime = Get-Date

# Initialize log file
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "WindowsUpdate-Critical_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
    UpdateHistory = @()
    RebootRequired = $false
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
            
            # Add category filter
            if ($Categories.Count -gt 0) {
                # PSWindowsUpdate uses different category names
                $Params.Category = $Categories
            }
            
            if ($SkipDriverUpdates) {
                $Params.NotCategory = "Drivers"
            }
            
            $AvailableUpdates = Get-WindowsUpdate @Params
            
            if ($AvailableUpdates) {
                Write-TaskLog "Found $($AvailableUpdates.Count) available update(s)" -Level "INFO"
                
                foreach ($Update in $AvailableUpdates) {
                    Write-TaskLog "  - $($Update.Title) [$($Update.Size) bytes]" -Level "DEBUG"
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
                
                foreach ($Update in $SearchResult.Updates) {
                    Write-TaskLog "  - $($Update.Title)" -Level "DEBUG"
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

function Get-UpdateHistory {
    <#
    .SYNOPSIS
        Gets recent Windows Update history
    #>
    
    Write-TaskLog "Retrieving Windows Update history..." -Level "DEBUG"
    
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
        
        if ($HistoryCount -gt 0) {
            $History = $UpdateSearcher.QueryHistory(0, [Math]::Min(10, $HistoryCount))
            
            Write-TaskLog "Recent update history ($([Math]::Min(10, $HistoryCount)) most recent):" -Level "DEBUG"
            
            foreach ($Item in $History) {
                $DateInstalled = $Item.Date
                $Title = $Item.Title
                Write-TaskLog "  - $DateInstalled : $Title" -Level "DEBUG"
            }
        }
        else {
            Write-TaskLog "No update history found" -Level "DEBUG"
        }
    }
    catch {
        Write-TaskLog "Could not retrieve update history: $_" -Level "DEBUG"
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
    
    Write-TaskLog "`n=== UPDATE ROUND $RoundNumber of $MaxUpdateRounds ===" -Level "INFO"
    
    try {
        # Build parameters
        $Params = @{
            MicrosoftUpdate = $true
            AcceptAll = $AcceptEULA
            Install = $true
            IgnoreReboot = (-not $AutoReboot)
            Verbose = $true
            ErrorAction = 'Stop'
        }
        
        # Add category filter
        if ($Categories.Count -gt 0) {
            $Params.Category = $Categories
        }
        
        if ($SkipDriverUpdates) {
            $Params.NotCategory = "Drivers"
        }
        
        Write-TaskLog "Starting update installation..." -Level "INFO"
        Write-TaskLog "Categories: $($Categories -join ', ')" -Level "INFO"
        
        # Install updates
        $Results = Get-WindowsUpdate @Params
        
        if ($Results) {
            foreach ($Result in $Results) {
                $UpdateInfo = @{
                    Title = $Result.Title
                    KB = $Result.KB
                    Size = $Result.Size
                    Status = $Result.Result
                    Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                $Global:UpdateResults.UpdateHistory += $UpdateInfo
                
                if ($Result.Result -eq "Installed" -or $Result.Result -eq "Succeeded") {
                    Write-TaskLog "✓ Installed: $($Result.Title) (KB$($Result.KB))" -Level "SUCCESS"
                    $Global:UpdateResults.TotalUpdatesInstalled++
                }
                elseif ($Result.Result -eq "Failed") {
                    Write-TaskLog "✗ Failed: $($Result.Title) (KB$($Result.KB))" -Level "ERROR"
                    $Global:UpdateResults.TotalUpdatesFailed++
                }
                else {
                    Write-TaskLog "⚠ $($Result.Result): $($Result.Title) (KB$($Result.KB))" -Level "WARNING"
                }
            }
            
            # Check if reboot is required
            $RebootRequired = Get-WURebootStatus -Silent
            if ($RebootRequired) {
                Write-TaskLog "⚠ Reboot required after this round" -Level "WARNING"
                $Global:UpdateResults.RebootRequired = $true
            }
            
            return $true
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
    
    Write-TaskLog "`n=== UPDATE ROUND $RoundNumber of $MaxUpdateRounds (Native API) ===" -Level "INFO"
    
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
            # Filter by category if specified
            $MatchesCategory = $false
            
            if ($Categories.Count -eq 0) {
                $MatchesCategory = $true
            }
            else {
                foreach ($Category in $Update.Categories) {
                    if ($Categories -contains $Category.Name) {
                        $MatchesCategory = $true
                        break
                    }
                }
            }
            
            # Skip drivers if requested
            if ($SkipDriverUpdates) {
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
            
            if ($MatchesCategory) {
                if ($Update.EulaAccepted -eq $false -and $AcceptEULA) {
                    $Update.AcceptEula()
                }
                
                $UpdatesToInstall.Add($Update) | Out-Null
                Write-TaskLog "Queued: $($Update.Title)" -Level "INFO"
                $Global:UpdateResults.TotalUpdatesFound++
            }
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
        for ($i = 0; $i -lt $UpdatesToInstall.Count; $i++) {
            $Update = $UpdatesToInstall.Item($i)
            $Result = $InstallResult.GetUpdateResult($i)
            
            $UpdateInfo = @{
                Title = $Update.Title
                KB = ($Update.KBArticleIDs | Select-Object -First 1)
                Status = $Result.ResultCode
                Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            $Global:UpdateResults.UpdateHistory += $UpdateInfo
            
            # Result codes: 2=Succeeded, 3=Succeeded with errors, 4=Failed, 5=Aborted
            if ($Result.ResultCode -eq 2) {
                Write-TaskLog "✓ Installed: $($Update.Title)" -Level "SUCCESS"
                $Global:UpdateResults.TotalUpdatesInstalled++
            }
            elseif ($Result.ResultCode -eq 3) {
                Write-TaskLog "⚠ Installed with errors: $($Update.Title)" -Level "WARNING"
                $Global:UpdateResults.TotalUpdatesInstalled++
            }
            else {
                Write-TaskLog "✗ Failed: $($Update.Title) (Result: $($Result.ResultCode))" -Level "ERROR"
                $Global:UpdateResults.TotalUpdatesFailed++
            }
            
            if ($Result.RebootRequired) {
                $Global:UpdateResults.RebootRequired = $true
            }
        }
        
        if ($InstallResult.RebootRequired) {
            Write-TaskLog "⚠ Reboot required after this round" -Level "WARNING"
            $Global:UpdateResults.RebootRequired = $true
        }
        
        return $true
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
        Write-TaskLog "`n========================================" -Level "INFO"
        Write-TaskLog "Starting Update Round $Round of $MaxUpdateRounds" -Level "INFO"
        Write-TaskLog "========================================" -Level "INFO"
        
        # Check if updates are available
        $UpdatesAvailable = Test-PendingUpdates
        
        if (-not $UpdatesAvailable) {
            Write-TaskLog "No more updates available - stopping update rounds" -Level "SUCCESS"
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
            Write-TaskLog "Update round $Round completed with issues" -Level "WARNING"
        }
        
        # If reboot required and AutoReboot enabled, break here
        if ($Global:UpdateResults.RebootRequired -and $AutoReboot) {
            Write-TaskLog "Reboot required - will initiate after all rounds complete" -Level "WARNING"
        }
        
        # Brief pause between rounds
        if ($Round -lt $MaxUpdateRounds) {
            Write-TaskLog "Waiting 10 seconds before next round..." -Level "INFO"
            Start-Sleep -Seconds 10
        }
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
        $Message = "Windows updates have been installed. Your computer will restart in $($RebootTimeout / 60) minutes. Please save your work."
        
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
    Write-TaskLog "WINDOWS UPDATE SUMMARY" -Level "INFO"
    Write-TaskLog "========================================" -Level "INFO"
    
    Write-TaskLog "Updates Found: $($Global:UpdateResults.TotalUpdatesFound)" -Level "INFO"
    Write-TaskLog "Updates Installed: $($Global:UpdateResults.TotalUpdatesInstalled)" -Level $(if($Global:UpdateResults.TotalUpdatesInstalled -gt 0){"SUCCESS"}else{"INFO"})
    Write-TaskLog "Updates Failed: $($Global:UpdateResults.TotalUpdatesFailed)" -Level $(if($Global:UpdateResults.TotalUpdatesFailed -gt 0){"ERROR"}else{"INFO"})
    Write-TaskLog "Reboot Required: $($Global:UpdateResults.RebootRequired)" -Level $(if($Global:UpdateResults.RebootRequired){"WARNING"}else{"INFO"})
    
    if ($Global:UpdateResults.UpdateHistory.Count -gt 0) {
        Write-TaskLog "`nUpdate Details:" -Level "INFO"
        foreach ($Update in $Global:UpdateResults.UpdateHistory) {
            $KB = if ($Update.KB) { "KB$($Update.KB)" } else { "N/A" }
            Write-TaskLog "  - $($Update.Title) [$KB] - $($Update.Status)" -Level "DEBUG"
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
    Write-TaskLog "Skip Drivers: $SkipDriverUpdates" -Level "INFO"
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
    
    Get-UpdateHistory
    
    if (-not $ForceInstall) {
        $UpdatesAvailable = Test-PendingUpdates
        
        if (-not $UpdatesAvailable) {
            Write-TaskLog "No updates available - system is up to date" -Level "SUCCESS"
            Write-TaskLog "Task completed in $([math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)) seconds" -Level "INFO"
            exit $ExitCode_AlreadyCompliant
        }
    }
    
    # Step 4: Install updates
    Write-TaskLog "`n--- Step 4: Update Installation ---" -Level "INFO"
    
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
    
    # Determine exit code
    $Duration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 2)
    
    if ($Global:UpdateResults.TotalUpdatesFailed -gt 0) {
        Write-TaskLog "`n========================================" -Level "ERROR"
        Write-TaskLog "TASK COMPLETED WITH ERRORS" -Level "ERROR"
        Write-TaskLog "Duration: $Duration seconds" -Level "ERROR"
        Write-TaskLog "Some updates failed to install" -Level "ERROR"
        Write-TaskLog "========================================" -Level "ERROR"
        exit $ExitCode_InstallFailed
    }
    elseif ($Global:UpdateResults.RebootRequired) {
        Write-TaskLog "`n========================================" -Level "WARNING"
        Write-TaskLog "TASK COMPLETED - REBOOT REQUIRED" -Level "WARNING"
        Write-TaskLog "Duration: $Duration seconds" -Level "WARNING"
        Write-TaskLog "========================================" -Level "WARNING"
        exit $ExitCode_RebootRequired
    }
    else {
        Write-TaskLog "`n========================================" -Level "SUCCESS"
        Write-TaskLog "TASK COMPLETED SUCCESSFULLY" -Level "SUCCESS"
        Write-TaskLog "Duration: $Duration seconds" -Level "SUCCESS"
        Write-TaskLog "Installed $($Global:UpdateResults.TotalUpdatesInstalled) update(s)" -Level "SUCCESS"
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