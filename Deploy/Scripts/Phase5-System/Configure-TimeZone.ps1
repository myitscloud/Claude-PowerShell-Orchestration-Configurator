<#
.SYNOPSIS
    Configure Time Zone and Time Synchronization
    
.DESCRIPTION
    Configures system time zone and Network Time Protocol (NTP) synchronization
    for Windows 11 workstations. Ensures accurate time across enterprise environment.
    
    Features:
    - Set system time zone based on location
    - Configure NTP server(s) for time synchronization
    - Enable/disable Windows Time service
    - Configure time synchronization intervals
    - Validate time synchronization
    - Force immediate time sync
    - Support for multiple NTP servers (primary + fallback)
    - Comprehensive logging and validation
    
.PARAMETER TimeZone
    Time zone to set. Must be a valid Windows time zone identifier.
    Examples: "Central Standard Time", "Eastern Standard Time", "Pacific Standard Time"
    Default: "Central Standard Time"
    
    To list all available time zones, run:
    Get-TimeZone -ListAvailable | Select-Object Id, DisplayName
    
.PARAMETER EnableNTP
    Enable Network Time Protocol synchronization. Default: $true
    
.PARAMETER NTPServer
    Primary NTP server address or hostname.
    Default: "time.windows.com"
    
    Common NTP servers:
    - time.windows.com (Microsoft)
    - time.nist.gov (NIST)
    - pool.ntp.org (NTP Pool Project)
    - Internal corporate NTP server
    
.PARAMETER FallbackNTPServers
    Array of fallback NTP servers. If primary fails, these will be tried.
    Default: @("time.nist.gov", "pool.ntp.org")
    
.PARAMETER SyncInterval
    Time synchronization interval in seconds.
    Default: 3600 (1 hour)
    Enterprise recommendation: 3600-86400 (1 hour to 1 day)
    
.PARAMETER ForceSync
    Force immediate time synchronization after configuration. Default: $true
    
.PARAMETER AdjustForDST
    Automatically adjust for Daylight Saving Time. Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-TimeZone.ps1
    Configures time zone and NTP with default settings (Central Standard Time)
    
.EXAMPLE
    .\Configure-TimeZone.ps1 -TimeZone "Eastern Standard Time"
    Sets time zone to Eastern and configures NTP
    
.EXAMPLE
    .\Configure-TimeZone.ps1 -NTPServer "ntp.company.com" -FallbackNTPServers @("time.windows.com")
    Uses corporate NTP server with Windows Time as fallback
    
.EXAMPLE
    .\Configure-TimeZone.ps1 -TimeZone "Pacific Standard Time" -SyncInterval 7200
    Sets Pacific time zone with 2-hour sync interval
    
.EXAMPLE
    .\Configure-TimeZone.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Time zone and NTP configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Invalid time zone
    4   = Configuration failed
    5   = Time synchronization failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - Network connectivity (for NTP synchronization)
    - Windows Time service (w32time)
    
    NOTES:
    - Time zone changes take effect immediately (no reboot required)
    - NTP configuration requires Windows Time service
    - Time synchronization needs network access to NTP servers
    - Script validates time zone before applying
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TimeZone = "Central Standard Time",
    
    [Parameter(Mandatory=$false)]
    [bool]$EnableNTP = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$NTPServer = "time.windows.com",
    
    [Parameter(Mandatory=$false)]
    [string[]]$FallbackNTPServers = @("time.nist.gov", "pool.ntp.org"),
    
    [Parameter(Mandatory=$false)]
    [int]$SyncInterval = 3600,
    
    [Parameter(Mandatory=$false)]
    [bool]$ForceSync = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AdjustForDST = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Initialize logging
$LogPath = "C:\ProgramData\OrchestrationLogs"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Configure-TimeZone_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    TimeZoneSet = ""
    PreviousTimeZone = ""
    NTPConfigured = $false
    TimeSynced = $false
    NTPServersConfigured = 0
    Errors = 0
    Warnings = 0
}

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-Log {
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
    
    # Update statistics
    if ($Level -eq "ERROR") { $Global:Stats.Errors++ }
    if ($Level -eq "WARNING") { $Global:Stats.Warnings++ }
}

function Write-LogHeader {
    param([string]$Title)
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region PREREQUISITE FUNCTIONS
#==============================================================================

function Test-Prerequisites {
    Write-LogHeader "PREREQUISITE CHECKS"
    
    $AllChecksPassed = $true
    
    # Check 1: Administrator privileges
    Write-Log "Checking administrator privileges..." -Level "INFO"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Log "FAILED: Script must be run as Administrator" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "Administrator privileges confirmed" -Level "SUCCESS"
    }
    
    # Check 2: Windows Time service
    Write-Log "Checking Windows Time service..." -Level "INFO"
    $W32TimeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    
    if (-not $W32TimeService) {
        Write-Log "ERROR: Windows Time service not found" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "Windows Time service found: $($W32TimeService.Status)" -Level "SUCCESS"
        
        if ($W32TimeService.Status -ne "Running" -and $EnableNTP) {
            Write-Log "Windows Time service not running - will start it" -Level "WARNING"
        }
    }
    
    # Check 3: Time zone parameter validation
    Write-Log "Validating time zone parameter..." -Level "INFO"
    $ValidTimeZone = Test-TimeZoneValid -TimeZoneId $TimeZone
    
    if (-not $ValidTimeZone) {
        Write-Log "ERROR: Invalid time zone: $TimeZone" -Level "ERROR"
        Write-Log "Run 'Get-TimeZone -ListAvailable' to see valid time zones" -Level "ERROR"
        $AllChecksPassed = $false
    }
    else {
        Write-Log "Time zone parameter is valid: $TimeZone" -Level "SUCCESS"
    }
    
    # Check 4: Network connectivity (if NTP enabled)
    if ($EnableNTP) {
        Write-Log "Checking network connectivity for NTP..." -Level "INFO"
        
        $NetworkTest = Test-Connection -ComputerName $NTPServer -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if ($NetworkTest) {
            Write-Log "Network connectivity to $NTPServer confirmed" -Level "SUCCESS"
        }
        else {
            Write-Log "WARNING: Cannot reach NTP server $NTPServer" -Level "WARNING"
            Write-Log "Time synchronization may fail without network connectivity" -Level "WARNING"
        }
    }
    
    return $AllChecksPassed
}

function Test-TimeZoneValid {
    param([string]$TimeZoneId)
    
    try {
        $AllTimeZones = Get-TimeZone -ListAvailable
        $IsValid = $AllTimeZones | Where-Object { $_.Id -eq $TimeZoneId }
        
        return ($null -ne $IsValid)
    }
    catch {
        Write-Log "Exception validating time zone: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region TIME ZONE CONFIGURATION
#==============================================================================

function Get-CurrentTimeZoneInfo {
    <#
    .SYNOPSIS
        Gets current time zone information
    #>
    
    try {
        $CurrentTimeZone = Get-TimeZone
        
        Write-Log "Current time zone information:" -Level "INFO"
        Write-Log "  ID: $($CurrentTimeZone.Id)" -Level "INFO"
        Write-Log "  Display Name: $($CurrentTimeZone.DisplayName)" -Level "INFO"
        Write-Log "  Standard Name: $($CurrentTimeZone.StandardName)" -Level "INFO"
        Write-Log "  Daylight Name: $($CurrentTimeZone.DaylightName)" -Level "INFO"
        Write-Log "  Base UTC Offset: $($CurrentTimeZone.BaseUtcOffset)" -Level "INFO"
        Write-Log "  Supports DST: $($CurrentTimeZone.SupportsDaylightSavingTime)" -Level "INFO"
        
        $Global:Stats.PreviousTimeZone = $CurrentTimeZone.Id
        
        return $CurrentTimeZone
    }
    catch {
        Write-Log "Exception getting current time zone: $_" -Level "ERROR"
        return $null
    }
}

function Set-SystemTimeZone {
    <#
    .SYNOPSIS
        Sets the system time zone
    #>
    
    Write-LogHeader "CONFIGURING TIME ZONE"
    
    try {
        # Get current time zone
        $CurrentTimeZone = Get-CurrentTimeZoneInfo
        
        if (-not $CurrentTimeZone) {
            Write-Log "Failed to get current time zone" -Level "ERROR"
            return $false
        }
        
        # Check if time zone needs to be changed
        if ($CurrentTimeZone.Id -eq $TimeZone) {
            Write-Log "Time zone already set to: $TimeZone" -Level "SUCCESS"
            $Global:Stats.TimeZoneSet = $TimeZone
            return $true
        }
        
        Write-Log "Changing time zone from '$($CurrentTimeZone.Id)' to '$TimeZone'" -Level "INFO"
        
        # Get target time zone details
        $TargetTimeZone = Get-TimeZone -Id $TimeZone -ErrorAction Stop
        Write-Log "Target time zone: $($TargetTimeZone.DisplayName)" -Level "INFO"
        Write-Log "  UTC Offset: $($TargetTimeZone.BaseUtcOffset)" -Level "DEBUG"
        Write-Log "  Supports DST: $($TargetTimeZone.SupportsDaylightSavingTime)" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set time zone to: $TimeZone" -Level "INFO"
            return $true
        }
        
        # Set the time zone
        Set-TimeZone -Id $TimeZone -ErrorAction Stop
        
        # Verify the change
        Start-Sleep -Seconds 1
        $NewTimeZone = Get-TimeZone
        
        if ($NewTimeZone.Id -eq $TimeZone) {
            Write-Log "Time zone successfully set to: $TimeZone" -Level "SUCCESS"
            Write-Log "System time is now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" -Level "SUCCESS"
            $Global:Stats.TimeZoneSet = $TimeZone
            return $true
        }
        else {
            Write-Log "Time zone change verification failed" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Exception setting time zone: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region NTP CONFIGURATION
#==============================================================================

function Start-WindowsTimeService {
    <#
    .SYNOPSIS
        Ensures Windows Time service is running
    #>
    
    try {
        $W32TimeService = Get-Service -Name "W32Time" -ErrorAction Stop
        
        if ($W32TimeService.Status -eq "Running") {
            Write-Log "Windows Time service is already running" -Level "SUCCESS"
            return $true
        }
        
        Write-Log "Starting Windows Time service..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would start Windows Time service" -Level "INFO"
            return $true
        }
        
        # Ensure service is not disabled
        if ($W32TimeService.StartType -eq "Disabled") {
            Write-Log "Enabling Windows Time service..." -Level "INFO"
            Set-Service -Name "W32Time" -StartupType Automatic -ErrorAction Stop
        }
        
        # Start the service
        Start-Service -Name "W32Time" -ErrorAction Stop
        
        # Wait for service to start
        $Timeout = 10
        $Counter = 0
        while ($Counter -lt $Timeout) {
            $W32TimeService.Refresh()
            if ($W32TimeService.Status -eq "Running") {
                break
            }
            Start-Sleep -Seconds 1
            $Counter++
        }
        
        if ($W32TimeService.Status -eq "Running") {
            Write-Log "Windows Time service started successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "Failed to start Windows Time service" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Exception starting Windows Time service: $_" -Level "ERROR"
        return $false
    }
}

function Set-NTPConfiguration {
    <#
    .SYNOPSIS
        Configures NTP servers and settings
    #>
    
    Write-LogHeader "CONFIGURING NTP SYNCHRONIZATION"
    
    if (-not $EnableNTP) {
        Write-Log "NTP synchronization disabled by parameter" -Level "INFO"
        return $true
    }
    
    try {
        # Start Windows Time service
        if (-not (Start-WindowsTimeService)) {
            Write-Log "Cannot configure NTP without Windows Time service" -Level "ERROR"
            return $false
        }
        
        # Build NTP server list (primary + fallbacks)
        $AllNTPServers = @($NTPServer) + $FallbackNTPServers
        $NTPServerString = ($AllNTPServers | ForEach-Object { "$_,0x9" }) -join " "
        
        Write-Log "Configuring NTP servers:" -Level "INFO"
        foreach ($Server in $AllNTPServers) {
            Write-Log "  - $Server" -Level "INFO"
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure NTP servers: $($AllNTPServers -join ', ')" -Level "INFO"
            Write-Log "[DRY RUN] Would set sync interval to: $SyncInterval seconds" -Level "INFO"
            return $true
        }
        
        # Stop Windows Time service to make changes
        Write-Log "Stopping Windows Time service to apply configuration..." -Level "DEBUG"
        Stop-Service -Name "W32Time" -Force -ErrorAction SilentlyContinue
        
        # Configure NTP servers
        Write-Log "Setting NTP server configuration..." -Level "INFO"
        $Result = w32tm /config /manualpeerlist:"$NTPServerString" /syncfromflags:manual /reliable:yes /update 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning configuring NTP servers: $Result" -Level "WARNING"
        }
        else {
            Write-Log "NTP servers configured successfully" -Level "SUCCESS"
            $Global:Stats.NTPServersConfigured = $AllNTPServers.Count
        }
        
        # Configure sync interval
        Write-Log "Setting synchronization interval to $SyncInterval seconds..." -Level "INFO"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" `
                        -Name "SpecialPollInterval" -Value $SyncInterval -Type DWord -Force
        
        # Set service to start automatically
        Write-Log "Setting Windows Time service to start automatically..." -Level "INFO"
        Set-Service -Name "W32Time" -StartupType Automatic -ErrorAction Stop
        
        # Restart Windows Time service
        Write-Log "Restarting Windows Time service..." -Level "INFO"
        Start-Service -Name "W32Time" -ErrorAction Stop
        
        # Wait for service to fully start
        Start-Sleep -Seconds 2
        
        # Register as time source
        Write-Log "Registering as time source..." -Level "DEBUG"
        w32tm /register 2>&1 | Out-Null
        
        Write-Log "NTP configuration completed successfully" -Level "SUCCESS"
        $Global:Stats.NTPConfigured = $true
        
        return $true
    }
    catch {
        Write-Log "Exception configuring NTP: $_" -Level "ERROR"
        return $false
    }
}

function Invoke-TimeSync {
    <#
    .SYNOPSIS
        Forces immediate time synchronization
    #>
    
    Write-LogHeader "SYNCHRONIZING TIME"
    
    if (-not $ForceSync) {
        Write-Log "Time synchronization skipped (ForceSync parameter disabled)" -Level "INFO"
        return $true
    }
    
    if (-not $EnableNTP) {
        Write-Log "Time synchronization skipped (NTP disabled)" -Level "INFO"
        return $true
    }
    
    try {
        Write-Log "Forcing immediate time synchronization..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would force time synchronization" -Level "INFO"
            return $true
        }
        
        # Get time before sync
        $TimeBefore = Get-Date
        Write-Log "Current system time: $($TimeBefore.ToString('yyyy-MM-dd HH:mm:ss.fff zzz'))" -Level "DEBUG"
        
        # Force time sync
        $Result = w32tm /resync /rediscover /nowait 2>&1
        
        # Wait for sync to complete
        Start-Sleep -Seconds 3
        
        # Check sync status
        $SyncStatus = w32tm /query /status 2>&1

        # Convert to string if it's an array
        if ($SyncStatus -is [array]) {
            $SyncStatusString = $SyncStatus -join "`n"
        }
        else {
            $SyncStatusString = $SyncStatus.ToString()
        }

        if ($SyncStatusString -match "Source:(.+)") {
            $Source = $matches[1].Trim()
            Write-Log "Time synchronized successfully from: $Source" -Level "SUCCESS"
            $Global:Stats.TimeSynced = $true
        }

        if ($SyncStatusString -match "Last Successful Sync Time:(.+)") {
            $LastSync = $matches[1].Trim()
            Write-Log "Last successful sync: $LastSync" -Level "INFO"
        }

        if ($SyncStatusString -match "Poll Interval:(.+)") {
            $PollInterval = $matches[1].Trim()
            Write-Log "Poll interval: $PollInterval" -Level "INFO"
        }
        
        # Get time after sync
        $TimeAfter = Get-Date
        Write-Log "Updated system time: $($TimeAfter.ToString('yyyy-MM-dd HH:mm:ss.fff zzz'))" -Level "DEBUG"
        
        # Calculate time adjustment
        $TimeDifference = ($TimeAfter - $TimeBefore).TotalMilliseconds
        if ([Math]::Abs($TimeDifference) -gt 100) {
            Write-Log "Time adjusted by: $([Math]::Round($TimeDifference, 2)) milliseconds" -Level "INFO"
        }
        else {
            Write-Log "Time already accurate (no significant adjustment needed)" -Level "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-Log "Exception during time synchronization: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-TimeConfiguration {
    <#
    .SYNOPSIS
        Validates time zone and NTP configuration
    #>
    
    Write-LogHeader "VALIDATING TIME CONFIGURATION"
    
    try {
        # Validate time zone
        Write-Log "Validating time zone setting..." -Level "INFO"
        $CurrentTimeZone = Get-TimeZone
        
        if ($CurrentTimeZone.Id -eq $TimeZone) {
            Write-Log "✓ Time zone correctly set to: $TimeZone" -Level "SUCCESS"
        }
        else {
            Write-Log "✗ Time zone mismatch: Expected '$TimeZone', Found '$($CurrentTimeZone.Id)'" -Level "ERROR"
        }
        
        # Validate NTP configuration
        if ($EnableNTP) {
            Write-Log " " -Level "INFO"
            Write-Log "Validating NTP configuration..." -Level "INFO"
            
            # Check Windows Time service
            $W32TimeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
            if ($W32TimeService.Status -eq "Running") {
                Write-Log "✓ Windows Time service is running" -Level "SUCCESS"
            }
            else {
                Write-Log "✗ Windows Time service is not running" -Level "ERROR"
            }
            
            # Check NTP configuration
            $NTPConfig = w32tm /query /configuration 2>&1 | Out-String
            
            if ($NTPConfig -match "NtpServer:\s*(.+)") {
                $ConfiguredServers = $matches[1].Trim()
                Write-Log "✓ NTP servers configured: $ConfiguredServers" -Level "SUCCESS"
            }
            else {
                Write-Log "✗ NTP servers not configured" -Level "WARNING"
            }
            
            # Check sync status
            Write-Log " " -Level "INFO"
            Write-Log "NTP Synchronization Status:" -Level "INFO"
            
            $Status = w32tm /query /status 2>&1 | Out-String
            
            # Parse status
            if ($Status -match "Source:(.+)") {
                Write-Log "  Source: $($matches[1].Trim())" -Level "INFO"
            }
            
            if ($Status -match "Last Successful Sync Time:(.+)") {
                Write-Log "  Last Sync: $($matches[1].Trim())" -Level "INFO"
            }
            
            if ($Status -match "Poll Interval:(.+)") {
                Write-Log "  Poll Interval: $($matches[1].Trim())" -Level "INFO"
            }
        }
        
        # Display current system time
        Write-Log " " -Level "INFO"
        Write-Log "Current System Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" -Level "SUCCESS"
        Write-Log "Current UTC Time: $(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Exception during validation: $_" -Level "ERROR"
        return $false
    }
}

function Show-ConfigurationSummary {
    <#
    .SYNOPSIS
        Displays comprehensive configuration summary
    #>
    
    Write-LogHeader "CONFIGURATION SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    Write-Log "  Dry Run Mode: $DryRun" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Time Zone Configuration:" -Level "INFO"
    Write-Log "  Previous Time Zone: $($Global:Stats.PreviousTimeZone)" -Level "INFO"
    Write-Log "  Current Time Zone: $($Global:Stats.TimeZoneSet)" -Level "SUCCESS"
    
    Write-Log " " -Level "INFO"
    Write-Log "NTP Configuration:" -Level "INFO"
    Write-Log "  NTP Enabled: $EnableNTP" -Level "INFO"
    Write-Log "  NTP Configured: $($Global:Stats.NTPConfigured)" -Level $(if($Global:Stats.NTPConfigured){"SUCCESS"}else{"INFO"})
    Write-Log "  NTP Servers Configured: $($Global:Stats.NTPServersConfigured)" -Level "INFO"
    Write-Log "  Time Synchronized: $($Global:Stats.TimeSynced)" -Level $(if($Global:Stats.TimeSynced){"SUCCESS"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
}

function Show-AvailableTimeZones {
    <#
    .SYNOPSIS
        Displays common time zones for reference
    #>
    
    Write-LogHeader "COMMON US TIME ZONES"
    
    $CommonTimeZones = @(
        "Pacific Standard Time",
        "Mountain Standard Time",
        "Central Standard Time",
        "Eastern Standard Time",
        "Alaskan Standard Time",
        "Hawaiian Standard Time",
        "Arizona Standard Time"
    )
    
    Write-Log "Common US Time Zones:" -Level "INFO"
    foreach ($TZ in $CommonTimeZones) {
        try {
            $TimeZoneInfo = Get-TimeZone -Id $TZ -ErrorAction SilentlyContinue
            if ($TimeZoneInfo) {
                Write-Log "  $TZ - $($TimeZoneInfo.DisplayName)" -Level "INFO"
            }
        }
        catch {
            # Skip if not available
        }
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "To see ALL available time zones, run:" -Level "INFO"
    Write-Log "  Get-TimeZone -ListAvailable | Select-Object Id, DisplayName" -Level "INFO"
}

#endregion

#region MAIN EXECUTION
#==============================================================================

try {
    # Display banner
    Clear-Host
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        TIME ZONE & NTP CONFIGURATION                          ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "TIME ZONE & NTP CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Time Zone: $TimeZone" -Level "INFO"
    Write-Log "  Enable NTP: $EnableNTP" -Level "INFO"
    if ($EnableNTP) {
        Write-Log "  NTP Server: $NTPServer" -Level "INFO"
        Write-Log "  Fallback Servers: $($FallbackNTPServers -join ', ')" -Level "INFO"
        Write-Log "  Sync Interval: $SyncInterval seconds" -Level "INFO"
    }
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        
        # Show available time zones if time zone validation failed
        if (-not (Test-TimeZoneValid -TimeZoneId $TimeZone)) {
            Show-AvailableTimeZones
        }
        
        exit 2
    }
    
    # Configure time zone
    $TimeZoneResult = Set-SystemTimeZone
    
    if (-not $TimeZoneResult) {
        Write-Log "Time zone configuration failed" -Level "ERROR"
        exit 3
    }
    
    # Configure NTP
    if ($EnableNTP) {
        $NTPResult = Set-NTPConfiguration
        
        if (-not $NTPResult) {
            Write-Log "NTP configuration failed" -Level "ERROR"
            exit 4
        }
        
        # Force time synchronization
        $SyncResult = Invoke-TimeSync
        
        if (-not $SyncResult) {
            Write-Log "Time synchronization failed" -Level "WARNING"
            # Not a critical error, just warn
        }
    }
    
    # Validate configuration
    Test-TimeConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Time zone and NTP configuration completed successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-ConfigurationSummary
    
    exit 1
}

#endregion
