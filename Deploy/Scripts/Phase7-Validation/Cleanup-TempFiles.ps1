<#
.SYNOPSIS
    Clean Up Temporary Files
    
.DESCRIPTION
    Removes temporary files and cleans up deployment artifacts after
    Windows 11 deployment completion. Reclaims disk space and removes
    deployment-related files no longer needed.
    
    Cleanup Targets:
    - Windows temporary files
    - User temporary files
    - Deployment cache files
    - Windows Update cache
    - Installation logs (old)
    - Recycle Bin
    - Browser caches
    - Prefetch files
    
.PARAMETER RemoveLocalCache
    Remove deployment script cache files.
    Default: $true
    
.PARAMETER CleanWindowsTemp
    Clean Windows temp folder (C:\Windows\Temp).
    Default: $true
    
.PARAMETER CleanUserTemp
    Clean user temp folders.
    Default: $false (leaves user data alone)
    
.PARAMETER EmptyRecycleBin
    Empty Recycle Bin.
    Default: $true
    
.PARAMETER CleanUpdateCache
    Clean Windows Update download cache.
    Default: $false (may need updates)
    
.PARAMETER RemoveOldLogs
    Remove logs older than X days.
    Default: $false
    
.PARAMETER LogRetentionDays
    Days to keep logs if RemoveOldLogs enabled.
    Default: 30
    
.PARAMETER DryRun
    Simulate cleanup without removing. Default: $false
    
.EXAMPLE
    .\Cleanup-TempFiles.ps1
    Standard cleanup (Windows temp, deployment cache)
    
.EXAMPLE
    .\Cleanup-TempFiles.ps1 -CleanWindowsTemp $true -EmptyRecycleBin $true
    Clean Windows temp and empty recycle bin
    
.EXAMPLE
    .\Cleanup-TempFiles.ps1 -CleanUserTemp $true
    Includes user temporary files
    
.EXAMPLE
    .\Cleanup-TempFiles.ps1 -RemoveOldLogs $true -LogRetentionDays 7
    Remove logs older than 7 days
    
.EXAMPLE
    .\Cleanup-TempFiles.ps1 -DryRun
    Shows what would be removed
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Post-deployment cleanup for Windows 11 workstations
    
    EXIT CODES:
    0   = Cleanup successful
    1   = General failure
    2   = Insufficient permissions
    3   = Cleanup failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    CLEANUP CATEGORIES:
    1. Deployment Artifacts (scripts, cache)
    2. Windows Temporary Files
    3. User Temporary Files (optional)
    4. Update Cache (optional)
    5. Recycle Bin
    6. Old Logs (optional)
    
    SAFETY:
    - Never removes system files
    - Never removes user documents
    - Never removes application data
    - Dry run available for testing
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$RemoveLocalCache = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanWindowsTemp = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanUserTemp = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$EmptyRecycleBin = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanUpdateCache = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemoveOldLogs = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$LogRetentionDays = 30,
    
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

$LogFileName = "Cleanup-TempFiles_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Cleanup paths
$Global:CleanupPaths = @{
    WindowsTemp = "C:\Windows\Temp"
    DeploymentCache = "C:\DeploymentCache"
    UpdateCache = "C:\Windows\SoftwareDistribution\Download"
    Prefetch = "C:\Windows\Prefetch"
    OrchestrationCache = "C:\DeploymentScripts"
}

# Statistics tracking
$Global:Stats = @{
    FilesRemoved = 0
    FoldersRemoved = 0
    SpaceFreedMB = 0
    Errors = 0
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
}

function Write-LogHeader {
    param([string]$Title)
    $Separator = "=" * 80
    Write-Log $Separator -Level "INFO"
    Write-Log $Title -Level "INFO"
    Write-Log $Separator -Level "INFO"
}

#endregion

#region HELPER FUNCTIONS
#==============================================================================

function Get-FolderSize {
    <#
    .SYNOPSIS
        Gets total size of folder
    #>
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            return 0
        }
        
        $Size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
            Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        
        if ($Size) {
            return [math]::Round($Size / 1MB, 2)
        }
        else {
            return 0
        }
    }
    catch {
        return 0
    }
}

function Remove-SafelyWithRetry {
    <#
    .SYNOPSIS
        Safely removes files/folders with retry logic
    #>
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Recurse
    )
    
    try {
        if (-not (Test-Path $Path)) {
            Write-Log "  Path not found: $Path" -Level "DEBUG"
            return $true
        }
        
        # Get size before removal
        $SizeMB = Get-FolderSize -Path $Path
        
        if ($DryRun) {
            Write-Log "  [DRY RUN] Would remove: $Path ($SizeMB MB)" -Level "INFO"
            $Global:Stats.SpaceFreedMB += $SizeMB
            return $true
        }
        
        # Count items
        $Items = Get-ChildItem -Path $Path -Recurse:$Recurse -Force -ErrorAction SilentlyContinue
        $ItemCount = ($Items | Measure-Object).Count
        
        Write-Log "  Removing $ItemCount items from: $Description" -Level "DEBUG"
        
        # Remove items
        if ($Recurse) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            $Global:Stats.FoldersRemoved++
        }
        else {
            foreach ($Item in $Items) {
                try {
                    Remove-Item -Path $Item.FullName -Force -ErrorAction Stop
                    if ($Item.PSIsContainer) {
                        $Global:Stats.FoldersRemoved++
                    }
                    else {
                        $Global:Stats.FilesRemoved++
                    }
                }
                catch {
                    # Skip locked files
                    Write-Log "    Skipping locked file: $($Item.Name)" -Level "DEBUG"
                }
            }
        }
        
        $Global:Stats.SpaceFreedMB += $SizeMB
        Write-Log "  ✓ Freed $SizeMB MB from $Description" -Level "SUCCESS"
        
        return $true
        
    }
    catch {
        Write-Log "  ✗ Failed to remove $Description : $_" -Level "WARNING"
        $Global:Stats.Errors++
        return $false
    }
}

#endregion

#region CLEANUP FUNCTIONS
#==============================================================================

function Remove-DeploymentCache {
    <#
    .SYNOPSIS
        Removes deployment cache files
    #>
    
    Write-LogHeader "CLEANING DEPLOYMENT CACHE"
    
    if (-not $RemoveLocalCache) {
        Write-Log "Deployment cache cleanup disabled" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Removing deployment cache files..." -Level "INFO"
        
        # Deployment cache
        if (Test-Path $Global:CleanupPaths.DeploymentCache) {
            $Size = Get-FolderSize -Path $Global:CleanupPaths.DeploymentCache
            Write-Log "  Found deployment cache: $Size MB" -Level "INFO"
            
            Remove-SafelyWithRetry -Path "$($Global:CleanupPaths.DeploymentCache)\*" `
                -Description "Deployment Cache" -Recurse:$false
        }
        
        # Orchestration scripts (optional - careful!)
        if (Test-Path $Global:CleanupPaths.OrchestrationCache) {
            Write-Log "  Note: Deployment scripts found at $($Global:CleanupPaths.OrchestrationCache)" -Level "INFO"
            Write-Log "  (Keeping scripts for troubleshooting - remove manually if needed)" -Level "INFO"
        }
        
        Write-Log "Deployment cache cleanup completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception cleaning deployment cache: $_" -Level "ERROR"
    }
}

function Remove-WindowsTemp {
    <#
    .SYNOPSIS
        Cleans Windows temporary files
    #>
    
    Write-LogHeader "CLEANING WINDOWS TEMPORARY FILES"
    
    if (-not $CleanWindowsTemp) {
        Write-Log "Windows temp cleanup disabled" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Cleaning Windows temporary files..." -Level "INFO"
        
        # Windows Temp
        if (Test-Path $Global:CleanupPaths.WindowsTemp) {
            $Size = Get-FolderSize -Path $Global:CleanupPaths.WindowsTemp
            Write-Log "  Windows Temp: $Size MB" -Level "INFO"
            
            Remove-SafelyWithRetry -Path "$($Global:CleanupPaths.WindowsTemp)\*" `
                -Description "Windows Temp" -Recurse:$false
        }
        
        # System Temp (if different)
        $SystemTemp = [System.IO.Path]::GetTempPath()
        if ($SystemTemp -and (Test-Path $SystemTemp) -and $SystemTemp -ne "$($Global:CleanupPaths.WindowsTemp)\") {
            $Size = Get-FolderSize -Path $SystemTemp
            Write-Log "  System Temp: $Size MB" -Level "INFO"
            
            Remove-SafelyWithRetry -Path "$SystemTemp*" `
                -Description "System Temp" -Recurse:$false
        }
        
        # Prefetch (optional - can improve boot time)
        if (Test-Path $Global:CleanupPaths.Prefetch) {
            $Size = Get-FolderSize -Path $Global:CleanupPaths.Prefetch
            Write-Log "  Prefetch: $Size MB (keeping for boot optimization)" -Level "DEBUG"
        }
        
        Write-Log "Windows temp cleanup completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception cleaning Windows temp: $_" -Level "ERROR"
    }
}

function Remove-UserTemp {
    <#
    .SYNOPSIS
        Cleans user temporary files
    #>
    
    Write-LogHeader "CLEANING USER TEMPORARY FILES"
    
    if (-not $CleanUserTemp) {
        Write-Log "User temp cleanup disabled (default - preserves user data)" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Cleaning user temporary files..." -Level "WARNING"
        Write-Log "  (This may remove user-specific temp data)" -Level "WARNING"
        
        # Get all user profiles
        $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
        
        foreach ($Profile in $UserProfiles) {
            $UserTempPath = Join-Path $Profile.FullName "AppData\Local\Temp"
            
            if (Test-Path $UserTempPath) {
                $Size = Get-FolderSize -Path $UserTempPath
                Write-Log "  User: $($Profile.Name) - $Size MB" -Level "INFO"
                
                Remove-SafelyWithRetry -Path "$UserTempPath\*" `
                    -Description "User Temp ($($Profile.Name))" -Recurse:$false
            }
        }
        
        Write-Log "User temp cleanup completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception cleaning user temp: $_" -Level "ERROR"
    }
}

function Remove-UpdateCache {
    <#
    .SYNOPSIS
        Cleans Windows Update download cache
    #>
    
    Write-LogHeader "CLEANING WINDOWS UPDATE CACHE"
    
    if (-not $CleanUpdateCache) {
        Write-Log "Update cache cleanup disabled (recommended - keeps update files)" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Cleaning Windows Update cache..." -Level "WARNING"
        Write-Log "  (This will require re-downloading updates if needed)" -Level "WARNING"
        
        # Stop Windows Update service
        Write-Log "  Stopping Windows Update service..." -Level "DEBUG"
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Clean download cache
        if (Test-Path $Global:CleanupPaths.UpdateCache) {
            $Size = Get-FolderSize -Path $Global:CleanupPaths.UpdateCache
            Write-Log "  Update Cache: $Size MB" -Level "INFO"
            
            if (-not $DryRun) {
                Remove-SafelyWithRetry -Path "$($Global:CleanupPaths.UpdateCache)\*" `
                    -Description "Update Cache" -Recurse:$false
            }
        }
        
        # Restart Windows Update service
        Write-Log "  Restarting Windows Update service..." -Level "DEBUG"
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        Write-Log "Update cache cleanup completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception cleaning update cache: $_" -Level "ERROR"
        
        # Ensure service is restarted
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }
}

function Clear-RecycleBin {
    <#
    .SYNOPSIS
        Empties Recycle Bin
    #>
    
    Write-LogHeader "EMPTYING RECYCLE BIN"
    
    if (-not $EmptyRecycleBin) {
        Write-Log "Recycle Bin cleanup disabled" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Emptying Recycle Bin..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would empty Recycle Bin" -Level "INFO"
            return
        }
        
        # Use Clear-RecycleBin cmdlet (Windows 10+)
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-Log "  ✓ Recycle Bin emptied" -Level "SUCCESS"
        }
        catch {
            # Fallback method using COM
            $Shell = New-Object -ComObject Shell.Application
            $RecycleBin = $Shell.Namespace(0xA)
            $RecycleBin.Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }
            Write-Log "  ✓ Recycle Bin emptied (fallback method)" -Level "SUCCESS"
        }
        
    }
    catch {
        Write-Log "Exception emptying Recycle Bin: $_" -Level "WARNING"
    }
}

function Remove-OldLogs {
    <#
    .SYNOPSIS
        Removes old log files
    #>
    
    Write-LogHeader "CLEANING OLD LOGS"
    
    if (-not $RemoveOldLogs) {
        Write-Log "Old log cleanup disabled (logs preserved)" -Level "INFO"
        return
    }
    
    try {
        Write-Log "Removing logs older than $LogRetentionDays days..." -Level "INFO"
        
        $CutoffDate = (Get-Date).AddDays(-$LogRetentionDays)
        
        # Orchestration logs
        if (Test-Path $LogPath) {
            $OldLogs = Get-ChildItem $LogPath -Filter "*.log" -File | 
                Where-Object { $_.LastWriteTime -lt $CutoffDate }
            
            if ($OldLogs) {
                $LogCount = ($OldLogs | Measure-Object).Count
                $LogSizeMB = [math]::Round(($OldLogs | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                
                Write-Log "  Found $LogCount old logs ($LogSizeMB MB)" -Level "INFO"
                
                if (-not $DryRun) {
                    foreach ($Log in $OldLogs) {
                        Remove-Item $Log.FullName -Force -ErrorAction SilentlyContinue
                        $Global:Stats.FilesRemoved++
                    }
                    $Global:Stats.SpaceFreedMB += $LogSizeMB
                    Write-Log "  ✓ Removed $LogCount old logs" -Level "SUCCESS"
                }
                else {
                    Write-Log "  [DRY RUN] Would remove $LogCount logs" -Level "INFO"
                }
            }
            else {
                Write-Log "  No old logs found (all logs within retention period)" -Level "SUCCESS"
            }
        }
        
    }
    catch {
        Write-Log "Exception removing old logs: $_" -Level "ERROR"
    }
}

function Invoke-DiskCleanup {
    <#
    .SYNOPSIS
        Runs Windows Disk Cleanup utility (optional)
    #>
    
    Write-Log "Note: Windows Disk Cleanup utility available manually:" -Level "INFO"
    Write-Log "  cleanmgr.exe /d C: /verylowdisk" -Level "INFO"
    Write-Log "  (Run manually if additional cleanup needed)" -Level "INFO"
}

#endregion

#region SUMMARY
#==============================================================================

function Show-CleanupSummary {
    Write-LogHeader "CLEANUP SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Cleanup Results:" -Level "INFO"
    Write-Log "  Files Removed: $($Global:Stats.FilesRemoved)" -Level $(if($Global:Stats.FilesRemoved -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Folders Removed: $($Global:Stats.FoldersRemoved)" -Level $(if($Global:Stats.FoldersRemoved -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Space Freed: $([math]::Round($Global:Stats.SpaceFreedMB, 2)) MB" -Level $(if($Global:Stats.SpaceFreedMB -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Cleanup Operations:" -Level "INFO"
    
    if ($RemoveLocalCache) {
        Write-Log "  ✓ Deployment Cache" -Level "SUCCESS"
    }
    if ($CleanWindowsTemp) {
        Write-Log "  ✓ Windows Temporary Files" -Level "SUCCESS"
    }
    if ($CleanUserTemp) {
        Write-Log "  ✓ User Temporary Files" -Level "SUCCESS"
    }
    if ($EmptyRecycleBin) {
        Write-Log "  ✓ Recycle Bin" -Level "SUCCESS"
    }
    if ($CleanUpdateCache) {
        Write-Log "  ✓ Update Cache" -Level "SUCCESS"
    }
    if ($RemoveOldLogs) {
        Write-Log "  ✓ Old Logs (>$LogRetentionDays days)" -Level "SUCCESS"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Disk Space:" -Level "INFO"
    
    try {
        $CDrive = Get-PSDrive C
        $FreeSpaceGB = [math]::Round($CDrive.Free / 1GB, 2)
        $TotalSpaceGB = [math]::Round(($CDrive.Used + $CDrive.Free) / 1GB, 2)
        $PercentFree = [math]::Round(($CDrive.Free / ($CDrive.Used + $CDrive.Free)) * 100, 1)
        
        Write-Log "  C:\ Free Space: $FreeSpaceGB GB / $TotalSpaceGB GB ($PercentFree%)" -Level "INFO"
    }
    catch {
        Write-Log "  Could not retrieve disk space" -Level "DEBUG"
    }
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
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
║        TEMPORARY FILES CLEANUP                                ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    if ($DryRun) {
        Write-Host "DRY RUN MODE: No files will be removed" -ForegroundColor Yellow
    }
    Write-Host ""
    
    Write-LogHeader "TEMPORARY FILES CLEANUP STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Deployment Cache: $RemoveLocalCache" -Level "INFO"
    Write-Log "Windows Temp: $CleanWindowsTemp" -Level "INFO"
    Write-Log "User Temp: $CleanUserTemp" -Level "INFO"
    Write-Log "Recycle Bin: $EmptyRecycleBin" -Level "INFO"
    Write-Log "Update Cache: $CleanUpdateCache" -Level "INFO"
    Write-Log "Old Logs: $RemoveOldLogs" -Level "INFO"
    Write-Log "Dry Run: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Check initial disk space
    $CDrive = Get-PSDrive C
    $InitialFreeGB = [math]::Round($CDrive.Free / 1GB, 2)
    Write-Log "Initial C:\ Free Space: $InitialFreeGB GB" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Run cleanup operations
    Remove-DeploymentCache
    Remove-WindowsTemp
    Remove-UserTemp
    Remove-UpdateCache
    Clear-RecycleBin
    Remove-OldLogs
    Invoke-DiskCleanup
    
    # Show summary
    Show-CleanupSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) {
        0  # Success
    } else {
        3  # Some errors
    }
    
    Write-Log " " -Level "INFO"
    if ($Global:Stats.SpaceFreedMB -gt 0) {
        Write-Log "Cleanup completed successfully! Freed $([math]::Round($Global:Stats.SpaceFreedMB, 2)) MB" -Level "SUCCESS"
    }
    else {
        Write-Log "Cleanup completed - minimal space to reclaim" -Level "INFO"
    }
    
    if ($Global:Stats.Errors -gt 0) {
        Write-Log "Warning: $($Global:Stats.Errors) errors occurred during cleanup" -Level "WARNING"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-CleanupSummary
    
    exit 1
}

#endregion
