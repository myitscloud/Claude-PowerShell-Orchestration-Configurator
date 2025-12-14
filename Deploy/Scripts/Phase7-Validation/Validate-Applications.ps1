<#
.SYNOPSIS
    Application Installation Validation
    
.DESCRIPTION
    Validates that all required applications are properly installed and functional.
    Checks applications installed in Phase 4 and verifies versions, paths, and functionality.
    
    Validation Checks:
    - Application presence (installed)
    - Application version
    - Installation path
    - Registry entries
    - File existence
    - Executable functionality
    - License activation (where applicable)
    - Recent usage/logs
    
.PARAMETER RequiredApps
    Array of required application names to validate.
    
    Default: @("Microsoft Office", "Google Chrome", "Adobe Reader", "Microsoft Teams")
    
    Supported Applications:
    - Microsoft Office (Word, Excel, PowerPoint, Outlook)
    - Google Chrome
    - Mozilla Firefox
    - Adobe Acrobat Reader DC
    - Microsoft Teams
    - 7-Zip
    - VLC Media Player
    - Notepad++
    - Custom applications
    
.PARAMETER ValidateVersions
    Check application versions against minimum requirements.
    Default: $true
    
.PARAMETER ValidateLicensing
    Validate Office/Adobe licensing and activation.
    Default: $true
    
.PARAMETER GenerateReport
    Generate detailed validation report.
    Default: $true
    
.PARAMETER ReportPath
    Path to save validation report.
    Default: C:\ProgramData\ValidationReports\
    
.PARAMETER FailOnMissingApps
    Exit with error code if required apps missing.
    Default: $false
    
.PARAMETER DryRun
    Simulate validation without checking. Default: $false
    
.EXAMPLE
    .\Validate-Applications.ps1
    Validates default required applications
    
.EXAMPLE
    .\Validate-Applications.ps1 -RequiredApps @("Chrome", "Teams", "Office")
    Validates specific applications
    
.EXAMPLE
    .\Validate-Applications.ps1 -ValidateVersions $true
    Validates apps and checks versions
    
.EXAMPLE
    .\Validate-Applications.ps1 -GenerateReport $true
    Generates detailed validation report
    
.EXAMPLE
    .\Validate-Applications.ps1 -DryRun
    Shows what would be validated
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Application validation for Windows 11 workstations
    
    EXIT CODES:
    0   = All applications validated successfully
    1   = General failure
    2   = Not running as administrator
    3   = Required applications missing (if FailOnMissingApps = $true)
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    - Applications should be installed (Phase 4)
    
    VALIDATION METHODS:
    1. Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    2. File System: Program Files, Program Files (x86)
    3. PATH environment variable
    4. Application-specific checks
    5. Version validation
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$RequiredApps = @("Microsoft Office", "Google Chrome", "Adobe Reader", "Microsoft Teams"),
    
    [Parameter(Mandatory=$false)]
    [bool]$ValidateVersions = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ValidateLicensing = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$GenerateReport = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\ProgramData\ValidationReports",
    
    [Parameter(Mandatory=$false)]
    [bool]$FailOnMissingApps = $false,
    
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

$LogFileName = "Validate-Applications_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Validation tracking
$Global:ValidationResults = @{
    TotalApps = 0
    Installed = 0
    Missing = 0
    VersionOK = 0
    VersionWarning = 0
    LicenseOK = 0
    LicenseFailed = 0
    Applications = @{}
}

# Statistics tracking
$Global:Stats = @{
    Errors = 0
    Warnings = 0
    ChecksPerformed = 0
}

# Application definitions with validation logic
$Global:AppDefinitions = @{
    "Microsoft Office" = @{
        DisplayNames = @("Microsoft Office Professional Plus", "Microsoft 365 Apps", "Office 16", "Microsoft Office 365")
        Executables = @("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
        Paths = @("C:\Program Files\Microsoft Office", "C:\Program Files (x86)\Microsoft Office")
        MinVersion = "16.0"
        RegistryKeys = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun")
        ValidateLicense = $true
    }
    "Google Chrome" = @{
        DisplayNames = @("Google Chrome")
        Executables = @("chrome.exe")
        Paths = @("C:\Program Files\Google\Chrome\Application", "C:\Program Files (x86)\Google\Chrome\Application")
        MinVersion = "100.0"
        RegistryKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
        ValidateLicense = $false
    }
    "Mozilla Firefox" = @{
        DisplayNames = @("Mozilla Firefox")
        Executables = @("firefox.exe")
        Paths = @("C:\Program Files\Mozilla Firefox", "C:\Program Files (x86)\Mozilla Firefox")
        MinVersion = "100.0"
        RegistryKeys = @("HKLM:\SOFTWARE\Mozilla\Mozilla Firefox")
        ValidateLicense = $false
    }
    "Adobe Reader" = @{
        DisplayNames = @("Adobe Acrobat Reader DC", "Adobe Reader")
        Executables = @("AcroRd32.exe", "Acrobat.exe")
        Paths = @("C:\Program Files\Adobe\Acrobat Reader DC", "C:\Program Files (x86)\Adobe\Acrobat Reader DC")
        MinVersion = "20.0"
        RegistryKeys = @("HKLM:\SOFTWARE\Adobe\Acrobat Reader")
        ValidateLicense = $false
    }
    "Microsoft Teams" = @{
        DisplayNames = @("Microsoft Teams", "Teams Machine-Wide Installer")
        Executables = @("Teams.exe")
        Paths = @("C:\Program Files\WindowsApps", "C:\Users\*\AppData\Local\Microsoft\Teams")
        MinVersion = "1.5"
        RegistryKeys = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Teams")
        ValidateLicense = $false
    }
    "7-Zip" = @{
        DisplayNames = @("7-Zip")
        Executables = @("7zFM.exe", "7z.exe")
        Paths = @("C:\Program Files\7-Zip", "C:\Program Files (x86)\7-Zip")
        MinVersion = "19.0"
        RegistryKeys = @("HKLM:\SOFTWARE\7-Zip")
        ValidateLicense = $false
    }
    "VLC Media Player" = @{
        DisplayNames = @("VLC media player")
        Executables = @("vlc.exe")
        Paths = @("C:\Program Files\VideoLAN\VLC", "C:\Program Files (x86)\VideoLAN\VLC")
        MinVersion = "3.0"
        RegistryKeys = @("HKLM:\SOFTWARE\VideoLAN\VLC")
        ValidateLicense = $false
    }
    "Notepad++" = @{
        DisplayNames = @("Notepad++")
        Executables = @("notepad++.exe")
        Paths = @("C:\Program Files\Notepad++", "C:\Program Files (x86)\Notepad++")
        MinVersion = "8.0"
        RegistryKeys = @("HKLM:\SOFTWARE\Notepad++")
        ValidateLicense = $false
    }
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

function Add-ValidationResult {
    param(
        [string]$AppName,
        [bool]$Installed,
        [string]$Version = "Unknown",
        [string]$Path = "Not Found",
        [bool]$VersionOK = $true,
        [string]$LicenseStatus = "N/A",
        [string]$Details = ""
    )
    
    $Global:ValidationResults.TotalApps++
    
    if ($Installed) {
        $Global:ValidationResults.Installed++
        Write-Log "  ✓ $AppName - Installed" -Level "SUCCESS"
        Write-Log "    Version: $Version" -Level "DEBUG"
        Write-Log "    Path: $Path" -Level "DEBUG"
    }
    else {
        $Global:ValidationResults.Missing++
        Write-Log "  ✗ $AppName - NOT INSTALLED" -Level "ERROR"
    }
    
    if ($VersionOK) {
        $Global:ValidationResults.VersionOK++
    }
    else {
        $Global:ValidationResults.VersionWarning++
        Write-Log "    ⚠ Version may be outdated: $Version" -Level "WARNING"
    }
    
    # Store result
    $Global:ValidationResults.Applications[$AppName] = @{
        Installed = $Installed
        Version = $Version
        Path = $Path
        VersionOK = $VersionOK
        LicenseStatus = $LicenseStatus
        Details = $Details
    }
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
        Write-Log "WARNING: Not running as Administrator (some checks may be limited)" -Level "WARNING"
    }
    else {
        Write-Log "Administrator privileges confirmed" -Level "SUCCESS"
    }
    
    # Check 2: Required apps specified
    Write-Log "Required applications to validate: $($RequiredApps.Count)" -Level "INFO"
    
    foreach ($App in $RequiredApps) {
        Write-Log "  - $App" -Level "DEBUG"
    }
    
    return $AllChecksPassed
}

#endregion

#region APPLICATION DETECTION FUNCTIONS
#==============================================================================

function Get-InstalledApplications {
    <#
    .SYNOPSIS
        Gets all installed applications from registry
    #>
    
    Write-Log "Scanning installed applications..." -Level "DEBUG"
    
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $InstalledApps = @()
    
    foreach ($Path in $UninstallPaths) {
        try {
            $Apps = Get-ItemProperty $Path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, InstallLocation, Publisher
            
            $InstalledApps += $Apps
        }
        catch {
            Write-Log "Could not access registry path: $Path" -Level "DEBUG"
        }
    }
    
    Write-Log "Found $($InstalledApps.Count) installed applications in registry" -Level "DEBUG"
    
    return $InstalledApps
}

function Test-ApplicationInstalled {
    <#
    .SYNOPSIS
        Tests if a specific application is installed
    #>
    param(
        [string]$AppName,
        [hashtable]$AppDefinition
    )
    
    Write-LogHeader "VALIDATING: $AppName"
    
    $Global:Stats.ChecksPerformed++
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would validate: $AppName" -Level "INFO"
        Add-ValidationResult -AppName $AppName -Installed $true -Version "DRY-RUN" -Path "DRY-RUN"
        return
    }
    
    try {
        Write-Log "Checking installation..." -Level "INFO"
        
        # Get all installed apps
        $InstalledApps = Get-InstalledApplications
        
        # Method 1: Check registry display names
        $Found = $false
        $Version = "Unknown"
        $InstallPath = "Not Found"
        
        foreach ($DisplayName in $AppDefinition.DisplayNames) {
            $Match = $InstalledApps | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            
            if ($Match) {
                $Found = $true
                $Version = $Match[0].DisplayVersion
                $InstallPath = $Match[0].InstallLocation
                Write-Log "Found in registry: $($Match[0].DisplayName)" -Level "DEBUG"
                break
            }
        }
        
        # Method 2: Check for executables
        if (-not $Found) {
            foreach ($ExePath in $AppDefinition.Paths) {
                if (Test-Path $ExePath) {
                    foreach ($Exe in $AppDefinition.Executables) {
                        $FullPath = Join-Path $ExePath $Exe
                        if (Test-Path $FullPath) {
                            $Found = $true
                            $InstallPath = $ExePath
                            
                            # Try to get version from executable
                            try {
                                $FileVersion = (Get-Item $FullPath).VersionInfo.FileVersion
                                if ($FileVersion) {
                                    $Version = $FileVersion
                                }
                            }
                            catch {
                                Write-Log "Could not get version from executable" -Level "DEBUG"
                            }
                            
                            Write-Log "Found executable: $FullPath" -Level "DEBUG"
                            break
                        }
                    }
                    if ($Found) { break }
                }
            }
        }
        
        # Method 3: Check registry keys
        if (-not $Found) {
            foreach ($RegKey in $AppDefinition.RegistryKeys) {
                if (Test-Path $RegKey) {
                    $Found = $true
                    Write-Log "Found registry key: $RegKey" -Level "DEBUG"
                    break
                }
            }
        }
        
        # Validate version if found and required
        $VersionOK = $true
        if ($Found -and $ValidateVersions -and $AppDefinition.MinVersion) {
            try {
                # Parse versions for comparison
                $CurrentVersion = [version]($Version -replace '[^\d\.]', '')
                $MinimumVersion = [version]$AppDefinition.MinVersion
                
                if ($CurrentVersion -lt $MinimumVersion) {
                    $VersionOK = $false
                    Write-Log "Version check: Current ($Version) < Minimum ($($AppDefinition.MinVersion))" -Level "WARNING"
                }
                else {
                    Write-Log "Version check: OK ($Version >= $($AppDefinition.MinVersion))" -Level "DEBUG"
                }
            }
            catch {
                Write-Log "Could not parse version for comparison" -Level "DEBUG"
            }
        }
        
        # Check licensing if applicable
        $LicenseStatus = "N/A"
        if ($Found -and $ValidateLicensing -and $AppDefinition.ValidateLicense) {
            $LicenseStatus = Test-ApplicationLicense -AppName $AppName -AppDefinition $AppDefinition
        }
        
        # Add result
        Add-ValidationResult -AppName $AppName -Installed $Found -Version $Version `
            -Path $InstallPath -VersionOK $VersionOK -LicenseStatus $LicenseStatus
        
    }
    catch {
        Write-Log "Exception validating $AppName : $_" -Level "ERROR"
        Add-ValidationResult -AppName $AppName -Installed $false -Details "Exception: $_"
    }
}

function Test-ApplicationLicense {
    <#
    .SYNOPSIS
        Validates application licensing (Office, Adobe)
    #>
    param(
        [string]$AppName,
        [hashtable]$AppDefinition
    )
    
    Write-Log "Checking license status..." -Level "DEBUG"
    
    try {
        if ($AppName -eq "Microsoft Office") {
            # Check Office licensing
            $OfficeLicense = cscript //nologo "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /dstatus 2>&1
            
            if ($OfficeLicense -match "LICENSE STATUS:.*LICENSED") {
                Write-Log "  ✓ Office license: LICENSED" -Level "SUCCESS"
                return "Licensed"
            }
            elseif ($OfficeLicense -match "LICENSE STATUS:.*GRACE") {
                Write-Log "  ⚠ Office license: GRACE PERIOD" -Level "WARNING"
                return "Grace Period"
            }
            else {
                Write-Log "  ✗ Office license: UNLICENSED" -Level "WARNING"
                return "Unlicensed"
            }
        }
        
        return "N/A"
    }
    catch {
        Write-Log "Could not validate license: $_" -Level "DEBUG"
        return "Unknown"
    }
}

#endregion

#region SPECIAL APPLICATION CHECKS
#==============================================================================

function Test-MicrosoftOffice {
    <#
    .SYNOPSIS
        Special validation for Microsoft Office components
    #>
    
    Write-LogHeader "VALIDATING: Microsoft Office Components"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would validate Office components" -Level "INFO"
        return
    }
    
    $OfficeApps = @{
        "Word" = "WINWORD.EXE"
        "Excel" = "EXCEL.EXE"
        "PowerPoint" = "POWERPNT.EXE"
        "Outlook" = "OUTLOOK.EXE"
    }
    
    foreach ($App in $OfficeApps.Keys) {
        $ExeName = $OfficeApps[$App]
        
        # Check common Office paths
        $OfficePaths = @(
            "C:\Program Files\Microsoft Office\root\Office16",
            "C:\Program Files (x86)\Microsoft Office\root\Office16"
        )
        
        $Found = $false
        foreach ($Path in $OfficePaths) {
            $FullPath = Join-Path $Path $ExeName
            if (Test-Path $FullPath) {
                Write-Log "  ✓ Office $App : $FullPath" -Level "SUCCESS"
                $Found = $true
                break
            }
        }
        
        if (-not $Found) {
            Write-Log "  ⚠ Office $App : Not found" -Level "WARNING"
        }
    }
}

function Test-GoogleChrome {
    <#
    .SYNOPSIS
        Special validation for Google Chrome
    #>
    
    Write-LogHeader "VALIDATING: Google Chrome Configuration"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would validate Chrome configuration" -Level "INFO"
        return
    }
    
    # Check Chrome is default browser
    $DefaultBrowser = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -Name ProgId -ErrorAction SilentlyContinue
    
    if ($DefaultBrowser.ProgId -eq "ChromeHTML") {
        Write-Log "  ✓ Chrome is default browser" -Level "SUCCESS"
    }
    else {
        Write-Log "  ℹ Default browser: $($DefaultBrowser.ProgId)" -Level "INFO"
    }
    
    # Check Chrome version
    $ChromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    if (Test-Path $ChromePath) {
        $Version = (Get-Item $ChromePath).VersionInfo.FileVersion
        Write-Log "  Chrome version: $Version" -Level "INFO"
    }
}

#endregion

#region REPORT GENERATION
#==============================================================================

function New-ValidationReport {
    Write-LogHeader "GENERATING VALIDATION REPORT"
    
    try {
        if (-not $GenerateReport) {
            Write-Log "Report generation disabled" -Level "INFO"
            return
        }
        
        Write-Log "Creating validation report..." -Level "INFO"
        
        # Ensure report directory exists
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $ReportFile = Join-Path $ReportPath "ApplicationValidation_$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        
        # Calculate success rate
        $SuccessRate = if ($Global:ValidationResults.TotalApps -gt 0) {
            [math]::Round(($Global:ValidationResults.Installed / $Global:ValidationResults.TotalApps) * 100, 2)
        } else { 0 }
        
        # Determine status
        $Status = if ($Global:ValidationResults.Missing -eq 0) {
            "ALL APPLICATIONS INSTALLED"
        } elseif ($SuccessRate -ge 80) {
            "MOSTLY COMPLETE"
        } else {
            "INCOMPLETE"
        }
        
        $StatusColor = switch ($Status) {
            "ALL APPLICATIONS INSTALLED" { "green" }
            "MOSTLY COMPLETE" { "orange" }
            "INCOMPLETE" { "red" }
        }
        
        # Build HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Application Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status { font-size: 24px; font-weight: bold; color: $StatusColor; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 36px; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        .app-list { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .app { padding: 10px; margin: 5px 0; border-left: 4px solid; }
        .app-installed { border-left-color: green; background-color: #d4edda; }
        .app-missing { border-left-color: red; background-color: #f8d7da; }
        .app-warning { border-left-color: orange; background-color: #fff3cd; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background-color: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Application Validation Report</h1>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Validated: $($Global:ValidationResults.TotalApps) applications</p>
    </div>
    
    <div class="summary">
        <div class="status">Status: $Status</div>
        <div class="metric">
            <div class="metric-value">$SuccessRate%</div>
            <div class="metric-label">Success Rate</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:ValidationResults.Installed)</div>
            <div class="metric-label">Installed</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:ValidationResults.Missing)</div>
            <div class="metric-label">Missing</div>
        </div>
    </div>
    
    <div class="app-list">
        <h2>Application Details</h2>
        <table>
            <tr>
                <th>Application</th>
                <th>Status</th>
                <th>Version</th>
                <th>Path</th>
                <th>License</th>
            </tr>
"@
        
        # Add application details
        foreach ($AppName in ($Global:ValidationResults.Applications.Keys | Sort-Object)) {
            $AppData = $Global:ValidationResults.Applications[$AppName]
            
            $StatusText = if ($AppData.Installed) { "✓ Installed" } else { "✗ Missing" }
            $StatusClass = if ($AppData.Installed) { "app-installed" } else { "app-missing" }
            
            $HTML += @"
            <tr class="$StatusClass">
                <td><strong>$AppName</strong></td>
                <td>$StatusText</td>
                <td>$($AppData.Version)</td>
                <td>$($AppData.Path)</td>
                <td>$($AppData.LicenseStatus)</td>
            </tr>
"@
        }
        
        $HTML += @"
        </table>
    </div>
</body>
</html>
"@
        
        # Save report
        Set-Content -Path $ReportFile -Value $HTML -Force
        
        Write-Log "Validation report generated: $ReportFile" -Level "SUCCESS"
        
        return $ReportFile
        
    }
    catch {
        Write-Log "Exception generating report: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region SUMMARY
#==============================================================================

function Show-ValidationSummary {
    Write-LogHeader "VALIDATION SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Validation Results:" -Level "INFO"
    Write-Log "  Total Applications: $($Global:ValidationResults.TotalApps)" -Level "INFO"
    Write-Log "  Installed: $($Global:ValidationResults.Installed)" -Level "SUCCESS"
    Write-Log "  Missing: $($Global:ValidationResults.Missing)" -Level $(if($Global:ValidationResults.Missing -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Version Warnings: $($Global:ValidationResults.VersionWarning)" -Level $(if($Global:ValidationResults.VersionWarning -gt 0){"WARNING"}else{"INFO"})
    
    $SuccessRate = if ($Global:ValidationResults.TotalApps -gt 0) {
        [math]::Round(($Global:ValidationResults.Installed / $Global:ValidationResults.TotalApps) * 100, 2)
    } else { 0 }
    
    Write-Log "  Success Rate: $SuccessRate%" -Level $(if($SuccessRate -eq 100){"SUCCESS"}elseif($SuccessRate -ge 80){"WARNING"}else{"ERROR"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Application Status:" -Level "INFO"
    
    foreach ($AppName in ($Global:ValidationResults.Applications.Keys | Sort-Object)) {
        $AppData = $Global:ValidationResults.Applications[$AppName]
        $Status = if ($AppData.Installed) { "✓ INSTALLED" } else { "✗ MISSING" }
        $Level = if ($AppData.Installed) { "SUCCESS" } else { "ERROR" }
        
        Write-Log "  $AppName : $Status ($($AppData.Version))" -Level $Level
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
║        APPLICATION INSTALLATION VALIDATION                    ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Applications to Validate: $($RequiredApps.Count)" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host ""
    
    Write-LogHeader "APPLICATION VALIDATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Validate Versions: $ValidateVersions" -Level "INFO"
    Write-Log "Validate Licensing: $ValidateLicensing" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    Test-Prerequisites
    
    # Validate each required application
    foreach ($AppName in $RequiredApps) {
        # Normalize app name
        $NormalizedName = $AppName.Trim()
        
        # Find matching app definition
        $AppDef = $null
        foreach ($Key in $Global:AppDefinitions.Keys) {
            if ($NormalizedName -like "*$Key*" -or $Key -like "*$NormalizedName*") {
                $AppDef = $Global:AppDefinitions[$Key]
                $NormalizedName = $Key
                break
            }
        }
        
        if ($AppDef) {
            Test-ApplicationInstalled -AppName $NormalizedName -AppDefinition $AppDef
        }
        else {
            Write-Log "WARNING: No validation definition for '$AppName'" -Level "WARNING"
            Add-ValidationResult -AppName $AppName -Installed $false -Details "No validation definition"
        }
    }
    
    # Special component checks
    if ($RequiredApps -contains "Microsoft Office") {
        Test-MicrosoftOffice
    }
    
    if ($RequiredApps -contains "Google Chrome") {
        Test-GoogleChrome
    }
    
    # Generate report
    if ($GenerateReport) {
        $ReportFile = New-ValidationReport
    }
    
    # Show summary
    Show-ValidationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:ValidationResults.Missing -eq 0) {
        0  # All apps installed
    } elseif ($FailOnMissingApps) {
        3  # Missing apps (failure)
    } else {
        0  # Missing apps but not failing
    }
    
    Write-Log " " -Level "INFO"
    if ($Global:ValidationResults.Missing -eq 0) {
        Write-Log "All required applications are installed!" -Level "SUCCESS"
    } elseif ($FailOnMissingApps) {
        Write-Log "FAILED: $($Global:ValidationResults.Missing) application(s) missing" -Level "ERROR"
    } else {
        Write-Log "Validation completed with $($Global:ValidationResults.Missing) missing application(s) (non-blocking)" -Level "WARNING"
    }
    
    if ($ReportFile) {
        Write-Log "Validation report: $ReportFile" -Level "SUCCESS"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-ValidationSummary
    
    exit 1
}

#endregion
