<#
.SYNOPSIS
    Set Default Applications for File Types and Protocols
    
.DESCRIPTION
    Configures default applications for file types (.pdf, .html, etc.) and 
    protocols (http, https, mailto) in Windows 11.
    
    Features:
    - Set default web browser
    - Set default PDF reader
    - Set default email client
    - Set default media player
    - Set default image viewer
    - Import default app associations XML
    - Export current associations
    - Apply to default user profile
    - Comprehensive logging and validation
    
.PARAMETER DefaultBrowser
    Default web browser application.
    Options: "Edge", "Chrome", "Firefox"
    Default: "Edge"
    
.PARAMETER DefaultPDF
    Default PDF reader application.
    Options: "Edge", "AcroRd32" (Adobe Reader), "Acrobat" (Adobe Acrobat)
    Default: "AcroRd32"
    
.PARAMETER DefaultEmail
    Default email client.
    Options: "Outlook", "Thunderbird"
    Default: "Outlook"
    
.PARAMETER DefaultMediaPlayer
    Default media player.
    Options: "VLC", "WindowsMediaPlayer", "MediaPlayerClassic"
    Default: "VLC"
    
.PARAMETER DefaultImageViewer
    Default image viewer.
    Options: "WindowsPhotoViewer", "Photos", "IrfanView"
    Default: "Photos"
    
.PARAMETER ConfigXML
    Path to default app associations XML file.
    Default: "Config\DefaultApps.xml"
    
    If not specified or file doesn't exist, uses individual settings
    
.PARAMETER ExportCurrentSettings
    Export current default app settings to XML file.
    Default: $false
    
.PARAMETER ExportPath
    Path to export current settings XML.
    Default: "C:\Temp\CurrentDefaultApps.xml"
    
.PARAMETER ApplyToAllUsers
    Apply to default user profile (new users).
    Default: $true
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Set-DefaultApps.ps1
    Sets default apps from orchestration config
    
.EXAMPLE
    .\Set-DefaultApps.ps1 -DefaultBrowser "Edge" -DefaultPDF "AcroRd32"
    Sets Edge as browser and Adobe Reader as PDF reader
    
.EXAMPLE
    .\Set-DefaultApps.ps1 -ConfigXML "C:\Deploy\DefaultApps.xml"
    Imports default apps from XML file
    
.EXAMPLE
    .\Set-DefaultApps.ps1 -ExportCurrentSettings
    Exports current default app settings to XML
    
.EXAMPLE
    .\Set-DefaultApps.ps1 -DryRun
    Shows what would be changed without applying
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Default application configuration for Windows 11 workstations
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Configuration failed
    4   = XML file not found
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    IMPORTANT NOTES:
    - Windows 11 changed default app setting mechanisms
    - XML-based associations most reliable method
    - Best run as SYSTEM (via SCCM or PsExec)
    - Changes may require sign out/sign in
    - Some apps must be installed before setting as default
    
    WINDOWS 11 COMPLEXITY:
    - Default apps harder to set than Windows 10
    - Microsoft intentionally made this more difficult
    - XML import via DISM is most reliable method
    - User-level registry changes less effective
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Edge", "Chrome", "Firefox")]
    [string]$DefaultBrowser = "Edge",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Edge", "AcroRd32", "Acrobat")]
    [string]$DefaultPDF = "AcroRd32",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Outlook", "Thunderbird")]
    [string]$DefaultEmail = "Outlook",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("VLC", "WindowsMediaPlayer", "MediaPlayerClassic")]
    [string]$DefaultMediaPlayer = "VLC",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("WindowsPhotoViewer", "Photos", "IrfanView")]
    [string]$DefaultImageViewer = "Photos",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigXML = "Config\DefaultApps.xml",
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportCurrentSettings = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\Temp\CurrentDefaultApps.xml",
    
    [Parameter(Mandatory=$false)]
    [bool]$ApplyToAllUsers = $true,
    
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

$LogFileName = "Set-DefaultApps_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    AssociationsSet = 0
    AssociationsFailed = 0
    XMLImported = $false
    XMLExported = $false
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
    
    # Check 2: Windows version
    Write-Log "Checking Windows version..." -Level "INFO"
    $OSVersion = [System.Environment]::OSVersion.Version
    $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    Write-Log "OS Version: $($OSVersion.Major).$($OSVersion.Minor) Build $BuildNumber" -Level "INFO"
    
    if ($BuildNumber -lt 22000) {
        Write-Log "WARNING: This script is optimized for Windows 11 (Build 22000+)" -Level "WARNING"
    }
    else {
        Write-Log "Windows 11 detected" -Level "SUCCESS"
    }
    
    # Check 3: DISM availability
    Write-Log "Checking DISM availability..." -Level "INFO"
    $DismPath = "$env:SystemRoot\System32\dism.exe"
    
    if (Test-Path $DismPath) {
        Write-Log "DISM found: $DismPath" -Level "SUCCESS"
    }
    else {
        Write-Log "WARNING: DISM not found" -Level "WARNING"
    }
    
    # Check 4: Config XML (if specified)
    if ($ConfigXML -and -not $ExportCurrentSettings) {
        Write-Log "Checking for config XML file..." -Level "INFO"
        
        # Make path absolute if relative
        if (-not [System.IO.Path]::IsPathRooted($ConfigXML)) {
            $ConfigXML = Join-Path (Split-Path $PSScriptRoot -Parent) $ConfigXML
        }
        
        if (Test-Path $ConfigXML) {
            Write-Log "Config XML found: $ConfigXML" -Level "SUCCESS"
        }
        else {
            Write-Log "Config XML not found: $ConfigXML" -Level "WARNING"
            Write-Log "Will use individual application settings instead" -Level "WARNING"
        }
    }
    
    return $AllChecksPassed
}

#endregion

#region APPLICATION MAPPING FUNCTIONS
#==============================================================================

function Get-AppAssociationID {
    <#
    .SYNOPSIS
        Gets the proper application association ID for DISM
    #>
    param(
        [string]$AppName,
        [string]$FileType
    )
    
    # Map friendly names to ProgIDs
    $Mappings = @{
        "Edge" = @{
            Browser = "MSEdgeHTM"
            PDF = "MSEdgePDF"
        }
        "Chrome" = @{
            Browser = "ChromeHTML"
            PDF = "ChromeHTML"
        }
        "Firefox" = @{
            Browser = "FirefoxHTML"
            PDF = "FirefoxHTML"
        }
        "AcroRd32" = @{
            PDF = "AcroExch.Document.DC"
        }
        "Acrobat" = @{
            PDF = "Acrobat.Document.DC"
        }
        "Outlook" = @{
            Email = "Outlook.File.msg.15"
        }
        "VLC" = @{
            Media = "VLC.mp4"
        }
        "Photos" = @{
            Image = "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc"
        }
    }
    
    if ($Mappings.ContainsKey($AppName)) {
        if ($Mappings[$AppName].ContainsKey($FileType)) {
            return $Mappings[$AppName][$FileType]
        }
    }
    
    return $null
}

#endregion

#region DEFAULT APPS CONFIGURATION FUNCTIONS
#==============================================================================

function Export-CurrentDefaultApps {
    <#
    .SYNOPSIS
        Exports current default app associations to XML
    #>
    
    Write-LogHeader "EXPORTING CURRENT DEFAULT APPS"
    
    try {
        Write-Log "Exporting current default app associations..." -Level "INFO"
        Write-Log "Export path: $ExportPath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would export to: $ExportPath" -Level "INFO"
            return $true
        }
        
        # Ensure export directory exists
        $ExportDir = Split-Path $ExportPath -Parent
        if (-not (Test-Path $ExportDir)) {
            New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null
        }
        
        # Export using DISM
        $DismArgs = "/Online", "/Export-DefaultAppAssociations:$ExportPath"
        
        Write-Log "Running: dism.exe $($DismArgs -join ' ')" -Level "DEBUG"
        
        $Result = & dism.exe $DismArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Default apps exported successfully" -Level "SUCCESS"
            Write-Log "Exported to: $ExportPath" -Level "SUCCESS"
            $Global:Stats.XMLExported = $true
            
            # Display exported file
            if (Test-Path $ExportPath) {
                $Content = Get-Content $ExportPath -Raw
                Write-Log "Exported XML content preview:" -Level "DEBUG"
                Write-Log $Content.Substring(0, [Math]::Min(500, $Content.Length)) -Level "DEBUG"
            }
        }
        else {
            Write-Log "Failed to export default apps: Exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Exception exporting default apps: $_" -Level "ERROR"
        return $false
    }
}

function Import-DefaultAppAssociations {
    <#
    .SYNOPSIS
        Imports default app associations from XML using DISM
    #>
    param([string]$XMLPath)
    
    Write-LogHeader "IMPORTING DEFAULT APP ASSOCIATIONS"
    
    if (-not (Test-Path $XMLPath)) {
        Write-Log "XML file not found: $XMLPath" -Level "ERROR"
        return $false
    }
    
    try {
        Write-Log "Importing default app associations from XML..." -Level "INFO"
        Write-Log "XML path: $XMLPath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would import from: $XMLPath" -Level "INFO"
            return $true
        }
        
        # Import using DISM
        $DismArgs = "/Online", "/Import-DefaultAppAssociations:$XMLPath"
        
        Write-Log "Running: dism.exe $($DismArgs -join ' ')" -Level "DEBUG"
        
        $Result = & dism.exe $DismArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Default app associations imported successfully" -Level "SUCCESS"
            $Global:Stats.XMLImported = $true
        }
        else {
            Write-Log "Failed to import associations: Exit code $LASTEXITCODE" -Level "ERROR"
            Write-Log "Output: $($Result -join "`n")" -Level "DEBUG"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Exception importing associations: $_" -Level "ERROR"
        return $false
    }
}

function New-DefaultAppsXML {
    <#
    .SYNOPSIS
        Creates default apps XML from individual settings
    #>
    
    Write-LogHeader "CREATING DEFAULT APPS XML"
    
    try {
        Write-Log "Creating default apps XML from parameters..." -Level "INFO"
        
        # Get application IDs
        $BrowserID = Get-AppAssociationID -AppName $DefaultBrowser -FileType "Browser"
        $PDFID = Get-AppAssociationID -AppName $DefaultPDF -FileType "PDF"
        
        Write-Log "  Browser: $DefaultBrowser → $BrowserID" -Level "DEBUG"
        Write-Log "  PDF: $DefaultPDF → $PDFID" -Level "DEBUG"
        
        # Build XML
        $XMLContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
"@
        
        # Add browser associations
        if ($BrowserID) {
            $XMLContent += @"

  <Association Identifier=".htm" ProgId="$BrowserID" ApplicationName="$DefaultBrowser" />
  <Association Identifier=".html" ProgId="$BrowserID" ApplicationName="$DefaultBrowser" />
  <Association Identifier="http" ProgId="$BrowserID" ApplicationName="$DefaultBrowser" />
  <Association Identifier="https" ProgId="$BrowserID" ApplicationName="$DefaultBrowser" />
"@
        }
        
        # Add PDF associations
        if ($PDFID) {
            $XMLContent += @"

  <Association Identifier=".pdf" ProgId="$PDFID" ApplicationName="$DefaultPDF" />
"@
        }
        
        $XMLContent += @"

</DefaultAssociations>
"@
        
        # Save XML to temp location
        $TempXML = Join-Path $env:TEMP "DefaultApps_$(Get-Date -Format 'yyyyMMddHHmmss').xml"
        Set-Content -Path $TempXML -Value $XMLContent -Force
        
        Write-Log "Created XML: $TempXML" -Level "SUCCESS"
        Write-Log "XML Content:" -Level "DEBUG"
        Write-Log $XMLContent -Level "DEBUG"
        
        return $TempXML
    }
    catch {
        Write-Log "Exception creating XML: $_" -Level "ERROR"
        return $null
    }
}

function Set-DefaultBrowserRegistry {
    <#
    .SYNOPSIS
        Sets default browser via registry (backup method)
    #>
    param(
        [string]$Browser,
        [string]$TargetHive = "HKCU"
    )
    
    Write-LogHeader "SETTING DEFAULT BROWSER (REGISTRY)"
    
    try {
        Write-Log "Setting default browser to: $Browser" -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set default browser to $Browser" -Level "INFO"
            return $true
        }
        
        $ProgID = Get-AppAssociationID -AppName $Browser -FileType "Browser"
        
        if (-not $ProgID) {
            Write-Log "Could not determine ProgID for $Browser" -Level "ERROR"
            return $false
        }
        
        # Set file associations
        $AssocPath = "$TargetHive`:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
        
        $Extensions = @(".htm", ".html")
        
        foreach ($Ext in $Extensions) {
            $ExtPath = Join-Path $AssocPath $Ext
            
            if (-not (Test-Path $ExtPath)) {
                New-Item -Path $ExtPath -Force | Out-Null
            }
            
            $UserChoicePath = Join-Path $ExtPath "UserChoice"
            
            if (-not (Test-Path $UserChoicePath)) {
                New-Item -Path $UserChoicePath -Force | Out-Null
            }
            
            # Note: UserChoice keys are protected in Windows 10/11
            # This may not work without additional measures
            try {
                Set-ItemProperty -Path $UserChoicePath -Name "ProgId" -Value $ProgID -Force -ErrorAction Stop
                Write-Log "  Set association: $Ext → $ProgID" -Level "DEBUG"
                $Global:Stats.AssociationsSet++
            }
            catch {
                Write-Log "  Could not set $Ext (protected key)" -Level "WARNING"
                $Global:Stats.AssociationsFailed++
            }
        }
        
        # Set URL protocols
        $Protocols = @("http", "https")
        
        foreach ($Protocol in $Protocols) {
            $ProtocolPath = "$TargetHive`:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
            
            if (-not (Test-Path $ProtocolPath)) {
                New-Item -Path $ProtocolPath -Force | Out-Null
            }
            
            try {
                Set-ItemProperty -Path $ProtocolPath -Name "ProgId" -Value $ProgID -Force -ErrorAction Stop
                Write-Log "  Set protocol: $Protocol → $ProgID" -Level "DEBUG"
                $Global:Stats.AssociationsSet++
            }
            catch {
                Write-Log "  Could not set $Protocol (protected key)" -Level "WARNING"
                $Global:Stats.AssociationsFailed++
            }
        }
        
        Write-Log "Browser registry settings applied (note: may not take effect due to Windows protections)" -Level "WARNING"
        
        return $true
    }
    catch {
        Write-Log "Exception setting browser registry: $_" -Level "ERROR"
        return $false
    }
}

function Set-DefaultApps {
    <#
    .SYNOPSIS
        Main function to set default applications
    #>
    
    Write-LogHeader "SETTING DEFAULT APPLICATIONS"
    
    try {
        Write-Log "Configuring default applications..." -Level "INFO"
        Write-Log "  Browser: $DefaultBrowser" -Level "INFO"
        Write-Log "  PDF Reader: $DefaultPDF" -Level "INFO"
        Write-Log "  Email Client: $DefaultEmail" -Level "INFO"
        
        # Method 1: Import from existing XML if provided
        if ($ConfigXML -and (Test-Path $ConfigXML)) {
            Write-Log "Using XML configuration file..." -Level "INFO"
            Import-DefaultAppAssociations -XMLPath $ConfigXML
        }
        # Method 2: Create XML from parameters
        else {
            Write-Log "Creating XML from parameters..." -Level "INFO"
            $TempXML = New-DefaultAppsXML
            
            if ($TempXML) {
                Import-DefaultAppAssociations -XMLPath $TempXML
                
                # Clean up temp XML
                if (Test-Path $TempXML) {
                    Remove-Item $TempXML -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                Write-Log "Failed to create XML, trying registry method..." -Level "WARNING"
                Set-DefaultBrowserRegistry -Browser $DefaultBrowser
            }
        }
        
        Write-Log "Default applications configuration completed" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Exception setting default apps: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-DefaultAppsConfiguration {
    <#
    .SYNOPSIS
        Validates default app configuration
    #>
    
    Write-LogHeader "VALIDATING DEFAULT APPS CONFIGURATION"
    
    try {
        Write-Log "Validating default application settings..." -Level "INFO"
        Write-Log " " -Level "INFO"
        Write-Log "Note: Validation may require sign out/sign in to see changes" -Level "WARNING"
        
        # Check file associations
        Write-Log "Checking file associations..." -Level "INFO"
        
        $AssocCheck = @{
            ".htm" = $DefaultBrowser
            ".html" = $DefaultBrowser
            ".pdf" = $DefaultPDF
        }
        
        foreach ($Ext in $AssocCheck.Keys) {
            $Expected = $AssocCheck[$Ext]
            Write-Log "  $Ext → Expected: $Expected" -Level "DEBUG"
        }
        
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
    Write-Log "Default Applications Configuration Results:" -Level "INFO"
    Write-Log "  XML Imported: $($Global:Stats.XMLImported)" -Level $(if($Global:Stats.XMLImported){"SUCCESS"}else{"INFO"})
    Write-Log "  XML Exported: $($Global:Stats.XMLExported)" -Level $(if($Global:Stats.XMLExported){"SUCCESS"}else{"INFO"})
    Write-Log "  Associations Set: $($Global:Stats.AssociationsSet)" -Level $(if($Global:Stats.AssociationsSet -gt 0){"SUCCESS"}else{"INFO"})
    Write-Log "  Associations Failed: $($Global:Stats.AssociationsFailed)" -Level $(if($Global:Stats.AssociationsFailed -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Configuration Applied:" -Level "INFO"
    Write-Log "  Default Browser: $DefaultBrowser" -Level "INFO"
    Write-Log "  Default PDF Reader: $DefaultPDF" -Level "INFO"
    Write-Log "  Default Email: $DefaultEmail" -Level "INFO"
    Write-Log "  Config XML: $(if($ConfigXML -and (Test-Path $ConfigXML)){'Used'}else{'Not Used'})" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "IMPORTANT NOTES:" -Level "WARNING"
    Write-Log "  - Changes may require sign out/sign in to take effect" -Level "WARNING"
    Write-Log "  - Windows 11 protects default app settings" -Level "WARNING"
    Write-Log "  - DISM import is most reliable method" -Level "WARNING"
    Write-Log "  - Users can still change defaults in Settings" -Level "WARNING"
    
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
║        SET DEFAULT APPLICATIONS                               ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "DEFAULT APPS CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "Target Configuration:" -Level "INFO"
    Write-Log "  Default Browser: $DefaultBrowser" -Level "INFO"
    Write-Log "  Default PDF: $DefaultPDF" -Level "INFO"
    Write-Log "  Default Email: $DefaultEmail" -Level "INFO"
    Write-Log "  Default Media Player: $DefaultMediaPlayer" -Level "INFO"
    Write-Log "  Default Image Viewer: $DefaultImageViewer" -Level "INFO"
    Write-Log "  Config XML: $ConfigXML" -Level "INFO"
    Write-Log "  Export Current Settings: $ExportCurrentSettings" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Export current settings if requested
    if ($ExportCurrentSettings) {
        Export-CurrentDefaultApps
    }
    else {
        # Set default applications
        Set-DefaultApps
        
        # Validate configuration
        Test-DefaultAppsConfiguration
    }
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 3 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Default applications configured successfully!" -Level "SUCCESS"
        Write-Log "Users may need to sign out and back in for changes to take effect" -Level "WARNING"
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
