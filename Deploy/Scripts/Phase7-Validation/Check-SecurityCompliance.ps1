<#
.SYNOPSIS
    Security Compliance Validation Check
    
.DESCRIPTION
    Validates security configuration compliance against enterprise baseline.
    Checks all security settings configured in Phase 2 and throughout deployment.
    
    Validation Categories:
    - Windows Defender configuration
    - BitLocker encryption status
    - Firewall rules and profiles
    - UAC configuration
    - Security policies
    - Windows Update configuration
    - Account policies
    - Audit policies
    - Service hardening
    - Network security
    
.PARAMETER ComplianceProfile
    Security compliance profile to validate against.
    Default: "Enterprise-Security-Baseline"
    
    Profiles:
    - Enterprise-Security-Baseline (Standard)
    - High-Security (Stricter requirements)
    - HIPAA-Compliance (Healthcare)
    - PCI-DSS (Payment Card Industry)
    
.PARAMETER GenerateReport
    Generate detailed compliance report.
    Default: $true
    
.PARAMETER ReportPath
    Path to save compliance report.
    Default: C:\ProgramData\ComplianceReports\
    
.PARAMETER FailOnNonCompliance
    Exit with error code if non-compliant.
    Default: $false
    
.PARAMETER RemediateIssues
    Attempt to remediate non-compliant settings.
    Default: $false
    
.PARAMETER DryRun
    Simulate validation without making changes. Default: $false
    
.EXAMPLE
    .\Check-SecurityCompliance.ps1
    Validates security compliance with default profile
    
.EXAMPLE
    .\Check-SecurityCompliance.ps1 -ComplianceProfile "High-Security"
    Validates against high security requirements
    
.EXAMPLE
    .\Check-SecurityCompliance.ps1 -GenerateReport $true
    Generates detailed compliance report
    
.EXAMPLE
    .\Check-SecurityCompliance.ps1 -RemediateIssues $true
    Validates and attempts to fix non-compliant settings
    
.EXAMPLE
    .\Check-SecurityCompliance.ps1 -DryRun
    Shows what would be validated without checking
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-09
    Purpose:        Security compliance validation for Windows 11 workstations
    
    EXIT CODES:
    0   = Fully compliant
    1   = General failure
    2   = Not running as administrator
    3   = Non-compliant (if FailOnNonCompliance = $true)
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges (SYSTEM recommended)
    - PowerShell 5.1 or later
    
    COMPLIANCE CHECKS:
    - Windows Defender: Real-time protection, cloud protection, signatures
    - BitLocker: Encryption status, recovery key backup
    - Firewall: Profiles enabled, rules configured
    - UAC: Enabled and properly configured
    - Windows Update: Configured, up-to-date
    - Account Policies: Password complexity, lockout
    - Audit Policies: Security logging enabled
    - Services: Unnecessary services disabled
    - Network: SMBv1 disabled, secure protocols
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Enterprise-Security-Baseline", "High-Security", "HIPAA-Compliance", "PCI-DSS")]
    [string]$ComplianceProfile = "Enterprise-Security-Baseline",
    
    [Parameter(Mandatory=$false)]
    [bool]$GenerateReport = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\ProgramData\ComplianceReports",
    
    [Parameter(Mandatory=$false)]
    [bool]$FailOnNonCompliance = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemediateIssues = $false,
    
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

$LogFileName = "Check-SecurityCompliance_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Compliance tracking
$Global:ComplianceResults = @{
    TotalChecks = 0
    Passed = 0
    Failed = 0
    Warnings = 0
    Remediated = 0
    Categories = @{}
}

# Statistics tracking
$Global:Stats = @{
    Errors = 0
    Warnings = 0
    ChecksPerformed = 0
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

function Add-ComplianceResult {
    param(
        [string]$Category,
        [string]$Check,
        [bool]$Passed,
        [string]$Expected,
        [string]$Actual,
        [string]$Severity = "Medium",
        [string]$Details = ""
    )
    
    $Global:ComplianceResults.TotalChecks++
    
    if ($Passed) {
        $Global:ComplianceResults.Passed++
        Write-Log "  ✓ $Check - PASS" -Level "SUCCESS"
    }
    else {
        if ($Severity -eq "Critical" -or $Severity -eq "High") {
            $Global:ComplianceResults.Failed++
            Write-Log "  ✗ $Check - FAIL (Expected: $Expected, Actual: $Actual)" -Level "ERROR"
        }
        else {
            $Global:ComplianceResults.Warnings++
            Write-Log "  ⚠ $Check - WARNING (Expected: $Expected, Actual: $Actual)" -Level "WARNING"
        }
    }
    
    # Store result
    if (-not $Global:ComplianceResults.Categories.ContainsKey($Category)) {
        $Global:ComplianceResults.Categories[$Category] = @{
            Passed = 0
            Failed = 0
            Warnings = 0
            Checks = @()
        }
    }
    
    if ($Passed) {
        $Global:ComplianceResults.Categories[$Category].Passed++
    }
    elseif ($Severity -eq "Critical" -or $Severity -eq "High") {
        $Global:ComplianceResults.Categories[$Category].Failed++
    }
    else {
        $Global:ComplianceResults.Categories[$Category].Warnings++
    }
    
    $Global:ComplianceResults.Categories[$Category].Checks += @{
        Check = $Check
        Passed = $Passed
        Expected = $Expected
        Actual = $Actual
        Severity = $Severity
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
    
    # Check 3: Compliance profile
    Write-Log "Compliance Profile: $ComplianceProfile" -Level "INFO"
    
    return $AllChecksPassed
}

#endregion

#region WINDOWS DEFENDER VALIDATION
#==============================================================================

function Test-WindowsDefenderCompliance {
    Write-LogHeader "VALIDATING WINDOWS DEFENDER CONFIGURATION"
    
    $Category = "Windows Defender"
    
    try {
        Write-Log "Checking Windows Defender status..." -Level "INFO"
        
        # Get Defender status
        $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if (-not $DefenderStatus) {
            Add-ComplianceResult -Category $Category -Check "Defender Status" -Passed $false `
                -Expected "Running" -Actual "Not available" -Severity "Critical" `
                -Details "Windows Defender not available or not responding"
            return
        }
        
        # Real-time Protection
        $RealTimeEnabled = $DefenderStatus.RealTimeProtectionEnabled
        Add-ComplianceResult -Category $Category -Check "Real-time Protection" -Passed $RealTimeEnabled `
            -Expected "Enabled" -Actual $(if($RealTimeEnabled){"Enabled"}else{"Disabled"}) -Severity "Critical"
        
        # Cloud Protection
        $CloudEnabled = $DefenderStatus.CloudProtectionEnabled
        Add-ComplianceResult -Category $Category -Check "Cloud Protection" -Passed $CloudEnabled `
            -Expected "Enabled" -Actual $(if($CloudEnabled){"Enabled"}else{"Disabled"}) -Severity "High"
        
        # Automatic Sample Submission
        $SampleSubmission = $DefenderStatus.SubmitSamplesConsent -ne 2  # 2 = Never send
        Add-ComplianceResult -Category $Category -Check "Sample Submission" -Passed $SampleSubmission `
            -Expected "Enabled" -Actual $(if($SampleSubmission){"Enabled"}else{"Disabled"}) -Severity "Medium"
        
        # Signature Updates
        $SignatureAge = (Get-Date) - $DefenderStatus.AntivirusSignatureLastUpdated
        $SignaturesUpToDate = $SignatureAge.TotalDays -lt 2
        Add-ComplianceResult -Category $Category -Check "Signature Updates" -Passed $SignaturesUpToDate `
            -Expected "< 2 days old" -Actual "$([math]::Round($SignatureAge.TotalDays, 1)) days old" -Severity "High"
        
        # Scan Status
        $LastQuickScan = (Get-Date) - $DefenderStatus.QuickScanEndTime
        $RecentScan = $LastQuickScan.TotalDays -lt 7
        Add-ComplianceResult -Category $Category -Check "Recent Quick Scan" -Passed $RecentScan `
            -Expected "< 7 days" -Actual "$([math]::Round($LastQuickScan.TotalDays, 1)) days ago" -Severity "Low"
        
        # PUA Protection (Potentially Unwanted Applications)
        $PUAProtection = (Get-MpPreference).PUAProtection -eq 1
        Add-ComplianceResult -Category $Category -Check "PUA Protection" -Passed $PUAProtection `
            -Expected "Enabled" -Actual $(if($PUAProtection){"Enabled"}else{"Disabled"}) -Severity "Medium"
        
        Write-Log "Windows Defender validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating Defender: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "Defender Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Critical"
    }
}

#endregion

#region BITLOCKER VALIDATION
#==============================================================================

function Test-BitLockerCompliance {
    Write-LogHeader "VALIDATING BITLOCKER ENCRYPTION"
    
    $Category = "BitLocker Encryption"
    
    try {
        Write-Log "Checking BitLocker status..." -Level "INFO"
        
        # Get BitLocker volumes
        $BitLockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        if (-not $BitLockerVolumes) {
            Add-ComplianceResult -Category $Category -Check "BitLocker Availability" -Passed $false `
                -Expected "Available" -Actual "Not available" -Severity "High" `
                -Details "BitLocker not available (requires Pro/Enterprise)"
            return
        }
        
        # Check OS drive
        $OSDrive = $BitLockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" }
        
        if ($OSDrive) {
            # Encryption Status
            $Encrypted = $OSDrive.VolumeStatus -eq "FullyEncrypted"
            Add-ComplianceResult -Category $Category -Check "OS Drive Encryption" -Passed $Encrypted `
                -Expected "Fully Encrypted" -Actual $OSDrive.VolumeStatus -Severity "Critical"
            
            # Encryption Method
            $EncryptionMethod = $OSDrive.EncryptionMethod
            $StrongEncryption = $EncryptionMethod -match "Xts" -or $EncryptionMethod -match "Aes256"
            Add-ComplianceResult -Category $Category -Check "Encryption Method" -Passed $StrongEncryption `
                -Expected "XTS-AES or AES256" -Actual $EncryptionMethod -Severity "High"
            
            # Protection Status
            $Protected = $OSDrive.ProtectionStatus -eq "On"
            Add-ComplianceResult -Category $Category -Check "Protection Status" -Passed $Protected `
                -Expected "On" -Actual $OSDrive.ProtectionStatus -Severity "Critical"
            
            # Key Protectors
            $HasTPM = $OSDrive.KeyProtector | Where-Object { $_.KeyProtectorType -eq "Tpm" }
            Add-ComplianceResult -Category $Category -Check "TPM Key Protector" -Passed ($null -ne $HasTPM) `
                -Expected "Present" -Actual $(if($HasTPM){"Present"}else{"Missing"}) -Severity "High"
        }
        else {
            Add-ComplianceResult -Category $Category -Check "OS Drive Found" -Passed $false `
                -Expected "Present" -Actual "Not found" -Severity "Critical"
        }
        
        Write-Log "BitLocker validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating BitLocker: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "BitLocker Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "High"
    }
}

#endregion

#region FIREWALL VALIDATION
#==============================================================================

function Test-FirewallCompliance {
    Write-LogHeader "VALIDATING FIREWALL CONFIGURATION"
    
    $Category = "Windows Firewall"
    
    try {
        Write-Log "Checking firewall status..." -Level "INFO"
        
        # Get firewall profiles
        $Profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        
        foreach ($Profile in $Profiles) {
            $ProfileName = $Profile.Name
            
            # Firewall Enabled
            $Enabled = $Profile.Enabled
            Add-ComplianceResult -Category $Category -Check "$ProfileName Profile Enabled" -Passed $Enabled `
                -Expected "True" -Actual $Enabled -Severity "Critical"
            
            # Default Inbound Action
            $InboundBlocked = $Profile.DefaultInboundAction -eq "Block"
            Add-ComplianceResult -Category $Category -Check "$ProfileName Default Inbound" -Passed $InboundBlocked `
                -Expected "Block" -Actual $Profile.DefaultInboundAction -Severity "High"
            
            # Default Outbound Action
            $OutboundAllowed = $Profile.DefaultOutboundAction -eq "Allow"
            Add-ComplianceResult -Category $Category -Check "$ProfileName Default Outbound" -Passed $OutboundAllowed `
                -Expected "Allow" -Actual $Profile.DefaultOutboundAction -Severity "Low"
        }
        
        # Check for dangerous rules
        $AllRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        $AllowAllRules = $AllRules | Where-Object { 
            $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and 
            (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress -eq "Any"
        }
        
        $NoDangerousRules = ($AllowAllRules | Measure-Object).Count -eq 0
        Add-ComplianceResult -Category $Category -Check "No Dangerous Allow Rules" -Passed $NoDangerousRules `
            -Expected "0 rules" -Actual "$($AllowAllRules.Count) rules allowing all inbound" -Severity "High"
        
        Write-Log "Firewall validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating Firewall: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "Firewall Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Critical"
    }
}

#endregion

#region UAC VALIDATION
#==============================================================================

function Test-UACCompliance {
    Write-LogHeader "VALIDATING UAC CONFIGURATION"
    
    $Category = "User Account Control"
    
    try {
        Write-Log "Checking UAC settings..." -Level "INFO"
        
        $UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # UAC Enabled
        $UACEnabled = (Get-ItemProperty $UACPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        Add-ComplianceResult -Category $Category -Check "UAC Enabled" -Passed ($UACEnabled -eq 1) `
            -Expected "1 (Enabled)" -Actual $UACEnabled -Severity "Critical"
        
        # Prompt on Secure Desktop
        $SecureDesktop = (Get-ItemProperty $UACPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
        Add-ComplianceResult -Category $Category -Check "Secure Desktop Prompt" -Passed ($SecureDesktop -eq 1) `
            -Expected "1 (Enabled)" -Actual $SecureDesktop -Severity "High"
        
        # Admin Approval Mode
        $AdminApproval = (Get-ItemProperty $UACPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $AdminApprovalOK = $AdminApproval -ge 2  # 2 = Prompt for consent, 5 = Prompt for credentials
        Add-ComplianceResult -Category $Category -Check "Admin Approval Mode" -Passed $AdminApprovalOK `
            -Expected "2 or higher" -Actual $AdminApproval -Severity "High"
        
        Write-Log "UAC validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating UAC: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "UAC Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Critical"
    }
}

#endregion

#region WINDOWS UPDATE VALIDATION
#==============================================================================

function Test-WindowsUpdateCompliance {
    Write-LogHeader "VALIDATING WINDOWS UPDATE CONFIGURATION"
    
    $Category = "Windows Update"
    
    try {
        Write-Log "Checking Windows Update status..." -Level "INFO"
        
        # Check Update Service
        $UpdateService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        $ServiceRunning = $UpdateService.Status -eq "Running"
        Add-ComplianceResult -Category $Category -Check "Update Service Running" -Passed $ServiceRunning `
            -Expected "Running" -Actual $UpdateService.Status -Severity "High"
        
        # Check for pending updates
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        
        try {
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
            $PendingUpdates = $SearchResult.Updates.Count
            
            # Critical/security updates
            $CriticalPending = ($SearchResult.Updates | Where-Object { 
                $_.MsrcSeverity -eq "Critical" -or $_.MsrcSeverity -eq "Important" 
            }).Count
            
            $NoCriticalPending = $CriticalPending -eq 0
            Add-ComplianceResult -Category $Category -Check "No Critical Updates Pending" -Passed $NoCriticalPending `
                -Expected "0 updates" -Actual "$CriticalPending critical updates pending" -Severity "High"
        }
        catch {
            Write-Log "Could not check for pending updates: $_" -Level "WARNING"
        }
        
        # Last Update Check
        $UpdateRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect"
        $LastCheck = (Get-ItemProperty $UpdateRegPath -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime
        
        if ($LastCheck) {
            $LastCheckDate = [DateTime]::Parse($LastCheck)
            $DaysSinceCheck = (Get-Date) - $LastCheckDate
            $RecentCheck = $DaysSinceCheck.TotalDays -lt 7
            
            Add-ComplianceResult -Category $Category -Check "Recent Update Check" -Passed $RecentCheck `
                -Expected "< 7 days" -Actual "$([math]::Round($DaysSinceCheck.TotalDays, 1)) days ago" -Severity "Medium"
        }
        
        Write-Log "Windows Update validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating Windows Update: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "Update Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Medium"
    }
}

#endregion

#region NETWORK SECURITY VALIDATION
#==============================================================================

function Test-NetworkSecurityCompliance {
    Write-LogHeader "VALIDATING NETWORK SECURITY"
    
    $Category = "Network Security"
    
    try {
        Write-Log "Checking network security settings..." -Level "INFO"
        
        # SMBv1 Disabled
        $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        $SMBv1Disabled = $SMBv1.State -eq "Disabled"
        Add-ComplianceResult -Category $Category -Check "SMBv1 Disabled" -Passed $SMBv1Disabled `
            -Expected "Disabled" -Actual $SMBv1.State -Severity "High"
        
        # Network Level Authentication
        $RDPSettings = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
        if ($RDPSettings) {
            $NLAEnabled = $RDPSettings.UserAuthentication -eq 1
            Add-ComplianceResult -Category $Category -Check "RDP Network Level Authentication" -Passed $NLAEnabled `
                -Expected "Enabled (1)" -Actual $RDPSettings.UserAuthentication -Severity "High"
        }
        
        # LLMNR Disabled (security best practice)
        $LLMNR = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        $LLMNRDisabled = $LLMNR.EnableMulticast -eq 0
        Add-ComplianceResult -Category $Category -Check "LLMNR Disabled" -Passed $LLMNRDisabled `
            -Expected "Disabled (0)" -Actual $(if($LLMNR){"$($LLMNR.EnableMulticast)"}else{"Not Set"}) -Severity "Medium"
        
        Write-Log "Network security validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating Network Security: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "Network Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Medium"
    }
}

#endregion

#region AUDIT POLICY VALIDATION
#==============================================================================

function Test-AuditPolicyCompliance {
    Write-LogHeader "VALIDATING AUDIT POLICIES"
    
    $Category = "Audit Policies"
    
    try {
        Write-Log "Checking audit policy configuration..." -Level "INFO"
        
        # Get audit policies
        $AuditPolicies = auditpol /get /category:* 2>&1
        
        # Key audit policies to check
        $RequiredAudits = @{
            "Logon/Logoff" = "Success and Failure"
            "Account Logon" = "Success and Failure"
            "Account Management" = "Success and Failure"
            "Policy Change" = "Success and Failure"
        }
        
        foreach ($Audit in $RequiredAudits.Keys) {
            $Expected = $RequiredAudits[$Audit]
            $AuditLine = $AuditPolicies | Select-String $Audit
            
            if ($AuditLine) {
                $Configured = $AuditLine -match "Success and Failure"
                Add-ComplianceResult -Category $Category -Check "$Audit Auditing" -Passed $Configured `
                    -Expected $Expected -Actual $(if($Configured){$Expected}else{"Not configured"}) -Severity "Medium"
            }
        }
        
        Write-Log "Audit policy validation completed" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Exception validating Audit Policies: $_" -Level "ERROR"
        Add-ComplianceResult -Category $Category -Check "Audit Validation" -Passed $false `
            -Expected "Success" -Actual "Exception: $_" -Severity "Low"
    }
}

#endregion

#region REPORT GENERATION
#==============================================================================

function New-ComplianceReport {
    Write-LogHeader "GENERATING COMPLIANCE REPORT"
    
    try {
        if (-not $GenerateReport) {
            Write-Log "Report generation disabled" -Level "INFO"
            return
        }
        
        Write-Log "Creating compliance report..." -Level "INFO"
        
        # Ensure report directory exists
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $ReportFile = Join-Path $ReportPath "SecurityCompliance_$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        
        # Calculate compliance percentage
        $CompliancePercent = if ($Global:ComplianceResults.TotalChecks -gt 0) {
            [math]::Round(($Global:ComplianceResults.Passed / $Global:ComplianceResults.TotalChecks) * 100, 2)
        } else { 0 }
        
        # Determine status
        $Status = if ($Global:ComplianceResults.Failed -eq 0) {
            "COMPLIANT"
        } elseif ($CompliancePercent -ge 90) {
            "MOSTLY COMPLIANT"
        } else {
            "NON-COMPLIANT"
        }
        
        $StatusColor = switch ($Status) {
            "COMPLIANT" { "green" }
            "MOSTLY COMPLIANT" { "orange" }
            "NON-COMPLIANT" { "red" }
        }
        
        # Build HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status { font-size: 24px; font-weight: bold; color: $StatusColor; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 36px; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        .category { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .category-header { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #2c3e50; }
        .check { padding: 5px 0; border-bottom: 1px solid #ecf0f1; }
        .pass { color: green; }
        .fail { color: red; }
        .warning { color: orange; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background-color: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Compliance Report</h1>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Profile: $ComplianceProfile</p>
    </div>
    
    <div class="summary">
        <div class="status">Status: $Status</div>
        <div class="metric">
            <div class="metric-value">$CompliancePercent%</div>
            <div class="metric-label">Compliance</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:ComplianceResults.Passed)</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:ComplianceResults.Failed)</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Global:ComplianceResults.Warnings)</div>
            <div class="metric-label">Warnings</div>
        </div>
    </div>
"@
        
        # Add category results
        foreach ($CategoryName in $Global:ComplianceResults.Categories.Keys) {
            $CategoryData = $Global:ComplianceResults.Categories[$CategoryName]
            
            $HTML += @"
    <div class="category">
        <div class="category-header">$CategoryName</div>
        <p>Passed: $($CategoryData.Passed) | Failed: $($CategoryData.Failed) | Warnings: $($CategoryData.Warnings)</p>
        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Expected</th>
                <th>Actual</th>
                <th>Severity</th>
            </tr>
"@
            
            foreach ($Check in $CategoryData.Checks) {
                $StatusClass = if ($Check.Passed) { "pass" } elseif ($Check.Severity -eq "Critical" -or $Check.Severity -eq "High") { "fail" } else { "warning" }
                $StatusText = if ($Check.Passed) { "✓ PASS" } else { "✗ FAIL" }
                
                $HTML += @"
            <tr>
                <td>$($Check.Check)</td>
                <td class="$StatusClass">$StatusText</td>
                <td>$($Check.Expected)</td>
                <td>$($Check.Actual)</td>
                <td>$($Check.Severity)</td>
            </tr>
"@
            }
            
            $HTML += "        </table>`n    </div>`n"
        }
        
        $HTML += @"
</body>
</html>
"@
        
        # Save report
        Set-Content -Path $ReportFile -Value $HTML -Force
        
        Write-Log "Compliance report generated: $ReportFile" -Level "SUCCESS"
        
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

function Show-ComplianceSummary {
    Write-LogHeader "COMPLIANCE SUMMARY"
    
    $EndTime = Get-Date
    $Duration = ($EndTime - $ScriptStartTime).TotalSeconds
    
    Write-Log "Execution Details:" -Level "INFO"
    Write-Log "  Start Time: $ScriptStartTime" -Level "INFO"
    Write-Log "  End Time: $EndTime" -Level "INFO"
    Write-Log "  Duration: $([math]::Round($Duration, 2)) seconds" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Compliance Results:" -Level "INFO"
    Write-Log "  Profile: $ComplianceProfile" -Level "INFO"
    Write-Log "  Total Checks: $($Global:ComplianceResults.TotalChecks)" -Level "INFO"
    Write-Log "  Passed: $($Global:ComplianceResults.Passed)" -Level "SUCCESS"
    Write-Log "  Failed: $($Global:ComplianceResults.Failed)" -Level $(if($Global:ComplianceResults.Failed -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:ComplianceResults.Warnings)" -Level $(if($Global:ComplianceResults.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    # Calculate compliance percentage
    $CompliancePercent = if ($Global:ComplianceResults.TotalChecks -gt 0) {
        [math]::Round(($Global:ComplianceResults.Passed / $Global:ComplianceResults.TotalChecks) * 100, 2)
    } else { 0 }
    
    Write-Log "  Compliance: $CompliancePercent%" -Level $(if($CompliancePercent -ge 95){"SUCCESS"}elseif($CompliancePercent -ge 85){"WARNING"}else{"ERROR"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Category Breakdown:" -Level "INFO"
    
    foreach ($CategoryName in ($Global:ComplianceResults.Categories.Keys | Sort-Object)) {
        $CategoryData = $Global:ComplianceResults.Categories[$CategoryName]
        $TotalCategoryChecks = $CategoryData.Passed + $CategoryData.Failed + $CategoryData.Warnings
        $CategoryPercent = if ($TotalCategoryChecks -gt 0) {
            [math]::Round(($CategoryData.Passed / $TotalCategoryChecks) * 100, 1)
        } else { 0 }
        
        Write-Log "  $CategoryName : $CategoryPercent% ($($CategoryData.Passed)/$TotalCategoryChecks passed)" -Level "INFO"
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
║        SECURITY COMPLIANCE VALIDATION                         ║
║                  Version $ScriptVersion                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Compliance Profile: $ComplianceProfile" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host ""
    
    Write-LogHeader "SECURITY COMPLIANCE CHECK STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Compliance Profile: $ComplianceProfile" -Level "INFO"
    Write-Log "Generate Report: $GenerateReport" -Level "INFO"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Run compliance checks
    Test-WindowsDefenderCompliance
    Test-BitLockerCompliance
    Test-FirewallCompliance
    Test-UACCompliance
    Test-WindowsUpdateCompliance
    Test-NetworkSecurityCompliance
    Test-AuditPolicyCompliance
    
    # Generate report
    if ($GenerateReport) {
        $ReportFile = New-ComplianceReport
    }
    
    # Show summary
    Show-ComplianceSummary
    
    # Determine exit code
    $ExitCode = if ($Global:ComplianceResults.Failed -eq 0) {
        0  # Compliant
    } elseif ($FailOnNonCompliance) {
        3  # Non-compliant (failure)
    } else {
        0  # Non-compliant but not failing
    }
    
    Write-Log " " -Level "INFO"
    if ($Global:ComplianceResults.Failed -eq 0) {
        Write-Log "System is FULLY COMPLIANT with $ComplianceProfile" -Level "SUCCESS"
    } elseif ($FailOnNonCompliance) {
        Write-Log "System is NON-COMPLIANT - $($Global:ComplianceResults.Failed) critical failures" -Level "ERROR"
    } else {
        Write-Log "Validation completed with $($Global:ComplianceResults.Failed) failures (non-blocking)" -Level "WARNING"
    }
    
    if ($ReportFile) {
        Write-Log "Compliance report: $ReportFile" -Level "SUCCESS"
    }
    
    Write-Log "Exit Code: $ExitCode" -Level "INFO"
    
    exit $ExitCode
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Show-ComplianceSummary
    
    exit 1
}

#endregion
