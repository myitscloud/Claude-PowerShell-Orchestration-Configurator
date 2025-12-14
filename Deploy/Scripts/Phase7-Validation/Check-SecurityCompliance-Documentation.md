# SECURITY COMPLIANCE VALIDATION - DOCUMENTATION

## Overview

Comprehensive guide for **Check-SecurityCompliance.ps1** — validating security configuration compliance against enterprise baseline.

**Script Location:** `Phase7-Validation\Check-SecurityCompliance.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## Quick Start

### Basic Usage

```powershell
# Default validation (Enterprise baseline)
.\Check-SecurityCompliance.ps1

# Generate detailed HTML report
.\Check-SecurityCompliance.ps1 -GenerateReport $true

# Validate against high security profile
.\Check-SecurityCompliance.ps1 -ComplianceProfile "High-Security"

# Fail deployment if non-compliant
.\Check-SecurityCompliance.ps1 -FailOnNonCompliance $true

# Test without checking
.\Check-SecurityCompliance.ps1 -DryRun
```

---

## What It Does

Validates security configuration across all deployment phases:

- ✅ **Windows Defender** - Real-time protection, signatures, cloud protection
- ✅ **BitLocker Encryption** - OS drive encrypted, TPM protected
- ✅ **Windows Firewall** - All profiles enabled, secure defaults
- ✅ **UAC Configuration** - Enabled, secure desktop prompts
- ✅ **Windows Update** - Service running, no critical updates pending
- ✅ **Network Security** - SMBv1 disabled, secure protocols
- ✅ **Audit Policies** - Security logging enabled
- ✅ **HTML Report** - Detailed compliance report with percentages

---

## Configuration from Orchestration

```powershell
TaskID: VAL-001
Parameters = @{
    ComplianceProfile = "Enterprise-Security-Baseline"
    GenerateReport = $true
}
```

### What This Validates

**Enterprise-Security-Baseline Profile:**

1. **Windows Defender (Critical)**
   - Real-time protection enabled
   - Cloud protection enabled
   - Signatures < 2 days old
   - PUA protection enabled

2. **BitLocker (Critical)**
   - OS drive fully encrypted
   - Strong encryption (XTS-AES or AES256)
   - TPM key protector present
   - Protection enabled

3. **Windows Firewall (Critical)**
   - All profiles enabled (Domain, Private, Public)
   - Default inbound: Block
   - Default outbound: Allow
   - No dangerous "allow all" rules

4. **UAC (Critical)**
   - UAC enabled
   - Secure desktop prompts
   - Admin approval mode

5. **Windows Update (High)**
   - Update service running
   - No critical updates pending
   - Recent update check (< 7 days)

6. **Network Security (High)**
   - SMBv1 disabled
   - RDP NLA enabled
   - LLMNR disabled

7. **Audit Policies (Medium)**
   - Logon/Logoff auditing
   - Account logon auditing
   - Account management auditing
   - Policy change auditing

**Result:** Comprehensive security validation across all critical areas

---

## Compliance Profiles

### Profile 1: Enterprise-Security-Baseline (Default)

**Target:** Standard enterprise security

```powershell
ComplianceProfile = "Enterprise-Security-Baseline"
```

**Requirements:**
- Windows Defender: Real-time + Cloud protection
- BitLocker: OS drive encrypted (if available)
- Firewall: All profiles enabled
- UAC: Enabled
- Windows Update: Service running
- Network: SMBv1 disabled

**Best For:** 90% of organizations

---

### Profile 2: High-Security

**Target:** Enhanced security requirements

```powershell
ComplianceProfile = "High-Security"
```

**Additional Requirements:**
- All baseline requirements
- BitLocker: **Required** (fails if not available)
- Signatures: < 1 day old (stricter)
- Firewall: Strict rule validation
- All audit policies: Must be enabled

**Best For:** Financial services, legal, high-value data

---

### Profile 3: HIPAA-Compliance

**Target:** Healthcare data protection

```powershell
ComplianceProfile = "HIPAA-Compliance"
```

**Focus Areas:**
- Encryption: BitLocker required
- Audit logging: Comprehensive
- Access controls: Strict UAC
- Network: Isolated, secure protocols

**Best For:** Healthcare organizations

---

### Profile 4: PCI-DSS

**Target:** Payment card data security

```powershell
ComplianceProfile = "PCI-DSS"
```

**Focus Areas:**
- Network segmentation validation
- Firewall: Very strict rules
- Audit: Comprehensive logging
- Encryption: Required

**Best For:** Retail, e-commerce, payment processing

---

## Validation Categories Explained

### 1. Windows Defender Validation

**What's Checked:**

```
✓ Real-time Protection Enabled (Critical)
  - Active malware scanning
  - Blocks threats in real-time
  - Must be ON

✓ Cloud Protection Enabled (High)
  - Microsoft cloud intelligence
  - Latest threat detection
  - Should be ON

✓ Signature Updates < 2 Days (High)
  - Definition freshness
  - Protection effectiveness
  - Auto-updates working

✓ PUA Protection Enabled (Medium)
  - Potentially Unwanted Applications
  - Blocks adware, toolbars
  - Recommended ON

✓ Recent Quick Scan < 7 Days (Low)
  - Regular scanning
  - Proactive detection
  - Scheduled scans working
```

**Why This Matters:**
- ✅ 40% malware reduction (real-time protection)
- ✅ 60% threat detection improvement (cloud protection)
- ✅ 30% attack prevention (recent signatures)

---

### 2. BitLocker Validation

**What's Checked:**

```
✓ OS Drive Fully Encrypted (Critical)
  - C:\ drive encrypted
  - Data protected at rest
  - Mandatory for compliance

✓ Encryption Method (High)
  - XTS-AES 128/256 (Windows 11)
  - AES 128/256 (Windows 10)
  - Strong encryption algorithms

✓ Protection Status ON (Critical)
  - Encryption active
  - Not suspended
  - Keys protecting data

✓ TPM Key Protector (High)
  - Hardware-backed keys
  - Secure key storage
  - Boot integrity check
```

**Why This Matters:**
- ✅ Protects data if laptop stolen
- ✅ Compliance requirement (HIPAA, PCI-DSS)
- ✅ Legal liability protection

---

### 3. Windows Firewall Validation

**What's Checked:**

```
✓ Domain Profile Enabled (Critical)
  - Corporate network protection
  - Must be ON

✓ Private Profile Enabled (Critical)
  - Home/private network protection
  - Must be ON

✓ Public Profile Enabled (Critical)
  - Public WiFi protection
  - Must be ON (most important!)

✓ Default Inbound: Block (High)
  - Unsolicited connections blocked
  - Secure default

✓ Default Outbound: Allow (Low)
  - Apps can reach internet
  - Standard configuration

✓ No Dangerous Rules (High)
  - No "allow all inbound from any"
  - Security validation
```

**Why This Matters:**
- ✅ First line of defense
- ✅ Blocks 80% of network attacks
- ✅ Critical when on public WiFi

---

### 4. UAC Validation

**What's Checked:**

```
✓ UAC Enabled (Critical)
  - Privilege escalation protection
  - Must be ON

✓ Secure Desktop Prompts (High)
  - Protected prompt screen
  - Prevents UI automation attacks

✓ Admin Approval Mode (High)
  - Admins must confirm
  - Value: 2 (consent) or 5 (credentials)
```

**Why This Matters:**
- ✅ Prevents unauthorized elevation
- ✅ Stops 75% of malware installations
- ✅ User awareness of privileged actions

---

### 5. Windows Update Validation

**What's Checked:**

```
✓ Update Service Running (High)
  - wuauserv service active
  - Can receive updates

✓ No Critical Updates Pending (High)
  - Security patches applied
  - System up-to-date

✓ Recent Update Check < 7 Days (Medium)
  - Update scanning working
  - Auto-updates functional
```

**Why This Matters:**
- ✅ 90% of attacks exploit known vulnerabilities
- ✅ Patches close security holes
- ✅ Compliance requirement

---

### 6. Network Security Validation

**What's Checked:**

```
✓ SMBv1 Disabled (High)
  - Legacy protocol removed
  - WannaCry/NotPetya protection

✓ RDP NLA Enabled (High)
  - Network Level Authentication
  - Pre-auth security

✓ LLMNR Disabled (Medium)
  - Link-Local Multicast Name Resolution
  - Prevents MITM attacks
```

**Why This Matters:**
- ✅ SMBv1: WannaCry used this (major ransomware)
- ✅ RDP NLA: Prevents brute force before login
- ✅ LLMNR: Stops credential theft attacks

---

### 7. Audit Policy Validation

**What's Checked:**

```
✓ Logon/Logoff Auditing (Medium)
  - Track user logins
  - Success and Failure

✓ Account Logon Auditing (Medium)
  - Authentication events
  - Success and Failure

✓ Account Management (Medium)
  - User/group changes
  - Success and Failure

✓ Policy Change (Medium)
  - Security policy modifications
  - Success and Failure
```

**Why This Matters:**
- ✅ Incident investigation
- ✅ Compliance requirement (HIPAA, PCI-DSS)
- ✅ Forensic evidence

---

## HTML Compliance Report

### Report Contents

**Summary Section:**
```
┌─────────────────────────────────────────┐
│ Status: COMPLIANT                       │
│ Compliance: 98%                         │
│                                         │
│ Passed:   45                            │
│ Failed:    1                            │
│ Warnings:  2                            │
└─────────────────────────────────────────┘
```

**Category Breakdown:**
```
Windows Defender:    100% (6/6 passed)
BitLocker:           100% (4/4 passed)
Windows Firewall:     95% (19/20 passed)
UAC:                 100% (3/3 passed)
Windows Update:       90% (4/5 passed)
Network Security:    100% (3/3 passed)
Audit Policies:      100% (4/4 passed)
```

**Detailed Checks:**
- Each check listed with Pass/Fail status
- Expected vs Actual values
- Severity level (Critical, High, Medium, Low)
- Color-coded for visibility

**Report Location:**
```
C:\ProgramData\ComplianceReports\SecurityCompliance_20241209-143022.html
```

---

## Compliance Scoring

### How Scoring Works

**Total Checks:** 48 (example)

**Calculation:**
```
Compliance % = (Passed / Total Checks) × 100

Example:
45 passed / 48 total = 93.75%
```

**Status Determination:**
- ✅ **COMPLIANT:** 0 failures, all passed
- ⚠️ **MOSTLY COMPLIANT:** 1-2 failures, >90% pass rate
- ❌ **NON-COMPLIANT:** 3+ failures, <90% pass rate

---

### Severity Impact

**Critical Severity:**
- Counts as FAIL (red)
- Examples: Defender disabled, BitLocker off, Firewall disabled

**High Severity:**
- Counts as FAIL (red)
- Examples: Old signatures, weak encryption

**Medium Severity:**
- Counts as WARNING (orange)
- Examples: Audit policy missing, recent scan overdue

**Low Severity:**
- Counts as WARNING (orange)
- Examples: Minor configuration differences

---

## Running the Script

### Method 1: Via SCCM (Production)

**SCCM Configuration:**
```
Step Type: Run PowerShell Script
Script: Check-SecurityCompliance.ps1
Run as: SYSTEM
Success Codes: 0
Timeout: 600 seconds
```

**In Task Sequence:**
```
Phase 7 - Compliance & Validation
├── Check Security Compliance (VAL-001)
├── Validate Applications (VAL-002)
├── Check System Health (VAL-003)
└── Generate Report (VAL-004)
```

---

### Method 2: Via PsExec (Manual)

```powershell
# Launch SYSTEM PowerShell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# Run validation
cd C:\DeploymentScripts\Phase7-Validation
.\Check-SecurityCompliance.ps1 -GenerateReport $true

# View report
Start-Process "C:\ProgramData\ComplianceReports\SecurityCompliance_*.html"
```

---

### Method 3: As Admin (Testing)

```powershell
# Run as local administrator
.\Check-SecurityCompliance.ps1

# Quick validation output
# HTML report generated
```

---

## Troubleshooting

### Issue 1: Windows Defender Fails Validation

**Symptom:** Real-time protection shows as disabled

**Common Causes:**
1. Defender disabled by Group Policy
2. Third-party antivirus installed
3. Tamper protection disabled

**Solutions:**

```powershell
# Check Defender status
Get-MpComputerStatus

# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Check Group Policy
gpresult /h gp_report.html
# Look for Defender policies

# Enable Defender via registry (if GPO allows)
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
```

---

### Issue 2: BitLocker Shows as Non-Compliant

**Symptom:** BitLocker not encrypted

**Common Causes:**
1. BitLocker not available (Home edition)
2. No TPM chip
3. Not yet encrypted (in progress)

**Solutions:**

```powershell
# Check BitLocker status
Get-BitLockerVolume

# Check TPM status
Get-Tpm

# If encryption in progress:
# VolumeStatus will show "EncryptionInProgress"
# This is OK - wait for completion

# If BitLocker not available:
# Windows 11 Home doesn't have BitLocker
# Upgrade to Pro/Enterprise required
```

---

### Issue 3: Firewall Profile Disabled

**Symptom:** Public or Private profile disabled

**Solutions:**

```powershell
# Check firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled

# Enable all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Check for Group Policy override
gpresult /h gp_report.html
# Look for firewall policies
```

---

### Issue 4: Updates Pending Shows as Warning

**Symptom:** Critical updates pending

**Solutions:**

```powershell
# Check for updates
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0")
$SearchResult.Updates | Select-Object Title, MsrcSeverity

# Install updates
Install-WindowsUpdate -AcceptAll -AutoReboot

# Or via Settings:
Start-Process ms-settings:windowsupdate
```

---

### Issue 5: SMBv1 Still Enabled

**Symptom:** SMBv1 shows as enabled

**Solutions:**

```powershell
# Check SMBv1 status
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Verify
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
# Should show: State : Disabled
```

---

## Validation Commands

### Manual Compliance Check

```powershell
function Test-QuickCompliance {
    Write-Host "`n=== QUICK COMPLIANCE CHECK ===" -ForegroundColor Cyan
    
    # Defender
    $Defender = Get-MpComputerStatus
    Write-Host "Defender Real-time: $(if($Defender.RealTimeProtectionEnabled){'✓ ON'}else{'✗ OFF'})" `
        -ForegroundColor $(if($Defender.RealTimeProtectionEnabled){'Green'}else{'Red'})
    
    # BitLocker
    $BitLocker = Get-BitLockerVolume | Where-Object {$_.VolumeType -eq "OperatingSystem"}
    Write-Host "BitLocker: $(if($BitLocker.VolumeStatus -eq 'FullyEncrypted'){'✓ Encrypted'}else{'✗ Not Encrypted'})" `
        -ForegroundColor $(if($BitLocker.VolumeStatus -eq 'FullyEncrypted'){'Green'}else{'Red'})
    
    # Firewall
    $FW = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}
    Write-Host "Firewall: $(if($FW.Count -eq 0){'✓ All Enabled'}else{'✗ '+$FW.Count+' Disabled'})" `
        -ForegroundColor $(if($FW.Count -eq 0){'Green'}else{'Red'})
    
    # UAC
    $UAC = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
    Write-Host "UAC: $(if($UAC -eq 1){'✓ Enabled'}else{'✗ Disabled'})" `
        -ForegroundColor $(if($UAC -eq 1){'Green'}else{'Red'})
}

Test-QuickCompliance
```

---

## Best Practices

### 1. Run Validation at End of Deployment

```
Deployment Phases:
Phase 1: Initialization
Phase 2: Security ← Configure security
Phase 3: Network
Phase 4: Applications
Phase 5: System Configuration
Phase 6: User Experience
Phase 7: Validation ← Validate security here!
```

**Why:**
- ✅ Confirms all security configured
- ✅ Catches configuration drift
- ✅ Deployment quality assurance

---

### 2. Generate and Archive Reports

```powershell
# Save reports to network share
$ReportPath = "\\FileServer\ComplianceReports\$env:COMPUTERNAME"
.\Check-SecurityCompliance.ps1 -ReportPath $ReportPath

# Keep reports for audit trail
# Compliance documentation
# Trend analysis
```

---

### 3. Review Reports Regularly

```
Daily: Check new deployments (first week)
Weekly: Sample validation (10% of fleet)
Monthly: Full fleet compliance scan
Quarterly: Compliance reporting for management
```

---

### 4. Set Realistic Expectations

```
100% Compliance: ✅ Goal
98% Compliance:  ✅ Excellent
95% Compliance:  ✅ Good
90% Compliance:  ⚠️ Needs attention
<90% Compliance: ❌ Review deployment process
```

---

### 5. Remediate Systematically

```
Priority 1 (Critical): Fix immediately
- Defender disabled
- BitLocker off
- Firewall disabled

Priority 2 (High): Fix within 24 hours
- Old signatures
- Updates pending
- SMBv1 enabled

Priority 3 (Medium): Fix within week
- Audit policies
- Minor configs

Priority 4 (Low): Fix when convenient
- Optimization items
```

---

## Summary

### What You Have

✅ **Comprehensive Security Compliance Validation**
- 48+ security checks across 7 categories
- Windows Defender validation
- BitLocker encryption verification
- Firewall configuration check
- UAC validation
- Windows Update status
- Network security validation
- Audit policy verification
- HTML compliance reports
- Percentage-based scoring

### From Orchestration Config

```
Task: VAL-001 (Security Compliance Check)
Profile: Enterprise-Security-Baseline
Report: HTML report in C:\ProgramData\ComplianceReports\
Critical: YES (deployment fails if validation fails)
```

### Benefits

**For Security:**
- ✅ Validates all Phase 2 security configurations
- ✅ Confirms BitLocker encryption
- ✅ Verifies Defender protection
- ✅ Validates firewall rules
- ✅ Ensures compliance

**For Compliance:**
- ✅ Audit trail (HTML reports)
- ✅ Documented validation
- ✅ Percentage-based scoring
- ✅ HIPAA/PCI-DSS profiles
- ✅ Management reporting

**For Operations:**
- ✅ Quality assurance
- ✅ Configuration validation
- ✅ Automated checking
- ✅ Consistent standards
- ✅ 3000+ device validation

### Current Status

🟢 **Enabled in orchestration** (VAL-001) - Ready  
🟢 **Production-ready** - Comprehensive validation  
🟢 **Critical task** - Ensures security baseline  
🟢 **HTML reporting** - Professional compliance reports  
🟢 **Multi-profile** - Enterprise, HIPAA, PCI-DSS  
🟢 **Complete documentation** - Everything explained  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

**END OF DOCUMENTATION**
