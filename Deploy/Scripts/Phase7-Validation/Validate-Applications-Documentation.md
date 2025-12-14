# APPLICATION INSTALLATION VALIDATION - DOCUMENTATION

## Overview

Comprehensive guide for **Validate-Applications.ps1** — validating that all required applications are properly installed and functional.

**Script Location:** `Phase7-Validation\Validate-Applications.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## Quick Start

### Basic Usage

```powershell
# Default validation (from orchestration config)
.\Validate-Applications.ps1

# Validate specific applications
.\Validate-Applications.ps1 -RequiredApps @("Chrome", "Teams", "Office")

# Include version checking
.\Validate-Applications.ps1 -ValidateVersions $true

# Generate detailed HTML report
.\Validate-Applications.ps1 -GenerateReport $true

# Test without checking
.\Validate-Applications.ps1 -DryRun
```

---

## What It Does

Validates application installations from Phase 4:

- ✅ **Presence Check** - Application installed
- ✅ **Version Validation** - Meets minimum version
- ✅ **Path Verification** - Installation location
- ✅ **Registry Validation** - Proper registration
- ✅ **Executable Check** - Files present
- ✅ **License Validation** - Office/Adobe licensing (optional)
- ✅ **Component Check** - Office apps (Word, Excel, PowerPoint, Outlook)
- ✅ **HTML Report** - Detailed validation results

---

## Configuration from Orchestration

```powershell
TaskID: VAL-002
Parameters = @{
    RequiredApps = @("Microsoft Office", "Google Chrome", "Adobe Reader", "Microsoft Teams")
}
```

### What This Validates

**From Phase 4 Application Installations:**

1. **Microsoft Office**
   - ✓ Word (WINWORD.EXE)
   - ✓ Excel (EXCEL.EXE)
   - ✓ PowerPoint (POWERPNT.EXE)
   - ✓ Outlook (OUTLOOK.EXE)
   - ✓ Version 16.0+ (Office 2016/365)
   - ✓ License activated

2. **Google Chrome**
   - ✓ chrome.exe present
   - ✓ Version 100.0+
   - ✓ Proper registration
   - ✓ Default browser check

3. **Adobe Acrobat Reader DC**
   - ✓ AcroRd32.exe present
   - ✓ Version 20.0+
   - ✓ PDF association

4. **Microsoft Teams**
   - ✓ Teams.exe present
   - ✓ Version 1.5+
   - ✓ Proper installation

**Result:** Confirms all Phase 4 applications installed correctly

---

## Supported Applications

### Built-in Application Definitions

The script includes pre-configured validation for:

**1. Microsoft Office**
```powershell
Display Names: "Microsoft Office Professional Plus", "Microsoft 365 Apps"
Executables: WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE
Paths: C:\Program Files\Microsoft Office\
Minimum Version: 16.0 (Office 2016/365)
License Check: Yes
```

**2. Google Chrome**
```powershell
Display Names: "Google Chrome"
Executables: chrome.exe
Paths: C:\Program Files\Google\Chrome\Application\
Minimum Version: 100.0
License Check: No
```

**3. Mozilla Firefox**
```powershell
Display Names: "Mozilla Firefox"
Executables: firefox.exe
Paths: C:\Program Files\Mozilla Firefox\
Minimum Version: 100.0
License Check: No
```

**4. Adobe Acrobat Reader DC**
```powershell
Display Names: "Adobe Acrobat Reader DC", "Adobe Reader"
Executables: AcroRd32.exe, Acrobat.exe
Paths: C:\Program Files\Adobe\Acrobat Reader DC\
Minimum Version: 20.0
License Check: No
```

**5. Microsoft Teams**
```powershell
Display Names: "Microsoft Teams", "Teams Machine-Wide Installer"
Executables: Teams.exe
Paths: C:\Program Files\WindowsApps\, C:\Users\*\AppData\Local\Microsoft\Teams\
Minimum Version: 1.5
License Check: No
```

**6. 7-Zip**
```powershell
Display Names: "7-Zip"
Executables: 7zFM.exe, 7z.exe
Paths: C:\Program Files\7-Zip\
Minimum Version: 19.0
License Check: No
```

**7. VLC Media Player**
```powershell
Display Names: "VLC media player"
Executables: vlc.exe
Paths: C:\Program Files\VideoLAN\VLC\
Minimum Version: 3.0
License Check: No
```

**8. Notepad++**
```powershell
Display Names: "Notepad++"
Executables: notepad++.exe
Paths: C:\Program Files\Notepad++\
Minimum Version: 8.0
License Check: No
```

---

## Validation Methods

### Method 1: Registry Detection (Primary)

**What It Checks:**
```
Registry Paths:
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

Keys Read:
- DisplayName (application name)
- DisplayVersion (version number)
- InstallLocation (installation path)
- Publisher (vendor)
```

**Why This Works:**
- ✅ Standard Windows installation method
- ✅ Accurate for MSI/EXE installers
- ✅ Contains version information
- ✅ Fast lookup

---

### Method 2: File System Check (Secondary)

**What It Checks:**
```
Common Installation Paths:
C:\Program Files\
C:\Program Files (x86)\
C:\Users\*\AppData\Local\

Executable Verification:
- File existence
- File version (from properties)
- Path validation
```

**When Used:**
- ✅ Registry method fails
- ✅ Portable installations
- ✅ User-specific installs (Teams)
- ✅ Backup validation

---

### Method 3: Registry Key Check (Tertiary)

**What It Checks:**
```
Application-Specific Keys:
HKLM:\SOFTWARE\Microsoft\Office\16.0\
HKLM:\SOFTWARE\Adobe\Acrobat Reader\
HKLM:\SOFTWARE\7-Zip\
HKLM:\SOFTWARE\VideoLAN\VLC\

Presence Check:
- Key exists = Application installed
- Key missing = Application not installed
```

**When Used:**
- ✅ Both previous methods fail
- ✅ Application has unique registry structure
- ✅ Final fallback

---

## Version Validation

### How Version Checking Works

**Enabled by Default:**
```powershell
ValidateVersions = $true  # Check minimum versions
```

**Version Comparison:**
```
Installed Version: 120.0.6099.109 (Chrome)
Minimum Required:  100.0
Comparison: 120.0 >= 100.0 ✓ PASS

Installed Version: 15.0.4569 (Office 2013)
Minimum Required:  16.0 (Office 2016+)
Comparison: 15.0 < 16.0 ✗ FAIL (outdated)
```

**Version Sources:**
1. Registry DisplayVersion (primary)
2. Executable FileVersion (secondary)
3. "Unknown" if cannot determine

---

### Minimum Version Requirements

**Why These Versions:**

| Application | Min Version | Reason |
|------------|-------------|---------|
| **Office** | 16.0 | Office 2016+ (modern features, security) |
| **Chrome** | 100.0 | Modern web standards, security patches |
| **Firefox** | 100.0 | Modern web standards, security |
| **Adobe Reader** | 20.0 | Security patches, PDF standards |
| **Teams** | 1.5 | Stable feature set, performance |
| **7-Zip** | 19.0 | Security, compression algorithms |
| **VLC** | 3.0 | Codec support, security |
| **Notepad++** | 8.0 | Modern features, performance |

**Version Warning vs Error:**
- ✅ Installed but old version: **WARNING** (app works, but outdated)
- ❌ Not installed: **ERROR** (missing completely)

---

## License Validation

### Office License Checking

**When Enabled:**
```powershell
ValidateLicensing = $true  # Check Office activation
```

**How It Works:**
```powershell
# Uses Office Software Protection Platform (OSPP)
cscript "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /dstatus

Results:
✓ LICENSE STATUS: LICENSED (activated)
⚠ LICENSE STATUS: GRACE (grace period, needs activation)
✗ LICENSE STATUS: UNLICENSED (not activated)
```

**License Statuses:**

**1. Licensed (✓)**
```
Status: Fully activated
Action: None required
Result: PASS
```

**2. Grace Period (⚠)**
```
Status: Temporary activation (30 days)
Action: Activate within grace period
Result: WARNING
```

**3. Unlicensed (✗)**
```
Status: Not activated
Action: Activate immediately
Result: WARNING (not error - may be intentional)
```

---

### Adobe Reader License

**Status:**
```
Adobe Reader DC is FREE
No license validation needed
Always: N/A
```

---

## Special Component Checks

### Microsoft Office Component Validation

**What's Checked:**
```
Individual Office Apps:
✓ Word       (WINWORD.EXE)
✓ Excel      (EXCEL.EXE)
✓ PowerPoint (POWERPNT.EXE)
✓ Outlook    (OUTLOOK.EXE)

Installation Paths:
C:\Program Files\Microsoft Office\root\Office16\
C:\Program Files (x86)\Microsoft Office\root\Office16\

Result:
If Office validated as installed, checks each component individually
```

**Why This Matters:**
- ✅ Confirms complete Office installation
- ✅ Catches partial installations (missing components)
- ✅ Validates Click-to-Run vs MSI installations

---

### Google Chrome Configuration Check

**What's Checked:**
```
Chrome as Default Browser:
Registry: HKCU:\...\UrlAssociations\http\UserChoice
ProgId: ChromeHTML (if Chrome is default)

Chrome Version:
File: C:\Program Files\Google\Chrome\Application\chrome.exe
Version: FileVersionInfo property

Result:
✓ Chrome installed: Confirmed
ℹ Default browser: ChromeHTML (or other)
ℹ Version: 120.0.6099.109
```

---

## HTML Validation Report

### Report Contents

**Summary Section:**
```html
┌────────────────────────────────────────┐
│ Status: ALL APPLICATIONS INSTALLED     │
│ Success Rate: 100%                     │
│                                        │
│ Installed: 4                           │
│ Missing:   0                           │
└────────────────────────────────────────┘
```

**Application Details Table:**
```
Application          Status         Version           Path                    License
-------------------- -------------- ----------------- ----------------------- ---------
Microsoft Office     ✓ Installed    16.0.16827.20166  C:\Program Files\...    Licensed
Google Chrome        ✓ Installed    120.0.6099.109    C:\Program Files\...    N/A
Adobe Reader         ✓ Installed    23.006.20360      C:\Program Files\...    N/A
Microsoft Teams      ✓ Installed    1.6.00.4472       C:\Users\...\Teams\     N/A
```

**Report Location:**
```
C:\ProgramData\ValidationReports\
ApplicationValidation_20241209-143500.html
```

---

### Report Color Coding

**Green (Installed):**
```
✓ Application installed
✓ Version OK
✓ All checks passed
```

**Red (Missing):**
```
✗ Application not found
✗ Not in registry
✗ Executables missing
```

**Orange (Warning):**
```
⚠ Installed but old version
⚠ License in grace period
⚠ Component missing
```

---

## Running the Script

### Method 1: Via SCCM (Production)

**SCCM Configuration:**
```
Step Type: Run PowerShell Script
Script: Validate-Applications.ps1
Run as: SYSTEM
Success Codes: 0
Timeout: 300 seconds
```

**In Task Sequence:**
```
Phase 7 - Validation
├── Check Security Compliance (VAL-001)
├── Validate Applications (VAL-002) ← HERE
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
.\Validate-Applications.ps1

# View report
Start-Process "C:\ProgramData\ValidationReports\ApplicationValidation_*.html"
```

---

### Method 3: As Admin (Testing)

```powershell
# Run as local administrator
.\Validate-Applications.ps1

# Quick check output in console
# HTML report generated
```

---

## Troubleshooting

### Issue 1: Application Shows as Missing But Is Installed

**Symptom:** Script says "NOT INSTALLED" but you can see the application

**Common Causes:**
1. Portable installation (not in registry)
2. User-specific install (not system-wide)
3. Different installation path

**Solutions:**

```powershell
# Check where application actually is
Get-ChildItem "C:\Program Files" -Recurse -Filter "chrome.exe" -ErrorAction SilentlyContinue

# Check registry manually
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
    Where-Object {$_.DisplayName -like "*Chrome*"} |
    Select-Object DisplayName, DisplayVersion, InstallLocation

# Check both architectures
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object {$_.DisplayName -like "*Chrome*"}
```

---

### Issue 2: Version Shows as "Unknown"

**Symptom:** Application installed but version shows "Unknown"

**Causes:**
- No DisplayVersion in registry
- Portable installation
- Executable has no version info

**Solutions:**

```powershell
# Check executable version manually
$ExePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (Test-Path $ExePath) {
    $Version = (Get-Item $ExePath).VersionInfo.FileVersion
    Write-Host "Chrome Version: $Version"
}

# Check registry version
$App = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object {$_.DisplayName -like "*Chrome*"}
Write-Host "Registry Version: $($App.DisplayVersion)"
```

---

### Issue 3: Office License Shows as Unlicensed

**Symptom:** Office installed but license status is "Unlicensed"

**Causes:**
1. Not yet activated
2. Activation in progress
3. KMS activation not completed
4. Volume license not applied

**Solutions:**

```powershell
# Check Office activation manually
cd "C:\Program Files\Microsoft Office\Office16"
cscript ospp.vbs /dstatus

# Attempt activation (if KMS)
cscript ospp.vbs /act

# Check license details
cscript ospp.vbs /dstatusall
```

**Note:** Unlicensed status is WARNING, not ERROR (may be intentional for delayed activation)

---

### Issue 4: Teams Not Detected

**Symptom:** Teams installed but not detected

**Causes:**
- User-specific installation (not system-wide)
- New Teams vs Classic Teams
- AppX package installation

**Solutions:**

```powershell
# Check system-wide Teams
Test-Path "C:\Program Files\WindowsApps\MicrosoftTeams*"

# Check user-specific Teams
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Teams\current\Teams.exe" -ErrorAction SilentlyContinue

# Check AppX Teams
Get-AppxPackage -Name "MicrosoftTeams" -AllUsers
```

---

### Issue 5: Validation Takes Long Time

**Symptom:** Script runs slowly, takes several minutes

**Causes:**
- Many user profiles to scan
- Slow network shares
- Large registry

**Solutions:**

```powershell
# Run with specific apps only (faster)
.\Validate-Applications.ps1 -RequiredApps @("Office", "Chrome")

# Disable version checking (faster)
.\Validate-Applications.ps1 -ValidateVersions $false

# Disable licensing check (faster)
.\Validate-Applications.ps1 -ValidateLicensing $false
```

---

## Validation Commands

### Quick Manual Validation

```powershell
function Test-QuickApps {
    Write-Host "`n=== QUICK APPLICATION CHECK ===" -ForegroundColor Cyan
    
    $Apps = @{
        "Office" = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        "Chrome" = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        "Adobe Reader" = "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
        "Teams" = "C:\Program Files\WindowsApps\MicrosoftTeams*\msteams.exe"
    }
    
    foreach ($App in $Apps.Keys) {
        $Path = $Apps[$App]
        $Found = Test-Path $Path
        
        $Status = if ($Found) { "✓ Installed" } else { "✗ Missing" }
        $Color = if ($Found) { "Green" } else { "Red" }
        
        Write-Host "$App : $Status" -ForegroundColor $Color
    }
}

Test-QuickApps
```

---

### Check All Installed Applications

```powershell
# List all installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object {$_.DisplayName} |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Format-Table -AutoSize
```

---

### Check Specific Application

```powershell
# Search for specific app
$AppName = "Chrome"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object {$_.DisplayName -like "*$AppName*"} |
    Select-Object DisplayName, DisplayVersion, InstallLocation
```

---

## Best Practices

### 1. Run Validation After Phase 4

```
Deployment Flow:
Phase 4: Install applications
         ↓
Phase 7: Validate installations ← HERE
         ↓
Phase 7: Generate report
```

**Why:**
- ✅ Confirms all installations succeeded
- ✅ Catches silent installation failures
- ✅ Quality assurance

---

### 2. Include All Phase 4 Applications

```powershell
# Match your Phase 4 installations
RequiredApps = @(
    "Microsoft Office"     # From APP-001
    "Google Chrome"        # From APP-002
    "Adobe Reader"         # From APP-004
    "Microsoft Teams"      # From APP-005
    "7-Zip"               # From APP-006
    "VLC Media Player"     # From APP-007
    "Notepad++"           # From APP-008
)
```

---

### 3. Generate and Archive Reports

```powershell
# Save reports for audit trail
$ReportPath = "\\FileServer\ValidationReports\$env:COMPUTERNAME"
.\Validate-Applications.ps1 -ReportPath $ReportPath

# Keep reports for:
- Audit documentation
- Troubleshooting
- Trend analysis
```

---

### 4. Don't Fail Deployment on Missing Apps

```powershell
FailOnMissingApps = $false  # Default (recommended)
```

**Why:**
- ✅ Applications may be optional
- ✅ May be installed later
- ✅ User-specific apps
- ✅ Non-critical for OS deployment

**When to Fail:**
- ❌ Critical line-of-business app
- ❌ Security requirement
- ❌ Compliance mandate

---

### 5. Review Reports Regularly

```
Daily: Check new deployments (first week)
Weekly: Sample validation (10% of fleet)
Monthly: Application version audit
Quarterly: Update minimum versions
```

---

## Summary

### What You Have

✅ **Comprehensive Application Validation**
- 8 pre-configured applications
- Multiple detection methods (registry, file system, registry keys)
- Version validation
- License checking (Office)
- Component validation (Office apps)
- HTML reporting
- Success rate calculation

### From Orchestration Config

```
Task: VAL-002 (Application Validation)
Apps: Microsoft Office, Chrome, Adobe Reader, Teams
Validation: Presence, Version, Licensing
Report: HTML in C:\ProgramData\ValidationReports\
Critical: NO (non-blocking)
```

### Benefits

**For Deployment:**
- ✅ Confirms Phase 4 installations
- ✅ Catches silent failures
- ✅ Quality assurance
- ✅ Automated validation

**For Operations:**
- ✅ Application inventory
- ✅ Version tracking
- ✅ License monitoring (Office)
- ✅ Audit documentation

**For Users:**
- ✅ All applications working
- ✅ Proper versions installed
- ✅ Licensed software (Office)
- ✅ Complete installations

### Success Criteria

**Validation PASSES if:**
- ✅ All required apps: Installed
- ✅ Versions: Meet minimum
- ✅ Licenses: Activated (Office)

**Validation WARNINGS if:**
- ⚠ Apps installed but old versions
- ⚠ Office in grace period
- ⚠ Missing optional components

**Validation FAILS if:**
- ❌ Required apps: Missing
- ❌ And FailOnMissingApps = $true

### Current Status

🟢 **Enabled in orchestration** (VAL-002) - Ready  
🟢 **Production-ready** - Multiple detection methods  
🟢 **Non-critical task** - Won't block deployment  
🟢 **HTML reporting** - Professional validation reports  
🟢 **8 supported apps** - Office, Chrome, Adobe, Teams, 7-Zip, VLC, Notepad++, Firefox  
🟢 **Complete documentation** - Everything explained  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

**END OF DOCUMENTATION**
