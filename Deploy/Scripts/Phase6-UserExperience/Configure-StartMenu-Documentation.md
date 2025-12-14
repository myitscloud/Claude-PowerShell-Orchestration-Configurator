# CONFIGURE START MENU - DOCUMENTATION

## Overview

Comprehensive guide for **Configure-StartMenu.ps1** — configuring Windows 11 Start Menu layout and settings.

**Script Location:** `Phase6-UserExperience\Configure-StartMenu.ps1`  
**Version:** 1.0.0  
**Status:** Production-ready for 3000+ device deployment

---

## ⚠️ IMPORTANT: Windows 11 Limitations

### What Changed in Windows 11

**Windows 10 Start Menu:**
```
✅ Full XML layout support
✅ Easy programmatic pinning
✅ Complete customization
✅ Group organization
✅ Tile sizing
```

**Windows 11 Start Menu:**
```
⚠️ Limited XML layout support
⚠️ Difficult programmatic pinning
⚠️ Reduced customization options
⚠️ No groups or folders
⚠️ Fixed tile sizes
❌ Cannot fully remove "Recommended" section
```

**Bottom Line:** Windows 11 Start Menu is less customizable than Windows 10

---

## Quick Start

### Basic Usage

```powershell
# Default configuration (run as SYSTEM via PsExec)
.\Configure-StartMenu.ps1

# With custom layout XML
.\Configure-StartMenu.ps1 -LayoutXML "C:\Deploy\StartLayout.xml"

# Disable recommendations
.\Configure-StartMenu.ps1 -ShowRecommendations $false -ShowRecentlyAdded $false

# Test without making changes
.\Configure-StartMenu.ps1 -DryRun
```

---

## What It Does

Configures Start Menu for professional use:

- ✅ **Hide recently added apps** (clean Start menu)
- ✅ **Hide most used apps** (privacy)
- ✅ **Hide recommendations** (no suggested content)
- ✅ **Remove default pins** (clean slate)
- ✅ **Set Start menu size** (More Pins vs More Recommendations)
- ⚠️ **Import layout XML** (limited Windows 11 support)
- ⚠️ **Pin applications** (difficult in Windows 11)
- ✅ **Apply to default profile** (new users)

---

## Configuration from Orchestration

```powershell
Parameters = @{
    LayoutXML = "Config\StartMenuLayout.xml"    # Optional layout file
    ApplyToAllUsers = $true                      # Configure default profile
}
```

### What This Configuration Does

**When Run as SYSTEM (via PsExec or SCCM):**
1. Configures Start Menu settings in default user profile
2. Removes default Windows pins
3. Applies layout XML (if provided)
4. All NEW users get clean Start Menu

**Result:**
- ✅ Clean, professional Start Menu
- ✅ No consumer app suggestions
- ✅ Consistent across all new users
- ✅ Privacy-focused (no tracking)

---

## Start Menu Settings Explained

### 1. Recently Added Apps

**What It Is:**
```
Start Menu shows:
  📱 Recently added
     - App you just installed
     - Another new app
     - Yet another app
```

**Configuration:**
```powershell
ShowRecentlyAdded = $false  # Recommended for enterprise
```

**Why Disable:**
- Cleaner Start Menu
- Users know what they installed
- Less clutter
- Professional appearance

---

### 2. Most Used Apps

**What It Is:**
```
Start Menu shows:
  📊 Most used
     - Chrome (opened 50 times)
     - Word (opened 30 times)
     - Outlook (opened 25 times)
```

**Configuration:**
```powershell
ShowMostUsed = $false  # Can enable if desired
```

**Why Disable:**
- Privacy (others can see usage)
- Users know their frequently-used apps
- Cleaner appearance

**Why Enable:**
- User convenience
- Quick access
- Saves pinning

**Recommendation:** Your choice — both valid

---

### 3. Recommendations Section

**What It Is:**
```
Start Menu shows:
  💡 Recommended
     - Recent documents
     - Recent websites
     - Suggested apps
     - Tips and tricks
```

**Configuration:**
```powershell
ShowRecommendations = $false  # Strongly recommended
```

**Why Disable:**
- **Privacy:** Shows recent documents to anyone
- **Professional:** Looks unprofessional
- **Distraction:** Users don't need "tips"
- **Security:** Can expose sensitive file names

**IMPORTANT:** Cannot be fully removed in Windows 11, only hidden

---

### 4. Start Menu Size

**Options:**

**MorePins (Recommended):**
```
┌─────────────────────┐
│ 📌 Pinned Apps      │
│    (Large area)     │
│                     │
│                     │
│                     │
│ 💡 Recommended      │
│    (Small area)     │
└─────────────────────┘
```

**MoreRecommendations:**
```
┌─────────────────────┐
│ 📌 Pinned Apps      │
│    (Small area)     │
│                     │
│ 💡 Recommended      │
│    (Large area)     │
│                     │
│                     │
└─────────────────────┘
```

**Configuration:**
```powershell
StartMenuSize = "MorePins"  # Recommended
```

**Recommendation:** Always use "MorePins" for enterprise

---

## Default Pins Removal

### What Windows Pins by Default

**Out-of-box Windows 11 Start Menu:**
```
📌 Pinned:
   - Microsoft Edge
   - Microsoft Store
   - Photos
   - Microsoft To Do
   - Settings
   - Microsoft Office (if installed)
   - Xbox (gaming)
   - Clipchamp (video editor)
   - Movies & TV
   - Spotify (OEM)
```

**After RemoveDefaultPins = $true:**
```
📌 Pinned:
   - (empty or minimal)
   
Users can pin what THEY want
```

**Why Remove:**
- ✅ Users choose their own apps
- ✅ Cleaner Start Menu
- ✅ Professional appearance
- ✅ No OEM bloatware pins

---

## Configuration Examples

### Example 1: Standard Enterprise (Recommended)

**Goal:** Clean, professional Start Menu

```powershell
.\Configure-StartMenu.ps1 `
    -RemoveDefaultPins $true `
    -ShowRecentlyAdded $false `
    -ShowMostUsed $false `
    -ShowRecommendations $false `
    -StartMenuSize "MorePins" `
    -ApplyToAllUsers $true
```

**Result:**
- ✅ Clean Start Menu
- ✅ No recommendations
- ✅ No default pins
- ✅ More space for user's apps
- ✅ Professional appearance

**Perfect for:** 95% of enterprises

---

### Example 2: User-Friendly (With Helpers)

**Goal:** Helpful Start Menu for less technical users

```powershell
.\Configure-StartMenu.ps1 `
    -RemoveDefaultPins $false `
    -ShowRecentlyAdded $true `
    -ShowMostUsed $true `
    -ShowRecommendations $false `
    -StartMenuSize "MorePins"
```

**Result:**
- ✅ Shows recently added (helpful)
- ✅ Shows most used (convenient)
- ✅ No recommendations (privacy)
- ✅ Keeps some default pins

**Perfect for:** Non-technical users, retail

---

### Example 3: Maximum Privacy

**Goal:** Hide everything possible

```powershell
.\Configure-StartMenu.ps1 `
    -RemoveDefaultPins $true `
    -ShowRecentlyAdded $false `
    -ShowMostUsed $false `
    -ShowRecommendations $false `
    -StartMenuSize "MorePins"
```

**Result:**
- ✅ Minimal Start Menu
- ✅ No usage tracking visible
- ✅ No recent documents exposed
- ✅ Maximum privacy

**Perfect for:** Shared workstations, kiosks, privacy-sensitive

---

### Example 4: With Layout XML (Advanced)

**Goal:** Deploy standardized Start Menu layout

```powershell
.\Configure-StartMenu.ps1 `
    -LayoutXML "C:\Deploy\Config\StartLayout.xml" `
    -ApplyToAllUsers $true
```

**Result:**
- ⚠️ Attempts to import layout XML
- ⚠️ Windows 11 has limited support
- ✅ Best deployed via Group Policy or Intune
- ✅ Settings still applied

**Perfect for:** Organizations with Group Policy infrastructure

---

## Layout XML (Advanced)

### Windows 11 Layout XML Support

**Reality Check:**
```
Windows 10: ✅ Full support, easy deployment
Windows 11: ⚠️ Limited support, difficult deployment
```

**What Works:**
- ✅ Partial layout via Group Policy
- ✅ Layout XML for locked Start Menus (kiosks)
- ⚠️ User customization difficult

**What Doesn't Work:**
- ❌ Full programmatic layout like Windows 10
- ❌ Easy XML-based pinning
- ❌ Complete user experience control

### Sample Layout XML

**Minimal Layout XML:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    Version="1">
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6">
                <!-- Windows 11 has limited layout XML support -->
                <!-- Primarily used for locked/kiosk scenarios -->
            </defaultlayout:StartLayout>
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
```

**Deployment:**
```powershell
# Copy layout file
Copy-Item "StartLayout.xml" "C:\ProgramData\StartMenuLayout.xml"

# Set Group Policy registry
$GPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
Set-ItemProperty $GPPath -Name "LockedStartLayout" -Value 1
Set-ItemProperty $GPPath -Name "StartLayoutFile" -Value "C:\ProgramData\StartMenuLayout.xml"

# Requires actual Group Policy to enforce
```

**Recommendation:** Use Intune or Group Policy for layout deployment

---

## Running the Script

### Method 1: Via PsExec (Manual - RECOMMENDED)

```powershell
# 1. Open elevated PowerShell as admin

# 2. Launch SYSTEM PowerShell
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe

# 3. In SYSTEM window, run script
cd C:\DeploymentScripts\Phase6-UserExperience
.\Configure-StartMenu.ps1

# 4. Configuration applies to default profile
# 5. New users get configured Start Menu
```

---

### Method 2: Via SCCM Task Sequence (Production)

**SCCM Configuration:**
```
Step Type: Run PowerShell Script
Script: Configure-StartMenu.ps1
Execution Policy: Bypass
Run as: SYSTEM (automatic in task sequence)
Success Codes: 0
```

**Result:**
- Runs during deployment
- Default profile configured
- All new users get settings

---

### Method 3: For Current User (Testing)

```powershell
# Run as your admin account (NOT SYSTEM)
.\Configure-StartMenu.ps1

# This configures YOUR Start Menu only
# Does NOT affect default profile or other users
# Good for testing what settings do
```

---

## Troubleshooting

### Issue 1: Settings Don't Apply to New Users

**Symptom:** New users don't get configured Start Menu

**Cause:** Script didn't run as SYSTEM or didn't modify default profile

**Solutions:**

```powershell
# 1. Verify script ran as SYSTEM
Get-Content "C:\ProgramData\OrchestrationLogs\Configure-StartMenu_*.log" | Select-String "SYSTEM"

# 2. Check default profile modified
Get-Item "C:\Users\Default\NTUSER.DAT" | Select-Object LastWriteTime

# 3. Check registry in default profile
reg load "HKU\TempCheck" "C:\Users\Default\NTUSER.DAT"
reg query "HKU\TempCheck\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
reg unload "HKU\TempCheck"

# 4. Re-run script as SYSTEM
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe
cd C:\DeploymentScripts\Phase6-UserExperience
.\Configure-StartMenu.ps1
```

---

### Issue 2: Recommendations Still Showing

**Symptom:** "Recommended" section still appears

**Cause:** Windows 11 cannot fully remove recommendations section

**Reality:**
```
❌ Cannot remove recommendations section completely
✅ Can hide it (minimize)
✅ Can reduce content shown
⚠️ It's always there in Windows 11
```

**Best You Can Do:**
```powershell
ShowRecommendations = $false  # Minimizes it
StartMenuSize = "MorePins"    # Makes it smaller
```

**Alternative:** Use Group Policy or Intune for stricter control

---

### Issue 3: Can't Pin Applications Programmatically

**Symptom:** PinApplications parameter doesn't work

**Cause:** Windows 11 removed easy programmatic pinning APIs

**Reality:**
```
Windows 10: ✅ Pin via COM object (easy)
Windows 11: ❌ Microsoft removed API (intentional)
```

**Workarounds:**
```
Option 1: Layout XML (limited support)
Option 2: Intune deployment (works better)
Option 3: Users pin their own apps (best UX)
Option 4: Third-party tools (risky)
```

**Recommendation:** Let users pin their own apps

---

### Issue 4: Layout XML Not Working

**Symptom:** Layout XML imported but not applied

**Cause:** Windows 11 has limited XML support

**Solutions:**

```powershell
# 1. Verify XML syntax
[xml]$Layout = Get-Content "C:\ProgramData\StartMenuLayout.xml"

# 2. Check Group Policy applied
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile"

# 3. Use Group Policy instead
# Computer Configuration > Administrative Templates > Start Menu and Taskbar
# "Start Layout"

# 4. Or use Intune
# Devices > Configuration profiles > Windows 10 and later
# Device restrictions > Start
```

**Best Approach:** Deploy via Group Policy or Intune, not script

---

### Issue 5: Default Pins Come Back

**Symptom:** Windows re-pins default apps

**Cause:** Windows Update or user profile recreation

**Solutions:**

```powershell
# 1. Verify RemoveDefaultPins setting
.\Configure-StartMenu.ps1 -RemoveDefaultPins $true

# 2. Check pin files deleted
Get-ChildItem "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_*\LocalState\start*.bin"

# 3. Disable consumer features (different script)
.\Disable-ConsumerFeatures.ps1

# 4. Re-apply after Windows Updates
# Schedule script to run monthly
```

---

## Validation Commands

### Check Current Start Menu Settings

```powershell
# Check current user settings
$StartPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

Write-Host "`nStart Menu Settings:" -ForegroundColor Cyan
Write-Host "  Recently Added: $((Get-ItemProperty $StartPath -Name 'Start_TrackProgs' -EA Silent).Start_TrackProgs)"
Write-Host "  Most Used: $((Get-ItemProperty $StartPath -Name 'Start_TrackDocs' -EA Silent).Start_TrackDocs)"

# 0 = Disabled, 1 = Enabled
```

### Check Default Profile Settings

```powershell
# Load default profile registry
reg load "HKU\TempCheck" "C:\Users\Default\NTUSER.DAT"

# Query settings
reg query "HKU\TempCheck\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs
reg query "HKU\TempCheck\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs

# Unload
reg unload "HKU\TempCheck"
```

### Test with New User

```powershell
# Create test user
net user TestUser P@ssw0rd123! /add

# Log out, log in as TestUser
# Check Start Menu configuration:
# - Recently added hidden?
# - Most used hidden?
# - Recommendations hidden/minimized?
# - Default pins removed?

# Delete test user when done
net user TestUser /delete
Remove-Item "C:\Users\TestUser" -Recurse -Force
```

---

## Best Practices

### 1. Set Realistic Expectations

✅ **What Script Can Do:**
- Configure Start Menu settings
- Hide recently added/most used
- Minimize recommendations
- Remove default pins
- Apply to default profile

❌ **What Script Cannot Do:**
- Fully remove recommendations section (Windows 11 limitation)
- Easily pin applications programmatically
- Full layout control like Windows 10

### 2. Use Right Tool for Job

**For Settings (Hide/Show):** ✅ Use this script  
**For Layout (Pins):** ⚠️ Use Group Policy or Intune  
**For Pinning Apps:** ⚠️ Let users do it themselves  

### 3. Always Run as SYSTEM

```powershell
# Run via PsExec for default profile
C:\Tools\PsExec64.exe -accepteula -i -s powershell.exe
```

Without SYSTEM:
- Only affects current user
- Doesn't configure default profile
- New users won't get settings

### 4. Test Before Production

```powershell
# Test on one PC first
.\Configure-StartMenu.ps1 -DryRun

# Create test user, verify settings
net user TestUser P@ssw0rd123! /add

# Roll out gradually
# Phase 1: IT department (10 PCs)
# Phase 2: Pilot users (50 PCs)
# Phase 3: Full deployment (3000 PCs)
```

---

## Windows 11 vs Windows 10 Comparison

| Feature | Windows 10 | Windows 11 |
|---------|------------|------------|
| **Layout XML** | ✅ Full support | ⚠️ Limited support |
| **Programmatic Pinning** | ✅ Easy (COM API) | ❌ Difficult/removed |
| **Tile Groups** | ✅ Supported | ❌ Removed |
| **Tile Sizes** | ✅ Small/Med/Large | ❌ Fixed size |
| **Remove Recommendations** | ✅ Fully removable | ❌ Can only minimize |
| **Script Configuration** | ✅ Excellent | ⚠️ Limited |
| **Group Policy** | ✅ Full control | ⚠️ Reduced options |
| **Intune** | ✅ Good support | ✅ Better than script |

**Conclusion:** Windows 11 Start Menu is less customizable by design

---

## Summary

### What You Have

✅ **Start Menu Configuration Script**
- Hide recently added/most used apps
- Minimize recommendations section
- Remove default pins
- Configure Start Menu size
- Apply to default profile (new users)
- Layout XML support (limited)

### From Orchestration Config

```
Layout XML:        Config\StartMenuLayout.xml (optional)
Apply To All Users: TRUE (configure default profile)
Run As:            SYSTEM (via PsExec or SCCM)
```

### Benefits

**For Users:**
- ✅ Clean Start Menu
- ✅ No clutter
- ✅ Professional appearance
- ✅ Privacy (no recent docs shown)

**For IT:**
- ✅ Standardized Start Menu
- ✅ Consistent user experience
- ✅ Automated deployment
- ✅ Professional image

**For Organization:**
- ✅ Enterprise appearance
- ✅ Reduced support calls
- ✅ Better productivity
- ✅ Professional environment

### Current Status

🟢 **Enabled in orchestration** - Ready for deployment  
🟢 **Production-ready** - Tested and validated  
⚠️ **Windows 11 limitations** - Less control than Windows 10  
🟢 **Best practices** - Works within limitations  
🟢 **Complete documentation** - Everything you need  

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-12-09  
**Script Version:** 1.0.0  
**Author:** IT Infrastructure Team

---

**END OF DOCUMENTATION**
