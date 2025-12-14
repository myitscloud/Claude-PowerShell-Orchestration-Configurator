# UNIVERSAL APP INSTALLER - ARCHITECTURE & WORKFLOW

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATION-MASTER.PS1                         │
│                    (Main Orchestration Engine)                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Reads Configuration
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATION-CONFIG.PS1                         │
│                    (Configuration File)                              │
│                                                                       │
│  $Phase4_Applications = @{                                           │
│      Tasks = @(                                                      │
│          @{ TaskID = "APP-010"                                      │
│             ScriptPath = "Scripts\Universal-AppInstaller.ps1"       │
│             Parameters = @{ ... } }                                 │
│          @{ TaskID = "APP-011" ... }                                │
│          @{ TaskID = "APP-012" ... }                                │
│      )                                                               │
│  }                                                                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Invokes for Each App
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│               UNIVERSAL-APPINSTALLER.PS1                            │
│               (Application Installer Script)                         │
│                                                                       │
│  [Detection] → [Find Installer] → [Install] → [Validate]           │
│       │              │                 │            │               │
│       ▼              ▼                 ▼            ▼               │
│   Registry       Search Paths     MSI/EXE      Re-check            │
│   File Path      • .\Installers   MSIX/APPX   Detection            │
│   AppX Pkg       • C:\Deploy      Process      Method              │
│   Package        • \\Server       Mgmt                             │
│   Custom                                                             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Writes Logs & Returns Exit Code
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│              C:\ProgramData\OrchestrationLogs\                      │
│                                                                       │
│  Orchestration_COMPUTER_20241208-143022.log  ← Main log            │
│  Apps\                                                               │
│      Install-7-Zip_20241208-143025.log       ← App-specific        │
│      Install-Notepad++_20241208-143030.log                         │
│      Install-VLC_20241208-143035.log                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Installation Workflow

### Step-by-Step Process for Each Application

```
START
  │
  ├─[1]─ Check if Already Installed (Detection Method)
  │      │
  │      ├─ YES → Log "Already Installed" → EXIT CODE 10 ✓
  │      │
  │      └─ NO → Continue to Step 2
  │
  ├─[2]─ Search for Installer File
  │      │
  │      ├─ Search Paths:
  │      │   • .\Installers\Apps
  │      │   • C:\Deploy\Apps
  │      │   • C:\Installers\Apps
  │      │   • $PSScriptRoot\..\Installers\Apps
  │      │   • \\FileServer\Deployment\Apps
  │      │
  │      ├─ FOUND → Continue to Step 3
  │      │
  │      └─ NOT FOUND → Log Error → EXIT CODE 2 ✗
  │
  ├─[3]─ Execute Pre-Install Script (Optional)
  │      │
  │      └─ Run Custom PowerShell if Provided
  │
  ├─[4]─ Determine Installer Type
  │      │
  │      ├─ Explicit (MSI, EXE, MSIX, APPX)
  │      │
  │      └─ AUTO (detect from extension)
  │
  ├─[5]─ Perform Installation
  │      │
  │      ├─ MSI  → msiexec /i "file.msi" /quiet /norestart
  │      ├─ EXE  → Start-Process "file.exe" /S (or custom args)
  │      └─ MSIX → Add-AppxPackage -Path "file.msix"
  │      │
  │      ├─ SUCCESS → Continue to Step 6
  │      │
  │      └─ FAILURE → Log Error → EXIT CODE 4 ✗
  │
  ├─[6]─ Execute Post-Install Script (Optional)
  │      │
  │      └─ Run Custom PowerShell if Provided
  │
  ├─[7]─ Validate Installation
  │      │
  │      ├─ Re-run Detection Method
  │      │
  │      ├─ DETECTED → Continue to Step 8
  │      │
  │      └─ NOT DETECTED → Log Error → EXIT CODE 5 ✗
  │
  └─[8]─ Log Success → EXIT CODE 0 ✓
```

---

## 🗂️ Data Flow Diagram

```
Configuration File                Orchestration Engine
┌──────────────┐                 ┌──────────────┐
│   TaskID     │────────────────▶│  Read Task   │
│   TaskName   │                 │  Parameters  │
│   Parameters │                 └──────┬───────┘
│   • AppName  │                        │
│   • Installer│                        │
│   • DetectMth│                        ▼
└──────────────┘                 ┌──────────────┐
                                 │   Invoke     │
        ┌────────────────────────│  Universal   │
        │                        │  Installer   │
        │                        └──────┬───────┘
        │                               │
        │                               ▼
        │                        ┌──────────────┐         ┌─────────────┐
        │                        │   Detection  │────────▶│  Already    │
        │                        │   Check      │  YES    │  Installed? │
        │                        └──────┬───────┘         └─────────────┘
        │                               │ NO                     │
        │                               ▼                        │
        │                        ┌──────────────┐                │
        │                        │ Find & Copy  │                │
        │                        │  Installer   │                │
        │                        └──────┬───────┘                │
        │                               │                        │
        │                               ▼                        │
        │                        ┌──────────────┐                │
        │                        │   Execute    │                │
        │                        │ Installation │                │
        │                        └──────┬───────┘                │
        │                               │                        │
        │                               ▼                        │
        │                        ┌──────────────┐                │
        │                        │   Validate   │                │
        │                        │ Installation │                │
        │                        └──────┬───────┘                │
        │                               │                        │
        │                               ▼                        │
        │                        ┌──────────────┐                │
        └───────────────────────▶│ Return Exit  │◀───────────────┘
                                 │     Code     │
                                 └──────┬───────┘
                                        │
                                        ▼
                                 ┌──────────────┐
                                 │   Update     │
                                 │   Logs &     │
                                 │   Report     │
                                 └──────────────┘
```

---

## 🎯 Detection Methods Flow

```
Detection Method Selection
           │
           ▼
    ┌──────────────┐
    │   REGISTRY   │───▶ Test-Path "HKLM:\SOFTWARE\App"
    └──────────────┘         │
           │                 ├─ Key Exists?
           │                 ├─ Value Exists?
           │                 └─ Version Check?
           │
    ┌──────────────┐
    │     FILE     │───▶ Test-Path "C:\Program Files\App\app.exe"
    └──────────────┘         │
           │                 ├─ File Exists?
           │                 └─ Version Check?
           │
    ┌──────────────┐
    │     APPX     │───▶ Get-AppxPackage -Name "AppName"
    └──────────────┘         │
           │                 ├─ Package Found?
           │                 └─ Version Check?
           │
    ┌──────────────┐
    │   PACKAGE    │───▶ Get-Package -Name "AppName"
    └──────────────┘         │
           │                 ├─ Package Found?
           │                 └─ Version Check?
           │
    ┌──────────────┐
    │    CUSTOM    │───▶ Execute Custom ScriptBlock
    └──────────────┘         │
           │                 └─ Return $true/$false
           │
    ┌──────────────┐
    │     NONE     │───▶ Always return $false (Force Install)
    └──────────────┘
```

---

## 📊 Exit Code Flow

```
Installation Process
        │
        ▼
┌───────────────────────┐
│   Already Installed?  │───YES──▶ EXIT 10 ✓ (Success - No Action)
└───────────┬───────────┘
            │ NO
            ▼
┌───────────────────────┐
│  Installer Found?     │───NO───▶ EXIT 2 ✗ (File Not Found)
└───────────┬───────────┘
            │ YES
            ▼
┌───────────────────────┐
│  Detection Valid?     │───NO───▶ EXIT 3 ✗ (Detection Failed)
└───────────┬───────────┘
            │ YES
            ▼
┌───────────────────────┐
│  Installation OK?     │───NO───▶ EXIT 4 ✗ (Install Failed)
└───────────┬───────────┘
            │ YES
            ▼
┌───────────────────────┐
│  Validation OK?       │───NO───▶ EXIT 5 ✗ (Validation Failed)
└───────────┬───────────┘
            │ YES
            ▼
       EXIT 0 ✓ (Success)
```

---

## 🔄 Integration with Orchestration

```
Orchestration-Master.ps1 Execution Flow
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Phase 1: Critical Infrastructure
├─ Windows Updates
├─ Drivers
└─ .NET Framework

Phase 2: Security
├─ BitLocker
├─ Firewall
└─ Antivirus

Phase 3: Network
├─ VPN
├─ Wi-Fi Profiles
└─ Proxy Settings

Phase 4: Applications ◄─── UNIVERSAL INSTALLER USED HERE
├─ APP-010: Install 7-Zip
│   └─ Invoke Universal-AppInstaller.ps1
│       Parameters: AppName="7-Zip", Installer="7z2408-x64.msi"...
│       Exit Code: 0 or 10 → Continue
│       Exit Code: 1-5 → Retry or Fail
│
├─ APP-020: Install Notepad++
│   └─ Invoke Universal-AppInstaller.ps1
│       Parameters: AppName="Notepad++", Installer="npp.exe"...
│
├─ APP-030: Install Adobe Reader
│   └─ Invoke Universal-AppInstaller.ps1
│
├─ APP-040: Install VLC
│   └─ Invoke Universal-AppInstaller.ps1
│
├─ APP-050: Install PuTTY
│   └─ Invoke Universal-AppInstaller.ps1
│
└─ ... (more applications)

Phase 5: System Configuration
├─ Power Settings
├─ Regional Settings
└─ Time Zone

Phase 6: User Experience
├─ Desktop Icons
├─ Start Menu
└─ Taskbar

Phase 7: Validation
├─ Verify Apps Installed
├─ Test Configurations
└─ Generate Report
```

---

## 📁 File System Layout

```
C:\
├─ Deploy\
│  ├─ Orchestration-Master.ps1
│  ├─ Orchestration-Config.ps1
│  │
│  ├─ Scripts\
│  │  ├─ Universal-AppInstaller.ps1 ◄─── NEW SCRIPT
│  │  ├─ Phase1-Critical\
│  │  │  ├─ WindowsUpdate.ps1
│  │  │  └─ Install-Drivers.ps1
│  │  ├─ Phase2-Security\
│  │  │  ├─ Configure-BitLocker.ps1
│  │  │  └─ Configure-Firewall.ps1
│  │  └─ ...
│  │
│  └─ Installers\
│     └─ Apps\ ◄─── NEW FOLDER
│        ├─ 7z2408-x64.msi
│        ├─ npp.8.6.9.Installer.x64.exe
│        ├─ AcroRdrDC2400221005_en_US.exe
│        ├─ vlc-3.0.21-win64.exe
│        ├─ putty-64bit-0.81-installer.msi
│        └─ ... (more installers)
│
└─ ProgramData\
   └─ OrchestrationLogs\
      ├─ Orchestration_COMPUTER_20241208-143022.log
      ├─ Checkpoint.xml
      │
      └─ Apps\ ◄─── NEW FOLDER
         ├─ Install-7-Zip_20241208-143025.log
         ├─ Install-Notepad++_20241208-143030.log
         ├─ Install-AdobeReader_20241208-143035.log
         ├─ Install-VLC_20241208-143040.log
         └─ ... (per-app logs)
```

---

## 🎭 Example: 7-Zip Installation Flow

```
[Configuration]
TaskID: APP-010
AppName: 7-Zip
Installer: 7z2408-x64.msi
Type: MSI
Args: /quiet /norestart
Detection: Registry
Path: HKLM:\SOFTWARE\7-Zip
         │
         ▼
[Orchestration Invokes]
.\Universal-AppInstaller.ps1 -AppName "7-Zip" ...
         │
         ▼
[Detection Check]
Test-Path "HKLM:\SOFTWARE\7-Zip"
Result: NOT FOUND
         │
         ▼
[Find Installer]
Searching:
  ✗ .\Installers\Apps\7z2408-x64.msi
  ✓ C:\Deploy\Apps\7z2408-x64.msi (FOUND)
         │
         ▼
[Installation]
msiexec /i "C:\Deploy\Apps\7z2408-x64.msi" /quiet /norestart
Process Exit Code: 0 (Success)
         │
         ▼
[Validation]
Test-Path "HKLM:\SOFTWARE\7-Zip"
Result: FOUND ✓
         │
         ▼
[Logging]
C:\ProgramData\OrchestrationLogs\Apps\Install-7-Zip_20241208-143025.log
[2024-12-08 14:30:25] [INFO] Starting installation of 7-Zip
[2024-12-08 14:30:26] [INFO] Application not currently installed
[2024-12-08 14:30:27] [SUCCESS] Installer found
[2024-12-08 14:30:35] [SUCCESS] Installation completed
[2024-12-08 14:30:36] [SUCCESS] Validation successful
[2024-12-08 14:30:36] [SUCCESS] Exit Code: 0
         │
         ▼
[Return to Orchestration]
Exit Code: 0
Orchestration logs: "APP-010: Install 7-Zip - SUCCESS"
Continue to next task (APP-020)
```

---

## 🔀 Decision Tree

```
                    ┌─────────────────────────┐
                    │  Need to Install App?   │
                    └────────┬────────────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
          ┌──────▼──────┐         ┌─────▼──────┐
          │   Simple    │         │  Complex   │
          │   Install?  │         │  Install?  │
          └──────┬──────┘         └─────┬──────┘
                 │                      │
        ┌────────┴────────┐             │
        │                 │             │
   ┌────▼────┐       ┌────▼────┐   ┌───▼────┐
   │ Standard│       │ Version │   │ Custom │
   │ Silent  │       │ Check   │   │ Script │
   │ Switches│       │ Needed? │   │ Needed │
   └────┬────┘       └────┬────┘   └───┬────┘
        │                 │             │
        │            ┌────┴────┐        │
        │            │ Registry│        │
        │            │  File   │        │
        │            │  AppX   │        │
        │            │ Package │        │
        │            └────┬────┘        │
        │                 │             │
        └─────────┬───────┘             │
                  │                     │
         ┌────────▼────────┐            │
         │   UNIVERSAL     │            │
         │   INSTALLER     │            │
         └─────────────────┘            │
                                        │
                              ┌─────────▼─────────┐
                              │  CUSTOM SCRIPT    │
                              │  (Office, SQL,    │
                              │   Chrome, etc.)   │
                              └───────────────────┘
```

---

## 📋 Summary: When to Use What

```
┌──────────────────────────────────────────────────────────────────┐
│                    DECISION MATRIX                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Universal Installer                    Custom Script            │
│  ═══════════════════                    ═══════════              │
│                                                                   │
│  ✓ Standard MSI/EXE                     ✓ Microsoft Office      │
│  ✓ Silent install switches work         ✓ SQL Server            │
│  ✓ Simple file/registry detection       ✓ Adobe Creative Cloud  │
│  ✓ No complex pre/post config           ✓ Enterprise browsers   │
│  ✓ Standalone operation                 ✓ Complex policies      │
│  ✓ 80% of apps                           ✓ Multi-step installs  │
│                                          ✓ 20% of apps           │
│  Examples:                               Examples:               │
│  • 7-Zip                                 • MS Office 365         │
│  • Notepad++                             • Chrome + policies     │
│  • VLC                                   • Firefox + policies    │
│  • Adobe Reader                          • BitLocker config      │
│  • PuTTY                                 • SQL Server            │
│  • Git                                   • LOB applications      │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🎬 Complete Deployment Timeline

```
Day 0: Preparation
├─ Download application installers
├─ Test silent install switches
└─ Verify detection methods work

Day 1: Implementation
├─ Copy Universal-AppInstaller.ps1 to Scripts\
├─ Copy installers to Installers\Apps\
├─ Update Orchestration-Config.ps1
└─ Add first 5 applications

Day 2: Testing
├─ Test installers manually
├─ Test Universal Installer directly
├─ Test with orchestration dry run
└─ Test Phase 4 execution

Day 3: Expansion
├─ Add remaining applications
├─ Optimize detection methods
├─ Fine-tune timeouts
└─ Document special requirements

Day 4: Pilot
├─ Deploy to pilot group (10 machines)
├─ Monitor logs and results
├─ Fix any issues discovered
└─ Gather feedback

Day 5: Production Rollout
├─ Deploy to Ring 1 (50 machines)
├─ Monitor and validate
├─ Deploy to Ring 2 (500 machines)
├─ Monitor and validate
└─ Deploy to remaining machines

Ongoing: Maintenance
├─ Update installer versions
├─ Add new applications
├─ Review logs for issues
└─ Optimize as needed
```

---

**This architecture provides:**
- ✅ Clear separation of concerns
- ✅ Modular design
- ✅ Easy to maintain
- ✅ Comprehensive logging
- ✅ Reliable error handling
- ✅ Scalable to 3000+ devices

---

**End of Architecture Guide**
