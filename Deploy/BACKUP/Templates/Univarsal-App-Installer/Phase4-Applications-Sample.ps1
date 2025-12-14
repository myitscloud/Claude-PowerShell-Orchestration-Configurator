#==============================================================================
# PHASE 4: APPLICATIONS - SAMPLE CONFIGURATION
# Universal App Installer Examples
#==============================================================================
# This file demonstrates how to configure 20+ common applications using the
# Universal App Installer template. Copy these examples into your main
# Orchestration-Config.ps1 file under $Phase4_Applications.
#==============================================================================

$Phase4_Applications = @{
    Enabled = $true
    PhaseName = "Application Installation"
    PhaseDescription = "Install standard enterprise applications"
    StopOnPhaseFailure = $false   # Continue even if some apps fail
    Tasks = @(
        
        #----------------------------------------------------------------------
        # COMPRESSION & ARCHIVE UTILITIES
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-010"
            TaskName = "Install 7-Zip"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs 7-Zip file compression utility"
            Parameters = @{
                AppName = "7-Zip"
                InstallerFileName = "7z2408-x64.msi"
                InstallerType = "MSI"
                InstallArguments = "/quiet /norestart"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\7-Zip"
                DetectionValue = "Path"
            }
        },
        
        @{
            TaskID = "APP-011"
            TaskName = "Install WinRAR"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Disabled - alternative to 7-Zip
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs WinRAR archive manager"
            Parameters = @{
                AppName = "WinRAR"
                InstallerFileName = "winrar-x64-700.exe"
                InstallerType = "EXE"
                InstallArguments = "/S"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\WinRAR"
                DetectionValue = "exe64"
            }
        },
        
        #----------------------------------------------------------------------
        # TEXT EDITORS & DEVELOPMENT TOOLS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-020"
            TaskName = "Install Notepad++"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Notepad++ advanced text editor"
            Parameters = @{
                AppName = "Notepad++"
                InstallerFileName = "npp.8.6.9.Installer.x64.exe"
                InstallerType = "EXE"
                InstallArguments = "/S"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Notepad++\notepad++.exe"
                RequiredVersion = "8.6.9"
            }
        },
        
        @{
            TaskID = "APP-021"
            TaskName = "Install Visual Studio Code"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Visual Studio Code editor"
            Parameters = @{
                AppName = "Visual Studio Code"
                InstallerFileName = "VSCodeSetup-x64-1.95.3.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Microsoft VS Code\Code.exe"
            }
        },
        
        @{
            TaskID = "APP-022"
            TaskName = "Install Sublime Text"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Optional alternative editor
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Sublime Text editor"
            Parameters = @{
                AppName = "Sublime Text"
                InstallerFileName = "sublime_text_build_4169_x64_setup.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Sublime Text\sublime_text.exe"
            }
        },
        
        #----------------------------------------------------------------------
        # PDF READERS & DOCUMENT VIEWERS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-030"
            TaskName = "Install Adobe Acrobat Reader"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Adobe Acrobat Reader DC"
            Parameters = @{
                AppName = "Adobe Acrobat Reader DC"
                InstallerFileName = "AcroRdrDC2400221005_en_US.exe"
                InstallerType = "EXE"
                InstallArguments = "/sAll /rs /msi EULA_ACCEPT=YES"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader\DC\Installer"
                DetectionValue = "Path"
            }
        },
        
        @{
            TaskID = "APP-031"
            TaskName = "Install Foxit PDF Reader"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Alternative to Adobe Reader
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Foxit PDF Reader"
            Parameters = @{
                AppName = "Foxit PDF Reader"
                InstallerFileName = "FoxitPDFReader1240_L10N_Setup.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files (x86)\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe"
            }
        },
        
        #----------------------------------------------------------------------
        # MEDIA PLAYERS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-040"
            TaskName = "Install VLC Media Player"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs VLC Media Player"
            Parameters = @{
                AppName = "VLC Media Player"
                InstallerFileName = "vlc-3.0.21-win64.exe"
                InstallerType = "EXE"
                InstallArguments = "/L=1033 /S"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\VideoLAN\VLC\vlc.exe"
                RequiredVersion = "3.0.21"
            }
        },
        
        @{
            TaskID = "APP-041"
            TaskName = "Install K-Lite Codec Pack"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Optional - only if needed
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs K-Lite Codec Pack for media playback"
            Parameters = @{
                AppName = "K-Lite Codec Pack"
                InstallerFileName = "K-Lite_Codec_Pack_1795_Standard.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\KLCodecPack"
            }
        },
        
        #----------------------------------------------------------------------
        # NETWORK & REMOTE ACCESS TOOLS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-050"
            TaskName = "Install PuTTY"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs PuTTY SSH/Telnet client"
            Parameters = @{
                AppName = "PuTTY"
                InstallerFileName = "putty-64bit-0.81-installer.msi"
                InstallerType = "MSI"
                InstallArguments = "/quiet /norestart"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\PuTTY\putty.exe"
            }
        },
        
        @{
            TaskID = "APP-051"
            TaskName = "Install WinSCP"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs WinSCP FTP/SFTP client"
            Parameters = @{
                AppName = "WinSCP"
                InstallerFileName = "WinSCP-6.3.5-Setup.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
                DetectionMethod = "Package"
                DetectionPath = "WinSCP*"
            }
        },
        
        @{
            TaskID = "APP-052"
            TaskName = "Install FileZilla"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs FileZilla FTP client"
            Parameters = @{
                AppName = "FileZilla Client"
                InstallerFileName = "FileZilla_3.67.1_win64-setup.exe"
                InstallerType = "EXE"
                InstallArguments = "/S"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\FileZilla Client"
                DetectionValue = "Version"
            }
        },
        
        #----------------------------------------------------------------------
        # VERSION CONTROL & GIT TOOLS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-060"
            TaskName = "Install Git for Windows"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Git version control system"
            Parameters = @{
                AppName = "Git for Windows"
                InstallerFileName = "Git-2.47.0-64-bit.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /COMPONENTS=`"icons,ext\reg\shellhere,assoc,assoc_sh`""
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Git\bin\git.exe"
            }
        },
        
        @{
            TaskID = "APP-061"
            TaskName = "Install TortoiseGit"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Optional Git GUI
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs TortoiseGit GUI client"
            Parameters = @{
                AppName = "TortoiseGit"
                InstallerFileName = "TortoiseGit-2.15.0.0-64bit.msi"
                InstallerType = "MSI"
                InstallArguments = "/quiet /norestart"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\TortoiseGit"
            }
        },
        
        #----------------------------------------------------------------------
        # IMAGE EDITORS & GRAPHICS TOOLS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-070"
            TaskName = "Install Paint.NET"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Paint.NET image editor"
            Parameters = @{
                AppName = "Paint.NET"
                InstallerFileName = "paint.net.5.0.13.install.x64.exe"
                InstallerType = "EXE"
                InstallArguments = "/auto"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\paint.net\PaintDotNet.exe"
            }
        },
        
        @{
            TaskID = "APP-071"
            TaskName = "Install IrfanView"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs IrfanView image viewer"
            Parameters = @{
                AppName = "IrfanView"
                InstallerFileName = "iview464_x64_setup.exe"
                InstallerType = "EXE"
                InstallArguments = "/silent /desktop=0 /thumbs=0 /group=1 /allusers=1 /assoc=0"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\IrfanView\i_view64.exe"
            }
        },
        
        #----------------------------------------------------------------------
        # SYSTEM UTILITIES
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-080"
            TaskName = "Install TreeSize Free"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs TreeSize disk space analyzer"
            Parameters = @{
                AppName = "TreeSize Free"
                InstallerFileName = "TreeSizeFree-Portable.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\JAM Software\TreeSize Free\TreeSizeFree.exe"
            }
        },
        
        @{
            TaskID = "APP-081"
            TaskName = "Install CCleaner"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Use with caution in enterprise
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs CCleaner system cleaner"
            Parameters = @{
                AppName = "CCleaner"
                InstallerFileName = "ccsetup619.exe"
                InstallerType = "EXE"
                InstallArguments = "/S"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\Piriform\CCleaner"
            }
        },
        
        #----------------------------------------------------------------------
        # BROWSERS (Basic Installation)
        #----------------------------------------------------------------------
        # Note: For enterprise browser deployments with policies,
        # use custom scripts instead of Universal Installer
        
        @{
            TaskID = "APP-090"
            TaskName = "Install Mozilla Firefox"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Mozilla Firefox (basic installation)"
            Parameters = @{
                AppName = "Mozilla Firefox"
                InstallerFileName = "Firefox Setup 128.0.exe"
                InstallerType = "EXE"
                InstallArguments = "/S /MaintenanceService=false"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox"
            }
        },
        
        #----------------------------------------------------------------------
        # COMMUNICATION TOOLS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-100"
            TaskName = "Install Zoom Client"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Zoom video conferencing client"
            Parameters = @{
                AppName = "Zoom Client"
                InstallerFileName = "ZoomInstallerFull.msi"
                InstallerType = "MSI"
                InstallArguments = "/quiet /norestart ZoomAutoUpdate=true"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\Zoom\Zoom Meeting"
            }
        },
        
        #----------------------------------------------------------------------
        # JAVA RUNTIME (if needed)
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-110"
            TaskName = "Install Java JRE"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Only enable if Java apps are used
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Java Runtime Environment"
            Parameters = @{
                AppName = "Java Runtime Environment"
                InstallerFileName = "jre-8u411-windows-x64.exe"
                InstallerType = "EXE"
                InstallArguments = "/s INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_ANALYTICS=0"
                DetectionMethod = "Registry"
                DetectionPath = "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment"
            }
        },
        
        #----------------------------------------------------------------------
        # OFFICE ALTERNATIVES (LibreOffice)
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-120"
            TaskName = "Install LibreOffice"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Only if not using Microsoft Office
            Timeout = 1200
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs LibreOffice office suite"
            Parameters = @{
                AppName = "LibreOffice"
                InstallerFileName = "LibreOffice_24.8.3_Win_x86-64.msi"
                InstallerType = "MSI"
                InstallArguments = "/quiet /norestart REGISTER_ALL_MSO_TYPES=0 ISCHECKFORPRODUCTUPDATES=0"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\LibreOffice\program\soffice.exe"
            }
        },
        
        #----------------------------------------------------------------------
        # PYTHON RUNTIME (if needed for development)
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-130"
            TaskName = "Install Python"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $false  # Only enable for development workstations
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Python programming language"
            Parameters = @{
                AppName = "Python"
                InstallerFileName = "python-3.12.7-amd64.exe"
                InstallerType = "EXE"
                InstallArguments = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Python312\python.exe"
            }
        },
        
        #----------------------------------------------------------------------
        # TERMINAL EMULATORS
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-140"
            TaskName = "Install Windows Terminal"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Windows Terminal"
            Parameters = @{
                AppName = "Windows Terminal"
                InstallerFileName = "Microsoft.WindowsTerminal.msixbundle"
                InstallerType = "MSIX"
                InstallArguments = ""
                DetectionMethod = "AppX"
                DetectionPath = "Microsoft.WindowsTerminal"
            }
        },
        
        #----------------------------------------------------------------------
        # SCREEN CAPTURE & RECORDING
        #----------------------------------------------------------------------
        
        @{
            TaskID = "APP-150"
            TaskName = "Install Greenshot"
            ScriptPath = "Scripts\Universal-AppInstaller.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Greenshot screenshot tool"
            Parameters = @{
                AppName = "Greenshot"
                InstallerFileName = "Greenshot-INSTALLER-1.3.274.exe"
                InstallerType = "EXE"
                InstallArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
                DetectionMethod = "File"
                DetectionPath = "C:\Program Files\Greenshot\Greenshot.exe"
            }
        }
        
        #----------------------------------------------------------------------
        # ADD MORE APPLICATIONS AS NEEDED
        #----------------------------------------------------------------------
        # Simply copy one of the examples above and modify:
        # - TaskID (increment number)
        # - TaskName
        # - InstallerFileName
        # - InstallArguments
        # - DetectionMethod and DetectionPath
        #----------------------------------------------------------------------
        
    )
}

#==============================================================================
# NOTES:
#==============================================================================
# 1. Enable/disable individual apps by changing "Enabled = $true/$false"
# 2. Adjust timeouts based on app size and network speed
# 3. Test installers manually first to verify silent switches work
# 4. Some apps may require custom scripts if they need special configuration
# 5. Review detection methods - choose the most reliable for each app
#
# INSTALLATION ORDER:
# - Apps install in the order listed above
# - Independent apps can be reordered without issues
# - Apps with dependencies should be ordered accordingly
#
# MAINTENANCE:
# - Update InstallerFileName when new versions are available
# - Update RequiredVersion if minimum version enforcement needed
# - Review logs in C:\ProgramData\OrchestrationLogs\Apps\
#==============================================================================

# Return the configuration
return $Phase4_Applications
