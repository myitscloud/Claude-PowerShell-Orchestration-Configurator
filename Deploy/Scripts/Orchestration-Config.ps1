#==============================================================================
# ENTERPRISE DESKTOP/LAPTOP ORCHESTRATION - CONFIGURATION FILE
# Version: 1.0
# Purpose: Configuration settings for post-imaging Windows 11 deployment
# Devices: 3000+ Windows 11 Professional/Enterprise workstations
#==============================================================================

#region GLOBAL SETTINGS
#==============================================================================

# Orchestration Behavior
$OrchestrationConfig = @{
    OrchestrationName = "Windows11-Enterprise-Deployment"
    Version = "1.0.0"
    ExecutionMode = "Sequential"  # Sequential or Parallel (Parallel not yet implemented)
    EnableCheckpoints = $true     # Save state between task executions
    EnableRetry = $true           # Retry failed tasks
    MaxRetryAttempts = 3          # Maximum retry attempts per task
    RetryDelaySeconds = 15        # Delay between retry attempts (optimized for post-imaging)
    ContinueOnError = $true      # Continue to next task even if current fails
    RequireAdminRights = $true    # Require script to run as administrator
    EnableDryRun = $false         # Simulate execution without making changes
}

# Logging Configuration
$LoggingConfig = @{
    EnableLogging = $true
    LogPath = "C:\ProgramData\OrchestrationLogs"
    LogFileName = "Orchestration_{ComputerName}_{DateTime}.log"
    MaxLogSizeMB = 50
    LogRetentionDays = 90
    EnableTranscript = $true
    TranscriptPath = "C:\ProgramData\OrchestrationLogs\Transcripts"
    LogLevel = "Verbose"  # Options: Minimal, Standard, Verbose, Debug
    EnableEventLog = $true
    EventLogSource = "DesktopOrchestration"
}

# SCCM Integration Settings
$SCCMConfig = @{
    UseSCCM = $false                      # Enable/disable SCCM integration
    SCCMReportingLevel = "TaskLevel"      # Options: None, PhaseLevel, TaskLevel, Detailed
    SCCMStatusMessageID = 11000           # Custom status message ID base
    UpdateHardwareInventory = $true       # Trigger hardware inventory after completion
    UpdateSoftwareInventory = $true       # Trigger software inventory after completion
    SCCMClientCheckTimeout = 30           # Seconds to wait for SCCM client verification
    WriteToSCCMRegistry = $true           # Write status to registry for SCCM monitoring
    SCCMRegistryPath = "HKLM:\SOFTWARE\Company\Orchestration"
}

# Device Detection & Profiling
$DeviceConfig = @{
    AutoDetectDeviceType = $true          # Automatically detect Desktop vs Laptop
    DeviceTypeOverride = ""               # Manual override: Desktop, Laptop, VIP, Kiosk
    AutoDetectOSEdition = $true           # Detect Professional vs Enterprise
    RequireWindows11 = $true              # Fail if not Windows 11
    MinimumOSBuild = 22000                # Minimum Windows build number
    CheckDomainJoinStatus = $true         # Verify domain join status
    RequireDomainJoin = $false            # Fail if not domain joined (set false for standalone)
    CheckTPMStatus = $true                # Verify TPM availability for BitLocker
    CheckSecureBootStatus = $true         # Verify Secure Boot is enabled
}

# Network & Connectivity
$NetworkConfig = @{
    RequireNetworkConnectivity = $false   # Fail if no network available
    TestInternetConnectivity = $true      # Test internet access
    InternetTestURL = "https://www.msft.com"
    NetworkTimeoutSeconds = 10
    RequireActiveDirectory = $false       # Require AD connectivity
    PreferredDNSServers = @("1.1.1.1", "8.8.8.8")  # Optional: Set DNS servers
}

# Source Paths & Content Locations
$SourceConfig = @{
    PrimarySourcePath = "\\FileServer\Deployment\Scripts"      # Network share
    SecondarySourcePath = "C:\Deploy\Scripts"                  # Local cache
    TertiarySourcePath = "D:\Scripts"                          # USB/External drive
    ApplicationSourcePath = "\\FileServer\Deployment\Apps"     # Application installers
    UpdateSourcePath = "\\FileServer\Deployment\Updates"       # Windows updates/patches
    DriverSourcePath = "\\FileServer\Deployment\Drivers"       # Device drivers
    CopyToLocalCache = $true                                   # Copy scripts locally before execution
    LocalCachePath = "C:\Windows\Temp\OrchestrationCache"
}

# Notification & Reporting
$NotificationConfig = @{
    EnableUserNotification = $true        # Show notifications to logged-in user
    NotificationTitle = "System Configuration in Progress"
    NotificationMessage = "Please do not shut down your computer. This process may take 30-60 minutes."
    ShowProgressToUser = $true            # Display progress window
    EnableEmailReporting = $false         # Send email report on completion
    EmailTo = "it-team@company.com"
    EmailFrom = "orchestration@company.com"
    SMTPServer = "smtp.company.com"
}

#endregion

#region PHASE 1: CRITICAL INFRASTRUCTURE
#==============================================================================
# Tasks that must complete first - OS updates, drivers, prerequisites
#==============================================================================

$Phase1_Critical = @{
    Enabled = $true
    PhaseName = "Critical Infrastructure"
    PhaseDescription = "Windows Updates, Drivers, and Core Prerequisites"
    StopOnPhaseFailure = $true           # Stop orchestration if this phase fails
    Tasks = @(
        @{
            TaskID = "CRIT-001"
            TaskName = "Pre-Flight Validation"
            ScriptPath = "Phase1-Critical\PreFlight-Validation.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Validates device meets minimum requirements"
            Parameters = @{}
        },
        @{
            TaskID = "CRIT-002"
            TaskName = "Windows Update - Critical"
            ScriptPath = "Phase1-Critical\WindowsUpdate-Critical.ps1"
            Enabled = $true
            Timeout = 3600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Installs critical Windows updates and security patches"
            Parameters = @{
                UpdateCategories = "Critical,Security"
                AutoReboot = $false
            }
        },
        @{
            TaskID = "CRIT-003"
            TaskName = "Hardware Drivers"
            ScriptPath = "Phase1-Critical\Install-Drivers.ps1"
            Enabled = $true
            Timeout = 1800
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Installs manufacturer and hardware-specific drivers"
            Parameters = @{
                DriverSource = $SourceConfig.DriverSourcePath
                AutoDetectHardware = $true
            }
        },
        @{
            TaskID = "CRIT-004"
            TaskName = "Install .NET Framework"
            ScriptPath = "Phase1-Critical\Install-DotNetFramework.ps1"
            Enabled = $false
            Timeout = 1200
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Installs required .NET Framework versions"
            Parameters = @{
                Versions = ".NET 4.8,.NET 6.0,.NET 8.0"
            }
        },
        @{
            TaskID = "CRIT-005"
            TaskName = "Windows Update - All Updates"
            ScriptPath = "Phase1-Critical\WindowsUpdate-All.ps1"
            Enabled = $true
            Timeout = 5400
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs all available Windows updates"
            Parameters = @{
                UpdateCategories = "All"
                MaxUpdateRounds = 3
            }
        }
    )
}

#endregion

#region PHASE 2: SECURITY CONFIGURATION
#==============================================================================
# Security hardening, BitLocker, firewall, antivirus
#==============================================================================

$Phase2_Security = @{
    Enabled = $true
    PhaseName = "Security Configuration"
    PhaseDescription = "Security hardening, encryption, and protection"
    StopOnPhaseFailure = $true
    Tasks = @(
        @{
            TaskID = "SEC-001"
            TaskName = "Configure Windows Firewall"
            ScriptPath = "Phase2-Security\Configure-Firewall.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Configures Windows Firewall rules and policies"
            Parameters = @{
                EnableFirewall = $true
                BlockInbound = $true
                AllowOutbound = $true
                ImportRules = $false
                # RulesPath = "Deploy\Config\FirewallRules.xml"
            }
        },
        @{
            TaskID = "SEC-004"
            TaskName = "Disable Insecure Features and Protocols"
            ScriptPath = "Phase2-Security\Disable-Insecure-Features-Protocols.ps1"
            Enabled = $true
            Timeout = 1200
            RunAs = "SYSTEM"
            RequiresReboot = $false  # SMBv1 and IPv6 require reboot
            AllowRetry = $true
            Critical = $true
            Description = "Disables insecure protocols and features (SMBv1, LLMNR, NetBIOS, etc.)"
            Parameters = @{
                DisableSMBv1 = $true
                DisableLLMNR = $true
                DisableNetBIOS = $true
                DisableIPv6 = $true
                SecureRDP = $true           # Harden RDP, don't disable
                DisableRDP = $false          # Keep RDP enabled
                DisablePrintSpooler = $false # Keep printing working
                DisableBluetooth = $false    # Keep for laptops
            }
        },
        @{
            TaskID = "SEC-002"
            TaskName = "Enable BitLocker"
            ScriptPath = "Phase2-Security\Enable-BitLocker.ps1"
            Enabled = $true
            Timeout = 1800
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Enables BitLocker drive encryption with TPM"
            Parameters = @{
                EncryptionMethod = "XtsAes256"
                SaveKeyToAD = $true
                EncryptUsedSpaceOnly = $false
                SkipHardwareTest = $false
                RequireTPM = $true
            }
        },
        @{
            TaskID = "SEC-003"
            TaskName = "Configure Windows Defender"
            ScriptPath = "Phase2-Security\Configure-WindowsDefender.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Configures Windows Defender antivirus settings"
            Parameters = @{
                EnableRealTimeProtection = $true
                EnableCloudProtection = $true
                EnableSampleSubmission = $true
                UpdateDefinitions = $true
            }
        },
        @{
            TaskID = "SEC-004"
            TaskName = "Security Baseline Configuration"
            ScriptPath = "Phase2-Security\Apply-SecurityBaseline.ps1"
            Enabled = $true
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Applies enterprise security baseline settings"
            Parameters = @{
                BaselineProfile = "Enterprise-HighSecurity"
                ApplyPasswordPolicy = $true
                ApplyAuditPolicy = $true
                DisableUnusedServices = $true
            }
        },
        @{
            TaskID = "SEC-005"
            TaskName = "Configure User Account Control"
            ScriptPath = "Phase2-Security\Configure-UAC.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures UAC elevation settings"
            Parameters = @{
                UACLevel = "AlwaysNotify"
                PromptOnSecureDesktop = $true
            }
        }
    )
}

#endregion

#region PHASE 3: NETWORKING & CONNECTIVITY
#==============================================================================
# Network settings, VPN, wireless, proxy configuration
#==============================================================================

$Phase3_Network = @{
    Enabled = $true
    PhaseName = "Network Configuration"
    PhaseDescription = "Network settings, VPN, and connectivity"
    StopOnPhaseFailure = $false
    Tasks = @(
        @{
            TaskID = "NET-001"
            TaskName = "Configure Network Adapters"
            ScriptPath = "Phase3-Network\Configure-NetworkAdapters.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures network adapter settings and priorities"
            Parameters = @{
                DisableIPv6 = $false
                SetDNSServers = $true
                DNSServers = $NetworkConfig.PreferredDNSServers
                DisableNetBIOS = $false
            }
        },
        @{
            TaskID = "NET-002"
            TaskName = "Install VPN Client"
            ScriptPath = "Phase3-Network\Install-VPNClient.ps1"
            Enabled = $false
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs and configures corporate VPN client"
            Parameters = @{
                VPNClientPath = "\\FileServer\Deployment\Apps\VPN\VPNSetup.exe"
                VPNProfile = "Corporate-VPN"
                AutoConnect = $false
            }
        },
        @{
            TaskID = "NET-003"
            TaskName = "Configure Wireless Networks"
            ScriptPath = "Phase3-Network\Configure-WiFi.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures corporate wireless network profiles"
            Parameters = @{
                WiFiProfilesPath = "Config\WiFiProfiles"
                AutoConnect = $true
            }
        },
        @{
            TaskID = "NET-004"
            TaskName = "Configure Proxy Settings"
            ScriptPath = "Phase3-Network\Configure-Proxy.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures proxy server settings"
            Parameters = @{
                ProxyServer = "proxy.company.com:8080"
                ProxyBypass = "*.company.com;localhost"
                AutoDetect = $false
            }
        }
    )
}

#endregion

#region PHASE 4: APPLICATION DEPLOYMENT
#==============================================================================
# Install enterprise applications and software
#==============================================================================

$Phase4_Applications = @{
    Enabled = $true
    PhaseName = "Application Deployment"
    PhaseDescription = "Install enterprise applications and software"
    StopOnPhaseFailure = $false
    Tasks = @(
        @{
            TaskID = "APP-001"
            TaskName = "Install Microsoft Office"
            ScriptPath = "Phase4-Applications\Install-Office.ps1"
            Enabled = $false
            Timeout = 2400
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Installs Microsoft Office suite"
            Parameters = @{
                OfficeVersion = "Microsoft365"
                Architecture = "64bit"
                ConfigurationXML = "Config\Office-Configuration.xml"
                RemovePreviousVersions = $true
            }
        },
        @{
            TaskID = "APP-002"
            TaskName = "Install Adobe Acrobat Reader"
            ScriptPath = "Phase4-Applications\Install-AdobeReader.ps1"
            Enabled = $false
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Adobe Acrobat Reader DC"
            Parameters = @{
                DisableAutoUpdates = $false
                SetAsDefault = $true
            }
        },
        @{
            TaskID = "APP-003"
            TaskName = "Install 7Zip x64 Utility"
            ScriptPath = "Phase4-Applications\Install-7Zip.ps1"
            Enabled = $false  # DISABLED: Script file missing - needs Universal-AppInstaller.ps1
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Install 7Zip x64 Utility"
            Parameters = @{
                DisableAutoUpdates = $false
                SetAsDefault = $true
            }
        },
        @{
            TaskID = "APP-004"
            TaskName = "Install Install-DTRuntimev10"
            ScriptPath = "Phase4-Applications\Install-DTRuntimev10.ps1"
            Enabled = $false  # DISABLED: Script file missing - needs Universal-AppInstaller.ps1
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Install Install-DTRuntimev10"
            Parameters = @{
                DisableAutoUpdates = $false
                SetAsDefault = $true
            }
        },
        @{
            TaskID = "APP-009"
            TaskName = "Install Google Chrome"
            ScriptPath = "Phase4-Applications\Install-Chrome.ps1"
            Enabled = $false
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Google Chrome browser"
            Parameters = @{
                Edition = "Enterprise"
                SetAsDefault = $false
                DeployExtensions = $true
            }
        },
        @{
            TaskID = "APP-005"
            TaskName = "Install Mozilla Firefox"
            ScriptPath = "Phase4-Applications\Install-Firefox.ps1"
            Enabled = $false
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Mozilla Firefox browser"
            Parameters = @{
                Edition = "ESR"
                SetAsDefault = $false
            }
        },
        @{
            TaskID = "APP-006"
            TaskName = "Install 7-Zip"
            ScriptPath = "Phase4-Applications\Install-7Zip.ps1"
            Enabled = $false  # DISABLED: Script file missing - needs Universal-AppInstaller.ps1
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs 7-Zip compression utility"
            Parameters = @{}
        },
        @{
            TaskID = "APP-007"
            TaskName = "Install Microsoft Teams"
            ScriptPath = "Phase4-Applications\Install-Teams.ps1"
            Enabled = $false  # DISABLED: Script file missing - needs Universal-AppInstaller.ps1
            Timeout = 900
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Installs Microsoft Teams client"
            Parameters = @{
                Version = "Teams2.0"
                InstallationType = "PerMachine"
            }
        }
        
    )
}

#endregion

#region PHASE 5: SYSTEM CONFIGURATION
#==============================================================================
# Power settings, regional settings, time zones, system preferences
#==============================================================================

$Phase5_SystemConfig = @{
    Enabled = $true
    PhaseName = "System Configuration"
    PhaseDescription = "Power settings, regional settings, and preferences"
    StopOnPhaseFailure = $false
    Tasks = @(
        @{
            TaskID = "SYS-001"
            TaskName = "Configure Power Settings"
            ScriptPath = "Phase5-System\Configure-PowerSettings.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures power plans based on device type"
            Parameters = @{
                DesktopPowerPlan = "High Performance"
                LaptopPowerPlan = "Balanced"
                DisableHibernation = $false
                DisableSleep = $false
                LidCloseAction = "Sleep"
            }
        },
        @{
            TaskID = "SYS-002"
            TaskName = "Configure Time Zone"
            ScriptPath = "Phase5-System\Configure-TimeZone.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Sets time zone and configures time synchronization"
            Parameters = @{
                TimeZone = "Central Standard Time"
                EnableNTP = $true
                NTPServer = "time.windows.com"
            }
        },
        @{
            TaskID = "SYS-003"
            TaskName = "Configure Regional Settings"
            ScriptPath = "Phase5-System\Configure-Regional.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures regional and language settings"
            Parameters = @{
                SystemLocale = "en-US"
                UserLocale = "en-US"
                KeyboardLayout = "0409:00000409"
            }
        },
        @{
            TaskID = "SYS-004"
            TaskName = "Configure Windows Features"
            ScriptPath = "Phase5-System\Configure-WindowsFeatures.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Enables/disables Windows optional features"
            Parameters = @{
                EnableFeatures = @("NetFx3", "Printing-XPSServices-Features")
                DisableFeatures = @("WindowsMediaPlayer", "Internet-Explorer-Optional-amd64")
            }
        },
        @{
            TaskID = "SYS-005"
            TaskName = "Configure Windows Explorer"
            ScriptPath = "Phase5-System\Configure-Explorer.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures File Explorer settings and preferences"
            Parameters = @{
                ShowFileExtensions = $true
                ShowHiddenFiles = $false
                OpenToThisPC = $true
                DisableQuickAccess = $false
            }
        },
        @{
            TaskID = "SYS-006"
            TaskName = "Configure Telemetry"
            ScriptPath = "Phase5-System\Configure-Telemetry.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures Windows telemetry and diagnostics"
            Parameters = @{
                TelemetryLevel = "Security"  # Options: Security, Basic, Enhanced, Full
                DisableFeedback = $true
            }
        },
        @{
            TaskID = "SYS-007"
            TaskName = "Disable Consumer Features"
            ScriptPath = "Phase5-System\Disable-ConsumerFeatures.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Disables Windows consumer features and suggestions"
            Parameters = @{
                DisableSuggestedApps = $true
                DisableTips = $true
                DisableAdvertising = $true
            }
        }
    )
}

#endregion

#region PHASE 6: USER EXPERIENCE & CUSTOMIZATION
#==============================================================================
# Desktop shortcuts, Start Menu layout, taskbar, default applications
#==============================================================================

$Phase6_UserExperience = @{
    Enabled = $true
    PhaseName = "User Experience"
    PhaseDescription = "Desktop customization and user experience settings"
    StopOnPhaseFailure = $false
    Tasks = @(
        @{
            TaskID = "UX-001"
            TaskName = "Configure Start Menu Layout"
            ScriptPath = "Phase6-UserExperience\Configure-StartMenu.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures Start Menu layout and pinned items"
            Parameters = @{
                LayoutXML = "Config\StartMenuLayout.xml"
                ApplyToAllUsers = $true
            }
        },
        @{
            TaskID = "UX-002"
            TaskName = "Configure Taskbar"
            ScriptPath = "Phase6-UserExperience\Configure-Taskbar.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Configures taskbar settings and pinned applications"
            Parameters = @{
                TaskbarAlignment = "Left"
                ShowTaskView = $false
                ShowWidgets = $false
                ShowChat = $false
                PinnedApps = @("Edge", "Explorer", "Outlook", "Teams")
            }
        },
        @{
            TaskID = "UX-003"
            TaskName = "Create Desktop Shortcuts"
            ScriptPath = "Phase6-UserExperience\Create-Shortcuts.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Creates desktop shortcuts for common applications"
            Parameters = @{
                PublicDesktop = $true
                Shortcuts = @(
                    @{Name="IT Help Desk"; Target="https://helpdesk.company.com"},
                    @{Name="Company Portal"; Target="https://portal.company.com"}
                )
            }
        },
        @{
            TaskID = "UX-004"
            TaskName = "Set Default Applications"
            ScriptPath = "Phase6-UserExperience\Set-DefaultApps.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Sets default applications for file types and protocols"
            Parameters = @{
                DefaultBrowser = "Edge"
                DefaultPDF = "AcroAdobe Acrobat"
                ConfigXML = "Deploy\Config\DefaultApps.xml"
            }
        },
        @{
            TaskID = "UX-005"
            TaskName = "Configure Desktop Wallpaper"
            ScriptPath = "Phase6-UserExperience\Set-Wallpaper.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Sets corporate desktop wallpaper"
            Parameters = @{
                WallpaperPath = "Deploy\Assets\Wallpaper.jpg"
                LockScreenPath = "Deploy\Assets\LockScreen.jpg"
            }
        }
    )
}

#endregion

#region PHASE 7: COMPLIANCE & VALIDATION
#==============================================================================
# Final compliance checks, validation, and reporting
#==============================================================================

$Phase7_Validation = @{
    Enabled = $true
    PhaseName = "Compliance & Validation"
    PhaseDescription = "Final compliance checks and validation"
    StopOnPhaseFailure = $false
    Tasks = @(
        @{
            TaskID = "VAL-001"
            TaskName = "Security Compliance Check"
            ScriptPath = "Phase7-Validation\Check-SecurityCompliance.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $true
            Description = "Validates security configuration compliance"
            Parameters = @{
                ComplianceProfile = "Enterprise-Security-Baseline"
                GenerateReport = $true
            }
        },
        @{
            TaskID = "VAL-002"
            TaskName = "Application Installation Validation"
            ScriptPath = "Phase7-Validation\Validate-Applications.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Validates all required applications are installed"
            Parameters = @{
                RequiredApps = @("Microsoft Office", "Google Chrome", "Adobe Reader", "Microsoft Teams")
            }
        },
        @{
            TaskID = "VAL-003"
            TaskName = "System Health Check"
            ScriptPath = "Phase7-Validation\Check-SystemHealth.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Performs comprehensive system health check"
            Parameters = @{
                CheckDiskSpace = $true
                CheckServices = $true
                CheckEventLog = $true
                CheckPerformance = $true
            }
        },
        @{
            TaskID = "VAL-004"
            TaskName = "Generate Deployment Report"
            ScriptPath = "Phase7-Validation\Generate-Report.ps1"
            Enabled = $true
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Generates final deployment report"
            Parameters = @{
                ReportPath = "C:\ProgramData\OrchestrationLogs\Reports"
                IncludeInventory = $true
                UploadToShare = $false
                SharePath = "\\FileServer\Deployment\Reports"
            }
        },
        @{
            TaskID = "VAL-005"
            TaskName = "Trigger SCCM Inventory"
            ScriptPath = "Phase7-Validation\Trigger-SCCMInventory.ps1"
            Enabled = $false
            Timeout = 300
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Triggers SCCM hardware and software inventory cycles"
            Parameters = @{
                TriggerHardware = $true
                TriggerSoftware = $true
                WaitForCompletion = $false
            }
        },
        @{
            TaskID = "VAL-006"
            TaskName = "Clean Up Temporary Files"
            ScriptPath = "Phase7-Validation\Cleanup-TempFiles.ps1"
            Enabled = $true
            Timeout = 600
            RunAs = "SYSTEM"
            RequiresReboot = $false
            AllowRetry = $true
            Critical = $false
            Description = "Removes temporary files and cleans up deployment artifacts"
            Parameters = @{
                RemoveLocalCache = $true
                CleanWindowsTemp = $true
                CleanUserTemp = $false
                EmptyRecycleBin = $true
            }
        }
    )
}

#endregion

#region DEVICE TYPE SPECIFIC CONFIGURATIONS
#==============================================================================
# Different configurations based on device type
#==============================================================================

$DeviceTypeProfiles = @{
    Desktop = @{
        ProfileName = "Standard Desktop"
        EnableBitLocker = $true
        PowerPlan = "High Performance"
        DisableWiFi = $false
        InstallVPN = $true
        AllowSleep = $false
        ScreenTimeout = 0
    }
    Laptop = @{
        ProfileName = "Standard Laptop"
        EnableBitLocker = $true
        PowerPlan = "Balanced"
        DisableWiFi = $false
        InstallVPN = $true
        AllowSleep = $true
        ScreenTimeout = 15
    }
    VIP = @{
        ProfileName = "VIP/Executive"
        EnableBitLocker = $true
        PowerPlan = "High Performance"
        DisableWiFi = $false
        InstallVPN = $true
        AllowSleep = $true
        ScreenTimeout = 30
        AdditionalApps = @("Zoom", "WebEx", "Skype")
    }
    Kiosk = @{
        ProfileName = "Kiosk/Public"
        EnableBitLocker = $true
        PowerPlan = "Balanced"
        DisableWiFi = $true
        InstallVPN = $false
        AllowSleep = $false
        ScreenTimeout = 0
        LockdownMode = $true
    }
}

#endregion

#region DEPARTMENT/OU SPECIFIC CONFIGURATIONS
#==============================================================================
# Configurations specific to departments or organizational units
#==============================================================================

$DepartmentProfiles = @{
    IT = @{
        DepartmentName = "Information Technology"
        AdditionalApplications = @("Putty", "WinSCP", "Sysinternals", "PowerShell 7")
        AdminRights = $true
        RemoteDesktopEnabled = $true
    }
    Finance = @{
        DepartmentName = "Finance Department"
        AdditionalApplications = @("QuickBooks", "SAP", "Excel Add-ins")
        AdminRights = $false
        RemoteDesktopEnabled = $false
        ExtraSecurityHardening = $true
    }
    HR = @{
        DepartmentName = "Human Resources"
        AdditionalApplications = @("Workday", "ADP")
        AdminRights = $false
        RemoteDesktopEnabled = $false
        ExtraSecurityHardening = $true
        EncryptionRequired = $true
    }
    Engineering = @{
        DepartmentName = "Engineering"
        AdditionalApplications = @("Visual Studio", "Git", "Docker Desktop", "AutoCAD")
        AdminRights = $true
        RemoteDesktopEnabled = $true
        HighPerformanceRequired = $true
    }
    Sales = @{
        DepartmentName = "Sales Department"
        AdditionalApplications = @("Salesforce", "Zoom", "Teams")
        AdminRights = $false
        RemoteDesktopEnabled = $true
        MobileOptimized = $true
    }
}

#endregion

#region ENVIRONMENT SPECIFIC SETTINGS
#==============================================================================
# Different settings for Dev, Test, Production environments
#==============================================================================

$EnvironmentProfiles = @{
    Development = @{
        EnvironmentName = "Development"
        EnableDebugLogging = $true
        SkipValidation = $false
        AllowTestCertificates = $true
        TestMode = $true
    }
    Testing = @{
        EnvironmentName = "Testing/QA"
        EnableDebugLogging = $true
        SkipValidation = $false
        AllowTestCertificates = $true
        TestMode = $true
    }
    Production = @{
        EnvironmentName = "Production"
        EnableDebugLogging = $false
        SkipValidation = $false
        AllowTestCertificates = $false
        TestMode = $false
    }
}

# Set current environment
$CurrentEnvironment = "Production"  # Change to Development, Testing, or Production

#endregion

#region REBOOT MANAGEMENT
#==============================================================================
# Configure how reboots are handled during orchestration
#==============================================================================

$RebootConfig = @{
    AllowReboots = $true
    AutoRebootAfterPhase = $true           # Reboot automatically after phase if required
    RebootTimeoutSeconds = 60              # Time to wait before forcing reboot (optimized for unattended)
    MaxRebootsAllowed = 5                  # Maximum number of reboots during orchestration
    NotifyUserBeforeReboot = $true         # Show countdown notification to user
    UserNotificationSeconds = 30           # Countdown warning (optimized for post-imaging)
    ForceRebootIfUserLoggedOn = $false     # Force reboot even if user is logged on
    RebootMessage = "System configuration requires a restart. Please save your work."
    SaveStateBeforeReboot = $true          # Save orchestration state before reboot
    ResumeAfterReboot = $true              # Continue orchestration after reboot
    ResumeDelaySeconds = 30                # Delay after boot before resuming (optimized for Windows 11)
}

#endregion

#region ERROR HANDLING & RECOVERY
#==============================================================================
# Configure error handling behavior
#==============================================================================

$ErrorHandlingConfig = @{
    StopOnCriticalError = $true            # Stop orchestration if critical task fails
    EmailOnError = $false                  # Send email notification on error
    ErrorEmailTo = "it-team@company.com"
    CreateErrorDump = $true                # Create detailed error dump
    ErrorDumpPath = "C:\ProgramData\OrchestrationLogs\ErrorDumps"
    RollbackOnFailure = $false             # Attempt to rollback changes on failure
    RollbackScriptPath = "Scripts\Rollback\Rollback-Master.ps1"
}

#endregion

#region PERFORMANCE & OPTIMIZATION
#==============================================================================
# Performance tuning and optimization settings
#==============================================================================

$PerformanceConfig = @{
    EnableParallelExecution = $false       # Enable parallel task execution (future)
    MaxParallelTasks = 3                   # Maximum concurrent tasks
    ThrottleNetworkUsage = $false          # Limit network bandwidth usage
    MaxNetworkMbps = 100                   # Maximum network bandwidth in Mbps
    PauseForUserActivity = $true           # Pause if user is actively working
    UserActivityCheckInterval = 300        # Check for user activity every 5 minutes
    LowPriorityExecution = $false          # Run with lower process priority
    DiskSpaceCheckBeforeTask = $true       # Verify sufficient disk space
    MinimumFreeDiskSpaceGB = 10            # Minimum free space required
}

#endregion

#region CUSTOM COMPANY SETTINGS
#==============================================================================
# Company-specific settings and customizations
#==============================================================================

$CompanyConfig = @{
    CompanyName = "Contoso Corporation"
    ITDepartment = "Information Technology Services"
    HelpDeskPhone = "1-800-555-1234"
    HelpDeskEmail = "helpdesk@contoso.com"
    HelpDeskURL = "https://helpdesk.contoso.com"
    ITPortalURL = "https://itportal.contoso.com"
    ComputerNameFormat = "PREFIX-{Type}-{SerialNumber}"  # PREFIX-DESK-12345, PREFIX-LAPT-67890
    ComputerNamePrefix = "CORP"
    JoinDomain = $false                    # Join to domain after configuration
    DomainName = "contoso.local"
    DomainOU = "OU=Workstations,OU=Computers,DC=contoso,DC=local"
    AssetTagFormat = "IT-{Year}-{Number}"  # IT-2024-00001
}

#endregion

#region PILOT & DEPLOYMENT RING CONFIGURATION
#==============================================================================
# Manage phased rollout and pilot groups
#==============================================================================

$DeploymentRings = @{
    CurrentRing = "Production"             # Pilot, Ring1, Ring2, Ring3, Production
    
    Pilot = @{
        RingName = "Pilot Group"
        DeviceCount = 10
        EnableAllFeatures = $true
        EnableDetailedLogging = $true
        NotifyITOnCompletion = $true
    }
    
    Ring1 = @{
        RingName = "Early Adopters"
        DeviceCount = 50
        EnableAllFeatures = $true
        EnableDetailedLogging = $true
        NotifyITOnCompletion = $true
    }
    
    Ring2 = @{
        RingName = "Main Deployment Wave 1"
        DeviceCount = 500
        EnableAllFeatures = $true
        EnableDetailedLogging = $false
        NotifyITOnCompletion = $false
    }
    
    Ring3 = @{
        RingName = "Main Deployment Wave 2"
        DeviceCount = 1000
        EnableAllFeatures = $true
        EnableDetailedLogging = $false
        NotifyITOnCompletion = $false
    }
    
    Production = @{
        RingName = "Full Production"
        DeviceCount = 3000
        EnableAllFeatures = $true
        EnableDetailedLogging = $false
        NotifyITOnCompletion = $false
    }
}

#endregion

#region MAINTENANCE WINDOWS
#==============================================================================
# Define when orchestration is allowed to run
#==============================================================================

$MaintenanceWindows = @{
    EnforceMaintenanceWindows = $false     # Only run during defined windows
    
    BusinessHours = @{
        StartTime = "08:00"
        EndTime = "18:00"
        Days = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
        BlockExecution = $true             # Block orchestration during business hours
    }
    
    MaintenanceWindow1 = @{
        Name = "Evening Maintenance"
        StartTime = "18:00"
        EndTime = "23:59"
        Days = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
        AllowExecution = $true
    }
    
    MaintenanceWindow2 = @{
        Name = "Weekend Maintenance"
        StartTime = "00:00"
        EndTime = "23:59"
        Days = @("Saturday", "Sunday")
        AllowExecution = $true
    }
}

#endregion

#region EXPORT CONFIGURATION
#==============================================================================
# Export all configuration objects for orchestration engine
#==============================================================================

# Master configuration export
$OrchestrationConfigurationExport = @{
    
    # Global Settings
    Orchestration = $OrchestrationConfig
    Logging = $LoggingConfig
    SCCM = $SCCMConfig
    Device = $DeviceConfig
    Network = $NetworkConfig
    Source = $SourceConfig
    Notification = $NotificationConfig
    Reboot = $RebootConfig
    ErrorHandling = $ErrorHandlingConfig
    Performance = $PerformanceConfig
    Company = $CompanyConfig
    
    # Phase Configurations
    Phases = @{
        Phase1 = $Phase1_Critical
        Phase2 = $Phase2_Security
        Phase3 = $Phase3_Network
        Phase4 = $Phase4_Applications
        Phase5 = $Phase5_SystemConfig
        Phase6 = $Phase6_UserExperience
        Phase7 = $Phase7_Validation
    }
    
    # Profile Configurations
    DeviceProfiles = $DeviceTypeProfiles
    DepartmentProfiles = $DepartmentProfiles
    EnvironmentProfiles = $EnvironmentProfiles
    DeploymentRings = $DeploymentRings
    MaintenanceWindows = $MaintenanceWindows
    
    # Metadata
    ConfigVersion = "1.0.0"
    LastModified = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ModifiedBy = $env:USERNAME
}

# Return the configuration object
return $OrchestrationConfigurationExport

#==============================================================================
# END OF CONFIGURATION FILE
#==============================================================================