<#
.SYNOPSIS
    Enterprise Windows Firewall Configuration Script
    
.DESCRIPTION
    Configures Windows Firewall with enterprise best practices, balancing security
    and functionality for diverse departmental needs. Implements defense-in-depth
    with sensible defaults while maintaining usability.
    
    This script:
    - Enables Windows Firewall on all profiles (Domain, Private, Public)
    - Configures default policies (block inbound, allow outbound)
    - Creates essential allow rules for enterprise services
    - Implements logging for security monitoring
    - Supports custom rule imports for department-specific needs
    - Maintains backward compatibility with legacy applications
    
.PARAMETER EnableFirewall
    Enable Windows Firewall on all profiles. Default: $true
    
.PARAMETER BlockInbound
    Block all inbound connections by default. Default: $true
    
.PARAMETER AllowOutbound
    Allow all outbound connections by default. Default: $true
    
.PARAMETER ImportRules
    Import custom firewall rules from XML file. Default: $false
    
.PARAMETER RulesPath
    Path to custom firewall rules XML file
    
.PARAMETER EnableLogging
    Enable firewall logging for security monitoring. Default: $true
    
.PARAMETER LogPath
    Path for firewall logs. Default: C:\ProgramData\FirewallLogs
    
.PARAMETER CreateEnterpriseRules
    Create standard enterprise allow rules. Default: $true
    
.PARAMETER CleanupExistingRules
    Remove non-essential existing rules. Default: $false
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-Firewall.ps1
    Configures firewall with default enterprise settings
    
.EXAMPLE
    .\Configure-Firewall.ps1 -ImportRules -RulesPath "C:\Config\CustomRules.xml"
    Configures firewall and imports custom department rules
    
.EXAMPLE
    .\Configure-Firewall.ps1 -DryRun
    Shows what changes would be made without applying them
    
.NOTES
    Version:        1.0.0
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        Enterprise firewall configuration for Windows 11 workstations
    
    SECURITY PHILOSOPHY:
    - Default Deny (Block inbound by default)
    - Explicit Allow (Only allow necessary services)
    - Least Privilege (Minimum required access)
    - Defense in Depth (Multiple layers of protection)
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = Firewall service not available
    4   = Configuration failed
    5   = Rule import failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - Windows Firewall service enabled
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$EnableFirewall = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$BlockInbound = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$AllowOutbound = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportRules = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$RulesPath = '',
    
    [Parameter(Mandatory=$false)]
    [bool]$EnableLogging = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\OrchestrationLogs",
    
    [Parameter(Mandatory=$false)]
    [bool]$CreateEnterpriseRules = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanupExistingRules = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Initialize logging
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Configure-Firewall_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    RulesCreated = 0
    RulesModified = 0
    RulesDeleted = 0
    ProfilesConfigured = 0
    Errors = 0
    Warnings = 0
}

#endregion

#region LOGGING FUNCTIONS
#==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes messages to log file and console
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
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
    <#
    .SYNOPSIS
        Validates system meets requirements for firewall configuration
    #>
    
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
    
    if ($OSVersion.Major -lt 10 -or $BuildNumber -lt 22000) {
        Write-Log "WARNING: This script is designed for Windows 11 (Build 22000+)" -Level "WARNING"
    }
    else {
        Write-Log "Windows version check passed" -Level "SUCCESS"
    }
    
    # Check 3: Firewall service
    Write-Log "Checking Windows Firewall service..." -Level "INFO"
    try {
        $FirewallService = Get-Service -Name "mpssvc" -ErrorAction Stop
        
        if ($FirewallService.Status -eq "Running") {
            Write-Log "Windows Firewall service is running" -Level "SUCCESS"
        }
        else {
            Write-Log "WARNING: Windows Firewall service is not running (Status: $($FirewallService.Status))" -Level "WARNING"
            Write-Log "Attempting to start service..." -Level "INFO"
            
            if (-not $DryRun) {
                Start-Service -Name "mpssvc" -ErrorAction Stop
                Write-Log "Windows Firewall service started successfully" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Cannot access Windows Firewall service: $_" -Level "ERROR"
        $AllChecksPassed = $false
    }
    
    # Check 4: NetSecurity module
    Write-Log "Checking NetSecurity PowerShell module..." -Level "INFO"
    $NetSecurityModule = Get-Module -Name "NetSecurity" -ListAvailable
    
    if ($NetSecurityModule) {
        Write-Log "NetSecurity module available" -Level "SUCCESS"
        Import-Module NetSecurity -ErrorAction SilentlyContinue
    }
    else {
        Write-Log "WARNING: NetSecurity module not found" -Level "WARNING"
    }
    
    # Check 5: Custom rules file (if import requested)
    if ($ImportRules -and -not [string]::IsNullOrWhiteSpace($RulesPath)) {
        Write-Log "Checking custom rules file..." -Level "INFO"
        if (Test-Path $RulesPath) {
            Write-Log "Custom rules file found: $RulesPath" -Level "SUCCESS"
        }
        else {
            Write-Log "WARNING: Custom rules file not found: $RulesPath" -Level "WARNING"
            Write-Log "Will proceed without importing custom rules" -Level "INFO"
        }
    }
    
    return $AllChecksPassed
}

#endregion

#region FIREWALL PROFILE FUNCTIONS
#==============================================================================

function Get-FirewallProfiles {
    <#
    .SYNOPSIS
        Retrieves current firewall profile configurations
    #>
    
    Write-LogHeader "CURRENT FIREWALL PROFILE STATUS"
    
    $Profiles = @("Domain", "Private", "Public")
    $ProfileStatus = @{}
    
    foreach ($Profile in $Profiles) {
        try {
            $ProfileConfig = Get-NetFirewallProfile -Name $Profile -ErrorAction Stop
            
            $ProfileStatus[$Profile] = @{
                Enabled = $ProfileConfig.Enabled
                DefaultInboundAction = $ProfileConfig.DefaultInboundAction
                DefaultOutboundAction = $ProfileConfig.DefaultOutboundAction
                LogAllowed = $ProfileConfig.LogAllowed
                LogBlocked = $ProfileConfig.LogBlocked
                LogFileName = $ProfileConfig.LogFileName
            }
            
            Write-Log "[$Profile Profile]" -Level "INFO"
            Write-Log "  Enabled: $($ProfileConfig.Enabled)" -Level "INFO"
            Write-Log "  Inbound: $($ProfileConfig.DefaultInboundAction)" -Level "INFO"
            Write-Log "  Outbound: $($ProfileConfig.DefaultOutboundAction)" -Level "INFO"
            Write-Log "  Logging: Allowed=$($ProfileConfig.LogAllowed), Blocked=$($ProfileConfig.LogBlocked)" -Level "INFO"
        }
        catch {
            Write-Log "Error retrieving $Profile profile: $_" -Level "ERROR"
        }
    }
    
    return $ProfileStatus
}

function Set-FirewallProfiles {
    <#
    .SYNOPSIS
        Configures firewall profiles with enterprise settings
    #>
    
    Write-LogHeader "CONFIGURING FIREWALL PROFILES"
    
    $Profiles = @("Domain", "Private", "Public")
    
    # Determine actions based on parameters
    $InboundAction = if ($BlockInbound) { "Block" } else { "Allow" }
    $OutboundAction = if ($AllowOutbound) { "Allow" } else { "Block" }
    
    Write-Log "Configuration settings:" -Level "INFO"
    Write-Log "  Enable Firewall: $EnableFirewall" -Level "INFO"
    Write-Log "  Default Inbound: $InboundAction" -Level "INFO"
    Write-Log "  Default Outbound: $OutboundAction" -Level "INFO"
    Write-Log "  Enable Logging: $EnableLogging" -Level "INFO"
    
    foreach ($Profile in $Profiles) {
        Write-Log "Configuring $Profile profile..." -Level "INFO"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would configure $Profile profile" -Level "INFO"
            $Global:Stats.ProfilesConfigured++
            continue
        }
        
        try {
            # Build configuration hashtable
            $Config = @{
                Name = $Profile
                Enabled = if ($EnableFirewall) { "True" } else { "False" }
                DefaultInboundAction = $InboundAction
                DefaultOutboundAction = $OutboundAction
            }
            
            # Add logging configuration if enabled
            if ($EnableLogging) {
                $LogFileName = Join-Path $LogPath "$($Profile.ToLower())-firewall.log"
                
                $Config["LogAllowed"] = "True"
                $Config["LogBlocked"] = "True"
                $Config["LogFileName"] = $LogFileName
                $Config["LogMaxSizeKilobytes"] = 16384  # 16 MB
            }
            else {
                $Config["LogAllowed"] = "False"
                $Config["LogBlocked"] = "False"
            }
            
            # Apply configuration
            Set-NetFirewallProfile @Config -ErrorAction Stop
            
            Write-Log "$Profile profile configured successfully" -Level "SUCCESS"
            $Global:Stats.ProfilesConfigured++
        }
        catch {
            Write-Log "Failed to configure $Profile profile: $_" -Level "ERROR"
            $Global:Stats.Errors++
        }
    }
}

#endregion

#region FIREWALL RULES MANAGEMENT
#==============================================================================

function Get-ExistingRules {
    <#
    .SYNOPSIS
        Retrieves and categorizes existing firewall rules
    #>
    
    Write-LogHeader "ANALYZING EXISTING FIREWALL RULES"
    
    try {
        $AllRules = Get-NetFirewallRule -ErrorAction Stop
        
        $Statistics = @{
            Total = $AllRules.Count
            Enabled = ($AllRules | Where-Object { $_.Enabled -eq "True" }).Count
            Disabled = ($AllRules | Where-Object { $_.Enabled -eq "False" }).Count
            Inbound = ($AllRules | Where-Object { $_.Direction -eq "Inbound" }).Count
            Outbound = ($AllRules | Where-Object { $_.Direction -eq "Outbound" }).Count
            System = ($AllRules | Where-Object { $_.DisplayGroup -like "*Windows*" }).Count
            Custom = ($AllRules | Where-Object { $_.DisplayGroup -notlike "*Windows*" -and $_.DisplayGroup -ne $null }).Count
        }
        
        Write-Log "Existing rules summary:" -Level "INFO"
        Write-Log "  Total rules: $($Statistics.Total)" -Level "INFO"
        Write-Log "  Enabled: $($Statistics.Enabled) | Disabled: $($Statistics.Disabled)" -Level "INFO"
        Write-Log "  Inbound: $($Statistics.Inbound) | Outbound: $($Statistics.Outbound)" -Level "INFO"
        Write-Log "  System: $($Statistics.System) | Custom: $($Statistics.Custom)" -Level "INFO"
        
        return @{
            Rules = $AllRules
            Statistics = $Statistics
        }
    }
    catch {
        Write-Log "Error retrieving existing rules: $_" -Level "ERROR"
        return $null
    }
}

function Remove-UnnecessaryRules {
    <#
    .SYNOPSIS
        Removes non-essential firewall rules to reduce attack surface
    #>
    
    Write-LogHeader "CLEANING UP FIREWALL RULES"
    
    if (-not $CleanupExistingRules) {
        Write-Log "Rule cleanup disabled - skipping" -Level "INFO"
        return
    }
    
    Write-Log "Identifying rules for removal..." -Level "INFO"
    
    # Rules to potentially remove (disabled by default for safety)
    $RemovalCandidates = @(
        # Uncomment categories as needed for your environment
        # "*Remote Desktop*"
        # "*HomeGroup*"
        # "*BranchCache*"
        # "*Work Folders*"
        # "*Wireless Display*"
    )
    
    if ($RemovalCandidates.Count -eq 0) {
        Write-Log "No removal candidates configured - skipping" -Level "INFO"
        return
    }
    
    foreach ($Pattern in $RemovalCandidates) {
        try {
            $Rules = Get-NetFirewallRule -DisplayName $Pattern -ErrorAction SilentlyContinue
            
            if ($Rules) {
                Write-Log "Found $($Rules.Count) rules matching: $Pattern" -Level "INFO"
                
                foreach ($Rule in $Rules) {
                    if ($DryRun) {
                        Write-Log "[DRY RUN] Would remove rule: $($Rule.DisplayName)" -Level "INFO"
                    }
                    else {
                        Remove-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
                        Write-Log "Removed rule: $($Rule.DisplayName)" -Level "SUCCESS"
                        $Global:Stats.RulesDeleted++
                    }
                }
            }
        }
        catch {
            Write-Log "Error removing rules matching '$Pattern': $_" -Level "ERROR"
        }
    }
}

#endregion

#region ENTERPRISE RULES CREATION
#==============================================================================

function New-EnterpriseFirewallRules {
    <#
    .SYNOPSIS
        Creates essential firewall rules for enterprise environment
    #>
    
    Write-LogHeader "CREATING ENTERPRISE FIREWALL RULES"
    
    if (-not $CreateEnterpriseRules) {
        Write-Log "Enterprise rule creation disabled - skipping" -Level "INFO"
        return
    }
    
    # Define enterprise firewall rules
    $EnterpriseRules = @(
        
        #----------------------------------------------------------------------
        # CORE NETWORK SERVICES
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - DNS (UDP Out)"
            Description = "Allow outbound DNS queries (UDP)"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "53"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - DNS (TCP Out)"
            Description = "Allow outbound DNS queries (TCP)"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "53"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - DHCP Client (UDP Out)"
            Description = "Allow DHCP client requests"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "68"
            RemotePort = "67"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Dhcp"
        },
        
        @{
            DisplayName = "Enterprise - DHCP Client (UDP In)"
            Description = "Allow DHCP client responses"
            Direction = "Inbound"
            Protocol = "UDP"
            LocalPort = "68"
            RemotePort = "67"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Dhcp"
        },
        
        @{
            DisplayName = "Enterprise - NTP (UDP Out)"
            Description = "Allow Network Time Protocol synchronization"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "123"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "%SystemRoot%\System32\svchost.exe"
            Service = "W32Time"
        },
        
        #----------------------------------------------------------------------
        # DOMAIN SERVICES
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - Active Directory (TCP Out)"
            Description = "Allow Active Directory authentication and queries"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "389,636,3268,3269,88,464"
            Action = "Allow"
            Profile = "Domain"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - Active Directory (UDP Out)"
            Description = "Allow Active Directory authentication (UDP)"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "389,88,464"
            Action = "Allow"
            Profile = "Domain"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - SMB/CIFS Client (TCP Out)"
            Description = "Allow SMB file sharing client connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "445"
            Action = "Allow"
            Profile = "Domain,Private"
            Program = "System"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - NetBIOS Name Service (UDP Out)"
            Description = "Allow NetBIOS name resolution (legacy support)"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "137"
            Action = "Allow"
            Profile = "Domain,Private"
            Program = "System"
            Service = "Any"
        },
        
        #----------------------------------------------------------------------
        # WINDOWS UPDATE & MANAGEMENT
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - Windows Update (HTTP Out)"
            Description = "Allow Windows Update HTTP connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "80"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "%SystemRoot%\System32\svchost.exe"
            Service = "wuauserv"
        },
        
        @{
            DisplayName = "Enterprise - Windows Update (HTTPS Out)"
            Description = "Allow Windows Update HTTPS connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "443"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "%SystemRoot%\System32\svchost.exe"
            Service = "wuauserv"
        },
        
        @{
            DisplayName = "Enterprise - WinRM (TCP In)"
            Description = "Allow Windows Remote Management for administration"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = "5985,5986"
            RemotePort = "Any"
            Action = "Allow"
            Profile = "Domain"
            Program = "System"
            Service = "WinRM"
        },
        
        #----------------------------------------------------------------------
        # WEB BROWSERS
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - Web Browsing HTTP (TCP Out)"
            Description = "Allow web browser HTTP connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "80"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - Web Browsing HTTPS (TCP Out)"
            Description = "Allow web browser HTTPS connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "443"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        #----------------------------------------------------------------------
        # EMAIL CLIENTS
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - Email SMTP (TCP Out)"
            Description = "Allow outbound SMTP for email clients"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "25,587"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - Email IMAP/POP3 (TCP Out)"
            Description = "Allow email client IMAP and POP3 connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "110,143,993,995"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        },
        
        #----------------------------------------------------------------------
        # NETWORK DISCOVERY (DOMAIN/PRIVATE ONLY)
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - ICMP Echo Request (In)"
            Description = "Allow ICMP ping responses for network diagnostics"
            Direction = "Inbound"
            Protocol = "ICMPv4"
            IcmpType = "8"  # Echo Request
            Action = "Allow"
            Profile = "Domain,Private"
            Program = "System"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - ICMP Echo Request (Out)"
            Description = "Allow ICMP ping requests for network diagnostics"
            Direction = "Outbound"
            Protocol = "ICMPv4"
            IcmpType = "8"  # Echo Request
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "System"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - LLMNR (UDP In/Out)"
            Description = "Allow Link-Local Multicast Name Resolution"
            Direction = "Inbound"
            Protocol = "UDP"
            LocalPort = "5355"
            RemotePort = "5355"
            Action = "Allow"
            Profile = "Domain,Private"
            Program = "Any"
            Service = "Any"
        },
        
        #----------------------------------------------------------------------
        # COMMON ENTERPRISE APPLICATIONS
        #----------------------------------------------------------------------
        
        @{
            DisplayName = "Enterprise - Microsoft Teams (TCP/UDP Out)"
            Description = "Allow Microsoft Teams communication"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "80,443"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "%LocalAppData%\Microsoft\Teams\current\Teams.exe"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - Remote Desktop (TCP Out)"
            Description = "Allow Remote Desktop client connections"
            Direction = "Outbound"
            Protocol = "TCP"
            LocalPort = "Any"
            RemotePort = "3389"
            Action = "Allow"
            Profile = "Domain,Private"
            Program = "%SystemRoot%\System32\mstsc.exe"
            Service = "Any"
        },
        
        @{
            DisplayName = "Enterprise - VPN Clients (UDP Out)"
            Description = "Allow common VPN protocols (IKEv2, L2TP)"
            Direction = "Outbound"
            Protocol = "UDP"
            LocalPort = "Any"
            RemotePort = "500,1701,4500"
            Action = "Allow"
            Profile = "Domain,Private,Public"
            Program = "Any"
            Service = "Any"
        }
    )
    
    Write-Log "Creating $($EnterpriseRules.Count) enterprise firewall rules..." -Level "INFO"
    
    foreach ($Rule in $EnterpriseRules) {
        try {
            # Check if rule already exists
            $ExistingRule = Get-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue
            
            if ($ExistingRule) {
                Write-Log "Rule already exists: $($Rule.DisplayName)" -Level "INFO"
                
                if ($DryRun) {
                    Write-Log "[DRY RUN] Would update existing rule" -Level "INFO"
                }
                else {
                    # Update existing rule
                    Set-NetFirewallRule -DisplayName $Rule.DisplayName -Enabled True -ErrorAction Stop
                    Write-Log "Updated existing rule: $($Rule.DisplayName)" -Level "SUCCESS"
                    $Global:Stats.RulesModified++
                }
                continue
            }
            
            # Create new rule
            if ($DryRun) {
                Write-Log "[DRY RUN] Would create rule: $($Rule.DisplayName)" -Level "INFO"
                $Global:Stats.RulesCreated++
                continue
            }
            
            # Build parameter hashtable (remove null/empty values)
            $Params = @{
                DisplayName = $Rule.DisplayName
                Description = $Rule.Description
                Direction = $Rule.Direction
                Protocol = $Rule.Protocol
                Action = $Rule.Action
                Profile = $Rule.Profile
                Enabled = "True"
            }
            
            # Add optional parameters
            if ($Rule.LocalPort -and $Rule.LocalPort -ne "Any") {
                $Params["LocalPort"] = $Rule.LocalPort
            }
            if ($Rule.RemotePort -and $Rule.RemotePort -ne "Any") {
                # Convert comma-separated string to array if needed
                if ($Rule.RemotePort -is [string] -and $Rule.RemotePort -match ',') {
                    $Params["RemotePort"] = $Rule.RemotePort -split ','  # ← Converts to array
                }
                else {
                    $Params["RemotePort"] = $Rule.RemotePort
                }
            }
            if ($Rule.IcmpType) {
                $Params["IcmpType"] = $Rule.IcmpType
            }
            
            # Create the rule
            New-NetFirewallRule @Params -ErrorAction Stop | Out-Null
            
            Write-Log "Created rule: $($Rule.DisplayName)" -Level "SUCCESS"
            $Global:Stats.RulesCreated++
        }
        catch {
            Write-Log "Failed to create rule '$($Rule.DisplayName)': $_" -Level "ERROR"
            $Global:Stats.Errors++
        }
    }
}

#endregion

#region CUSTOM RULES IMPORT
#==============================================================================

function Import-CustomFirewallRules {
    <#
    .SYNOPSIS
        Imports custom firewall rules from XML file
    #>
    
    Write-LogHeader "IMPORTING CUSTOM FIREWALL RULES"
    
    if (-not $ImportRules) {
        Write-Log "Custom rule import disabled - skipping" -Level "INFO"
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($RulesPath)) {
        Write-Log "No rules path specified - skipping" -Level "WARNING"
        return
    }
    
    if (-not (Test-Path $RulesPath)) {
        Write-Log "Rules file not found: $RulesPath" -Level "ERROR"
        return
    }
    
    Write-Log "Importing rules from: $RulesPath" -Level "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would import custom rules" -Level "INFO"
        return
    }
    
    try {
        # Import rules using netsh (alternative method)
        $Result = netsh advfirewall firewall import $RulesPath 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Custom rules imported successfully" -Level "SUCCESS"
        }
        else {
            Write-Log "Failed to import custom rules: $Result" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error importing custom rules: $_" -Level "ERROR"
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-FirewallConfiguration {
    <#
    .SYNOPSIS
        Validates firewall configuration after changes
    #>
    
    Write-LogHeader "VALIDATING FIREWALL CONFIGURATION"
    
    $ValidationResults = @{
        Passed = $true
        Checks = @()
    }
    
    # Check 1: Firewall enabled on all profiles
    Write-Log "Checking firewall is enabled on all profiles..." -Level "INFO"
    $Profiles = @("Domain", "Private", "Public")
    
    foreach ($Profile in $Profiles) {
        $ProfileConfig = Get-NetFirewallProfile -Name $Profile
        
        if ($ProfileConfig.Enabled) {
            Write-Log "  $Profile profile: ENABLED ✓" -Level "SUCCESS"
            $ValidationResults.Checks += @{
                Check = "$Profile Enabled"
                Status = "PASS"
            }
        }
        else {
            Write-Log "  $Profile profile: DISABLED ✗" -Level "ERROR"
            $ValidationResults.Passed = $false
            $ValidationResults.Checks += @{
                Check = "$Profile Enabled"
                Status = "FAIL"
            }
        }
    }
    
    # Check 2: Default inbound policy
    Write-Log "Checking default inbound policies..." -Level "INFO"
    foreach ($Profile in $Profiles) {
        $ProfileConfig = Get-NetFirewallProfile -Name $Profile
        $Expected = if ($BlockInbound) { "Block" } else { "Allow" }
        
        if ($ProfileConfig.DefaultInboundAction -eq $Expected) {
            Write-Log "  $Profile inbound: $($ProfileConfig.DefaultInboundAction) ✓" -Level "SUCCESS"
        }
        else {
            Write-Log "  $Profile inbound: $($ProfileConfig.DefaultInboundAction) (Expected: $Expected) ✗" -Level "WARNING"
        }
    }
    
    # Check 3: Essential rules exist
    Write-Log "Checking essential enterprise rules exist..." -Level "INFO"
    $EssentialRules = @(
        "Enterprise - DNS (UDP Out)",
        "Enterprise - DHCP Client (UDP Out)",
        "Enterprise - Web Browsing HTTPS (TCP Out)"
    )
    
    foreach ($RuleName in $EssentialRules) {
        $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if ($Rule -and $Rule.Enabled -eq "True") {
            Write-Log "  ${RuleName}: EXISTS ✓" -Level "SUCCESS"
        }
        else {
            Write-Log "  ${RuleName}: MISSING ✗" -Level "WARNING"
        }
    }
    
    # Check 4: Logging enabled (if configured)
    if ($EnableLogging) {
        Write-Log "Checking firewall logging..." -Level "INFO"
        foreach ($Profile in $Profiles) {
            $ProfileConfig = Get-NetFirewallProfile -Name $Profile
            
            if ($ProfileConfig.LogBlocked -or $ProfileConfig.LogAllowed) {
                Write-Log "  $Profile logging: ENABLED ✓" -Level "SUCCESS"
            }
            else {
                Write-Log "  $Profile logging: DISABLED ✗" -Level "WARNING"
            }
        }
    }
    
    return $ValidationResults
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
    Write-Log "Configuration Changes:" -Level "INFO"
    Write-Log "  Profiles Configured: $($Global:Stats.ProfilesConfigured)" -Level "INFO"
    Write-Log "  Rules Created: $($Global:Stats.RulesCreated)" -Level "SUCCESS"
    Write-Log "  Rules Modified: $($Global:Stats.RulesModified)" -Level "INFO"
    Write-Log "  Rules Deleted: $($Global:Stats.RulesDeleted)" -Level "INFO"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
    Write-Log " " -Level "INFO"
    Write-Log "Log File: $Global:LogFile" -Level "INFO"
    
    # Current firewall status
    Write-Log " " -Level "INFO"
    Write-Log "Current Firewall Status:" -Level "INFO"
    
    $Profiles = @("Domain", "Private", "Public")
    foreach ($Profile in $Profiles) {
        $ProfileConfig = Get-NetFirewallProfile -Name $Profile
        Write-Log "  [$Profile] Enabled: $($ProfileConfig.Enabled) | In: $($ProfileConfig.DefaultInboundAction) | Out: $($ProfileConfig.DefaultOutboundAction)" -Level "INFO"
    }
    
    # Rule counts
    $AllRules = Get-NetFirewallRule
    $EnabledRules = ($AllRules | Where-Object { $_.Enabled -eq "True" }).Count
    
    Write-Log " " -Level "INFO"
    Write-Log "Firewall Rules:" -Level "INFO"
    Write-Log "  Total: $($AllRules.Count)" -Level "INFO"
    Write-Log "  Enabled: $EnabledRules" -Level "INFO"
    Write-Log "  Disabled: $($AllRules.Count - $EnabledRules)" -Level "INFO"
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
║        ENTERPRISE WINDOWS FIREWALL CONFIGURATION              ║
║                        Version $ScriptVersion                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WINDOWS FIREWALL CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    
    # Step 1: Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
        exit 2
    }
    
    # Step 2: Get current state
    $CurrentState = Get-FirewallProfiles
    $ExistingRules = Get-ExistingRules
    
    # Step 3: Configure profiles
    Set-FirewallProfiles
    
    # Step 4: Clean up rules (if enabled)
    Remove-UnnecessaryRules
    
    # Step 5: Create enterprise rules
    New-EnterpriseFirewallRules
    
    # Step 6: Import custom rules (if requested)
    Import-CustomFirewallRules
    
    # Step 7: Validate configuration
    $ValidationResults = Test-FirewallConfiguration
    
    # Step 8: Display summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "Firewall configuration completed successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "Firewall configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
