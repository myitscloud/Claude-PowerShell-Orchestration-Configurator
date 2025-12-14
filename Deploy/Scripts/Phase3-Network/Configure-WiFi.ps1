<#
.SYNOPSIS
    Configure Corporate Wireless Network Profiles (TEMPLATE)
    
.DESCRIPTION
    Deploys and configures corporate wireless network profiles on Windows 11 workstations.
    
    ⚠️ THIS IS A TEMPLATE - Customize before deployment!
    
    Features:
    - Deploy multiple WiFi profiles (XML-based)
    - Configure WPA2-PSK (pre-shared key) networks
    - Configure WPA2-Enterprise (802.1X) networks
    - Set network priority order
    - Configure auto-connect behavior
    - Deploy certificates for enterprise authentication
    - Support for hidden networks
    - Intelligent detection (skips if no WiFi adapter)
    - Comprehensive logging and error handling
    
    The script can work in two modes:
    1. XML Profile Mode: Import pre-created WiFi profile XML files
    2. Built-in Profile Mode: Use profiles defined in this script
    
.PARAMETER WiFiProfilesPath
    Path to directory containing WiFi profile XML files.
    If path doesn't exist, script will use built-in profiles instead.
    
.PARAMETER AutoConnect
    Enable auto-connect for deployed WiFi profiles. Default: $true
    
.PARAMETER RemoveExistingProfiles
    Remove existing WiFi profiles before deploying new ones. Default: $false
    
.PARAMETER SetNetworkPriority
    Configure network connection priority order. Default: $true
    
.PARAMETER DeployCertificates
    Deploy certificates for 802.1X authentication. Default: $false
    
.PARAMETER CertificatePath
    Path to certificate files for WiFi authentication.
    
.PARAMETER DryRun
    Simulate changes without applying them. Default: $false
    
.EXAMPLE
    .\Configure-WiFi.ps1
    Deploys WiFi profiles using default settings
    
.EXAMPLE
    .\Configure-WiFi.ps1 -WiFiProfilesPath "\\Server\Profiles" -AutoConnect $true
    Deploys profiles from network share with auto-connect enabled
    
.EXAMPLE
    .\Configure-WiFi.ps1 -DryRun
    Shows what would be configured without making changes
    
.NOTES
    Version:        1.0.0 (TEMPLATE)
    Author:         IT Infrastructure Team
    Creation Date:  2024-12-08
    Purpose:        WiFi profile deployment for Windows 11 workstations
    
    ⚠️ IMPORTANT: This is a TEMPLATE script!
    Before deploying, customize the following sections:
    1. Built-in WiFi profiles (search for "CUSTOMIZE")
    2. Corporate WiFi SSIDs and passwords
    3. Certificate paths (if using 802.1X)
    4. Network priority order
    
    EXIT CODES:
    0   = Success
    1   = General failure
    2   = Not running as administrator
    3   = No WiFi adapter found (not an error, just skipped)
    4   = Configuration failed
    
    REQUIREMENTS:
    - Windows 11 Professional or Enterprise
    - Administrator privileges
    - WiFi adapter present (script auto-detects and skips if none)
    - WiFi adapter drivers installed
    
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$WiFiProfilesPath = "Config\WiFiProfiles",
    
    [Parameter(Mandatory=$false)]
    [bool]$AutoConnect = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$RemoveExistingProfiles = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$SetNetworkPriority = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DeployCertificates = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "\\FileServer\Deployment\WiFi\Certs",
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

#region INITIALIZATION
#==============================================================================

$ScriptVersion = "1.0.0-TEMPLATE"
$ScriptStartTime = Get-Date

# Initialize logging
$LogPath = "C:\ProgramData\OrchestrationLogs"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$LogFileName = "Configure-WiFi_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$Global:LogFile = Join-Path $LogPath $LogFileName

# Statistics tracking
$Global:Stats = @{
    WiFiAdaptersFound = 0
    ProfilesDeployed = 0
    ProfilesFailed = 0
    CertificatesImported = 0
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
    
    # Check 2: WiFi adapter presence
    Write-Log "Checking for WiFi adapters..." -Level "INFO"
    $WiFiAdapters = Get-NetAdapter | Where-Object {
        ($_.InterfaceDescription -like "*Wireless*" -or 
         $_.InterfaceDescription -like "*Wi-Fi*" -or 
         $_.InterfaceDescription -like "*802.11*") -and
        $_.Status -ne "Not Present"
    }
    
    if (-not $WiFiAdapters) {
        Write-Log "No WiFi adapters found - script will exit gracefully" -Level "WARNING"
        Write-Log "This is not an error (desktops don't need WiFi configuration)" -Level "INFO"
        $Global:Stats.WiFiAdaptersFound = 0
        return $false  # Return false to indicate script should exit (but not as error)
    }
    else {
        Write-Log "Found $($WiFiAdapters.Count) WiFi adapter(s)" -Level "SUCCESS"
        $Global:Stats.WiFiAdaptersFound = $WiFiAdapters.Count
        
        foreach ($Adapter in $WiFiAdapters) {
            Write-Log "  [$($Adapter.Status)] $($Adapter.Name) - $($Adapter.InterfaceDescription)" -Level "DEBUG"
        }
    }
    
    # Check 3: Wireless service
    Write-Log "Checking WLAN AutoConfig service..." -Level "INFO"
    $WLANService = Get-Service -Name "WlanSvc" -ErrorAction SilentlyContinue
    
    if (-not $WLANService) {
        Write-Log "WARNING: WLAN AutoConfig service not found" -Level "WARNING"
    }
    elseif ($WLANService.Status -ne "Running") {
        Write-Log "WLAN AutoConfig service is not running - attempting to start..." -Level "WARNING"
        try {
            Start-Service -Name "WlanSvc" -ErrorAction Stop
            Write-Log "WLAN AutoConfig service started successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to start WLAN AutoConfig service: $_" -Level "ERROR"
            $AllChecksPassed = $false
        }
    }
    else {
        Write-Log "WLAN AutoConfig service is running" -Level "SUCCESS"
    }
    
    return $AllChecksPassed
}

#endregion

#region WIFI PROFILE DEFINITIONS
#==============================================================================

function Get-BuiltInWiFiProfiles {
    <#
    .SYNOPSIS
        Returns built-in WiFi profile definitions (used when XML files not available)
    .DESCRIPTION
        ⚠️ CUSTOMIZE THESE PROFILES FOR YOUR ENVIRONMENT!
        
        This function contains template WiFi profiles. Before deployment:
        1. Replace "YourCompanyWiFi" with your actual SSID
        2. Replace "YourWiFiPassword123!" with your actual password
        3. Add/remove profiles as needed for your organization
        4. Configure security settings (WPA2/WPA3)
        5. Set appropriate priority order
    #>
    
    Write-Log "Using built-in WiFi profile definitions" -Level "INFO"
    
    # =========================================================================
    # ⚠️ CUSTOMIZE THIS SECTION FOR YOUR ENVIRONMENT
    # =========================================================================
    
    $Profiles = @()
    
    # Profile 1: Main Corporate WiFi (WPA2-PSK)
    # ⚠️ CUSTOMIZE: Replace with your corporate WiFi details
    $Profiles += @{
        ProfileName = "CorpWiFi-Main"
        SSID = "YourCompanyWiFi"  # ⚠️ CHANGE THIS
        Password = "YourWiFiPassword123!"  # ⚠️ CHANGE THIS
        Authentication = "WPA2PSK"  # WPA2PSK, WPA3SAE, or WPA2
        Encryption = "AES"
        AutoConnect = $true
        Priority = 1  # Highest priority
        Hidden = $false
        Description = "Primary corporate wireless network"
    }
    
    # Profile 2: Guest WiFi (WPA2-PSK)
    # ⚠️ CUSTOMIZE: Add if you have guest WiFi
    $Profiles += @{
        ProfileName = "CorpWiFi-Guest"
        SSID = "YourCompanyGuest"  # ⚠️ CHANGE THIS
        Password = "GuestPassword123!"  # ⚠️ CHANGE THIS
        Authentication = "WPA2PSK"
        Encryption = "AES"
        AutoConnect = $false
        Priority = 2
        Hidden = $false
        Description = "Guest wireless network"
    }
    
    # Profile 3: Secondary Office WiFi
    # ⚠️ CUSTOMIZE: Add if you have multiple office locations
    $Profiles += @{
        ProfileName = "CorpWiFi-Office2"
        SSID = "YourCompanyOffice2"  # ⚠️ CHANGE THIS
        Password = "Office2Password123!"  # ⚠️ CHANGE THIS
        Authentication = "WPA2PSK"
        Encryption = "AES"
        AutoConnect = $true
        Priority = 3
        Hidden = $false
        Description = "Secondary office wireless network"
    }
    
    # =========================================================================
    # Advanced Profile Example: 802.1X Enterprise Authentication
    # ⚠️ Uncomment and customize if you use 802.1X authentication
    # =========================================================================
    <#
    $Profiles += @{
        ProfileName = "CorpWiFi-Enterprise"
        SSID = "YourCompanySecure"  # ⚠️ CHANGE THIS
        Authentication = "WPA2"  # WPA2 for 802.1X
        Encryption = "AES"
        AutoConnect = $true
        Priority = 1
        Hidden = $false
        Description = "Corporate wireless with 802.1X authentication"
        Enterprise = $true
        EAPType = "PEAP"  # PEAP, TLS, TTLS
        UseWindowsCredentials = $true
        ServerValidation = $true
        TrustedRootCA = "YourCAThumbprint"  # Certificate thumbprint
    }
    #>
    
    # =========================================================================
    # Hidden Network Example
    # ⚠️ Uncomment and customize if you use hidden SSIDs
    # =========================================================================
    <#
    $Profiles += @{
        ProfileName = "CorpWiFi-Hidden"
        SSID = "YourHiddenNetwork"  # ⚠️ CHANGE THIS
        Password = "HiddenPassword123!"  # ⚠️ CHANGE THIS
        Authentication = "WPA2PSK"
        Encryption = "AES"
        AutoConnect = $true
        Priority = 1
        Hidden = $true  # Network doesn't broadcast SSID
        Description = "Hidden corporate network"
    }
    #>
    
    # ⚠️ ADD MORE PROFILES AS NEEDED FOR YOUR ENVIRONMENT
    
    return $Profiles
}

function New-WiFiProfileXML {
    <#
    .SYNOPSIS
        Generates WiFi profile XML from profile definition
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Profile
    )
    
    # Determine connection type
    $ConnectionType = if ($Profile.Hidden) { "ESS" } else { "ESS" }
    $ConnectionMode = if ($Profile.AutoConnect) { "auto" } else { "manual" }
    
    # Non-broadcast (hidden) configuration
    $NonBroadcast = if ($Profile.Hidden) {
        "<nonBroadcast>true</nonBroadcast>"
    } else {
        "<nonBroadcast>false</nonBroadcast>"
    }
    
    # Build security section based on authentication type
    if ($Profile.Enterprise) {
        # 802.1X Enterprise authentication
        $SecurityXML = @"
        <security>
            <authEncryption>
                <authentication>$($Profile.Authentication)</authentication>
                <encryption>$($Profile.Encryption)</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>machineOrUser</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>25</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
                                        <ServerNames></ServerNames>
                                    </ServerValidation>
                                    <FastReconnect>true</FastReconnect>
                                    <InnerEapOptional>false</InnerEapOptional>
                                    <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                        <Type>26</Type>
                                        <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
                                            <UseWinLogonCredentials>true</UseWinLogonCredentials>
                                        </EapType>
                                    </Eap>
                                    <EnableQuarantineChecks>false</EnableQuarantineChecks>
                                    <RequireCryptoBinding>false</RequireCryptoBinding>
                                    <PeapExtensions>
                                        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation>
                                        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName>
                                    </PeapExtensions>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
"@
    }
    else {
        # WPA2-PSK (pre-shared key) authentication
        $SecurityXML = @"
        <security>
            <authEncryption>
                <authentication>$($Profile.Authentication)</authentication>
                <encryption>$($Profile.Encryption)</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$($Profile.Password)</keyMaterial>
            </sharedKey>
        </security>
"@
    }
    
    # Build complete profile XML
    $ProfileXML = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$($Profile.ProfileName)</name>
    <SSIDConfig>
        <SSID>
            <hex>$([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($Profile.SSID)).Replace('-',''))</hex>
            <name>$($Profile.SSID)</name>
        </SSID>
        $NonBroadcast
    </SSIDConfig>
    <connectionType>$ConnectionType</connectionType>
    <connectionMode>$ConnectionMode</connectionMode>
    <MSM>
$SecurityXML
    </MSM>
</WLANProfile>
"@
    
    return $ProfileXML
}

#endregion

#region WIFI PROFILE DEPLOYMENT
#==============================================================================

function Import-WiFiProfileFromXML {
    <#
    .SYNOPSIS
        Imports WiFi profile from XML file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$XMLFilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$InterfaceName = "Wi-Fi"
    )
    
    try {
        # Read XML file
        if (-not (Test-Path $XMLFilePath)) {
            Write-Log "Profile XML not found: $XMLFilePath" -Level "ERROR"
            return $false
        }
        
        $ProfileXML = Get-Content -Path $XMLFilePath -Raw
        $ProfileName = ([xml]$ProfileXML).WLANProfile.name
        
        Write-Log "Importing WiFi profile: $ProfileName" -Level "INFO"
        Write-Log "  Source: $XMLFilePath" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would import profile: $ProfileName" -Level "INFO"
            return $true
        }
        
        # Import profile using netsh
        $TempFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $TempFile -Value $ProfileXML -Force
        
        $Result = netsh wlan add profile filename="$TempFile" user=all 2>&1
        Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Profile imported successfully: $ProfileName" -Level "SUCCESS"
            $Global:Stats.ProfilesDeployed++
            return $true
        }
        else {
            Write-Log "Failed to import profile: $ProfileName" -Level "ERROR"
            Write-Log "  Error: $Result" -Level "ERROR"
            $Global:Stats.ProfilesFailed++
            return $false
        }
    }
    catch {
        Write-Log "Exception importing profile: $_" -Level "ERROR"
        $Global:Stats.ProfilesFailed++
        return $false
    }
}

function Deploy-WiFiProfile {
    <#
    .SYNOPSIS
        Deploys a WiFi profile from hashtable definition
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Profile
    )
    
    try {
        Write-Log "Deploying WiFi profile: $($Profile.ProfileName)" -Level "INFO"
        Write-Log "  SSID: $($Profile.SSID)" -Level "DEBUG"
        Write-Log "  Authentication: $($Profile.Authentication)" -Level "DEBUG"
        Write-Log "  Auto-Connect: $($Profile.AutoConnect)" -Level "DEBUG"
        Write-Log "  Priority: $($Profile.Priority)" -Level "DEBUG"
        
        # Generate XML
        $ProfileXML = New-WiFiProfileXML -Profile $Profile
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would deploy profile: $($Profile.ProfileName)" -Level "INFO"
            return $true
        }
        
        # Save to temp file and import
        $TempFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $TempFile -Value $ProfileXML -Force
        
        $Result = netsh wlan add profile filename="$TempFile" user=all 2>&1
        Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Profile deployed successfully: $($Profile.ProfileName)" -Level "SUCCESS"
            $Global:Stats.ProfilesDeployed++
            
            # Set priority if requested
            if ($SetNetworkPriority) {
                Set-WiFiProfilePriority -ProfileName $Profile.ProfileName -Priority $Profile.Priority
            }
            
            return $true
        }
        else {
            Write-Log "Failed to deploy profile: $($Profile.ProfileName)" -Level "ERROR"
            Write-Log "  Error: $Result" -Level "ERROR"
            $Global:Stats.ProfilesFailed++
            return $false
        }
    }
    catch {
        Write-Log "Exception deploying profile: $_" -Level "ERROR"
        $Global:Stats.ProfilesFailed++
        return $false
    }
}

function Set-WiFiProfilePriority {
    <#
    .SYNOPSIS
        Sets WiFi profile connection priority
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        
        [Parameter(Mandatory=$true)]
        [int]$Priority
    )
    
    try {
        # Get WiFi adapter name
        $WiFiAdapter = Get-NetAdapter | Where-Object {
            ($_.InterfaceDescription -like "*Wireless*" -or 
             $_.InterfaceDescription -like "*Wi-Fi*") -and
            $_.Status -ne "Not Present"
        } | Select-Object -First 1
        
        if (-not $WiFiAdapter) {
            Write-Log "No WiFi adapter found for priority setting" -Level "WARNING"
            return
        }
        
        Write-Log "Setting priority $Priority for profile: $ProfileName" -Level "DEBUG"
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set priority to $Priority" -Level "INFO"
            return
        }
        
        $Result = netsh wlan set profileorder name="$ProfileName" interface="$($WiFiAdapter.Name)" priority=$Priority 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Priority set successfully for $ProfileName" -Level "SUCCESS"
        }
        else {
            Write-Log "Warning: Could not set priority for $ProfileName : $Result" -Level "WARNING"
        }
    }
    catch {
        Write-Log "Exception setting priority: $_" -Level "WARNING"
    }
}

function Remove-ExistingWiFiProfiles {
    <#
    .SYNOPSIS
        Removes all existing WiFi profiles (if requested)
    #>
    
    if (-not $RemoveExistingProfiles) {
        Write-Log "Skipping removal of existing profiles (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "REMOVING EXISTING WIFI PROFILES"
    
    try {
        # Get all WiFi profiles
        $ProfileList = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ':')[1].Trim()
        }
        
        if (-not $ProfileList) {
            Write-Log "No existing WiFi profiles found" -Level "INFO"
            return
        }
        
        Write-Log "Found $($ProfileList.Count) existing profile(s)" -Level "INFO"
        
        foreach ($ProfileName in $ProfileList) {
            Write-Log "Removing profile: $ProfileName" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would remove profile: $ProfileName" -Level "INFO"
                continue
            }
            
            $Result = netsh wlan delete profile name="$ProfileName" 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Profile removed: $ProfileName" -Level "SUCCESS"
            }
            else {
                Write-Log "Failed to remove profile: $ProfileName - $Result" -Level "WARNING"
            }
        }
    }
    catch {
        Write-Log "Exception removing profiles: $_" -Level "ERROR"
    }
}

#endregion

#region CERTIFICATE DEPLOYMENT
#==============================================================================

function Deploy-WiFiCertificates {
    <#
    .SYNOPSIS
        Deploys certificates for 802.1X authentication
    #>
    
    if (-not $DeployCertificates) {
        Write-Log "Certificate deployment skipped (parameter disabled)" -Level "INFO"
        return
    }
    
    Write-LogHeader "DEPLOYING WIFI CERTIFICATES"
    
    if (-not (Test-Path $CertificatePath)) {
        Write-Log "Certificate path not found: $CertificatePath" -Level "WARNING"
        return
    }
    
    # =========================================================================
    # ⚠️ CUSTOMIZE: Certificate deployment for your environment
    # =========================================================================
    
    try {
        # Find certificate files
        $Certificates = Get-ChildItem -Path $CertificatePath -Filter "*.cer" -ErrorAction SilentlyContinue
        
        if (-not $Certificates) {
            Write-Log "No certificates found in: $CertificatePath" -Level "WARNING"
            return
        }
        
        Write-Log "Found $($Certificates.Count) certificate(s) to deploy" -Level "INFO"
        
        foreach ($Cert in $Certificates) {
            Write-Log "Importing certificate: $($Cert.Name)" -Level "INFO"
            
            if ($DryRun) {
                Write-Log "[DRY RUN] Would import certificate: $($Cert.Name)" -Level "INFO"
                continue
            }
            
            try {
                # Import to Trusted Root CA store
                Import-Certificate -FilePath $Cert.FullName -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction Stop
                Write-Log "Certificate imported successfully: $($Cert.Name)" -Level "SUCCESS"
                $Global:Stats.CertificatesImported++
            }
            catch {
                Write-Log "Failed to import certificate: $($Cert.Name) - $_" -Level "ERROR"
            }
        }
    }
    catch {
        Write-Log "Exception deploying certificates: $_" -Level "ERROR"
    }
}

#endregion

#region VALIDATION & REPORTING
#==============================================================================

function Test-WiFiConfiguration {
    <#
    .SYNOPSIS
        Validates WiFi configuration after deployment
    #>
    
    Write-LogHeader "VALIDATING WIFI CONFIGURATION"
    
    try {
        # List all WiFi profiles
        Write-Log "Current WiFi profiles:" -Level "INFO"
        $ProfileList = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ':')[1].Trim()
        }
        
        if ($ProfileList) {
            foreach ($Profile in $ProfileList) {
                Write-Log "  ✓ $Profile" -Level "SUCCESS"
            }
        }
        else {
            Write-Log "  No profiles configured" -Level "WARNING"
        }
        
        # Check for available networks
        Write-Log " " -Level "INFO"
        Write-Log "Scanning for available networks..." -Level "INFO"
        
        $Result = netsh wlan show networks 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Network scan completed successfully" -Level "SUCCESS"
        }
        
    }
    catch {
        Write-Log "Exception during validation: $_" -Level "ERROR"
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
    Write-Log "WiFi Configuration Results:" -Level "INFO"
    Write-Log "  WiFi Adapters Found: $($Global:Stats.WiFiAdaptersFound)" -Level "INFO"
    Write-Log "  Profiles Deployed: $($Global:Stats.ProfilesDeployed)" -Level "SUCCESS"
    Write-Log "  Profiles Failed: $($Global:Stats.ProfilesFailed)" -Level $(if($Global:Stats.ProfilesFailed -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Certificates Imported: $($Global:Stats.CertificatesImported)" -Level "SUCCESS"
    
    Write-Log " " -Level "INFO"
    Write-Log "Status:" -Level "INFO"
    Write-Log "  Errors: $($Global:Stats.Errors)" -Level $(if($Global:Stats.Errors -gt 0){"ERROR"}else{"INFO"})
    Write-Log "  Warnings: $($Global:Stats.Warnings)" -Level $(if($Global:Stats.Warnings -gt 0){"WARNING"}else{"INFO"})
    
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
║        WIFI CONFIGURATION (TEMPLATE)                          ║
║                  Version $ScriptVersion                       ║
║                                                               ║
║  ⚠️  THIS IS A TEMPLATE - Customize before deployment!       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Start Time: $ScriptStartTime" -ForegroundColor White
    Write-Host "Mode: $(if($DryRun){'DRY RUN (simulation)'}else{'LIVE (applying changes)'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host ""
    
    Write-LogHeader "WIFI CONFIGURATION STARTED"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Computer Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "User: $env:USERNAME" -Level "INFO"
    Write-Log "Dry Run Mode: $DryRun" -Level "INFO"
    Write-Log " " -Level "INFO"
    Write-Log "⚠️  REMINDER: This is a TEMPLATE script!" -Level "WARNING"
    Write-Log "⚠️  Ensure you've customized WiFi profiles before production use!" -Level "WARNING"
    Write-Log " " -Level "INFO"
    
    # Prerequisites
    $PrereqResult = Test-Prerequisites
    
    if (-not $PrereqResult) {
        if ($Global:Stats.WiFiAdaptersFound -eq 0) {
            # No WiFi adapter found - this is OK for desktops
            Write-Log "No WiFi adapter detected - exiting gracefully (not an error)" -Level "INFO"
            Write-Log "This machine does not require WiFi configuration" -Level "SUCCESS"
            Show-ConfigurationSummary
            exit 0  # Success exit code (script ran correctly, just nothing to do)
        }
        else {
            # Other prerequisite failure
            Write-Log "Prerequisites failed - cannot continue" -Level "ERROR"
            exit 2
        }
    }
    
    # Remove existing profiles (if requested)
    Remove-ExistingWiFiProfiles
    
    # Deploy WiFi profiles
    Write-LogHeader "DEPLOYING WIFI PROFILES"
    
    # Check if XML profiles exist
    $UseXMLProfiles = $false
    if (Test-Path $WiFiProfilesPath) {
        $XMLFiles = Get-ChildItem -Path $WiFiProfilesPath -Filter "*.xml" -ErrorAction SilentlyContinue
        if ($XMLFiles) {
            Write-Log "Found $($XMLFiles.Count) XML profile(s) in: $WiFiProfilesPath" -Level "INFO"
            $UseXMLProfiles = $true
            
            # Import each XML profile
            foreach ($XMLFile in $XMLFiles) {
                Import-WiFiProfileFromXML -XMLFilePath $XMLFile.FullName
            }
        }
    }
    
    # Use built-in profiles if no XML files found
    if (-not $UseXMLProfiles) {
        Write-Log "No XML profiles found - using built-in profile definitions" -Level "INFO"
        Write-Log "⚠️  Remember to customize built-in profiles before production use!" -Level "WARNING"
        
        $BuiltInProfiles = Get-BuiltInWiFiProfiles
        
        foreach ($Profile in $BuiltInProfiles) {
            Deploy-WiFiProfile -Profile $Profile
        }
    }
    
    # Deploy certificates (if requested)
    Deploy-WiFiCertificates
    
    # Validate configuration
    Test-WiFiConfiguration
    
    # Summary
    Show-ConfigurationSummary
    
    # Determine exit code
    $ExitCode = if ($Global:Stats.Errors -eq 0) { 0 } else { 4 }
    
    Write-Log " " -Level "INFO"
    if ($ExitCode -eq 0) {
        Write-Log "WiFi configuration completed successfully!" -Level "SUCCESS"
    }
    else {
        Write-Log "WiFi configuration completed with $($Global:Stats.Errors) error(s)" -Level "ERROR"
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
