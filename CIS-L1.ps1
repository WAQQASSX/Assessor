#Requires -RunAsAdministrator
# CIS Benchmark Level 1 - Windows 10 & 11 Auto-Remediation
# Run as Administrator:
#   PowerShell.exe -ExecutionPolicy Bypass -File ".\CIS-L1.ps1"

$ErrorActionPreference = "Continue"
$LogFile = ".\CIS-L1-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log {
    param([string]$msg, [string]$status = "INFO")
    $line = "[$(Get-Date -Format 'HH:mm:ss')][$status] $msg"
    Add-Content $LogFile $line
    switch ($status) {
        "PASS"  { Write-Host "  [PASS] $msg" -ForegroundColor Green }
        "FIX"   { Write-Host "  [FIX]  $msg" -ForegroundColor Cyan }
        "FAIL"  { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
        "SKIP"  { Write-Host "  [SKIP] $msg" -ForegroundColor DarkGray }
        "HEAD"  { Write-Host "`n--- $msg ---" -ForegroundColor Yellow }
        default { Write-Host "  $msg" -ForegroundColor Gray }
    }
}

function Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord", [string]$Desc)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $cur = $null
        try { $cur = (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch {}
        if ("$cur" -eq "$Value") {
            Log "$Desc" "PASS"
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Log "$Desc [was: $cur]" "FIX"
        }
    } catch {
        Log "$Desc [ERROR: $_]" "FAIL"
    }
}

function SecPol {
    param([string]$Section, [string]$Key, [string]$Value, [string]$Desc)
    try {
        $cfg = [IO.Path]::GetTempFileName() + ".cfg"
        $db  = [IO.Path]::GetTempFileName() + ".sdb"
        secedit /export /cfg $cfg /quiet 2>$null
        $raw = Get-Content $cfg -Raw
        if ($raw -match "(?m)^$([regex]::Escape($Key))\s*=\s*(.+)$") {
            $cur = $Matches[1].Trim()
            if ($cur -eq $Value) {
                Log "$Desc" "PASS"
                Remove-Item $cfg,$db -EA SilentlyContinue
                return
            }
            $raw = $raw -replace "(?m)^$([regex]::Escape($Key))\s*=\s*.+$", "$Key = $Value"
        } else {
            $raw = $raw -replace "\[$([regex]::Escape($Section))\]", "[$Section]`r`n$Key = $Value"
        }
        Set-Content $cfg $raw -Encoding Unicode
        secedit /configure /db $db /cfg $cfg /quiet 2>$null
        Log "$Desc" "FIX"
        Remove-Item $cfg,$db -EA SilentlyContinue
    } catch {
        Log "$Desc [ERROR: $_]" "FAIL"
    }
}

function Audit {
    param([string]$Sub, [bool]$S, [bool]$F, [string]$Desc)
    try {
        $sa = if ($S) { "/success:enable" } else { "/success:disable" }
        $fa = if ($F) { "/failure:enable" } else { "/failure:disable" }
        auditpol /set /subcategory:"$Sub" $sa $fa 2>$null | Out-Null
        Log "$Desc" "FIX"
    } catch {
        Log "$Desc [ERROR: $_]" "FAIL"
    }
}

function DisableSvc {
    param([string]$Name, [string]$Desc)
    $s = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $s) { Log "$Desc [not installed]" "SKIP"; return }
    if ($s.StartType -eq "Disabled") { Log "$Desc" "PASS"; return }
    try {
        Stop-Service $Name -Force -EA SilentlyContinue
        Set-Service  $Name -StartupType Disabled
        Log "$Desc" "FIX"
    } catch { Log "$Desc [ERROR: $_]" "FAIL" }
}

# ============================================================
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CIS Level 1 - Windows 10/11 Auto-Remediation" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Log: $LogFile" -ForegroundColor Gray
Write-Host ""

$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$isWin11 = $build -ge 22000
Log "OS: $($os.Caption) | Build: $build | $(if ($isWin11) {'Windows 11'} else {'Windows 10'})" "INFO"

# ============================================================
Log "SECTION 1 - Account Policies" "HEAD"
# ============================================================
SecPol "System Access" "PasswordHistorySize"   "24"  "1.1.1 Password history: 24"
SecPol "System Access" "MaximumPasswordAge"    "365" "1.1.2 Max password age: 365 days"
SecPol "System Access" "MinimumPasswordAge"    "1"   "1.1.3 Min password age: 1 day"
SecPol "System Access" "MinimumPasswordLength" "14"  "1.1.4 Min password length: 14"
SecPol "System Access" "PasswordComplexity"    "1"   "1.1.5 Password complexity: Enabled"
SecPol "System Access" "ClearTextPassword"     "0"   "1.1.6 Reversible encryption: Disabled"
SecPol "System Access" "LockoutDuration"       "15"  "1.2.1 Lockout duration: 15 min"
SecPol "System Access" "LockoutBadCount"       "5"   "1.2.2 Lockout threshold: 5 attempts"
SecPol "System Access" "ResetLockoutCount"     "15"  "1.2.3 Reset lockout counter: 15 min"

# ============================================================
Log "SECTION 2.2 - User Rights Assignment" "HEAD"
# ============================================================
SecPol "Privilege Rights" "SeNetworkLogonRight"             "*S-1-5-32-544,*S-1-5-32-551"           "2.2.1  Access from network: Admins+BackupOps"
SecPol "Privilege Rights" "SeTrustedCredManAccessPrivilege" ""                                       "2.2.2  Credential Manager trusted caller: No One"
SecPol "Privilege Rights" "SeTcbPrivilege"                  ""                                       "2.2.3  Act as OS: No One"
SecPol "Privilege Rights" "SeIncreaseQuotaPrivilege"        "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"     "2.2.4  Adjust memory quotas: LocalSvc/NetSvc/Admins"
SecPol "Privilege Rights" "SeInteractiveLogonRight"         "*S-1-5-32-544"                          "2.2.5  Log on locally: Admins"
SecPol "Privilege Rights" "SeRemoteInteractiveLogonRight"   "*S-1-5-32-544,*S-1-5-32-578"            "2.2.6  Log on via RDP: Admins+RDUsers"
SecPol "Privilege Rights" "SeBackupPrivilege"               "*S-1-5-32-544,*S-1-5-32-551"            "2.2.7  Back up files: Admins+BackupOps"
SecPol "Privilege Rights" "SeSystemTimePrivilege"           "*S-1-5-19,*S-1-5-32-544"                "2.2.8  Change system time: LocalSvc+Admins"
SecPol "Privilege Rights" "SeTimeZonePrivilege"             "*S-1-5-19,*S-1-5-32-544"                "2.2.9  Change time zone: LocalSvc+Admins"
SecPol "Privilege Rights" "SeCreatePagefilePrivilege"       "*S-1-5-32-544"                          "2.2.10 Create pagefile: Admins"
SecPol "Privilege Rights" "SeCreateTokenPrivilege"          ""                                       "2.2.11 Create token: No One"
SecPol "Privilege Rights" "SeCreateGlobalPrivilege"         "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"     "2.2.12 Create global objects: LocalSvc/NetSvc/Admins"
SecPol "Privilege Rights" "SeCreatePermanentPrivilege"      ""                                       "2.2.13 Create permanent objects: No One"
SecPol "Privilege Rights" "SeCreateSymbolicLinkPrivilege"   "*S-1-5-32-544"                          "2.2.14 Create symbolic links: Admins"
SecPol "Privilege Rights" "SeDebugPrivilege"                "*S-1-5-32-544"                          "2.2.15 Debug programs: Admins"
SecPol "Privilege Rights" "SeDenyNetworkLogonRight"         "*S-1-5-32-546"                          "2.2.16 Deny network access: Guests"
SecPol "Privilege Rights" "SeDenyBatchLogonRight"           "*S-1-5-32-546"                          "2.2.17 Deny batch logon: Guests"
SecPol "Privilege Rights" "SeDenyServiceLogonRight"         "*S-1-5-32-546"                          "2.2.18 Deny service logon: Guests"
SecPol "Privilege Rights" "SeDenyInteractiveLogonRight"     "*S-1-5-32-546"                          "2.2.19 Deny local logon: Guests"
SecPol "Privilege Rights" "SeDenyRemoteInteractiveLogonRight" "*S-1-5-32-546"                        "2.2.20 Deny RDP logon: Guests"
SecPol "Privilege Rights" "SeEnableDelegationPrivilege"     ""                                       "2.2.21 Enable delegation: No One"
SecPol "Privilege Rights" "SeRemoteShutdownPrivilege"       "*S-1-5-32-544"                          "2.2.22 Remote shutdown: Admins"
SecPol "Privilege Rights" "SeAuditPrivilege"                "*S-1-5-19,*S-1-5-20"                    "2.2.23 Generate audit events: LocalSvc+NetSvc"
SecPol "Privilege Rights" "SeImpersonatePrivilege"          "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"     "2.2.24 Impersonate client: LocalSvc/NetSvc/Admins"
SecPol "Privilege Rights" "SeIncreaseBasePriorityPrivilege" "*S-1-5-32-544"                          "2.2.25 Increase scheduling priority: Admins"
SecPol "Privilege Rights" "SeLoadDriverPrivilege"           "*S-1-5-32-544"                          "2.2.26 Load/unload drivers: Admins"
SecPol "Privilege Rights" "SeLockMemoryPrivilege"           ""                                       "2.2.27 Lock pages in memory: No One"
SecPol "Privilege Rights" "SeManageVolumePrivilege"         "*S-1-5-32-544"                          "2.2.28 Volume maintenance: Admins"
SecPol "Privilege Rights" "SeProfileSingleProcessPrivilege" "*S-1-5-32-544"                          "2.2.29 Profile single process: Admins"
SecPol "Privilege Rights" "SeSystemProfilePrivilege"        "*S-1-5-32-544"                          "2.2.30 Profile system performance: Admins"
SecPol "Privilege Rights" "SeAssignPrimaryTokenPrivilege"   "*S-1-5-19,*S-1-5-20"                    "2.2.31 Replace process token: LocalSvc+NetSvc"
SecPol "Privilege Rights" "SeRestorePrivilege"              "*S-1-5-32-544,*S-1-5-32-551"            "2.2.32 Restore files: Admins+BackupOps"
SecPol "Privilege Rights" "SeShutdownPrivilege"             "*S-1-5-32-544"                          "2.2.33 Shut down system: Admins"
SecPol "Privilege Rights" "SeTakeOwnershipPrivilege"        "*S-1-5-32-544"                          "2.2.34 Take ownership: Admins"

# ============================================================
Log "SECTION 2.3 - Security Options" "HEAD"
# ============================================================

# Guest account
try {
    $g = Get-LocalUser -Name "Guest" -EA SilentlyContinue
    if ($g -and $g.Enabled) { Disable-LocalUser -Name "Guest"; Log "2.3 Guest account: Disabled" "FIX" }
    else { Log "2.3 Guest account: Already disabled" "PASS" }
} catch { Log "2.3 Guest account [ERROR: $_]" "FAIL" }

# Rename built-in Administrator
try {
    $a = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($a -and $a.Name -eq "Administrator") {
        Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin"
        Log "2.3 Administrator renamed to LocalAdmin" "FIX"
    } else { Log "2.3 Administrator already renamed: $($a.Name)" "PASS" }
} catch { Log "2.3 Rename Administrator [ERROR: $_]" "FAIL" }

Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1 "DWord" "2.3.2.1 Force audit policy subcategories"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"            0 "DWord" "2.3.2.2 Do not shut down if audit log full"

Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"             0    "DWord" "2.3.7.1 Require CTRL+ALT+DEL"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" 1   "DWord" "2.3.7.2 Do not display last username"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"   900 "DWord" "2.3.7.3 Machine inactivity limit: 900 sec"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "Authorized Use Only" "String" "2.3.7.4 Logon banner title"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" "This system is for authorized users only." "String" "2.3.7.5 Logon banner text"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PasswordExpiryWarning"   14   "DWord" "2.3.7.6 Password expiry warning: 14 days"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ScRemoveOption"          "1"  "String" "2.3.7.7 Smart card removal: Lock workstation"

Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature"  1 "DWord" "2.3.8.1 Network client: Sign comms always"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1 "DWord" "2.3.8.2 Network client: Sign comms if agreed"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"  0 "DWord" "2.3.8.3 Network client: No plain-text passwords"

Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect"          15 "DWord" "2.3.9.1 Network server: Idle disconnect: 15 min"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature" 1 "DWord" "2.3.9.2 Network server: Sign comms always"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableSecuritySignature"  1 "DWord" "2.3.9.3 Network server: Sign comms if agreed"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableForcedLogOff"       1 "DWord" "2.3.9.4 Network server: Disconnect when hours expire"

Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"     1 "DWord" "2.3.10.1 No anonymous SAM enumeration"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"        1 "DWord" "2.3.10.2 No anonymous SAM+share enumeration"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0 "DWord" "2.3.10.3 Everyone excludes anonymous"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "AllowInsecureGuestAuth" 0 "DWord" "2.3.10.4 No insecure guest auth"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" "String" "2.3.10.5 Restrict remote SAM calls"

Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5 "DWord" "2.3.11.1 LAN Manager auth: NTLMv2 only"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"             1 "DWord" "2.3.11.2 Do not store LM hash"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "allownullsessionfallback" 0 "DWord" "2.3.11.3 No NULL session fallback"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NTLMMinClientSec" 537395200 "DWord" "2.3.11.4 NTLM min client security: NTLMv2+128bit"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NTLMMinServerSec" 537395200 "DWord" "2.3.11.5 NTLM min server security: NTLMv2+128bit"

Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" 0 "DWord" "2.3.13.1 No shutdown without logon"

Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" 1 "DWord" "2.3.15.1 UAC: Admin Approval Mode for built-in Admin"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2 "DWord" "2.3.15.2 UAC: Prompt for credentials on secure desktop"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser"  0 "DWord" "2.3.15.3 UAC: Auto-deny elevation for standard users"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"   1 "DWord" "2.3.15.4 UAC: Detect app installs"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths"       1 "DWord" "2.3.15.5 UAC: Elevate only secure UIAccess paths"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"                  1 "DWord" "2.3.15.6 UAC: Admin Approval Mode enabled"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"      1 "DWord" "2.3.15.7 UAC: Use secure desktop for prompt"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization"       1 "DWord" "2.3.15.8 UAC: Virtualize file/registry writes"

# ============================================================
Log "SECTION 9 - Windows Defender Firewall" "HEAD"
# ============================================================

# Domain Profile
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall"        1 "DWord" "9.1.1 Firewall Domain: On"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction"  1 "DWord" "9.1.2 Firewall Domain: Block inbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" 0 "DWord" "9.1.3 Firewall Domain: Allow outbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications"  0 "DWord" "9.1.4 Firewall Domain: Show notifications"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets"        1     "DWord"        "9.1.5 Firewall Domain: Log dropped"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" 0     "DWord"        "9.1.6 Firewall Domain: No log success"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize"              16384 "DWord"        "9.1.7 Firewall Domain: Log size 16384"

# Private Profile
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall"        1 "DWord" "9.2.1 Firewall Private: On"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction"  1 "DWord" "9.2.2 Firewall Private: Block inbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" 0 "DWord" "9.2.3 Firewall Private: Allow outbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications"  0 "DWord" "9.2.4 Firewall Private: Show notifications"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets"        1     "DWord"        "9.2.5 Firewall Private: Log dropped"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" 0     "DWord"        "9.2.6 Firewall Private: No log success"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize"              16384 "DWord"        "9.2.7 Firewall Private: Log size 16384"

# Public Profile
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall"        1 "DWord" "9.3.1 Firewall Public: On"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction"  1 "DWord" "9.3.2 Firewall Public: Block inbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" 0 "DWord" "9.3.3 Firewall Public: Allow outbound"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications"  0 "DWord" "9.3.4 Firewall Public: Show notifications"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets"        1     "DWord"        "9.3.5 Firewall Public: Log dropped"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" 0     "DWord"        "9.3.6 Firewall Public: No log success"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize"              16384 "DWord"        "9.3.7 Firewall Public: Log size 16384"

try { Set-NetFirewallProfile -Profile Domain  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}
try { Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}
try { Set-NetFirewallProfile -Profile Public  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}

# ============================================================
Log "SECTION 17 - Advanced Audit Policy" "HEAD"
# ============================================================
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1 "DWord" "17.0 Force advanced audit policy settings"

Audit "Credential Validation"                $true  $true  "17.1.1 Audit: Credential Validation"
Audit "Application Group Management"         $true  $true  "17.2.1 Audit: App Group Management"
Audit "Computer Account Management"          $true  $false "17.2.2 Audit: Computer Account Mgmt"
Audit "Other Account Management Events"      $true  $false "17.2.3 Audit: Other Account Mgmt"
Audit "Security Group Management"            $true  $false "17.2.4 Audit: Security Group Mgmt"
Audit "User Account Management"              $true  $true  "17.2.5 Audit: User Account Mgmt"
Audit "Plug and Play Events"                 $true  $false "17.3.1 Audit: PnP Events"
Audit "Process Creation"                     $true  $false "17.3.2 Audit: Process Creation"
Audit "Account Lockout"                      $false $true  "17.5.1 Audit: Account Lockout"
Audit "Group Membership"                     $true  $false "17.5.2 Audit: Group Membership"
Audit "Logon"                                $true  $true  "17.5.3 Audit: Logon"
Audit "Logoff"                               $true  $false "17.5.4 Audit: Logoff"
Audit "Other Logon/Logoff Events"            $true  $true  "17.5.5 Audit: Other Logon Events"
Audit "Special Logon"                        $true  $false "17.5.6 Audit: Special Logon"
Audit "Detailed File Share"                  $false $true  "17.6.1 Audit: Detailed File Share"
Audit "File Share"                           $true  $true  "17.6.2 Audit: File Share"
Audit "Other Object Access Events"           $true  $true  "17.6.3 Audit: Other Object Access"
Audit "Removable Storage"                    $true  $true  "17.6.4 Audit: Removable Storage"
Audit "Audit Policy Change"                  $true  $false "17.7.1 Audit: Policy Change"
Audit "Authentication Policy Change"         $true  $false "17.7.2 Audit: Auth Policy Change"
Audit "Authorization Policy Change"          $true  $false "17.7.3 Audit: Authz Policy Change"
Audit "MPSSVC Rule-Level Policy Change"      $true  $true  "17.7.4 Audit: MPSSVC Rule Change"
Audit "Other Policy Change Events"           $false $true  "17.7.5 Audit: Other Policy Change"
Audit "Sensitive Privilege Use"              $true  $true  "17.8.1 Audit: Sensitive Privilege Use"
Audit "IPsec Driver"                         $true  $true  "17.9.1 Audit: IPsec Driver"
Audit "Other System Events"                  $true  $true  "17.9.2 Audit: Other System Events"
Audit "Security State Change"                $true  $false "17.9.3 Audit: Security State Change"
Audit "Security System Extension"            $true  $false "17.9.4 Audit: Security System Ext"
Audit "System Integrity"                     $true  $true  "17.9.5 Audit: System Integrity"

# ============================================================
Log "SECTION 18 - Administrative Templates" "HEAD"
# ============================================================

# Control Panel
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"    1 "DWord" "18.1.1 No lock screen camera"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1 "DWord" "18.1.2 No lock screen slideshow"

# MS Security Guide
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"                         "UseLogonCredential"    0 "DWord" "18.4.1 WDigest: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"    "AllowProtectedCreds"   1 "DWord" "18.4.2 Allow delegation of non-exportable creds"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"                   "EnableAuthEpResolution" 1 "DWord" "18.4.3 RPC Endpoint Mapper Auth: Enabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"      "DisableExceptionChainValidation" 0 "DWord" "18.4.4 SEHOP: Enabled"

# MSS Legacy
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"  "DisableIPSourceRouting"    2 "DWord" "18.5.1 IPv4 source routing: Disabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"    2 "DWord" "18.5.2 IPv6 source routing: Disabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"  "EnableICMPRedirect"        0 "DWord" "18.5.3 ICMP redirects: Disabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"  "NoNameReleaseOnDemand"     1 "DWord" "18.5.4 No NetBIOS name release on demand"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"  "PerformRouterDiscovery"    0 "DWord" "18.5.5 Router discovery: Disabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"    "SafeDllSearchMode"         1 "DWord" "18.5.6 Safe DLL search mode: Enabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"    "ScreenSaverGracePeriod"    "0" "String" "18.5.7 Screen saver grace period: 0"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"  "TcpMaxDataRetransmissions" 3 "DWord" "18.5.8 TCP max retransmissions IPv4: 3"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "TcpMaxDataRetransmissions" 3 "DWord" "18.5.9 TCP max retransmissions IPv6: 3"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "WarningLevel" 90 "DWord" "18.5.10 Warning level: 90%"

# Network
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"      "NC_ShowSharedAccessUI" 0 "DWord" "18.6.1 No Internet Connection Sharing"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"     "fMinimizeConnections"  3 "DWord" "18.6.2 Minimize simultaneous connections"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition"     "ISATAP_State"  "Disabled" "String" "18.6.3 ISATAP: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition"     "6to4_State"    "Disabled" "String" "18.6.4 6to4: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition"     "Teredo_State"  "Disabled" "String" "18.6.5 Teredo: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"           "EnableMulticast" 0 "DWord" "18.6.6 LLMNR: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" "RequireMutualAuthentication=1,RequireIntegrity=1" "String" "18.6.7 Hardened UNC: NETLOGON"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL"   "RequireMutualAuthentication=1,RequireIntegrity=1" "String" "18.6.8 Hardened UNC: SYSVOL"

# System
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" 0 "DWord" "18.8.1 Offer Remote Assistance: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"   0 "DWord" "18.8.2 Solicited Remote Assistance: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"               "RestrictRemoteClients" 1 "DWord" "18.8.3 Restrict unauthenticated RPC clients"
Reg "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"            "DriverLoadPolicy"  3 "DWord" "18.8.4 Boot-start driver init: Good+unknown+bad critical"

# Windows Components
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"                      "NoAutoplayfornonVolume"  1   "DWord" "18.9.1  No AutoPlay for non-volume devices"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"       "NoAutorun"               1   "DWord" "18.9.2  AutoRun: Disabled"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"       "NoDriveTypeAutoRun"      255 "DWord" "18.9.3  AutoPlay: Disabled all drives"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\FVE"                                   "RDVDenyWriteAccess"      1   "DWord" "18.9.4  BitLocker: Deny write to unprotected removable"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Camera"                                "AllowCamera"             0   "DWord" "18.9.5  Camera: Disabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"                  "DisableWindowsConsumerFeatures" 1 "DWord" "18.9.6  No consumer experiences"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"                        "DisablePasswordReveal"   1   "DWord" "18.9.7  No password reveal button"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"                        "EnumerateAdministrators" 0   "DWord" "18.9.8  No admin enumeration on elevation"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                "AllowTelemetry"          1   "DWord" "18.9.9  Telemetry: Required only"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                "DisableEnterpriseAuthProxy" 1 "DWord" "18.9.10 No auth proxy for telemetry"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                "DoNotShowFeedbackNotifications" 1 "DWord" "18.9.11 No feedback notifications"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                "LimitDiagnosticLogCollection" 1 "DWord" "18.9.12 Limit diagnostic log collection"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                "LimitDumpCollection"     1   "DWord" "18.9.13 Limit dump collection"

# Event Log Sizes
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize"   32768  "DWord"  "18.9.14 App event log: 32768 KB"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0"    "String" "18.9.14 App event log: Overwrite as needed"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"    "MaxSize"   196608 "DWord"  "18.9.15 Security log: 196608 KB"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"    "Retention" "0"    "String" "18.9.15 Security log: Overwrite as needed"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"       "MaxSize"   32768  "DWord"  "18.9.16 Setup event log: 32768 KB"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"       "Retention" "0"    "String" "18.9.16 Setup event log: Overwrite as needed"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"      "MaxSize"   32768  "DWord"  "18.9.17 System event log: 32768 KB"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"      "Retention" "0"    "String" "18.9.17 System event log: Overwrite as needed"

# File Explorer
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"                      "NoDataExecutionPrevention"      0 "DWord" "18.9.18 Explorer DEP: Enabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"                      "NoHeapTerminationOnCorruption"  0 "DWord" "18.9.19 Heap termination on corruption: Enabled"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"       "PreXPSP2ShellProtocolBehavior"  0 "DWord" "18.9.20 Shell protected mode: Enabled"

# Location
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 "DWord" "18.9.21 Location: Disabled"

# OneDrive
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1 "DWord" "18.9.22 OneDrive file sync: Disabled"

# Remote Desktop
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"  1      "DWord" "18.9.23 RDP: NLA required"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"  3      "DWord" "18.9.24 RDP: Encryption high"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"  1      "DWord" "18.9.25 RDP: Always prompt for password"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime" 60000 "DWord" "18.9.26 RDP: Disconnect after 1 min idle"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"         900000 "DWord" "18.9.27 RDP: End session after 15 min idle"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fSingleSessionPerUser" 1    "DWord" "18.9.28 RDP: One session per user"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit"  1    "DWord" "18.9.29 RDP: Delete temp folders on exit"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir"     1    "DWord" "18.9.30 RDP: Unique temp folder per session"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic"    1    "DWord" "18.9.31 RDP: Encrypt RPC traffic"

# Search
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" 0 "DWord" "18.9.32 No indexing encrypted files"

# SmartScreen
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"  1       "DWord"  "18.9.33 SmartScreen: Enabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Block" "String" "18.9.34 SmartScreen: Block"

# WinRM Client
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"            0 "DWord" "18.9.35 WinRM Client: No Basic auth"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" 0 "DWord" "18.9.36 WinRM Client: No unencrypted traffic"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest"           0 "DWord" "18.9.37 WinRM Client: No Digest auth"

# WinRM Service
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"             0 "DWord" "18.9.38 WinRM Service: No Basic auth"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" 0 "DWord" "18.9.39 WinRM Service: No unencrypted traffic"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs"            1 "DWord" "18.9.40 WinRM Service: No RunAs"

# Windows Defender
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"                          "DisableAntiSpyware"         0 "DWord" "18.9.41 Defender: AntiSpyware on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"     "DisableBehaviorMonitoring"  0 "DWord" "18.9.42 Defender: Behavior monitoring on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"     "DisableIOAVProtection"      0 "DWord" "18.9.43 Defender: Scan downloads on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"     "DisableRealtimeMonitoring"  0 "DWord" "18.9.44 Defender: Real-time protection on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"     "DisableScriptScanning"      0 "DWord" "18.9.45 Defender: Script scanning on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"                   "DisableBlockAtFirstSeen"    0 "DWord" "18.9.46 Defender: Block at first seen on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"                   "SpynetReporting"            2 "DWord" "18.9.47 Defender: MAPS advanced membership"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"                   "SubmitSamplesConsent"       1 "DWord" "18.9.48 Defender: Send safe samples"

# ============================================================
Log "SECTION 19 - User Configuration Templates" "HEAD"
# ============================================================
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"                              "AllowGameDVR"            0   "DWord" "19.1.1 Game DVR: Disabled"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"           "SaveZoneInformation"     1   "DWord" "19.2.1 Preserve zone info in attachments"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"           "HideZoneInfoOnProperties" 1  "DWord" "19.2.2 Hide zone removal mechanism"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"              "NoDriveTypeAutoRun"      255 "DWord" "19.3.1 AutoPlay disabled all drives (user)"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"                             "DisableSearchBoxSuggestions" 1 "DWord" "19.5.1 No search box suggestions"

# ============================================================
Log "SERVICES - Disable insecure services" "HEAD"
# ============================================================
DisableSvc "RemoteRegistry"      "Remote Registry"
DisableSvc "Browser"             "Computer Browser"
DisableSvc "SSDPSRV"             "SSDP Discovery"
DisableSvc "upnphost"            "UPnP Device Host"
DisableSvc "SharedAccess"        "Internet Connection Sharing"
DisableSvc "Fax"                 "Fax Service"
DisableSvc "irmon"               "Infrared Monitor"
DisableSvc "TlntSvr"             "Telnet Server"
DisableSvc "simptcp"             "Simple TCP/IP Services"
DisableSvc "FTPSVC"              "FTP Publishing Service"
DisableSvc "W3SVC"               "World Wide Web Publishing (IIS)"
DisableSvc "WMSvc"               "IIS Web Management Service"
DisableSvc "XboxGipSvc"          "Xbox Accessory Management"
DisableSvc "XblAuthManager"      "Xbox Live Auth Manager"
DisableSvc "XblGameSave"         "Xbox Live Game Save"
DisableSvc "XboxNetApiSvc"       "Xbox Live Networking"

# ============================================================
Log "FEATURES - Disable SMBv1, PowerShell v2, Telnet" "HEAD"
# ============================================================
$featureList = @(
    "SMB1Protocol",
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2",
    "TelnetClient",
    "TFTP"
)
foreach ($feat in $featureList) {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -EA SilentlyContinue
        if ($f -and $f.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -EA Stop | Out-Null
            Log "Feature disabled: $feat" "FIX"
        } elseif ($f) {
            Log "Feature already disabled: $feat" "PASS"
        } else {
            Log "Feature not found: $feat" "SKIP"
        }
    } catch { Log "Feature $feat [ERROR: $_]" "FAIL" }
}

# SMBv1 via registry
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 "DWord" "SMBv1 registry: Disabled"
Reg "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4 "DWord" "SMBv1 driver: Disabled"

# ============================================================
Log "POWERSHELL - Logging and execution policy" "HEAD"
# ============================================================
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"                    "EnableScripts"    1            "DWord"  "PS: Script execution enabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"                    "ExecutionPolicy"  "RemoteSigned" "String" "PS: Execution policy: RemoteSigned"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"           1 "DWord" "PS: Script block logging on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockInvocationLogging" 1 "DWord" "PS: Invocation logging on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"      "EnableTranscripting"   1 "DWord" "PS: Transcription on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"      "EnableInvocationHeader" 1 "DWord" "PS: Invocation header on"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"      "EnableModuleLogging"    1 "DWord" "PS: Module logging on"

# ============================================================
Log "SCREEN LOCK - Screensaver and idle timeout" "HEAD"
# ============================================================
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive"    "1"   "String" "Screen saver: Enabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" "1"   "String" "Screen saver: Password protected"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut"   "900" "String" "Screen saver: Timeout 900 sec"
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 900 "DWord"  "Machine inactivity timeout: 900 sec"

# ============================================================
Log "WINDOWS UPDATE - Auto-update settings" "HEAD"
# ============================================================
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"            0 "DWord" "WU: Auto updates enabled"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"               4 "DWord" "WU: Auto-install and schedule restart"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AutoInstallMinorUpdates" 1 "DWord" "WU: Auto-install minor updates"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    "DeferFeatureUpdates"            1   "DWord" "WU: Defer feature updates"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    "DeferFeatureUpdatesPeriodInDays" 180 "DWord" "WU: Feature update deferral: 180 days"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    "DeferQualityUpdates"             0   "DWord" "WU: Quality updates not deferred"
Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    "SetDisablePauseUXAccess"         1   "DWord" "WU: Users cannot pause updates"

# ============================================================
Log "ADDITIONAL - LSASS, TLS, SCHANNEL, NetBIOS" "HEAD"
# ============================================================

# Credential Guard + LSASS PPL
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"    1 "DWord" "LSASS: Protected Process Light"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags" 1 "DWord" "Credential Guard: Enabled with UEFI lock"

# Disable weak TLS/SSL
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" "Enabled" 0 "DWord" "SCHANNEL: Disable SSL 2.0 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" "DisabledByDefault" 1 "DWord" "SCHANNEL: SSL 2.0 client disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" "Enabled" 0 "DWord" "SCHANNEL: Disable SSL 2.0 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" "DisabledByDefault" 1 "DWord" "SCHANNEL: SSL 2.0 server disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" "Enabled" 0 "DWord" "SCHANNEL: Disable SSL 3.0 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" "DisabledByDefault" 1 "DWord" "SCHANNEL: SSL 3.0 client disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" "Enabled" 0 "DWord" "SCHANNEL: Disable SSL 3.0 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" "DisabledByDefault" 1 "DWord" "SCHANNEL: SSL 3.0 server disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" "Enabled" 0 "DWord" "SCHANNEL: Disable TLS 1.0 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" "DisabledByDefault" 1 "DWord" "SCHANNEL: TLS 1.0 client disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled" 0 "DWord" "SCHANNEL: Disable TLS 1.0 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "DisabledByDefault" 1 "DWord" "SCHANNEL: TLS 1.0 server disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" "Enabled" 0 "DWord" "SCHANNEL: Disable TLS 1.1 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" "DisabledByDefault" 1 "DWord" "SCHANNEL: TLS 1.1 client disabled by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled" 0 "DWord" "SCHANNEL: Disable TLS 1.1 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "DisabledByDefault" 1 "DWord" "SCHANNEL: TLS 1.1 server disabled by default"

# Enable TLS 1.2 and 1.3
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" "Enabled" 1 "DWord" "SCHANNEL: Enable TLS 1.2 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" "DisabledByDefault" 0 "DWord" "SCHANNEL: TLS 1.2 client on by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "Enabled" 1 "DWord" "SCHANNEL: Enable TLS 1.2 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "DisabledByDefault" 0 "DWord" "SCHANNEL: TLS 1.2 server on by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" "Enabled" 1 "DWord" "SCHANNEL: Enable TLS 1.3 client"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" "DisabledByDefault" 0 "DWord" "SCHANNEL: TLS 1.3 client on by default"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" "Enabled" 1 "DWord" "SCHANNEL: Enable TLS 1.3 server"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" "DisabledByDefault" 0 "DWord" "SCHANNEL: TLS 1.3 server on by default"

# Disable weak ciphers
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"           "Enabled" 0 "DWord" "Cipher: Disable NULL"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"      "Enabled" 0 "DWord" "Cipher: Disable DES 56/56"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"     "Enabled" 0 "DWord" "Cipher: Disable RC2 40/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"     "Enabled" 0 "DWord" "Cipher: Disable RC2 56/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"    "Enabled" 0 "DWord" "Cipher: Disable RC2 128/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"     "Enabled" 0 "DWord" "Cipher: Disable RC4 40/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"     "Enabled" 0 "DWord" "Cipher: Disable RC4 56/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"     "Enabled" 0 "DWord" "Cipher: Disable RC4 64/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"    "Enabled" 0 "DWord" "Cipher: Disable RC4 128/128"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" "Enabled" 0 "DWord" "Cipher: Disable 3DES"

# Spectre/Meltdown
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"     0 "DWord" "Spectre/Meltdown: Override=0"
Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" 3 "DWord" "Spectre/Meltdown: Mask=3"

# Disable NetBIOS over TCP on all adapters
try {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    foreach ($a in $adapters) {
        $a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} -EA SilentlyContinue | Out-Null
    }
    Log "NetBIOS over TCP: Disabled on all adapters" "FIX"
} catch { Log "NetBIOS disable [ERROR: $_]" "FAIL" }

# Kerberos encryption
Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" 2147483640 "DWord" "Kerberos: AES128/AES256 only"

# Windows 11 specific
if ($isWin11) {
    Log "WINDOWS 11 SPECIFIC CONTROLS" "HEAD"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"          "AllowCrossDeviceClipboard"  0 "DWord" "Win11: No cross-device clipboard"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"  "AllowDeviceNameInTelemetry" 0 "DWord" "Win11: No device name in telemetry"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"     "DisableSettingSync"         2 "DWord" "Win11: Disable settings sync"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"     "DisableSettingSyncUserOverride" 1 "DWord" "Win11: Users cannot override sync"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"                     "AllowNewsAndInterests"      0 "DWord" "Win11: Disable Widgets"
    Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"    "ChatIcon"                   3 "DWord" "Win11: Remove Chat from taskbar"
    if ($build -ge 26100) {
        Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" 1 "DWord" "Win11: Disable Recall"
    }
}

# ============================================================
# SUMMARY
# ============================================================
$pass = (Select-String -Path $LogFile -Pattern "\[PASS\]").Count
$fix  = (Select-String -Path $LogFile -Pattern "\[FIX\]").Count
$fail = (Select-String -Path $LogFile -Pattern "\[FAIL\]").Count
$skip = (Select-String -Path $LogFile -Pattern "\[SKIP\]").Count
$total = $pass + $fix + $fail + $skip
$rate = if ($total -gt 0) { [math]::Round(($pass + $fix) / $total * 100, 1) } else { 0 }

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  COMPLETE - Compliance Rate: $rate%" -ForegroundColor Cyan
Write-Host "  Already OK : $pass" -ForegroundColor Green
Write-Host "  Fixed      : $fix"  -ForegroundColor Cyan
Write-Host "  Failed     : $fail" -ForegroundColor Red
Write-Host "  Skipped    : $skip" -ForegroundColor DarkGray
Write-Host "  Log saved  : $LogFile" -ForegroundColor Gray
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  REBOOT REQUIRED for all changes to take effect." -ForegroundColor Yellow
Write-Host ""

$r = Read-Host "  Reboot now? (Y/N)"
if ($r -match "^[Yy]") { Restart-Computer -Force }
