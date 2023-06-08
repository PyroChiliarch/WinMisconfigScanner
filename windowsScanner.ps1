Write-Host "########## Windows Security Checker ##########"
Write-Host "https://github.com/PyroChiliarch/WinMisconfigScanner"


####################### Priv Checks ########################
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin -eq $FALSE)
{
    Write-Host "Script requires elevated priveledges!"
    Write-Host "Please run this script as an administrator"
    Exit
}


Write-Host ""
Write-Host ""
####################### Get Generic Details ###########################
Write-Host "##### Computer Details #####"

$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem


$DeviceName = $ComputerSystem.Name
$CurUser = $ComputerSystem.UserName
$DomainName = $ComputerSystem.Domain
$PrimaryOwnerName = $ComputerSystem.PrimaryOwnerName

Write-Host "Computer Name : $DeviceName"
Write-Host "Current User : $CurUser"
Write-Host "Primary Owner Name : $PrimaryOwnerName"

Write-Host ""
Write-Host ""
####################### Check domain join status ###########################
Write-Host "##### Domain Details #####"



$DomainJoined = $FALSE
$DomainName = ""


$Workgroup = ""

$AzureJoined = $FALSE
$AzureTenant = ""
$AzureAccount = ""

### Domain Checks

$DomainName = $ComputerSystem.Domain
if ($DomainName -like "*.*") { #Test if workgroup or domain
  $DomainJoined = $TRUE
}


### Azure Checks
try 
{
    $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo" 2>$null
    $AzureJoined = TRUE
    $guids = $subKey.GetSubKeyNames()
    foreach($guid in $guids) {
        $guidSubKey = $subKey.OpenSubKey($guid);
        $AzureTenant = $guidSubKey.GetValue("TenantId");
        $AzureAccount = $guidSubKey.GetValue("UserEmail");
    }
}
catch {}



### Print Results

if ($DomainJoined)
{
    Write-Host "DomainJoined : TRUE" -ForegroundColor "Green"
    Write-Host "DomainName : $DomainName" -ForegroundColor "Green"
}
else
{
    Write-Host "DomainJoined : FALSE" -ForegroundColor "Yellow"
}


if ($AzureJoined)
{
    Write-Host "AzureJoined : TRUE" -ForegroundColor "Green"
    Write-Host "AzureTenant : $AzureTenant" -ForegroundColor "Green"
}
else
{
    Write-Host "AzureJoined : FALSE" -ForegroundColor "Yellow"
}

if (-NOT $DomainJoined -and -NOT $AzureJoined) {
    Write-Host "Device is not joined to any domain" -ForegroundColor "Red"
}


















Write-Host ""
Write-Host ""
####################### Check network misconfigurations ###########################
Write-Host "##### Network Configs #####"







Write-Host ""
Write-Host "##### LLMNR"
Write-Host "# https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/"
### LLMNR is disabled
$LLMNR = 1 #No value is on
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient").EnableMulticast 2>$null #Check if disabled
    $LLMNR = $Result
}
catch
{
    $LLMNR = 1 #Error on set will delete value
}

if ($LLMNR -eq $null -OR $LLMNR -eq 1)
{
    Write-Host "LLMNR Disabled: FALSE" -ForegroundColor "Red" -BackgroundColor White
}
else
{
    Write-Host "LLMNR Disabled: TRUE" -ForegroundColor "Green"
}










### mDNS is disabled

# Check if mDNS disabled in Registry
# Only Disables systems the use the Windows resolver, other such as chrome have a built in resolver
Write-Host ""
Write-Host "##### mDNS"
Write-Host "# https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777"
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\").EnableMDNS 2>$null
    $WindowsmDNS = $Result
} catch {}

if ($WindowsmDNS -eq $null -OR $mDNS -eq 1)
{
    Write-Host "Windows mDNS Disabled : FALSE" -ForegroundColor "Yellow"
}
else
{
    Write-Host "Windows mDNS Disabled : TRUE" -ForegroundColor "Green"
}



# Check if mDNS is disabled in firewall
# Programs such as chrome have a built in resolver
# Depending on the specific configuration any of the firewalls could be in use, so best to check all
$mDNSinPrivateEnabled = (Get-NetFirewallRule "MDNS-In-UDP-Private-Active").Enabled
$mDNSinPublicEnabled = (Get-NetFirewallRule "MDNS-In-UDP-Public-Active").Enabled
$mDNSinDomainEnabled = (Get-NetFirewallRule "MDNS-In-UDP-Domain-Active").Enabled

if ($mDNSinPrivateEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-In)`" Private Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-In)`" Private Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}

if ($mDNSinPublicEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-In)`" Public Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-In)`" Public Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}

if ($mDNSinDomainEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-In)`" Domain Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-In)`" Domain Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}



# Outbound Allow for mDNS is not does not allow any (known) vulnerabilities, but can lead to information leakage
$mDNSoutPrivateEnabled = (Get-NetFirewallRule "MDNS-Out-UDP-Private-Active").Enabled
$mDNSoutPublicEnabled = (Get-NetFirewallRule "MDNS-Out-UDP-Public-Active").Enabled
$mDNSoutDomainEnabled = (Get-NetFirewallRule "MDNS-Out-UDP-Domain-Active").Enabled

if ($mDNSoutPrivateEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-Out)`" Private Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-Out)`" Private Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}

if ($mDNSoutPublicEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-Out)`" Public Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-Out)`" Public Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}

if ($mDNSoutDomainEnabled -eq "False")
{
    Write-Host "`"mDNS (UDP-Out)`" Domain Firewall Allow Rule Enabled : FALSE" -ForegroundColor "Green"
}
else
{
    Write-Host "`"mDNS (UDP-Out)`" Domain Firewall Allow Rule Enabled : TRUE" -ForegroundColor "Red" -BackgroundColor White
}











Write-Host ""
Write-Host "##### SMB"
Write-Host "# https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102"
# Check if SMB signing is enabled and enforced
# Domain controllers use a different setting to enable SMB Signing, 
# workstations and standard servers count as SMB clients as far as settings go
# Client SMB Signing enabled
$clientSMBSigEnabled = 0
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters").EnableSecuritySignature 2>$null #Check if disabled
    $clientSMBSigEnabled = $Result
}
catch
{
    $clientSMBSigEnabled = 0 #Error on set will delete value
}

# Client SMB Signing enforced
$clientSMBSigEnforced = 0
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters").RequireSecuritySignature 2>$null #Check if disabled
    $clientSMBSigEnforced = $Result
}
catch
{
    $clientSMBSigEnforced = 0 #Error on set will delete value
}

# Server SMB signing enabled
$serverSMBSigEnabled = 0
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters").EnableSecuritySignature 2>$null #Check if disabled
    $serverSMBSigEnabled = $Result
}
catch
{
    $serverSMBSigEnabled = 0 #Error on set will delete value
}

# Server SMB signing enforced
$serverSMBSigEnforced = 0
try 
{
    $Result = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters").RequireSecuritySignature 2>$null #Check if disabled
    $serverSMBSigEnforced = $Result
}
catch
{
    $serverSMBSigEnforced = 0 #Error on set will delete value
}





### Output SMB signing findings

if ($OperatingSystem.ProductType -ne 2) # Device is not a domain controller
{
    if ($clientSMBSigEnabled -eq 1)
    {
        Write-Host "`"Client SMB signing enabled : TRUE" -ForegroundColor "Green"
    }
    else
    {
        Write-Host "`"Client SMB signing enabled : FALSE" -ForegroundColor "Red" -BackgroundColor White
    }
    
    if ($clientSMBSigEnforced -eq 1)
    {
        Write-Host "`"Client SMB signing enforced : TRUE" -ForegroundColor "Green"
    }
    else
    {
        Write-Host "`"Client SMB signing enforced : FALSE" -ForegroundColor "Red" -BackgroundColor White
    }
}
else # device is a domain controller, check Server settings
{
    if ($serverSMBSigEnabled -eq 1)
    {
        Write-Host "`"Server SMB signing enabled : TRUE" -ForegroundColor "Green"
    }
    else
    {
        Write-Host "`"Server SMB signing enabled : FALSE" -ForegroundColor "Red" -BackgroundColor White
    }


    if ($serverSMBSigEnforced -eq 1)
    {
        Write-Host "`"Server SMB signing enforced : TRUE" -ForegroundColor "Green"
    }
    else
    {
        Write-Host "`"Server SMB signing enforced : FALSE" -ForegroundColor "Red" -BackgroundColor White
    }
}








