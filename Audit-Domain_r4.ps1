<#
.NAME
  Audit-Domain

.SYNOPSIS

  Performs an audit on an Active Directory Domain, DNS and DHCP and reports key configuration settings in to a main text file and several supporting files.

.SYNTAX
  This script is intended to be run on a Domain Controller in a PowerShell window
  PowerShell should be run as Administrator as modules will need to be loaded
  It is recomended that the script file (and its supporting file) be coppied to a folder on C-Drive called PS (MD C:\PS)
  Change the PowerShell Working Directory to this folder (CD C:\PS)

  In preparation, the "OtherDNS-servers.txt" file should be edited and the hostname of all other DNS Servers in the domain be listed, one per line

  .\Audit-Domain.ps1


.DESCRIPTION

  .




.PARAMETER <Parameter_Name>

  .



.INPUTS

  Supporting Input Files: 
	 - Get-NoSettingsGPO.ps1
	 - Get-ServerDNS.ps1
	 - Get-UnlinkedGPO.ps1
	 - OtherDNS-servers.txt  - Add hostnames or IP Addresses of other DNS Servers in the organisation



.OUTPUTS
	Output Files are stored in a Subfolder called DomainAudit_Date
	The main output file is called "DomainAudit_ClientName_Date.txt"
	Several other supporting Text / CSV Files are created, including:
	 - ActiveUsers.txt
	 - PasswordNeverExpires.txt
	 - SecurityGroups.txt
	 - dcdiag_SERVERNAME.txt (Multiple Files - 1 Per DC)
	 - GPOReportsAll.html
	 - DNS_Server_FullDetails.txt




.NOTES

  Author:         Jay Hallsworth
  Creation Date:  17th April 2018

  Version:        r4.0
  Editor:         Jay Hallsworth
  Modified Date:  30th Aug 2019
  Purpose/Change: Remove Refereences to FL & FT

.EXAMPLE

  .\Audit-Domain.ps1

#>


#Requires -RunAsAdministrator

 Clear-Host

#Collect Info and Set Output File
 Clear-Host
write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
write-host "~~~~~~~~~~~~~~~~     Active Directory Audit      ~~~~~~~~~~~~~~~~"
write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
write-host " "
whoami 
write-host " "
$ClientName = read-host "Client Name"
$Location = read-host "Client Site"
$ConsultantName = read-host "Consultants Name"
$AuditDate = get-date -DisplayHint Date

$ClientNoSPace = $ClientName.replace(' ','')
$AuditMonth = get-date -Format MMM
$AuditYear = get-date -Format yy
$OutputFolder = "DomainAudit_"+$AuditMonth+$AuditYear
mkdir $OutputFolder


$OutputFile = "$PWD\$OutputFolder\AD_Audit_"+$ClientNoSPace+"_"+$AuditMonth+$AuditYear+".txt"

#Write To File
Add-Content -Path $OutputFile -Value " "
Add-Content -Path $OutputFile -Value "##################################################################### "
Add-Content -Path $OutputFile -Value "##################################################################### "
Add-Content -Path $OutputFile -Value "##################                                 ################## "
Add-Content -Path $OutputFile -Value "##################     Active Directory Audit      ################## "
Add-Content -Path $OutputFile -Value "##################                                 ################## "
Add-Content -Path $OutputFile -Value "##################################################################### "
Add-Content -Path $OutputFile -Value "##################################################################### "
Add-Content -Path $OutputFile -Value " "
Add-Content -Path $OutputFile -Value " "
Add-Content -Path $OutputFile -Value $ClientName
Add-Content -Path $OutputFile -Value $Location
Add-Content -Path $OutputFile -Value " "
Add-Content -Path $OutputFile -Value "Audit By $ConsultantName"
Add-Content -Path $OutputFile -Value "Audit Date: $AuditDate"
Add-Content -Path $OutputFile -Value " "


#####################################################################
#Import AD, DHCP, DNS and GPO Modules if they are not already there #
#####################################################################

if (Get-Module -Name ActiveDirectory) {
# Clear-Host
write-host " "
    Write-Host "ActiveDirectory Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
# Clear-Host
write-host " "
    Write-Host "Installing ActiveDirectory Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name ActiveDirectory -Force
Import-Module -Name ActiveDirectory -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}


$DHCPServer = Get-Service | where-object { $_.Name -like "*DHCPServer*" }
if ($Null -eq $DHCPServer) { $IsDHCPServer = $False } else { $IsDHCPServer = $True }

If ($IsDHCPServer -eq $True) {


  if (Get-Module -Name DhcpServer) {
    # Clear-Host
    write-host " "
    Write-Host "DhcpServer Module exists" -ForegroundColor black -BackgroundColor Green
    write-host " "
  }
  else {
    # Clear-Host
    write-host " "
    Write-Host "Installing DhcpServer Module..." -ForegroundColor black -BackgroundColor Green
    #Install-module -name DhcpServer -Force
    Import-Module -Name DhcpServer -Force

    Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
    write-host " "
  }
}




if (Get-Module -Name DnsServer) {
# Clear-Host
write-host " "
    Write-Host "DnsServer Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
# Clear-Host
write-host " "
    Write-Host "Installing DnsServer Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name DnsServer -Force
Import-Module -Name DnsServer -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}

if (Get-Module -Name GroupPolicy) {
# Clear-Host
write-host " "
    Write-Host "GroupPolicy Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
# Clear-Host
write-host " "
    Write-Host "Installing GroupPolicy Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name GroupPolicy -Force
Import-Module -Name GroupPolicy -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}

#####################################################################
#Checks for additional scripts that are called from this script     #
#####################################################################

#Get-UnlinkedGPO.ps1 - https://gallery.technet.microsoft.com/Get-Unlinked-Group-Policy-4dda4aa3 
#Get-NoSettingsGPO.ps1 - https://gallery.technet.microsoft.com/Get-Group-Policy-Objects-baaf5f61 
#Get-ServerDNS.ps1 - From Jay
#OtherDNS-servers.txt - Create / Edit a list of DNS Servers

#This script needs Get-UnlinkedGPO.ps1 in the same folder
# - https://gallery.technet.microsoft.com/Get-Unlinked-Group-Policy-4dda4aa3  
if (-NOT (Test-Path "$Pwd\Get-UnlinkedGPO.ps1")) {

write-host "This script needs Get-UnlinkedGPO.ps1"
write-host "It can be downloaded from here: "
write-host "https://gallery.technet.microsoft.com/Get-Unlinked-Group-Policy-4dda4aa3 "
pause
exit
}

#This script needs Get-NoSettingsGPO.ps1 in the same folder
# - https://gallery.technet.microsoft.com/Get-Group-Policy-Objects-baaf5f61 

if (-NOT (Test-Path "$Pwd\Get-NoSettingsGPO.ps1")) {

write-host "This script needs Get-NoSettingsGPO.ps1"
write-host "It can be downloaded from here: "
write-host "https://gallery.technet.microsoft.com/Get-Group-Policy-Objects-baaf5f61 "
pause
exit
}

#This script needs Get-ServerDNS.ps1 in the same folder
#Get this file from Jay
if (-NOT (Test-Path "$Pwd\Get-ServerDNS.ps1")) {

write-host "This script needs Get-ServerDNS.ps1"
write-host "It should be in the ZIP File, if not, get it from Jay "
#write-host "https://gallery.technet.microsoft.com/ "
pause
exit
}

#This script needs OtherDNS-servers.txt in the same folder
#Create a text file and list Other DNS Servers
#In future I will create this file automatically

if (-NOT (Test-Path "$Pwd\OtherDNS-servers.txt")) {

    write-host "This script needs OtherDNS-servers.txt"
    write-host "Please create this file and add the hostnames of all other DNS Servers in the Domain "
    #write-host "https://gallery.technet.microsoft.com/ "
    pause
    exit
    }



#####################################################################
#Begin Script                                                       #
#####################################################################




Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~     Active Directory Details     ~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content -Path $OutputFile -Value " "


Add-Content $OutputFile 'Forest Details'
Add-Content $OutputFile "--------------"
Get-ADForest | Select-Object Name, RootDomain, ForestMode, Domains, SchemaMaster, DomainNamingMaster, Sites | Out-File $OutputFile -NoClobber -Append -Encoding ascii

$UPNs = (Get-ADForest).UPNSuffixes
$NumberOfUPNs = "There Are " + $UPNs.count + " UPN Suffix's in the forest: "
Add-Content $OutputFile $NumberOfUPNs
(Get-ADForest).UPNSuffixes | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile " "
Add-Content $OutputFile 'Domain Details'
Add-Content $OutputFile "--------------"
Get-ADDomain | Select-Object Name, NetBIOSName, DomainMode, DNSRoot, PDCEmulator, RIDMaster, InfrastructureMaster | Out-File $OutputFile -NoClobber -Append -Encoding ascii


Add-Content $OutputFile 'AD Sites'
Add-Content $OutputFile "--------"

$Sites =(Get-ADForest).sites
$NumberOfSites = "There Are " + $Sites.count + " sites in the forest: "
Add-Content $OutputFile $NumberOfSites
(Get-ADForest).sites | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile " "
Add-Content $OutputFile "Subnets"

$Subnets = Get-ADReplicationSubnet -Filter *
$NumberOfSubnets = "There Are " + $Subnets.count + " Subnets: "
Add-Content $OutputFile $NumberOfSubnets
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile 'Site Links'
Get-ADReplicationSiteLink -filter * | Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded | Out-File $OutputFile -NoClobber -Append -Encoding ascii





Add-Content $OutputFile " "
Add-Content $OutputFile "Trusts"
Add-Content $OutputFile "------"
$Trusts = Get-ADTrust -Filter *
 if ($null -eq $Trusts) {Add-Content $OutputFile "There Are No Trusts"} else {$Trusts | Select-Object * | Out-File $OutputFile -NoClobber -Append -Encoding ascii}



Add-Content $OutputFile " "
Add-Content $OutputFile "Fine Grain Password Policy"
Add-Content $OutputFile "--------------------------"
$FGPP = Get-ADFineGrainedPasswordPolicy -Filter *
 if ($null -eq $FGPP) {Add-Content $OutputFile "There Are No Fine Grain Password Policies"} else {$FGPP | Select-Object * | Out-File $OutputFile -NoClobber -Append -Encoding ascii}




#########################################################################################
Add-Content $OutputFile " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     Domain Controllers     ~~~~~~~~~~~~~~~"

$GCs = (Get-ADForest).GlobalCatalogs
$NumberOfGCs = "There are " + $GCs.Count + " GCs In The Forest:"
Add-Content $OutputFile $NumberOfGCs
$GCs | Out-File $OutputFile -NoClobber -Append -Encoding ascii

(Get-ADForest).GlobalCatalogs | .\Get-ServerDNS.ps1 | Out-File $OutputFile -NoClobber -Append -Encoding ascii

#This typically errors with DC's that aren't ready for remote powershell
foreach ($GC in $GCs) {

Get-ADDomainController -Server $GC | Select-Object Site, Name, IsGlobalCatalog, IsReadOnly, IPv4Address | Out-File $OutputFile -NoClobber -Append -Encoding ascii

}

#This typically errors with DC's that aren't ready for remote powershell
foreach ($GC in $GCs) {

Get-ADDomainController -Server $GC | Select-Object HostName, OperatingSystem, OperatingSystemHotfix, OperatingSystemServicePack, OperatingSystemVersion | Out-File $OutputFile -NoClobber -Append -Encoding ascii

}

Add-Content $OutputFile "ReplicaDirectoryServer In The Domain"
(Get-ADDomain).ReplicaDirectoryServers | Out-File $OutputFile -NoClobber -Append -Encoding ascii

#########################################################################################
#Run DCDIAG for all Global Catalog DCs                                                  #
#########################################################################################
Add-Content $OutputFile " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     DCDIAG Results     ~~~~~~~~~~~~~~~"

$globalcatalogs = (Get-ADForest).globalcatalogs
foreach ($globalcatalog in $globalcatalogs) {
$globalcatalog
$OutFile = ".\"+$OutputFolder+"\dcdiag_" + $globalcatalog + ".txt"
dcdiag /S:$globalcatalog /V > $OutFile
$DGDiagMessage = "DCDIAG has been run on " + $globalcatalog + " And the output saved to " + $OutFile
Add-Content $OutputFile $DGDiagMessage

 }

Add-Content $OutputFile " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     Repadmin Results     ~~~~~~~~~~~~~~~"

foreach ($globalcatalog in $globalcatalogs) {

    $Repadmin = Repadmin /showrepl $globalcatalog
    Add-Content $OutputFile "Repadmin /ShowRepl $globalcatalog"
    Add-Content $OutputFile " "
    Add-Content $OutputFile $Repadmin
    Add-Content $OutputFile " "
    }

#########################################################################################
Add-Content $OutputFile " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     Users & Groups     ~~~~~~~~~~~~~~~"
$Users = @(Get-ADUser -Filter *)
$NumberOfUsers = "There are " + $Users.Count + " User Accounts In Total"
Add-Content $OutputFile $NumberOfUsers
$InactiveUsers = search-adaccount -accountinactive -usersonly -timespan "105"
$NumberOfInactiveUsers = " - Of which approximatly " + $InactiveUsers.Count + " have been inactive for 90 days"
Add-Content $OutputFile $NumberOfInactiveUsers

$ActiveUsers = (Get-ADUser -Filter * -Properties Enabled, AccountExpirationDate, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath |Sort-Object -Property LastLogonDate -Descending | Where-Object { ($_.Enabled -EQ $True) -OR `
$_.LastLogonDate -NE $NULL -AND $_.LastLogonDate -GE (Get-Date).AddDays(-90) })

#$ActiveUsers | Select-Object  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath | Out-File $OutputFile -NoClobber -Append
#Do we want this to go in to the audit file, or to a separate CSV???
#$ActiveUsers | Select-Object  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath | export-csv -path "$PWD\ActiveUsers.csv" -NoTypeInformation
$ActiveUsers | Select-Object  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath | Out-File -FilePath "$PWD\$OutputFolder\ActiveUsers.txt" -NoClobber -Append -Encoding ascii
Add-Content -Path $OutputFile -Value "A list of Active Users has been output to the ActiveUsers.txt file "

Add-Content $OutputFile " "
Add-Content $OutputFile "Users With Password Never Expires"
$UsersWithPwdNeverExpires = Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)}
$NumberOfUsersWithPwdNeverExpires = "There are " + $UsersWithPwdNeverExpires.count + " Users with password never expires"
Add-Content $OutputFile $NumberOfUsersWithPwdNeverExpires
if($NumberOfUsersWithPwdNeverExpires -gt 25) {
    Get-ADUser -properties * -filter { (PasswordNeverExpires -eq $true) } | Select-Object SamAccountName, PasswordNeverExpires, PasswordLastSet | Out-File "$PWD\$OutputFolder\PasswordNeverExpires.txt" -NoClobber -Append -Encoding ascii 
#Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | Select-Object SamAccountName, PasswordNeverExpires, PasswordLastSet | export-csv -path "$PWD\PasswordNeverExpires.csv" -NoTypeInformation
Add-Content -Path $OutputFile -Value "A list of Users with password never expires has been output to the PasswordNeverExpires.txt file "
} else {Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | Select-Object SamAccountName, PasswordNeverExpires, PasswordLastSet | Out-File $OutputFile -NoClobber -Append -Encoding ascii 
}

Add-Content $OutputFile "Domain Admin Security Group Members"
$DomainAdmins = Get-ADGroupMember -ID "Domain Admins" -Recursive
$NumberOfDomainAdmins = "There are " + $DomainAdmins.count + " Users In The Domain Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfDomainAdmins
Get-ADGroupMember -ID "Domain Admins" -Recursive | Select-Object Name | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Enterprise Admin Security Group Members"
$EnterpriseAdmins = Get-ADGroupMember -ID "Enterprise Admins" -Recursive
$NumberOfEnterpriseAdmins = "There are " + $EnterpriseAdmins.count + " Users In The Enterprise Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfEnterpriseAdmins
Get-ADGroupMember -ID "Enterprise Admins" -Recursive | Select-Object Name | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Schema Admin Security Group Members"
$SchemaAdmins = Get-ADGroupMember -ID "Schema Admins" -Recursive
$NumberOfSchemaAdmins = "There are " + $SchemaAdmins.count + " Users In The Schema Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfSchemaAdmins
Get-ADGroupMember -ID "Schema Admins" -Recursive | Select-Object Name | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Security Groups"
Add-Content $OutputFile "---------------"
$DLGroups = (Get-ADGroup -Filter 'GroupCategory -eq "Security" -and GroupScope -EQ "DomainLocal"')
$GlobalGroups = (Get-ADGroup -Filter 'GroupCategory -eq "Security" -and GroupScope -EQ "Global"')
$UniversalGroups = (Get-ADGroup -Filter 'GroupCategory -eq "Security" -and GroupScope -EQ "Universal"')
$DLGroupMsg = "There are " + $DLGroups.count + " Domain Local Groups"
$GlobalGroupMsg = "There are " + $GlobalGroups.count + " Global Groups"
$UniversalGroupMsg = "There are " + $UniversalGroups.count + " Universal Groups"
Add-Content $OutputFile  $DLGroupMsg
Add-Content $OutputFile  $GlobalGroupMsg
Add-Content $OutputFile  $UniversalGroupMsg
get-adgroup -Filter 'GroupCategory -eq "Security"' | Select-Object Name, GroupCategory, GroupScope | out-file -filepath "$PWD\$OutputFolder\SecurityGroups.txt" -NoClobber -Append -Encoding ascii 
Add-Content $OutputFile  " "
Add-Content -Path $OutputFile -Value "A list of Security Groups has been output to the SecurityGroups.txt file "

#########################################################################################
Add-Content $OutputFile  " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     OU Details     ~~~~~~~~~~~~~~~"
Add-Content $OutputFile  " "
Add-Content $OutputFile "OU Structure"
Add-Content $OutputFile "------------"
Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' } -Properties CanonicalName | Select-Object -Property CanonicalName | Sort-Object CanonicalName | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

#########################################################################################

Add-Content $OutputFile "~~~~~~~~~~~~~~~     Group Policy Details     ~~~~~~~~~~~~~~~"

$GPOs = get-gpo -all
$NumberOfGPOs = "There are " + $GPOs.count + " GPOs"
Add-Content $OutputFile  $NumberOfGPOs

get-gpo -all | Sort-Object -Property DisplayName | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime | Out-File $OutputFile -NoClobber -Append -Encoding ascii 

Add-Content $OutputFile "Settings Report - See GPOReportsAll.html "
Import-Module GroupPolicy
$dc = Get-ADDomainController -Discover -Service PrimaryDC
Get-GPOReport -All -Domain (Get-ADForest).RootDomain -Server $dc -ReportType HTML -Path $PWD\$OutputFolder\GPOReportsAll.html


#This script needs Get-NoSettingsGPO.ps1 in the same folder
Add-Content $OutputFile " "
Add-Content $OutputFile "GPOs With No Settings"
Add-Content $OutputFile "---------------------"

$GPOsWithNoSettings = .\Get-NoSettingsGPO.ps1
$NumberOfGPOsWithNoSettings = "There are " + $GPOsWithNoSettings.count + " GPOs with no settings"
Add-Content $OutputFile  $NumberOfGPOsWithNoSettings
$GPOsWithNoSettings | Out-File $OutputFile -NoClobber -Append -Encoding ascii

#This script needs Get-UnlinkedGPO.ps1 in the same folder
Add-Content $OutputFile " "
Add-Content $OutputFile "Unlinked GPOs"

$UnlinkedGPOs = .\Get-UnlinkedGPO.ps1
$NumberOfUnlinkedGPOs = "There are " + $UnlinkedGPOs.count + " Unlinked GPO's"

Add-Content $OutputFile  $NumberOfUnlinkedGPOs
$UnlinkedGPOs | Out-File $OutputFile -NoClobber -Append -Encoding ascii


#########################################################################################

Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~     DNS Server Settings     ~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

#Get-Module DNSServer –ListAvailable
#Import-Module DnsServer



#Get-DnsClientServerAddress -AddressFamily IPv4
#$DNSServer = read-host "What is the Hostname or IP of a DNS Server?"


$DNSServer = (Get-ADDomainController).IPv4Address
Get-DnsServer -ComputerName $DNSServer | Out-File $PWD\$OutputFolder\DNS_Server_FullDetails.txt -NoClobber -Append -Encoding ascii  

$CheckedDNSServer = "The DNS Server checked is:- " + $DNSServer
Add-Content $OutputFile $CheckedDNSServer
Add-Content $OutputFile "Full Details can be found in this file - DNS_Server_FullDetails.txt"
Add-Content $OutputFile " "
Add-Content $OutputFile "Server Settings"
Add-Content $OutputFile "---------------"
Get-DnsServerSetting -ComputerName $DNSServer | Select-Object ComputerName | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

Get-DnsServerDsSetting -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

Add-Content $OutputFile "Forwarding"
Add-Content $OutputFile "----------"
Get-DnsServerForwarder -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii  


Add-Content $OutputFile " "
Add-Content $OutputFile "Server Scavenging Settings"
Add-Content $OutputFile "--------------------------"
Get-DnsServerScavenging  -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii 



Add-Content $OutputFile "~~~~~~~~~~~~~~~     Zone Details     ~~~~~~~~~~~~~~~"
Get-DnsServerZone -ComputerName $DNSServer | Where-Object -FilterScript { $_.IsAutoCreated -eq $False -AND $_.ZoneName -notlike "_msdcs*" -AND $_.ZoneName -notlike "Trust*" } | Sort-Object IsReverseLookupZone | Select-Object ZoneName, ZoneType, IsReverseLookupZone, ReplicationScope, Notify, NotifyServers, SecondaryServers, SecureSecondaries, DynamicUpdate | Out-File $OutputFile -NoClobber -Append -Encoding ascii


# Get-DnsServerForwarder -ComputerName $DNSServer

# Get-DnsServerZoneScope -ComputerName $DNSServer -ZoneName jayhallsworth.uk | Select-Object * 
# Get-DnsServerZoneTransferPolicy  -ComputerName $DNSServer -ZoneName jayhallsworth.uk

$DnsZonesOfInterest = @((Get-DnsServerZone -ComputerName $DNSServer | Where-Object -FilterScript {$_.IsAutoCreated -eq $False -AND $_.IsReverseLookupZone -eq $False -AND $_.ZoneName -notlike "_msdcs*" -AND $_.ZoneName -notlike "Trust*" }).ZoneName)
#$DnsZonesOfInterest


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content $OutputFile $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "NS" -Node | Out-File $OutputFile -NoClobber -Append -Encoding ascii

} 


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content $OutputFile $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "SOA" -Node | Out-File $OutputFile -NoClobber -Append -Encoding ascii

} 


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content $OutputFile $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "A" -Node | Out-File $OutputFile -NoClobber -Append -Encoding ascii

} 



foreach ($Zone in $DnsZonesOfInterest) {

Add-Content $OutputFile $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "A" | where-object {-not $_.TimeStamp} | Out-File $OutputFile -NoClobber -Append -Encoding ascii

} 


Add-Content $OutputFile "~~~~~~~~~~~~~~~     Other DNS Server Settings     ~~~~~~~~~~~~~~~"


if (-NOT (Test-Path "$Pwd\OtherDNS-servers.txt")) {

Add-Content $OutputFile "The File OtherDNS-servers.txt Does Not Exist - Details of other DNS Servers will not be recorded"

} else {

$DNSSvrs = Get-Content -Path "OtherDNS-servers.txt"

foreach ($DNSSvr in $DNSSvrs) {

Add-Content $OutputFile $DNSSvr
Add-Content $OutputFile "DNS Server Settings"
Get-DnsServerDsSetting -ComputerName $DNSSvr | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "DNS Forwarder Settings"
Get-DnsServerForwarder -ComputerName $DNSSvr | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "DNS Scavenging Settings"
Get-DnsServerScavenging  -ComputerName $DNSSvr | Out-File $OutputFile -NoClobber -Append -Encoding ascii
Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
}

}


Add-Content $OutputFile " "

Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~     DHCP Server Settings     ~~~~~~~~~~~~~~~"
Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

$DHCPServer = Get-Service | where-object { $_.Name -like "*DHCPServer*" }
if ($Null -eq $DHCPServer) { $IsDHCPServer = $False } else { $IsDHCPServer = $True }

If ($IsDHCPServer -eq $True) {

  #Run Scripts for DHCP Server

  Get-DhcpServerInDC | Sort-Object -Property IPAddress | Out-File $OutputFile -NoClobber -Append -Encoding ascii

  $DHCPServers = Get-DhcpServerInDC | Sort-Object -Property IPAddress

  foreach ($DHCPServer in $DHCPServers) {


    Add-Content $OutputFile $DHCPServer.DnsName
    $DHCPServer.DnsName

    Add-Content $OutputFile "DHCP Server Settings"
    Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~"
    Get-DhcpServerSetting -ComputerName $DHCPServer.DnsName | Select-Object IsDomainJoined, IsAuthorizedNap, ConflictDetectionAttempts, NapEnabled | Out-File $OutputFile -NoClobber -Append -Encoding ascii

    Add-Content $OutputFile "Server Options"
    Add-Content $OutputFile "~~~~~~~~~~~~~~"
    Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName | Select-Object OptionId, Name, Value | Out-File $OutputFile -NoClobber -Append -Encoding ascii

    Add-Content $OutputFile "DHCP Scopes"
    Add-Content $OutputFile "~~~~~~~~~~~"
    $DHCPScopesMsg = "There are " + (Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName).count + " DHCP Scopes on this server"
    Add-Content $OutputFile $DHCPScopesMsg
    Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName | Out-File $OutputFile -NoClobber -Append -Encoding ascii

    Add-Content $OutputFile "Scope Details"
    Add-Content $OutputFile "~~~~~~~~~~~~~"

    $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName 
    foreach ($Scope in $Scopes) {
      Add-Content $OutputFile $Scope.ScopeID

      Add-Content $OutputFile "Scope Stats"
      Add-Content $OutputFile "~~~~~~~~~~~"
      Get-DhcpServerv4ScopeStatistics  -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID | Out-File $OutputFile -NoClobber -Append -Encoding ascii

      Add-Content $OutputFile "Scope Options"
      Add-Content $OutputFile "~~~~~~~~~~~~~"
      Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID | Sort-Object -Property OptionID | Select-Object -Property OptionId, Name, Value | Out-File $OutputFile -NoClobber -Append -Encoding ascii

      Add-Content $OutputFile "Exclusions"
      Add-Content $OutputFile "~~~~~~~~~~"
      Get-DhcpServerv4ExclusionRange -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID | Out-File $OutputFile -NoClobber -Append -Encoding ascii

      Add-Content $OutputFile "Reservations"
      Add-Content $OutputFile "~~~~~~~~~~~~"
      Get-DhcpServerv4Reservation -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID | Out-File $OutputFile -NoClobber -Append -Encoding ascii


    }
  }
}
else {
  $WriteNoteOnDHCP = "This Server is not a DHCP Server so tests not run"
  $WriteNoteOnDHCP | Out-File $OutputFile -NoClobber -Append -Encoding ascii
}
write-host " "
write-host "Audit is complete"