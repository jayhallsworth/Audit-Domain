﻿#Requires -RunAsAdministrator
cls

#Collect Info and Set Output File
cls
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
MD $OutputFolder


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
#CLS
write-host " "
    Write-Host "ActiveDirectory Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
#CLS
write-host " "
    Write-Host "Installing ActiveDirectory Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name ActiveDirectory -Force
Import-Module -Name ActiveDirectory -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}

if (Get-Module -Name DhcpServer) {
#CLS
write-host " "
    Write-Host "DhcpServer Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
#CLS
write-host " "
    Write-Host "Installing DhcpServer Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name DhcpServer -Force
Import-Module -Name DhcpServer -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}

if (Get-Module -Name DnsServer) {
#CLS
write-host " "
    Write-Host "DnsServer Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
#CLS
write-host " "
    Write-Host "Installing DnsServer Module..." -ForegroundColor black -BackgroundColor Green
#Install-module -name DnsServer -Force
Import-Module -Name DnsServer -Force

Write-Host "Module Installed!" -ForegroundColor black -BackgroundColor Green
write-host " "
}

if (Get-Module -Name GroupPolicy) {
#CLS
write-host " "
    Write-Host "GroupPolicy Module exists" -ForegroundColor black -BackgroundColor Green
write-host " "
} else {
#CLS
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
#




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


if (-NOT (Test-Path "$Pwd\Get-ServerDNS.ps1")) {

write-host "This script needs Get-ServerDNS.ps1"
#write-host "It can be downloaded from here: "
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
Get-ADForest | FL Name, RootDomain, ForestMode, Domains, SchemaMaster, DomainNamingMaster, Sites | Out-File $OutputFile -NoClobber -Append -Encoding ascii

$UPNs = (Get-ADForest).UPNSuffixes
$NumberOfUPNs = "There Are " + $UPNs.count + " UPN Suffix's in the forest: "
Add-Content $OutputFile $NumberOfUPNs
(Get-ADForest).UPNSuffixes | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile " "
Add-Content $OutputFile 'Domain Details'
Add-Content $OutputFile "--------------"
Get-ADDomain | FL Name, NetBIOSName, DomainMode, DNSRoot, PDCEmulator, RIDMaster, InfrastructureMaster | Out-File $OutputFile -NoClobber -Append -Encoding ascii


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
Get-ADReplicationSubnet -Filter * | FT Name, Site -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile 'Site Links'
Get-ADReplicationSiteLink -filter * | FL Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded | Out-File $OutputFile -NoClobber -Append -Encoding ascii





Add-Content $OutputFile " "
Add-Content $OutputFile "Trusts"
Add-Content $OutputFile "------"
$Trusts = Get-ADTrust -Filter *
 if ($Trusts -eq $null) {Add-Content $OutputFile "There Are No Trusts"} else {$Trusts | Select * | Out-File $OutputFile -NoClobber -Append -Encoding ascii}



Add-Content $OutputFile " "
Add-Content $OutputFile "Fine Grain Password Policy"
Add-Content $OutputFile "--------------------------"
$FGPP = Get-ADFineGrainedPasswordPolicy -Filter *
 if ($FGPP -eq $null) {Add-Content $OutputFile "There Are No Fine Grain Password Policies"} else {$FGPP | Select * | Out-File $OutputFile -NoClobber -Append -Encoding ascii}




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

Get-ADDomainController -Server $GC | FT Site, Name, IsGlobalCatalog, IsReadOnly, IPv4Address  -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii

}

#This typically errors with DC's that aren't ready for remote powershell
foreach ($GC in $GCs) {

Get-ADDomainController -Server $GC | FT HostName, OperatingSystem, OperatingSystemHotfix, OperatingSystemServicePack, OperatingSystemVersion | Out-File $OutputFile -NoClobber -Append -Encoding ascii

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

$ActiveUsers = (Get-ADUser -Filter * -Properties Enabled, AccountExpirationDate, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath |sort -Property LastLogonDate -Descending | ? { ($_.Enabled -EQ $True) -OR `
$_.LastLogonDate -NE $NULL -AND $_.LastLogonDate -GE (Get-Date).AddDays(-90) })

#$ActiveUsers | FT  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath -AutoSize | Out-File $OutputFile -NoClobber -Append
#Do we want this to go in to the audit file, or to a separate CSV???
#$ActiveUsers | FT  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath -AutoSize | export-csv -path "$PWD\ActiveUsers.csv" -NoTypeInformation
$ActiveUsers | FT  SamAccountName, LastLogonDate, HomeDirectory, HomeDrive, ProfilePath -AutoSize | Out-File -FilePath "$PWD\$OutputFolder\ActiveUsers.txt" -NoClobber -Append -Encoding ascii
Add-Content -Path $OutputFile -Value "A list of Active Users has been output to the ActiveUsers.txt file "

Add-Content $OutputFile " "
Add-Content $OutputFile "Users With Password Never Expires"
$UsersWithPwdNeverExpires = Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)}
$NumberOfUsersWithPwdNeverExpires = "There are " + $UsersWithPwdNeverExpires.count + " Users with password never expires"
Add-Content $OutputFile $NumberOfUsersWithPwdNeverExpires
if($NumberOfUsersWithPwdNeverExpires -gt 25) {
Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | FT SamAccountName, PasswordNeverExpires, PasswordLastSet -AutoSize | Out-File "$PWD\$OutputFolder\PasswordNeverExpires.txt" -NoClobber -Append -Encoding ascii 
#Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | FT SamAccountName, PasswordNeverExpires, PasswordLastSet -AutoSize | export-csv -path "$PWD\PasswordNeverExpires.csv" -NoTypeInformation
Add-Content -Path $OutputFile -Value "A list of Users with password never expires has been output to the PasswordNeverExpires.txt file "
} else {Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | FT SamAccountName, PasswordNeverExpires, PasswordLastSet -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii 
}

Add-Content $OutputFile "Domain Admin Security Group Members"
$DomainAdmins = Get-ADGroupMember -ID "Domain Admins" -Recursive
$NumberOfDomainAdmins = "There are " + $DomainAdmins.count + " Users In The Domain Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfDomainAdmins
Get-ADGroupMember -ID "Domain Admins" -Recursive | FT Name -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Enterprise Admin Security Group Members"
$EnterpriseAdmins = Get-ADGroupMember -ID "Enterprise Admins" -Recursive
$NumberOfEnterpriseAdmins = "There are " + $EnterpriseAdmins.count + " Users In The Enterprise Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfEnterpriseAdmins
Get-ADGroupMember -ID "Enterprise Admins" -Recursive | FT Name -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Schema Admin Security Group Members"
$SchemaAdmins = Get-ADGroupMember -ID "Schema Admins" -Recursive
$NumberOfSchemaAdmins = "There are " + $SchemaAdmins.count + " Users In The Schema Admins Group (Recursive)"
Add-Content $OutputFile  $NumberOfSchemaAdmins
Get-ADGroupMember -ID "Schema Admins" -Recursive | FT Name -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii

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
get-adgroup -Filter 'GroupCategory -eq "Security"' | FT Name, GroupCategory, GroupScope -AutoSize | out-file -filepath "$PWD\$OutputFolder\SecurityGroups.txt" -NoClobber -Append -Encoding ascii 
Add-Content $OutputFile  " "
Add-Content -Path $OutputFile -Value "A list of Security Groups has been output to the SecurityGroups.txt file "

#########################################################################################
Add-Content $OutputFile  " "
Add-Content $OutputFile "~~~~~~~~~~~~~~~     OU Details     ~~~~~~~~~~~~~~~"
Add-Content $OutputFile  " "
Add-Content $OutputFile "OU Structure"
Add-Content $OutputFile "------------"
Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' } -Properties CanonicalName | Select-Object -Property CanonicalName | Sort CanonicalName | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

#########################################################################################

Add-Content $OutputFile "~~~~~~~~~~~~~~~     Group Policy Details     ~~~~~~~~~~~~~~~"

$GPOs = get-gpo -all
$NumberOfGPOs = "There are " + $GPOs.count + " GPOs"
Add-Content $OutputFile  $NumberOfGPOs

get-gpo -all | Sort-Object -Property DisplayName | FT DisplayName, GpoStatus, CreationTime, ModificationTime -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii 

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
Get-DnsServerSetting -ComputerName $DNSServer | Select ComputerName | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

Get-DnsServerDsSetting -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii  

Add-Content $OutputFile "Forwarding"
Add-Content $OutputFile "----------"
Get-DnsServerForwarder -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii  


Add-Content $OutputFile " "
Add-Content $OutputFile "Server Scavenging Settings"
Add-Content $OutputFile "--------------------------"
Get-DnsServerScavenging  -ComputerName $DNSServer  | Out-File $OutputFile -NoClobber -Append -Encoding ascii 



Add-Content $OutputFile "~~~~~~~~~~~~~~~     Zone Details     ~~~~~~~~~~~~~~~"
Get-DnsServerZone -ComputerName $DNSServer | Where-Object -FilterScript {$_.IsAutoCreated -eq $False -AND $_.ZoneName -notlike "_msdcs*" -AND $_.ZoneName -notlike "Trust*" } | Sort IsReverseLookupZone | FT ZoneName, ZoneType, IsReverseLookupZone, ReplicationScope, Notify, NotifyServers, SecondaryServers, SecureSecondaries, DynamicUpdate -AutoSize | Out-File $OutputFile -NoClobber -Append -Encoding ascii


# Get-DnsServerForwarder -ComputerName $DNSServer

# Get-DnsServerZoneScope -ComputerName $DNSServer -ZoneName jayhallsworth.uk | select * 
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


if (-NOT (Test-Path "$Pwd\DNS-servers_List.txt")) {

Add-Content $OutputFile "The File DNS-servers_List.txt Does Not Exist - Details of other DNS Servers will not be recorded"

} else {

$DNSSvrs = Get-Content -Path "DNS-servers_List.txt"

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

Get-DhcpServerInDC | sort -Property IPAddress | Out-File $OutputFile -NoClobber -Append -Encoding ascii

$DHCPServers = Get-DhcpServerInDC | sort -Property IPAddress

foreach ($DHCPServer in $DHCPServers) {


Add-Content $OutputFile $DHCPServer.DnsName
$DHCPServer.DnsName

Add-Content $OutputFile "DHCP Server Settings"
Add-Content $OutputFile "~~~~~~~~~~~~~~~~~~~"
Get-DhcpServerSetting -ComputerName $DHCPServer.DnsName | select IsDomainJoined, IsAuthorizedNap, ConflictDetectionAttempts, NapEnabled | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Server Options"
Add-Content $OutputFile "~~~~~~~~~~~~~~"
Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName | select OptionId, Name, Value | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "DHCP Scopes"
Add-Content $OutputFile "~~~~~~~~~~~"
$DHCPScopesMsg = "There are " + (Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName).count + " DHCP Scopes on this server"
Add-Content $OutputFile $DHCPScopesMsg
Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName  | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Scope Details"
Add-Content $OutputFile "~~~~~~~~~~~~~"

$Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName 
foreach ($Scope in $Scopes) {
Add-Content $OutputFile $Scope.ScopeID

Add-Content $OutputFile "Scope Stats"
Add-Content $OutputFile "~~~~~~~~~~~"
Get-DhcpServerv4ScopeStatistics  -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID  | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Scope Options"
Add-Content $OutputFile "~~~~~~~~~~~~~"
Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID  | Sort -Property OptionID | select -Property OptionId, Name, Value | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Exclusions"
Add-Content $OutputFile "~~~~~~~~~~"
Get-DhcpServerv4ExclusionRange -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID  | Out-File $OutputFile -NoClobber -Append -Encoding ascii

Add-Content $OutputFile "Reservations"
Add-Content $OutputFile "~~~~~~~~~~~~"
Get-DhcpServerv4Reservation -ComputerName $DHCPServer.DnsName -ScopeId $Scope.ScopeID  | Out-File $OutputFile -NoClobber -Append -Encoding ascii


}
}


write-host " "
write-host "Audit is complete"