
whoami | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     Active Directory Details     ~~~~~~~~~~~~~~~"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' 'Forest Details'
Get-ADForest | FL Name, RootDomain, ForestMode, Domains, SchemaMaster, DomainNamingMaster, Sites, UPNSuffixes | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' 'Domain Details'
Get-ADDomain | FL Name, NetBIOSName, DomainMode, DNSRoot, PDCEmulator, RIDMaster, InfrastructureMaster | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' 'AD Sites'

Get-ADReplicationSubnet -Filter * | FT Name, Site -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' 'Site Links'
Get-ADReplicationSiteLink -filter * | FL Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append



Add-Content 'C:\RSAT_Tools\AD_Notes.txt' 'Domain Controllers'
$DCs = @(Get-ADDomainController)
$NumberOfDCs = "There are " + $DCs.Count + " DCs"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $NumberOfDCs

Get-ADDomainController | FT Site, Name, IsGlobalCatalog, IsReadOnly, IPv4Address  -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append
Get-ADDomainController | FL HostName, OperatingSystem, OperatingSystemHotfix, OperatingSystemServicePack, OperatingSystemVersion | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append



Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Trusts"
Get-ADTrust -Filter * | Select * | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  



Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Fine Grain Password Policy"
Get-ADFineGrainedPasswordPolicy -Filter * | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  


#########################################################################################

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     Users & Groups     ~~~~~~~~~~~~~~~"
$Users = @(Get-ADUser -Filter *)
$NumberOfUsers = "There are " + $Users.Count + " User Accounts In Total"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $NumberOfUsers


Get-ADUser -properties * -Filter * | FT SamAccountName, HomeDirectory, HomeDrive, ProfilePath -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

#####################################################################################################

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Users With Password Never Expires"

Get-ADUser -properties * -filter {(PasswordNeverExpires -eq $true)} | FT SamAccountName, PasswordNeverExpires, PasswordLastSet -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Domain Admin Security Group Members"
Get-ADGroupMember -ID "Domain Admins" -Recursive | FT Name -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Enterprise Admin Security Group Members"
Get-ADGroupMember -ID "Enterprise Admins" -Recursive | FT Name -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Schema Admin Security Group Members"
Get-ADGroupMember -ID "Schema Admins" -Recursive | FT Name -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Admins Security Group Members"
Get-ADGroupMember -ID "Administrators" -Recursive | FT Name -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Security Groups"
get-adgroup -Filter 'GroupCategory -eq "Security"' | FT Name, GroupCategory, GroupScope -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  



Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     OU Details     ~~~~~~~~~~~~~~~"

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "OU Structure"
Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' } -Properties CanonicalName | Select-Object -Property CanonicalName | Sort CanonicalName | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     Group Policy Details     ~~~~~~~~~~~~~~~"

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "Settings Report - See GPOReportsAll.html "
Import-Module GroupPolicy
$dc = Get-ADDomainController -Discover -Service PrimaryDC
Get-GPOReport -All -Domain (Get-ADForest).RootDomain -Server $dc -ReportType HTML -Path C:\RSAT_Tools\GPOReportsAll.html


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     DNS Server Settings     ~~~~~~~~~~~~~~~"
Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

#Get-Module DNSServer –ListAvailable
#Import-Module DnsServer



Get-DnsClientServerAddress -AddressFamily IPv4

$DNSServer = read-host "What is the Hostname or IP of a DNS Server?"


Get-DnsServer -ComputerName $DNSServer | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append  


Add-Content 'C:\RSAT_Tools\AD_Notes.txt' "~~~~~~~~~~~~~~~     Zone Details     ~~~~~~~~~~~~~~~"
Get-DnsServerZone -ComputerName $DNSServer | Where-Object -FilterScript {$_.IsAutoCreated -eq $False -AND $_.ZoneName -notlike "_msdcs*" -AND $_.ZoneName -notlike "Trust*" } | Sort IsReverseLookupZone | FT ZoneName, ZoneType, IsReverseLookupZone, ReplicationScope, Notify, NotifyServers, SecondaryServers, SecureSecondaries, DynamicUpdate -AutoSize | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append


# Get-DnsServerForwarder -ComputerName $DNSServer

# Get-DnsServerZoneScope -ComputerName $DNSServer -ZoneName jayhallsworth.uk | select * 
# Get-DnsServerZoneTransferPolicy  -ComputerName $DNSServer -ZoneName jayhallsworth.uk

$DnsZonesOfInterest = @((Get-DnsServerZone -ComputerName $DNSServer | Where-Object -FilterScript {$_.IsAutoCreated -eq $False -AND $_.IsReverseLookupZone -eq $False -AND $_.ZoneName -notlike "_msdcs*" -AND $_.ZoneName -notlike "Trust*" }).ZoneName)
$DnsZonesOfInterest


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "NS" -Node | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

} 


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "SOA" -Node | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

} 


foreach ($Zone in $DnsZonesOfInterest) {

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "A" -Node | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

} 



foreach ($Zone in $DnsZonesOfInterest) {

Add-Content 'C:\RSAT_Tools\AD_Notes.txt' $Zone 

Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType "A" | where-object {-not $_.TimeStamp} | Out-File C:\RSAT_Tools\AD_Notes.txt -NoClobber -Append

} 




