whoami | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~~~     DHCP Server Settings     ~~~~~~~~~~~~~~~"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

#Get-Module DNSServer –ListAvailable
#Import-Module DnsServer

#This script needs DHCP-servers.txt in the same folder
 
#if (-NOT Test-Path ".\DHCP-servers.txt") {
#write-host "This script needs DHCP-servers.txt"
#write-host "Please create a text file called DHCP-Servers.txt with all of the hostnames"
#exit
#}

Get-DhcpServerInDC | sort -Property IPAddress | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

$DHCPServers = Get-Content -Path "DHCP-servers.txt"
foreach ($DHCPServer in $DHCPServers) {


Add-Content $PWD\DHCP_AllServers_Notes.txt $DHCPServer


Add-Content $PWD\DHCP_AllServers_Notes.txt "DHCP Server Settings"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~"
Get-DhcpServerSetting -ComputerName $DHCPServer | select IsDomainJoined, IsAuthorizedNap, ConflictDetectionAttempts, NapEnabled | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "Server Options"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~~"
Get-DhcpServerv4OptionValue -ComputerName $DHCPServer | select OptionId, Name, Value | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "DHCP Scopes"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~"
Get-DhcpServerv4Scope -ComputerName $DHCPServer  | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "Scope Details"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~"

$Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer 
foreach ($Scope in $Scopes) {
Add-Content $PWD\DHCP_AllServers_Notes.txt $Scope.ScopeID

Add-Content $PWD\DHCP_AllServers_Notes.txt "Scope Stats"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~"
Get-DhcpServerv4ScopeStatistics  -ComputerName $DHCPServer -ScopeId $Scope.ScopeID  | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "Scope Options"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~~"
Get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $Scope.ScopeID  | Sort -Property OptionID | select -Property OptionId, Name, Value | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "Exclusions"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~"
Get-DhcpServerv4ExclusionRange -ComputerName $DHCPServer -ScopeId $Scope.ScopeID  | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DHCP_AllServers_Notes.txt "Reservations"
Add-Content $PWD\DHCP_AllServers_Notes.txt "~~~~~~~~~~~~"
Get-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $Scope.ScopeID  | Out-File $PWD\DHCP_AllServers_Notes.txt -NoClobber -Append


}
}
