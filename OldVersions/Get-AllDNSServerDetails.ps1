whoami | Out-File $PWD\DNS_AllServers_Notes.txt -NoClobber -Append
Add-Content $PWD\DNS_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


$DNSServers = Get-Content -Path "DNS-servers.txt"

foreach ($DNSServer in $DNSServers) {
Add-Content $PWD\DNS_AllServers_Notes.txt $DNSServer
Add-Content $PWD\DNS_AllServers_Notes.txt "DNS Server Settings"
Add-Content $PWD\DNS_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~"
Get-DnsServerDsSetting -ComputerName $DNSServer | Out-File $PWD\DNS_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DNS_AllServers_Notes.txt "DNS Forwarder Settings"
Add-Content $PWD\DNS_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~"
Get-DnsServerForwarder -ComputerName $DNSServer | Out-File $PWD\DNS_AllServers_Notes.txt -NoClobber -Append

Add-Content $PWD\DNS_AllServers_Notes.txt "DNS Scavenging Settings"
Add-Content $PWD\DNS_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~~"
Get-DnsServerScavenging  -ComputerName $DNSServer | Out-File $PWD\DNS_AllServers_Notes.txt -NoClobber -Append
Add-Content $PWD\DNS_AllServers_Notes.txt "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
}