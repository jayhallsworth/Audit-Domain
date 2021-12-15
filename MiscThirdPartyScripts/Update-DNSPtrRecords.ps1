[string]$ForwardZone = Read-Host "Type Forward lookup zone name in format - DOMAIN.NAME "
[string]$ReverseZone = Read-Host "Type Reverse lookup zone name in format - 1.16.172.in-addr.arpa "
$DomainController = Get-ADDomainController | select -ExpandProperty Name
$Records = Get-DnsServerResourceRecord -ComputerName $DomainController -ZoneName $ForwardZone -RRType A | where {$_.HostName -notlike "*DnsZones*" -and $_.HostName -notlike "*@*"} | Select RecordData,Hostname
foreach ($Record in $Records) {
    $Domain = $env:USERDNSDOMAIN.ToString()
    $IPAddress = $($Record.RecordData.IPv4Address).ToString()
    $SplitedIP = $IPAddress.Split(".")[3]
    $IPstring = $SplitedIP.ToString()
    $HostName = $($Record.HostName).ToString()
    $FQDN = "$HostName."+"$Domain"
    Add-DnsServerResourceRecordPtr -Name "$IPstring" -ZoneName "$ReverseZone" -AllowUpdateAny -TimeToLive 01:00:00 -AgeRecord -PtrDomainName "$FQDN" -ComputerName $DomainController
}

