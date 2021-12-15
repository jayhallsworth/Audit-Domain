import-module grouppolicy

function IsNotLinked($xmldata){
    If ($xmldata.GPO.LinksTo -eq $null) {
        Return $true
    }
    
    Return $false
}

$unlinkedGPOs = @()

Get-GPO -All | ForEach-Object { $gpo = $_ ; $_ | Get-GPOReport -ReportType xml | ForEach-Object { If(IsNotLinked([xml]$_)){$unlinkedGPOs += $gpo} }}

If ($unlinkedGPOs.Count -eq 0) {
    "No Unlinked GPO's Found"
}
Else{
    $unlinkedGPOs | Select-Object DisplayName,ID | Select-Object
}