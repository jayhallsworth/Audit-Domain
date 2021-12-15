<#
.Synopsis
   Domain Controller Health check ]

.DESCRIPTION
  This script will check the Domain controller health. script will check the SysVol, services, ping etc. This script will mail the all information to recipent user.
  
  Script will auto detect the Domain controller only you have Schedule in tasks  

  we need to modify the Email server Setting 

  Script will email you the Status 

  if you want to change message in body u can change in $report Variable at bottom of script 


.EXAMPLE

 .\adhealthcheck.ps1 


.NOTES
   Need administrator Access
    
   MOdify EMail setting as per your  oragnsation 
   

###############################################################
  Author :- Abhinav joshi
  Email ID :- Abhinav.joshi1293@hotmail.com
  Any bug please Email Me.
  Version :- V1.0
##############################################################
#>#comment

#script Start Here

#file path
Write-Verbose "Setting File path"
$reportpath = ".\abhinav.txt"

if((test-path $reportpath) -like $false)
{
Write-Verbose "Creating New File"

new-item $reportpath -type file

}
else
{
Write-Verbose "File Exist, Deleting file"

Remove-Item $reportpath 

new-item $reportpath -type file

}
 
#import Module 

      Write-Verbose -Message "Importing active directory module"
if (! (Get-Module ActiveDirectory) ) 
 {
                   Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                   Write-Host ("[SUCCESS]") ("ActiveDirectory Powershell Module Loaded")
                   Write-Verbose -Message "Active directory Module import successfully"
                   
   
 }
else 
 { 
      Write-Host ("[INFO]") ("ActiveDirectory Powershell Module Already Loaded")
      Write-Verbose -Message "ActiveDirectory Powershell Module Already Loaded"
  }

#get-domain controller 
      Write-Verbose "selecting Domain controllers"

      $DC = Get-ADDomainController 

#foreach domain controller 
foreach ($Dcserver in $dc.hostname){
if (Test-Connection -ComputerName $Dcserver -Count 4 -Quiet)
 {
  try
     {
 #set ping = ok 
      Write-Verbose "setping = ok"

      $setping = "OK"

 # Netlogon Service Status  
   
      Write-Verbose "checking status of netlogon"

      $DcNetlogon = Get-Service -ComputerName $Dcserver -Name "Netlogon" -ErrorAction SilentlyContinue
   
  if ($DcNetlogon.Status -eq "Running")
   {

      $setnetlogon = "ok"     
      
    }
   
  else  
   {
   
   $setnetlogon = "$DcNetlogon.status"
   
   }

 #NTDS Service Status

     Write-Verbose "checking status of NTDS"

     $dcntds = Get-Service -ComputerName $Dcserver -Name "NTDS" -ErrorAction SilentlyContinue 

 if ($dcntds.Status -eq "running")
  {
    
    $setntds = "ok"

   }

 else 
  {

       $setntds = "$dcntds.status"

    }

   #DNS Service Status 
   
      Write-Verbose "checking status of DNS"

      $dcdns = Get-Service -ComputerName $Dcserver -Name "DNS" -ea SilentlyContinue 
   
 if ($dcdns.Status -eq "running")
  {
      $setdcdns = "ok"                    
  }

 else
  {

     $setdcdns = "$dcdns.Status"

    }
    
   #Dcdiag netlogons "Checking now"
     
     Write-Verbose "Checking Status of netlogns"

     $dcdiagnetlogon = dcdiag /test:netlogons /s:$dcserver
 if ($dcdiagnetlogon -match "passed test NetLogons")
  {

  $setdcdiagnetlogon = "ok"

  }
 else
   {

  $setdcdiagnetlogon = $dcdiagnetlogon 
   
   }

   #Dcdiag services check

   Write-Verbose "Checking status of DCdiag Services"

   $dcdiagservices = dcdiag /test:services /s:$dcserver

 if ($dcdiagservices -match "passed test services")
  {

  $setdcdiagservices = "ok"

  }
 else
   {

  $setdcdiagservices = $dcdiagservices 
   
   }

   
   #Dcdiag Replication Check

   Write-Verbose "Checking status of DCdiag Replication"

   $dcdiagreplications = dcdiag /test:Replications /s:$dcserver

 if ($dcdiagreplications -match "passed test Replications")
  {

  $setdcdiagreplications = "ok"

  }
 else
   {

  $setdcdiagreplications = $dcdiagreplications 
   
   }

   #Dcdiag FSMOCheck Check

   Write-Verbose "Checking status of DCdiag FSMOCheck"

   $dcdiagFsmoCheck = dcdiag /test:FSMOCheck /s:$dcserver

 if ($dcdiagFsmoCheck -match "passed test FsmoCheck")
  {

  $setdcdiagFsmoCheck = "ok"

  }
 else
   {

  $setdcdiagFsmoCheck = $dcdiagFsmoCheck 
   
   }

   #Dcdiag Advertising Check

   Write-Verbose "Checking status of DCdiag Advertising"

   $dcdiagAdvertising = dcdiag /test:Advertising /s:$dcserver

 if ($dcdiagAdvertising -match "passed test Advertising")
  {

  $setdcdiagAdvertising = "ok"

  }
 else
   {

  $setdcdiagAdvertising = $dcdiagAdvertising 
   
   }
  
    $tryok = "ok"

  }
 catch 
    {
    
    $ErrorMessage = $_.Exception.Message

    }
 if ($tryok -eq "ok"){
    #new-object Created

$csvObject = New-Object PSObject

Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCName" -value $dcserver
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Ping" -value $setping
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Netlogon" -value $setnetlogon
Add-Member -inputObject $csvObject -memberType NoteProperty -name "NTDS" -value $setntds
Add-Member -inputObject $csvObject -memberType NoteProperty -name "DNS" -value $setdcdns
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_netlogons" -value $setdcdiagnetlogon
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_Services" -value $setdcdiagservices
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_replications" -value $setdcdiagreplications
Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_FSMOCheck" -value $setdcdiagFsmoCheck
Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCdiag_Advertising" -value $setdcdiagAdvertising

#set DC status 

$setdcstatus = "ok"

 }
 }
else
 {
#if Server Down
Write-Verbose "Server Down"

$setdcstatus = "$dcserver is down"

Add-Member -inputObject $csvObject -memberType NoteProperty -name "Server_down" -value $setdcstatus
   
 }
#Output of Property
}
$csvobject  | ft -AutoSize | Out-file "$reportpath"

#Report body 
Write-Verbose "Creating report for body"
$report = @"
Hi Team,
 
Here is the Report of ADHealth Check 

$(Get-Content $reportpath | Out-String)

please report any problems.

Regards,
Team Name
"@

# subject 
if ($setping -like "ok" -and $setnetlogon -like "ok" -and $setntds -like "ok" -and ` 
$setdcdns -like "ok" -and $setdcdiagnetlogon -like "ok" -and $setdcdiagservices -like "ok" -and `
 $setdcdiagreplications -like "ok" -and $setdcdiagFsmoCheck -like "ok" -and $setdcdiagAdvertising -like "ok" -and $setdcstatus -like "ok" ) 
{

$Subject = "Domain Controller Daily Server Status :- All servers are 'ok' "

}
else 
{
$Subject = "Domain Controller Daily Server Status :- ERROR "
}
try
{
$From = "fromaddress@domain.com"
$To = "toaddress@domain.com"
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
$Username = "username@gmail.com" # depend on your org setup Optional ---------------if not required remove 
$Password = "gmailpassword" # depend on your org setup Optional--------------------if not required remove

$smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort);
$smtp.EnableSSL = $true # optional if u don't want to use SSL change to false
$smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
$smtp.Send($From, $To, $subject, $report)
}
catch
{
$Errormail = $_.Exception.Message
$date = (Get-Date)
Add-Content log.txt -Value "$Errormail $date"
}