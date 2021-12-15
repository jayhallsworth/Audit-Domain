# User Choice Handling
function Ask-ForChoice
{
	param
	(
		[Parameter(ValueFromPipeline = $false, Mandatory = $true)]
		[Alias("CT")]
		[String] $ChoiceTle,
		
		[Parameter(ValueFromPipeline = $false, Mandatory = $true)]
		[Alias("CM")]
		[String] $ChoiceMsg,
		
		[Parameter(ValueFromPipeline = $false, Mandatory = $true)]
		[Alias("YM")]
		[String] $YesMsg,
		
		[Parameter(ValueFromPipeline = $false, Mandatory = $true)]
		[Alias("NM")]
		[String] $NoMsg
	)
	
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Y',$YesMsg
	$no = New-Object System.Management.Automation.Host.ChoiceDescription '&N',$NoMsg
	
	$ChoiceOpt = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	
	$Choice = $host.ui.PromptForChoice($ChoiceTle,$ChoiceMsg,$ChoiceOpt,0)
	
	return $Choice
}

# Credential Handling
function Get-DomainCredential
{
	param
	(
		[Parameter(ValueFromPipeline = $false, Mandatory = $false)]
		[Alias("Forest")]
		[String] $Forest_FQDN = (Get-ADForest).name,
		
		[Parameter(ValueFromPipeline = $false, Mandatory = $false)]
		[Alias("Domain")]
		[String[]] $Domain_FQDN_List = @((Get-ADForest).domains)
	)
	
	$Forest_FQDN = $Forest_FQDN.ToLower()
	$Domain_FQDN_List = @($Domain_FQDN_List.ToLower())
	
	$LoginPwd = {
		param
		(	
			[String] $Msg_Login
		)
	
		$Login = Read-Host $Msg_Login
		$Pwd = Read-Host "Password" -AsSecureString
				
		New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Login, $Pwd
	}
	
	if($Domain_FQDN_List.Count -ne 1)
	{
		$Choice_Tle = 'Credential Management :'
		$Choice_Msg = 'Do you want to use same credential for all domains ?'
		$Choice_YesMsg = 'Same credential confirmed.'
		$Choice_NoMsg = 'Separate credential for each domain confirmed.'
		$UniqCredential = Ask-ForChoice $Choice_Tle $Choice_Msg $Choice_YesMsg $Choice_NoMsg

		if ($UniqCredential -eq 0)
		{
			$Msg = "`n" + ('Enterprise Admin login for "{0}" (DomainName\Login)' -f $Forest_FQDN)
			$Msg = $Msg + "`n" + 'or delegated User with necessary rights over Domains listed below:'
			$Msg = $Msg + "`n" + ($Domain_FQDN_List | Out-String).Trim()
			$Credential = &$LoginPwd $Msg
		
			foreach ($FQDN in $Domain_FQDN_List)
			{	
				$Credential_Pso = New-Object PSObject -Property @{
					Credential = $Credential
					Domain = $FQDN
				}
		
				$Credential_PsoCol = $Credential_PsoCol + @($Credential_Pso)
			}
		}
		else
		{
			foreach ($FQDN in $Domain_FQDN_List)
			{
				$Msg = "`n" + ('Domain Admin login for "{0}" (DomainName\Login)' -f $FQDN)
				$Credential = &$LoginPwd $Msg

				$Credential_Pso = New-Object PSObject -Property @{
					Credential = $Credential
					Domain = $FQDN
				}
			
				$Credential_PsoCol = $Credential_PsoCol + @($Credential_Pso)
			}
		}
	}
	else
	{
		$Msg = "`n" + ('Domain Admin Login for "{0}" (DomainName\Login)' -f $Domain_FQDN_List)
		$Credential = &$LoginPwd $Msg

		$Credential_Pso = New-Object PSObject -Property @{
			Credential = $Credential
			Domain = $Domain_FQDN_List
		}
			
		$Credential_PsoCol = @($Credential_Pso)
	}
	
	Write-Host "`n" -NoNewline
	
	return $Credential_PsoCol
}

# Group Policy Status Checking
function Get-GPStatus
{
	<#   
		.SYNOPSIS
		Group Policy Status Checking over Site(s) and per Domain 
		 
		.DESCRIPTION
		Considering site(s), one domain 'DOM', his root and child organizational unit(s):
		- retrieves all group policy links and link options (enabled, enforced, disabled), wherever targeted group policy objects are stored in the forest;
		  and identifies orphaned links, i.e. links targeting group policy objects that no longer exist;
		- retrieves all group policy objects stored in domain 'DOM', but not linked on his root and child organizational unit(s) nor any site;
		- retrieves all group policy directories stored in domain 'DOM';
		  identifies NTFRS conflicts and orphaned directories, i.e. directories without parent group policy object ;
		- retrieves group policy directories status for all group policies linked and group policies stored.

		.PARAMETER Domain
		A single domain distinguishedName or a list.
		If not provided, uses current domain.

		.NOTES
		Name: Get-GPStatus.ps1
		Author: Axel Limousin
		Version: 1.1

		.EXAMPLE
		
		Load function stored on user desktop, get group policy status over the forest and record in a variable, export variable to csv file.
		
		."$Env:USERPROFILE\Desktop\Get-GPStatus.ps1"
		$GPStatus = Get-GPStatus (Get-ADForest).Domains
		
		$GPStatus | Export-Csv -Path "$Env:USERPROFILE\Desktop\GPStatus.csv" -Delimiter ';' -NoTypeInformation
		# or
		$GPStatus | Format-Table -Property * -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$Env:USERPROFILE\Desktop\GPStatus.csv"
		
		.EXAMPLE
	
		Enumerate group policy directory status retrieved.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'	
		$GPStatus.sysvol | Select -Unique
		
		.EXAMPLE
		
		Find unlinked group policies objects.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.existsInPolicies -and !($_.enabledOn) -and !($_.enforcedOn) -and !($_.disabledOn) }
		
		Warning : a group policy object (gpo) not linked in a domain may be linked in another, to be sure that a gpo is not used anywhere please run status check over the forest.
		
		.EXAMPLE
		
		Find orphaned group policy links.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { !($_.existsInPolicies) -and ($_.enabledOn -or $_.enforcedOn -or $_.disabledOn) }
		
		.EXAMPLE
		
		Find orphaned directories.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { !($_.existsInPolicies) -and $_.sysvol -ne 'no_Directory' }
		
		.EXAMPLE
		
		Find group policy directories with NTFRS conflict.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.sysvol -like '*NTFRS*' }
		
		.EXAMPLE
		
		Find empty group policies.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.sysvol -eq 'no_mConfiguration, no_uConfiguration' }
		
		.EXAMPLE
		
		Find group policies with computer settings.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.sysvol -like 'ok_mConfiguration*' }
		
		.EXAMPLE
		
		Find group policies with only user settings.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.sysvol -eq 'no_mConfiguration, ok_uConfiguration' }
		
		.EXAMPLE
		
		Find group policy directories denying access to user/admin account used by status checking process.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'
		$GPStatus | ? { $_.sysvol -like '*deniedAccess*' }
	 
		.EXAMPLE
	
		Find group policy object denying user/admin account used by status checking process to read displayName property.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'	
		$GPStatus | ? { $_.existsInPolicies -and !($_.displayName) }
		
		.EXAMPLE
	
		Find group policy directory status of group policy links enabled on organizational unit 'MyChildOU'.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'	
		$GPStatus | ? { $_.enabledOn -like '*MyDomainFQDN/MyParentOU/MyChildOU*' } | Select displayName, name, hostingDomain, existsInPolicies, sysvol
		
		.EXAMPLE
	
		Considering group policies linked on organizational unit 'MyChildOU', find other place over site(s) or domain 'MyDomainFQDN' where they are linked.
		
		$GPStatus = Get-GPStatus 'MyDomainFQDN'	
		$GPStatus | ? { $_.enabledOn -like '*MyDomainFQDN/MyParentOU/MyChildOU*' } | Select displayName, name, existsInPolicies, sysvol, enabledOn
		 
		and many more Where-Object combination...
	#>
	#Requires -Version 3.0
    
	[cmdletbinding()]
	
	param 
    (
		[Parameter(ValueFromPipeline = $false, Mandatory = $false)]
		[Alias('Domain')]
        [String[]] $FQDN_List = @((Get-ADDomain).DNSRoot)
    )
	
	$Msg = "`n" + 'Initialization'
	Write-Host $Msg -Foreground Cyan -BackgroundColor Blue
	
	$FQDN_List = $FQDN_List.ToLower()
    $Forest_FQDN = ((Get-ADForest).Name).ToLower()
	$Forest_Domain_FQDN_List = @(((Get-ADForest).Domains).ToLower())
	
	foreach ($FQDN in $FQDN_List)
	{	
		if ($Forest_Domain_FQDN_List.IndexOf($FQDN) -eq -1)
		{
			Write-Host "`n" -NoNewline
			
			$Msg = "`n" + ('"{0}" is not a valid Fully Qualified Domain Name in "{1}" Forest.' -f $FQDN, $Forest_FQDN)
			$Msg = $Msg + "`n" + 'It will be ignored.'
			Write-Warning $Msg
			
			Write-Host "`n" -NoNewline
		}
		else
		{
			$Domain_FQDN_List = $Domain_FQDN_List + @($FQDN)
		}
	}
	
	if ($Domain_FQDN_List -eq $null)
	{
		Write-Host "`n" -NoNewline
		
		$Msg = "`n" + ('No valid Fully Qualified Domain Name provided for Forest "{0}".' -f $Forest_FQDN)
		$Msg = $Msg + "`n" + 'Script aborted.'
		Write-Warning $Msg
		
		Write-Host "`n" -NoNewline
		
		return
	}
	
	$Sites_DN = 'CN=Sites,' + (Get-ADRootDSE).configurationNamingContext
	
	if ($Domain_FQDN_List.IndexOf($Forest_FQDN) -eq -1)
	{
		$Domain_FQDN_Credential_List = $Domain_FQDN_List + @($Forest_FQDN)
	}
	else
	{
		$Domain_FQDN_Credential_List = $Domain_FQDN_List
	}
	
	$Credential_PsoCol = 
	@(
		Get-DomainCredential -Forest $Forest_FQDN -Domain $Domain_FQDN_Credential_List
	)

	$Msg = 'Collecting Group Policy Link(s) on Site(s)'
	Write-Host $Msg -ForegroundColor White
	
	$Credential = ($Credential_PsoCol | Where { $_.Domain -eq $Forest_FQDN }).Credential
	
	$Site_Col = 
	@(
		Get-ADObject -SearchBase $Sites_DN -LDAPFilter 'objectClass=site' -SearchScope 'Subtree' -Properties canonicalName, gPLink -Credential $Credential
	)
	
    $Site_wGPLink_Col =
	@(
		$Site_Col | 
        Where { $_.gPLink -ne $null -and $_.gPLink -ne ' ' } |
		Select canonicalName, gPLink
	)
	
	$Msg = '=> {0} Sites, {1} Sites with Group Policy Link(s)' -f $Site_Col.Count, $Site_wGPLink_Col.Count
	Write-Host $Msg
	
	$ADo_wGPLink_Col = $Site_wGPLink_Col
	
	foreach ($Domain_FQDN in $Domain_FQDN_List)
	{
		$Domain_DN = 'DC=' + ($Domain_FQDN -replace '\.',',DC=')
		$Policies_DN = 'CN=Policies,CN=System,' + $Domain_DN
	
		$Credential = ($Credential_PsoCol | Where { $_.Domain -eq $Domain_FQDN }).Credential
	
		$Msg = 'Collecting Group Policy(ies) stored in Domain "{0}":' -f $Domain_FQDN
		Write-Host $Msg -ForegroundColor White
		
		$GPO_Domain_Col =
		@(
			Get-ADObject -SearchBase $Policies_DN -LDAPFilter 'objectClass=groupPolicyContainer' -Server $Domain_FQDN -Credential $Credential
		)
	
		# I use \\server\share instead of DFS \\domain\share to bypass network drive mapping limitation:
		# multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed.
		# Here already exists a connection to Current Domain DFS Sysvol Share
		$Msg = '=> {0} Object(s) stored in Policies Container' -f $GPO_Domain_Col.Count
		Write-Host $Msg
	
		$DC_FQDN = ((Get-ADDomainController -DomainName $Domain_FQDN -Discover).hostName)[0]
		
		$PSDrive_Index = $Domain_FQDN_List.IndexOf($Domain_FQDN)
		$PSDrive_Name = 'Sysvol_' + $PSDrive_Index
		$PSDrive_Root = '\\' + $DC_FQDN + '\SYSVOL\' + $Domain_FQDN + '\Policies'
		
		try
		{
			New-PSDrive -Name $PSDrive_Name -Root $PSDrive_Root -PSProvider FileSystem -Credential $Credential | Out-Null
		}
		catch
		{
			Write-Host "`n" -NoNewline
	
			$Msg =  "`n" + ('No access to "{0}".' -f $PSDrive_Root)
			$Msg = $Msg + "`n" + 'Script aborted.'
			Write-Warning $Msg
			
			Write-Host "`n" -NoNewline
			
			return
		}
		
		$PSDrive = $PSDrive_Name + ':'
		$GP_Domain_Directory_List = (Get-ChildItem $PSDrive).Name
		
		$Msg = '=> {0} Directory(ies) stored in "{1}"' -f $GP_Domain_Directory_List.Count, $PSDrive_Root
		Write-Host $Msg
		
		$GP_Domain_Directory_nNTFRS_List = $GP_Domain_Directory_List | Where { $_ -notlike '*_NTFRS*' }	
		$cptr = 0
		
		foreach ($Name in $GP_Domain_Directory_List)
		{
			if ($Name -like '*_NTFRS*')
			{
				$Name_Cleaned = ($Name -split '_NTFRS')[0]
				$GPO_DN = 'CN=' + $Name_Cleaned + ',' + $Policies_DN
				
				$GP_Domain_Directory_NTFRS_DN_List = $GP_Domain_Directory_NTFRS_DN_List + @($GPO_DN)
				
				if ($GP_Domain_Directory_nNTFRS_List.IndexOf($Name_Cleaned) -eq -1 -and ($GPO_Domain_Col.distinguishedName).IndexOf($GPO_DN) -eq -1)
				{
					$GP_Domain_Directory_Orph_DN_List = $GP_Domain_Directory_Orph_DN_List + @($GPO_DN)
					
					$cptr++
				}
			}
			else
			{
				$GPO_DN = 'CN=' + $Name + ',' + $Policies_DN
				
				if (($GPO_Domain_Col.distinguishedName).IndexOf($GPO_DN) -eq -1 )
				{
					$GP_Domain_Directory_Orph_DN_List = $GP_Domain_Directory_Orph_DN_List + @($GPO_DN)
				}
			}
		}
		
		$GP_Domain_Directory_NTFRS_DN_List = $GP_Domain_Directory_NTFRS_DN_List | Sort -Unique
		$GP_Domain_Directory_Orph_DN_List = $GP_Domain_Directory_Orph_DN_List | Sort -Unique
		
		$Msg = '=> {0} NTFRS conflict(s) including {1} orphaned Directory(ies)' -f $GP_Domain_Directory_NTFRS_DN_List.Count, $cptr
		Write-Host $Msg
		
		$Msg = '=> {0} orphaned Directory(ies)' -f $GP_Domain_Directory_Orph_DN_List.Count
		Write-Host $Msg		
	
		$Msg = 'Collecting Group Policy Link(s) on Domain "{0}":' -f $Domain_FQDN
		Write-Host $Msg -ForegroundColor White
	
		$Msg = '- on Root'
		Write-Host $Msg
	
		$Root_wGPLink = 
		@(
    		Get-ADObject -Identity $Domain_DN -Properties canonicalName, gPLink -Server $Domain_FQDN -Credential $Credential |  
        	Where { $_.gPLink -ne $null -and $_.gPLink -ne ' ' } |
			Select canonicalName, gPLink
		)
		
		if ($Root_wGPLink.Count -eq 0)
		{ 	
			Write-Host "`n" -NoNewline
			
			$Msg = "`n" + ('No Group Policy Link on Root of Domain "{0}"' -f $Domain_FQDN)
			Write-Warning $Msg
			
			Write-Host "`n" -NoNewline
		}
	
		$Msg = '- on Organizational Units'
		Write-Host $Msg

		$OU_Col =
		@(
			Get-ADObject -SearchBase $Domain_DN -LDAPFilter 'objectClass=organizationalUnit' -SearchScope 'Subtree' -Properties canonicalName, gPLink -Server $Domain_FQDN -Credential $Credential
		)

    	$OU_wGPLink_Col =
		@(
			$OU_Col | 
        	Where { $_.gPLink -ne $null -and $_.gPLink -ne ' ' } | 
			Select canonicalName, gPLink
		)

		$Msg = '=> {0} OUs, {1} OUs with Group Policy Link(s)' -f $OU_Col.Count, $OU_wGPLink_Col.Count
		Write-Host $Msg
		
		$GPO_DN_List = $GPO_DN_List + @($GPO_Domain_Col.distinguishedName)
		$GP_Directory_NTFRS_DN_List = $GP_Directory_NTFRS_DN_List + @($GP_Domain_Directory_NTFRS_DN_List)
		$GP_Directory_Orph_DN_List = $GP_Directory_Orph_DN_List + @($GP_Domain_Directory_Orph_DN_List)
		$ADo_wGPLink_Col = $ADo_wGPLink_Col + @($Root_wGPLink) + @($OU_wGPLink_Col)
        $global:Debug_ADo_wGPLink_Col = $ADo_wGPLink_Col
	}
	
	if ($ADo_wGPLink_Col.Count -eq 0)
	{
			Write-Host "`n" -NoNewline
	
			$Msg =  "`n" + 'No Group Policy Link.'
			$Msg = $Msg + "`n" + 'Script aborted.'
			Write-Warning $Msg
			
			Write-Host "`n" -NoNewline
			
			return
	}
	
	Remove-Variable -Name @(
	'Domain_DN',
	'Policies_DN',
	'GPO_Domain_Col',
	'GP_Domain_Directory_List',
	'GP_Domain_Directory_nNTFRS_List',
	'GP_Domain_Directory_NTFRS_DN_List',
	'GP_Domain_Directory_Orph_DN_List',
	'Root_wGPLink',
	'OU_Col',
	'OU_wGPLink_Col'
	)
	
	$Msg = "`n" + 'Processing'
	Write-Host $Msg -Foreground Cyan -BackgroundColor Blue

	$Msg = "`n" + 'Preparing status record of Group Policy(ies) linked on Site(s) and Domain(s) listed below:'
	$Msg = $Msg + "`n" + ($Domain_FQDN_List | Out-String).Trim()  
	Write-Host $Msg -ForegroundColor White
		
	$GPLink_Status_List =
	@(
		$ADo_wGPLink_Col.gPLink -split '\]\[' -replace '\[|LDAP\:\/\/|\]','' | 
		Sort -Unique
	)
	$GPLink_DN_List = 
	@(
		$GPLink_Status_List -replace ';\d','' | 
		Sort -Unique
	) # Using Sort -Unique because here there could be upper and lower case, Select -Unique and Get-Unique are case sensitiv
	
	$GPLink_DN_List_lc = 
	@(
		$GPLink_DN_List.ToLower()
	)
	
	foreach ($GPLink_DN in $GPLink_DN_List_lc)
	{
		$GP_hostingDomain_DN_List = $GP_hostingDomain_DN_List + 
		@(
			$GPLink_DN.Substring($GPLink_DN.IndexOf('dc='))
		)
	}
	
	$GP_hostingDomain_FQDN_List = 
	@(
		($GP_hostingDomain_DN_List | Select -Unique) -replace 'dc=','' -replace ',','.'
	)
	
	foreach ($GP_hostingDomain_FQDN in $GP_hostingDomain_FQDN_List)
	{
		if ($Domain_FQDN_Credential_List.IndexOf($GP_hostingDomain_FQDN) -eq -1)
		{
			$Domain_FQDN_Credential_extra_List = $Domain_FQDN_Credential_extra_List + @($GP_hostingDomain_FQDN)
		}
	}
	
	if ($Domain_FQDN_Credential_extra_List -ne $null)
	{
		$Credential_PsoCol = $Credential_PsoCol +
		@(
			Get-DomainCredential -Forest $Forest_FQDN -Domain $Domain_FQDN_Credential_extra_List
		)
	}

	foreach ($GPLink_DN in $GPLink_DN_List)
	{
		$GPLink_DN_lc = $GPLink_DN.ToLower()
		$GP_hostingDomain_FQDN = $GPLink_DN_lc.Substring($GPLink_DN_lc.IndexOf('dc=')) -replace 'dc=','' -replace ',','.' # IndexOf case sensitiv, replace not
		
		$Credential = ($Credential_PsoCol | Where { $_.Domain -eq $GP_hostingDomain_FQDN }).Credential
		
		try
		{
			$GP_Status_Pso = Get-ADObject $GPLink_DN -Properties displayName, flags, gPCFileSysPath, whenChanged, whenCreated -Server $GP_hostingDomain_FQDN -Credential $Credential |
			Select displayName,
				distinguishedName,
				whenChanged,
				whenCreated,
				@{ n = 'disabledOn'; e = { $null } },
				@{ n = 'enabledOn'; e = { $null } },
				@{ n = 'enforcedOn'; e = { $null } },				
				@{ n = 'existsInPolicies'; e = { $true } },				
				@{ n = 'hostingDomain'; e = { $GP_hostingDomain_FQDN } },
				@{ n = 'name'; e = { if ($_.name -ne $null) { $_.name } else { ($_.distinguishedName -split ',')[0] -replace 'CN=','' } } },
				@{ n = 'settings'; e = {switch($_.flags){0{'Computer Enabled, User Enabled'; break};1{'Computer Enabled, User Disabled'; break};2{'Computer Disabled, User Enabled'; break};3{'Computer Disabled, User Disabled'}}}},
				@{ n = 'sysvol'; e = { $null } },
				@{ n = 'sysvolServer'; e = { $null } }
		}
		catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
		{
			Write-Host "`n" -NoNewline
			
			$Msg = "`n" + ('Group Policy Object "{0}" appears as linked somewhere but does not exist anymore in Policies Container of "{1}"' -f $GPLink_DN, $GP_hostingDomain_FQDN)
			Write-Warning $Msg
			
			Write-Host "`n" -NoNewline
			
			$GPLink_Name = ($GPLink_DN -split ',')[0] -replace 'CN=',''
			
			$GP_Status_Pso =  New-Object PSObject -Property @{
				disabledOn = $null
				displayName = $null
				distinguishedName = $GPLink_DN
				enabledOn = $null
				enforcedOn = $null				
				existsInPolicies = $false
				hostingDomain = $GP_hostingDomain_FQDN
				name = $GPLink_Name
				settings = $null
				sysvol = $null
				sysvolServer = $null
				whenChanged = $null
				whenCreated = $null
			}
		}
		
		$GP_Linked_Status_PsoCol = $GP_Linked_Status_PsoCol + @($GP_Status_Pso)
	}
	
	$Msg = '=> {0} Group Policy(ies) linked' -f $GP_Linked_Status_PsoCol.Count
	Write-Host $Msg
	
	$Msg = 'Checking Link options : enabled, enforced, disabled'
	Write-Host $Msg -ForegroundColor White

	foreach ($GPLink_Status in $GPLink_Status_List)
	{
		$OU_List = @()
		
		foreach ($ADo_wGPLink in $ADo_wGPLink_Col)
		{
			$Filter =  '*' + $GPLink_Status + '*'
		
			if ($ADo_wGPLink.gPLink -like $Filter)
			{
				$OU_List = $OU_List + @($ADo_wGPLink.canonicalName)
			}
		}
		
		$GPLink_DN = $GPLink_Status -replace ';\d',''
		
		switch ($GPLink_Status)
		{
			{ $_.EndsWith(';0') }
			{
				($GP_Linked_Status_PsoCol | Where { $_.distinguishedName -eq $GPLink_DN}).enabledOn = (@($OU_List) | Out-String).Trim()
                break
			}
			
			{ $_.EndsWith(';1') }
			{
				($GP_Linked_Status_PsoCol | Where { $_.distinguishedName -eq $GPLink_DN}).disabledOn += (@($OU_List) | Out-String).Trim()
                break
			}
			
			{ $_.EndsWith(';2') }
			{
				($GP_Linked_Status_PsoCol | Where { $_.distinguishedName -eq $GPLink_DN}).enforcedOn += (@($OU_List) | Out-String).Trim()
                break
			}
			
			{ $_.EndsWith(';3') }
			{
				($GP_Linked_Status_PsoCol | Where { $_.distinguishedName -eq $GPLink_DN}).disabledOn += (@($OU_List) | Out-String).Trim()
                ($GP_Linked_Status_PsoCol | Where { $_.distinguishedName -eq $GPLink_DN}).enforcedOn += (@($OU_List) | Out-String).Trim()		
				break
			}
		}
	}
	
	$GP_Status_PsoCol = @($GP_Linked_Status_PsoCol)
	
	$Msg = 'Preparing status record of Group Policy(ies) not linked on Site(s) or Domain(s) listed below but stored in the latter:'
	$Msg = $Msg + "`n" + ($Domain_FQDN_List | Out-String).Trim()  
	Write-Host $Msg -ForegroundColor White
	
	foreach ($GPO_DN in $GPO_DN_List)
	{
		$GPO_DN_lc = $GPO_DN.ToLower()
		
		if ($GPLink_DN_List_lc.IndexOf($GPO_DN_lc) -eq -1)
		{
			$GPO_nLinked_DN_List = $GPO_nLinked_DN_List + @($GPO_DN)
		}
	}

	if ($GPO_nLinked_DN_List -ne $null)
	{
		foreach ($GPO_DN in $GPO_nLinked_DN_List)
		{
			$GPO_DN_lc = $GPO_DN.ToLower()
			$GP_hostingDomain_FQDN = $GPO_DN_lc.Substring($GPO_DN_lc.IndexOf('dc=')) -replace 'dc=','' -replace ',','.' # IndexOf case sensitiv, replace not
		
			$Credential = ($Credential_PsoCol | Where { $_.Domain -eq $GP_hostingDomain_FQDN }).Credential
			
			$GP_Status_Pso = Get-ADObject $GPO_DN -Properties displayName, flags, whenChanged, whenCreated -Server $GP_hostingDomain_FQDN -Credential $Credential |
			Select displayName,
				distinguishedName,
				whenChanged,
				whenCreated,
				@{ n = 'disabledOn'; e = { $null } },
				@{ n = 'enabledOn'; e = { $null } },
				@{ n = 'enforcedOn'; e = { $null } },			
				@{ n = 'existsInPolicies'; e = { $true } },
				@{ n = 'hostingDomain'; e = { $GP_hostingDomain_FQDN } },
				@{ n = 'name'; e = { if ($_.name -ne $null) { $_.name } else { ($_.distinguishedName -split ',')[0] -replace 'CN=','' } } },
				@{ n = 'settings'; e = {switch($_.flags){0{'Computer Enabled, User Enabled'; break};1{'Computer Enabled, User Disabled'; break};2{'Computer Disabled, User Enabled'; break};3{'Computer Disabled, User Disabled'}}}},
				@{ n = 'sysvol'; e = { $null } },
				@{ n = 'sysvolServer'; e = { $null } }

			$GP_nLinked_Status_PsoCol = $GP_nLinked_Status_PsoCol + @($GP_Status_Pso)
		}
		
		# Here are all GP linked and not linked but not yet orphaned
		$GP_Status_PsoCol = $GP_Status_PsoCol + @($GP_nLinked_Status_PsoCol)
	}
	
	$Msg = '=> {0} Group Policy(ies) not linked' -f $GP_nLinked_Status_PsoCol.Count
	Write-Host $Msg
	
	$Msg = 'Adding status record(s) considering orphaned Group Policy Directory(ies)'
	Write-Host $Msg -ForegroundColor White

	if ($GP_Directory_Orph_DN_List -ne $null)
	{
		$GP_Status_DN_List_lc = ($GP_Status_PsoCol.distinguishedName | Out-String).ToLower()
		
		foreach ($GP_Directory_Orph_DN in $GP_Directory_Orph_DN_List)
		{	
			$GP_Directory_Orph_DN_lc = $GP_Directory_Orph_DN.ToLower()
			
			if($GP_Status_DN_List_lc.IndexOf($GP_Directory_Orph_DN_lc) -eq -1)
			{
				$GP_Directory_Orph_Name = ($GP_Directory_Orph_DN -split 'CN=')[1] -replace ',',''
				$GP_Directory_hostingDomain_FQDN = $GP_Directory_Orph_DN.Substring($GP_Directory_Orph_DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
			
				$GP_Status_Pso =  New-Object PSObject -Property @{
					disabledOn = $null
					displayName = $null
					distinguishedName = $GP_Directory_Orph_DN
					enabledOn = $null
					enforcedOn = $null					
					existsInPolicies = $false
					hostingDomain = $GP_Directory_hostingDomain_FQDN
					name = $GP_Directory_Orph_Name
					settings = $null
					sysvol = $null
					sysvolServer = $null
					whenChanged = $null
					whenCreated = $null
				}
				
				$GP_Orph_Status_PsoCol = $GP_Orph_Status_PsoCol + @($GP_Status_Pso)
			}
		}
		
		$Msg = '=> {0} orphaned Directory(ies)' -f $GP_Directory_Orph_DN_List.Count
		Write-Host $Msg
	
		# Here are all GP linked, not linked and orphaned
		$GP_Status_PsoCol = $GP_Status_PsoCol + @($GP_Orph_Status_PsoCol)
	}
	
	$Msg = 'Checking Sysvol status:'
	Write-Host $Msg -ForegroundColor White
	
	Add-Type -TypeDefinition {
		[System.Flags]
		public enum sysvolStatus
		{
			ok_mConfiguration = 1,
			ok_uConfiguration = 2,
			no_mConfiguration = 4,
			no_uConfiguration = 8,
			no_Directory = 16,
			no_mFolder = 32,
			no_uFolder = 64,
			deniedAccess_Directory = 128,
			deniedAccess_mFolder = 256,
			deniedAccess_uFolder = 512,
			conflict_NTFRS = 1024
		}
	}
	
	$Check_SysvolStatus = {
		param
		(
			$GP_Status_Pso
		)
	
		$PSDrive_Filter = '*\SYSVOL\' + $GP_Status_Pso.hostingDomain + '\Policies'
		$PSDrive = Get-PSDrive -Name 'Sysvol_*' -PSProvider 'FileSystem' | Where { $_.Root -like $PSDrive_Filter }
		
		$GP_Directory = $PSDrive.Name + ':\' + $GP_Status_Pso.name
		
		$GP_Status_Pso.sysvolServer = ($PSDrive.Root -split '\\')[2]
		
		$Sysvol_Status = $null
		
		try
		{
			$GP_Directory_Exists = Test-Path $GP_Directory -PathType 'Container'
		}
		catch [System.UnauthorizedAccessException]
		{
			$GP_Status_Pso.sysvol = [sysvolStatus]128
			
			return $GP_Status_Pso
		}
		
		if ($GP_Directory_Exists)
		{
			$ErrorVar = $null
		
			$GP_Directory_mFolder = $GP_Directory + '\' + 'Machine'
			
			try
			{		
				$GP_Directory_mFolder_Count = 
				@(
					(Get-Childitem -Filter * -Path $GP_Directory_mFolder -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorVar | 
					Where { $_.Mode -notmatch 'd' })
				).Count
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				$Sysvol_Status = 32
			}
			catch [System.UnauthorizedAccessException]
			{
				$Sysvol_Status = 256
			}
			
			if ($ErrorVar.Exception -ne $null) # $_.Exception.GetType().Name -eq 'UnauthorizedAccessException' 
        	{
				$Sysvol_Status = 256
            }
			
			if ($GP_Directory_mFolder_Count -ge 1)
			{
				$Sysvol_Status = 1
			}
			elseif ($Sysvol_Status -eq $null)
			{
				$Sysvol_Status = 4
			}
			
			$ErrorVar = $null
			
			$GP_Directory_uFolder = $GP_Directory + '\' + 'User'
			
			try
			{
				$GP_Directory_uFolder_Count = 
				@(
					(Get-Childitem -Filter * -Path $GP_Directory_uFolder -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorVar | 
					Where { $_.Mode -notmatch 'd' })
				).Count
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				$Sysvol_Status += 64
			}
			catch [System.UnauthorizedAccessException]
			{
				$Sysvol_Status += 512
			}
			
			if ($ErrorVar.Exception -ne $null) # $_.Exception.GetType().Name -eq 'UnauthorizedAccessException' 
        	{
				$Sysvol_Status += 512
            }
	
			if ($GP_Directory_uFolder_Count -ge 1)
			{
				$Sysvol_Status += 2
			}
			elseif ( $([sysvolStatus]$Sysvol_Status) -notmatch 'uFolder') # -notmatch 'no_uFolder|deniedAccess_uFolder'
			{
				$Sysvol_Status += 8
			}

			$GP_Status_Pso.sysvol = [sysvolStatus]$Sysvol_Status
			
			return $GP_Status_Pso
		}
		else
		{
			$GP_Status_Pso.sysvol = [sysvolStatus]16
			
			return $GP_Status_Pso
		}
	}

	$Msg = '- selecting Domain Controller to query'
	Write-Host $Msg

	foreach ($GP_hostingDomain_FQDN in $GP_hostingDomain_FQDN_List)
	{
		if ($Domain_FQDN_List.IndexOf($GP_hostingDomain_FQDN) -eq -1)
		{
			$DC_FQDN = ((Get-ADDomainController -DomainName $GP_hostingDomain_FQDN -Discover).hostName)[0]
	
			$Credential = ($Credential_PsoCol | Where { $_.Domain -eq $GP_hostingDomain_FQDN }).Credential
		
			$PSDrive_Index = $Domain_FQDN_List.Count + $GP_hostingDomain_FQDN_List.IndexOf($GP_hostingDomain_FQDN)
			$PSDrive_Name = 'Sysvol_' + $PSDrive_Index
			$PSDrive_Root = '\\' + $DC_FQDN + '\SYSVOL\' + $GP_hostingDomain_FQDN + '\Policies'
		
			$Msg = '- mounting Network Drive "{0}" on "{1}"' -f $PSDrive_Name, $PSDrive_Root
			Write-Host $Msg
		
			try
			{
				New-PSDrive -Name $PSDrive_Name -Root $PSDrive_Root -PSProvider FileSystem -Credential $Credential | Out-Null
			}
			catch
			{
				Write-Host "`n" -NoNewline
			
				$Msg = "`n" + 'No access' + "`n" + 'Sysvol status checking aborted'
				Write-Warning $Msg
			
				$Msg = "`n" + 'Ending'
				Write-Host $Msg -Foreground Cyan -BackgroundColor Blue
			
				$GP_Status_PsoCol = $GP_Status_PsoCol | 
					Select hostingDomain,
						distinguishedName,
						name,
						displayName,
						enabledOn,
						enforcedOn,
						disabledOn,
						existsInPolicies,
						settings,
						sysvol,
						sysvolServer
						
				return $GP_Status_PsoCol
			}
		}
		else
		{
			$PSDrive_Index = $Domain_FQDN_List.IndexOf($GP_hostingDomain_FQDN)
			$PSDrive_Name = 'Sysvol_' + $PSDrive_Index
			$PSDrive_Root = '\\' + $DC_FQDN + '\SYSVOL\' + $GP_hostingDomain_FQDN + '\Policies'
		
			$Msg = '- Network Drive "{0}" on "{1}" already mounted' -f $PSDrive_Name,$PSDrive_Root
			Write-Host $Msg
		}
	}
	
	$Msg = '- checking Directory, Folder(s) and Setting(s) existence'
	Write-Host $Msg
	
	foreach ($GP_Status_Pso in $GP_Status_PsoCol)
	{
		$GP_Status_Pso = &$Check_SysvolStatus $GP_Status_Pso
	}
	
	$Msg = '- updating Sysvol status considering NTFRS conflict(s)'
	Write-Host $Msg	
	
	if ($GP_Directory_NTFRS_DN_List -ne $null)
	{
		$cptr = 0
		$GP_Directory_NTFRS_DN_List_lc = $GP_Directory_NTFRS_DN_List.ToLower()
		
		foreach ($GP_Status_Pso in $GP_Status_PsoCol)
		{
			$GP_Status_DN_lc = ($GP_Status_Pso.distinguishedName).ToLower()
			
			if($GP_Directory_NTFRS_DN_List_lc.IndexOf($GP_Status_DN_lc ) -ne -1)
			{
				$Sysvol_Status = [Int]($GP_Status_Pso.sysvol) + 1024
		
				$GP_Status_Pso.sysvol = [sysvolStatus]$Sysvol_Status
			
				$cptr++
			}
			
			if ($cptr -eq $GP_Directory_NTFRS_DN_List.Count)
			{
				break
			}
		}
		
		$Msg = '=> {0} NTFRS conflict(s)' -f $GP_Directory_NTFRS_DN_List.Count
		Write-Host $Msg
	}
	
	$Msg = "`n" + 'Ending'
	Write-Host $Msg -Foreground Cyan -BackgroundColor Blue
	Write-Host
	
	$GP_Status_PsoCol = $GP_Status_PsoCol | 
	Select hostingDomain,
		distinguishedName,
		name,
		displayName,
		enabledOn,
		enforcedOn,
		disabledOn,
		existsInPolicies,
		settings,
		sysvol,
		sysvolServer
	
	return $GP_Status_PsoCol
}
