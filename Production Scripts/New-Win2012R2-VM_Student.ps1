<#
 * Copyright Tim Song
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
#>

$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition
. "$scriptFolder\HelperFunctions.ps1"

################## Functions ##############################

function ExecuteDeployment()
{
	param(
		[switch]$CreateAffinityGroup = $false,
		[switch]$CreateNetwork = $false,
		[switch]$CreateDC = $false
	)
	
	# Set the output level to verbose and make the script stop on error
	$VerbosePreference = "Continue"
	$ErrorActionPreference = "Stop"
	
	cls
	
	if((IsAdmin) -eq $false)
    {
        Write-Host "Must run PowerShell elevated."
        return
    }
	
	Write-Host "Enabling PowerShell remoting and the CredSSP client on the local machine..."
    Enable-PSRemoting -Force -ErrorAction Stop | Out-Null
    Enable-WSManCredSSP -Role client -DelegateComputer "*.cloudapp.net" -Force -ErrorAction Stop | Out-Null
    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentialsWhenNTLMOnlyDomain"
    Set-ItemProperty $regKey -Name WSMan -Value "WSMAN/*.cloudapp.net" -ErrorAction Stop | Out-Null
    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentialsWhenNTLMOnly"
    Set-ItemProperty $regKey -Name WSMan -Value "WSMAN/*.cloudapp.net" -ErrorAction Stop | Out-Null
	
	$date = Get-Date
    Write-Host "Starting New Windows Server 2012 R2 Deployment $date"
	
	#region Initialize Azure variables
	
	Import-AzurePublishSettingsFile "$scriptFolder\Config\Broadleaf Prod-9-15-2014-credentials.publishsettings"
	
    $subscription = Get-AzureSubscription -Current -ErrorAction Stop
	if($subscription -eq $null)
    {
        Write-Host "Windows Azure Subscription is not configured or the specified subscription name is invalid."
        Write-Host "Use Get-AzurePublishSettingsFile and Import-AzurePublishSettingsFile first"
        return
    }

    [xml] $config = gc "$scriptFolder\Config\DeploymentConfig.xml"

    #endregion
	
	#region Creating Azure Environment
	
	# Create AffinityGroup
	if($CreateAffinityGroup -eq $true)
	{
		New-AzureAffinityGroup `
			-Name $config.Azure.AffinityGroup `
			-Location $config.Azure.Location `
			-ErrorAction Stop
	}
	
	# Create Network
	if($CreateNetwork -eq $true)
	{	
		Set-AzureVNetConfig `
			-ConfigurationPath "$scriptFolder\Config\NetworkConfig.xml" `
			-ErrorAction Stop
	}
	
	# Create Storage Account
	$storageAccountName = (Get-AzureStorageAccount | where {$_.StorageAccountName -eq $config.Azure.StorageAccountName}).StorageAccountName	
	
	if(-Not $storageAccountName)
	{
		New-AzureStorageAccount `
			-StorageAccountName $config.Azure.StorageAccountName `
			-Location $config.Azure.Location `
			-ErrorAction Stop |
				Out-Null

		$storageAccountName = $config.Azure.StorageAccountName
	}
	
	
	Set-AzureSubscription `
        -SubscriptionName $subscription.SubscriptionName `
        -CurrentStorageAccount $storageAccountName `
        -ErrorAction Stop |
            Out-Null
	
	#endregion
	
	#region Create and Configure Domain Controllers
	
	if($CreateDC -eq $true)
	{
	}
	else
	{
		$ad = $config.Azure.ActiveDirectory
		$dc = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "DomainControllers"}
	}
	
	#endregion
	
	#region Create and Configure VMs for WSFC Nodes
	
    $vmRoles = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "WindowsServerStudent"}
    $password = GetPasswordByUserName $vmRoles.ServiceAccountName $config.Azure.ServiceAccounts.ServiceAccount 
    $DBAAcct = $config.Azure.ServiceAccounts.ServiceAccount | where {$_.Type -eq "DBA"}
    $domainAcct = $config.Azure.ServiceAccounts.ServiceAccount | where {$_.Type -eq "WindowsDomain"}
    $dnsIP = (Get-AzureVM -ServiceName $dc.ServiceName -Name $dc.AzureVM.Name).IpAddress    
    
	foreach($vm in $vmRoles.AzureVM)    
    {	
        $newService = $false        

        if ($vmRoles.AzureVM.IndexOf($vm) -eq 0)
        {         
           $newService = $true;
        }

        if((Get-Module ServerManager)){
            Remove-Module ServerManager
        }
                
        $vmName = $vm.Name
		$vmSize = $vm.VMSize
        $vmSubnetNames = $vmRoles.SubnetNames
        $vmServiceAccountName = $vmRoles.ServiceAccountName
        $vmServiceName = $vmRoles.ServiceName
		$vmAvailabilitySet = $vmRoles.AvailabilitySet
        $vnetName = $config.Azure.VNetName
        $vmLocation = $config.Azure.Location
        $vmDrive = $vm.Drive
        $image = GetVMImage $vm.ImageName

		Write-Host "Creating VM $($vmName)..."
		Write-Host "Service Account Name $($vmServiceAccountName)"		
                
		CreateVM `
			-vmName $vmName `
			-imageName $image `
			-size $vmSize `
			-subnetNames $vmSubnetNames `
			-adminUserName $vmServiceAccountName `
			-password $password `
			-serviceName $vmServiceName `
			-newService $newService `
			-availabilitySet $vmAvailabilitySet `
			-vnetName $vnetName `
			-affinityGroup $vmLocation `
			-windowsDomain $true `
			-dnsIP $dnsIP `
			-domainJoin $ad.DnsDomain `
			-domain $ad.Domain `
			-domainUserName $domainAcct.UserName `
			-domainPassword $domainAcct.Password `
			-dataDisks $vmDrive

		Write-Host "Initializing $($vmName)..."
		RunWSManScriptBlock `
            -serviceName $vmServiceName `
            -vmName $vmName `
            -userName ($vmName + "\" + $vmServiceAccountName) `
            -password $password `
            -argumentList $DBAAcct.UserName `
            -scriptBlock `
			{
				param($domainAcct)

				#Write-Host " Adding $domainAcct as local administrator"
				#net localgroup administrators "$domainAcct" /Add				

				Set-ExecutionPolicy -Execution RemoteSigned -Force
				Write-Host "Installing windows features"

				Import-Module ServerManager
				Install-WindowsFeature -Name Web-Common-Http
                Install-WindowsFeature -Name Web-Http-Redirect
                Install-WindowsFeature -Name Web-DAV-Publishing
                Install-WindowsFeature -Name Web-Performance
                Install-WindowsFeature -Name Web-Stat-Compression
                Install-WindowsFeature -Name Web-Dyn-Compression
                Install-WindowsFeature -Name Web-App-Dev
                #Install-WindowsFeature -Name Web-Net-Ext 
                Install-WindowsFeature -Name Web-Net-Ext45                  
                Install-WindowsFeature -Name Web-AppInit                    
                Install-WindowsFeature -Name Web-ASP                        
                #Install-WindowsFeature -Name Web-Asp-Net                    
                Install-WindowsFeature -Name Web-Asp-Net45                  
                Install-WindowsFeature -Name Web-CGI                    
                Install-WindowsFeature -Name Web-ISAPI-Ext
                Install-WindowsFeature -Name Web-ISAPI-Filter               
                Install-WindowsFeature -Name Web-Includes                
                Install-WindowsFeature -Name Web-WebSockets
                Install-WindowsFeature -Name Web-Mgmt-Tools
                Install-WindowsFeature -Name Web-Mgmt-Console
                Install-WindowsFeature -Name Web-Mgmt-Compat
                Install-WindowsFeature -Name Web-Mgmt-Servce
                Install-WindowsFeature -Name Web-Scripting-Tools                
                Install-WindowsFeature -Name Web-WHC

				$websiteDir = "C:\inetpub\websites"
				$iisAcct = "IIS AppPool\Multi.Staff"

                Write-Host "Setting Server TimeZone to Central Standard Time..."
                tzutil.exe /s "Central Standard Time"

				Write-Host "Create websites folder"
				New-Item $websiteDir -ItemType directory #| Out-Null

				Write-Host "Adding Permissions to websites folder"
				net share $web "/grant:$iisAcct,READ/WRITE" #| Out-Null				 
				    
				Write-Host " Opening firewall port 80"					
				netsh advfirewall firewall add rule name='Staff TCP In Port 80' dir=in localport=80 action=allow protocol=TCP #| Out-Null

                Write-Host " Opening firewall port 443"                    
                netsh advfirewall firewall add rule name='Staff TCP In Port 443' localport=443 action=allow dir=in protocol=TCP #| Out-Null

                Write-Host " Opening firewall port 8080"
                netsh advfirewall firewall add rule name='Staff TCP In Port 8080' dir=in localport=8080 action=allow protocol=TCP #| Out-Null
				    
				Write-Host " Enable delegation of client credentials for PS remoting"
				Enable-WSManCredSSP -Role Server -Force #| Out-Null					
                
				Write-Host "Done with $env:COMPUTERNAME"
			}

        Write-Host "Create Azure Endpoints"         

         $VMData = ( 
        @{ 
            ServiceName = $vmServiceName; 
            VMName = $vmName; 
            AEName = "HTTP"; 
            AEProtocol = "TCP" 
            AEPublicPort = "80"; 
            AELocalPort = "80";
            AELBSetName = "HTTP-LB";
        }, 
      
        @{ 
            ServiceName = $vmServiceName; 
            VMName = $vmName; 
            AEName = "HTTPS"; 
            AEProtocol = "TCP" 
            AEPublicPort = "443"; 
            AELocalPort = "443";
            AELBSetName = "HTTPS-LB";
        },
        @{ 
            ServiceName = $vmServiceName; 
            VMName = $vmName; 
            AEName = "PowerShell"; 
            AEProtocol = "TCP" 
            AEPublicPort = "5986"; 
            AELocalPort = "5986";
            AELBSetName = "PowerShell-LB";
        })


        foreach ($VME in $VMData) 
        { 
            Get-AzureVM -ServiceName $VME.ServiceName -Name $VME.VMName | `

            Add-AzureEndpoint -Name $VME.AEName -LBSetName $VME.AELBSetName -ProbePort $VME.AEPublicPort -ProbeProtocol $VME.AEProtocol -Protocol $VME.AEProtocol -LocalPort $VME.AELocalPort -PublicPort $VME.AEPublicPort | `
             
            Update-AzureVM
         
            Write-Output "Finished adding azure endpoints..."
	    }
	}

	Write-Verbose "Script is complete."
	# Mark the finish time of the script execution
	$finishTime = Get-Date
	# Output the time consumed in seconds
	$TotalTime = ($finishTime - $date).TotalSeconds
	Write-Output "Total time used (seconds): $TotalTime"
}

function GetVMImage($imageName)
{
	$image = (Get-AzureVMImage | where {$_.ImageFamily -eq $imageName} | sort PublishedDate -Descending)[0].ImageName
	return $image
}

function CreateVM (
	$vmName, 
	$imageName, 
	$size,
	$subnetNames,
	$adminUserName,
	$password,
	$serviceName,
	$newService = $false,
	$availabilitySet = "",
	$vnetName,
	$affinityGroup,
	$windowsDomain = $false,
	$dnsIP,
	$domainJoin,
	$domain,
	$domainUserName,
	$domainPassword,
	$dataDisks
)
{
    if($availabilitySet -ne "")
    {
    	$vmConfig = New-AzureVMConfig -Name $vmName -InstanceSize $size -ImageName $imageName -AvailabilitySetName $availabilitySet -ErrorAction Stop
    }
    else
    {
    	$vmConfig = New-AzureVMConfig -Name $vmName -InstanceSize $size -ImageName $imageName -ErrorAction Stop
    }

    $vmConfig | Set-AzureSubnet -SubnetNames $subnetNames -ErrorAction Stop | Out-Null
	
    if ($dataDisks -ne $null)
    {
	    for($i=0; $i -lt $dataDisks.Count; $i++)
	    {
	  	    $disk = $dataDisks[$i]
		    $dataDiskLabel = $disk.Name
	  	    $dataDiskSize = $disk.Size
	  	    Write-Host ("Adding disk {0} with size {1}" -f $dataDiskLabel, $dataDiskSize)	
		
		    #Add Data Disk to the newly created VM
		    $vmConfig | Add-AzureDataDisk -CreateNew -DiskSizeInGB $dataDiskSize -DiskLabel $dataDiskLabel -LUN $i -ErrorAction Stop | Out-Null
	    }
    }
	
	if($windowsDomain)
	{
		$vmConfig | Add-AzureProvisioningConfig -WindowsDomain -Password $password -AdminUserName $adminUserName -JoinDomain $domainjoin -Domain $domain -DomainPassword $domainPassword -DomainUserName $domainUserName -ErrorAction Stop | Out-Null
	}
	else
	{
		$vmConfig | Add-AzureProvisioningConfig -Windows -Password $password -AdminUserName $adminUserName -ErrorAction Stop | Out-Null
	}

    if($newService)
    {
        if($windowsDomain)
        {
            $dns = New-AzureDns -Name "DNS" -IPAddress $dnsIP
    		New-AzureVM -ServiceName $serviceName -Location $affinityGroup -VNetName $vnetName -DnsSettings $dns -VMs $vmConfig -WaitForBoot -Verbose -ErrorAction Stop
        }
        else
        {
    		New-AzureVM -ServiceName $serviceName -Location $affinityGroup -VNetName $vnetName -VMs $vmConfig -WaitForBoot -Verbose -ErrorAction Stop
        }
    }
    else
    {
		New-AzureVM -ServiceName $serviceName -VMs $vmConfig -WaitForBoot -Verbose -ErrorAction Stop
    }

    InstallWinRMCertificateForVM $serviceName $vmName
    # Download remote desktop file to working directory (just in case)
    Get-AzureRemoteDesktopFile -ServiceName $serviceName -Name $vmName -LocalPath "$scriptFolder\$vmName.rdp" -ErrorAction Stop | Out-Null
    
    Write-Host "Pausing for Services to Start"
    Start-Sleep 60 
}

function RunWSManScriptBlock (
	$serviceName,
	$vmName,
	$userName,
	$password,
	$credSSP = $false,
	$argumentList,
	$scriptBlock
)
{
    $uri = Get-AzureWinRMUri -ServiceName $serviceName -Name $vmName -ErrorAction Stop
    $credential = New-Object System.Management.Automation.PSCredential($userName, $(ConvertTo-SecureString $password -AsPlainText -Force))
		
    if($credSSP)
    {
        Invoke-Command `
            -ConnectionUri $uri.ToString() `
            -Credential $credential `
            -EnableNetworkAccess `
            -Authentication Credssp `
            -ArgumentList $argumentList `
            -ScriptBlock $scriptBlock `
            -ErrorAction Continue
    }
    else
    {
        Invoke-Command `
            -ConnectionUri $uri.ToString() `
            -Credential $credential `
            -ArgumentList $argumentList `
            -ScriptBlock $scriptBlock `
            -ErrorAction Continue
    }
}

################## End Functions ##############################

################## Script Execution ###########################

#Call ExecuteDeployment
ExecuteDeployment

################## End Script Execution #######################