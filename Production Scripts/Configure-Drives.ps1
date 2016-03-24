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
    Write-Host "Starting New SQL Always On Deployment $date"
	
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
	
	$ad = $config.Azure.ActiveDirectory
	$dc = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "DomainControllers"}
	
	#endregion
	
	#region Create and Configure VMs for WSFC Nodes
	
	$sql = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "SQLServers"}
    $password = GetPasswordByUserName $sql.ServiceAccountName $config.Azure.ServiceAccounts.ServiceAccount 
    $DBAAcct = $config.Azure.ServiceAccounts.ServiceAccount | where {$_.Type -eq "DBA"}
    
	foreach($vm in $sql.AzureVM)
    {	
		Write-Host "Configuring VM $($vm.Name) Disk Drives..."

		if($vm.Type -eq "QUORUM")
		{
			RunWSManScriptBlock `
				-serviceName $sql.ServiceName `
				-vmName $vm.Name `
				-userName ($vm.Name + "\" + $sql.ServiceAccountName) `
				-password $password `
				-scriptBlock `
				{
					Write-Host "Getting DATA disks to stripe for disks..."
					Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
    
					Write-Host "Data Drive"
					$dataPool = "Data01"
					$dataDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk2")
					New-StoragePool `
						-FriendlyName $dataPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $dataDisks |
						New-VirtualDisk `
							-FriendlyName $dataPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false

					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $poolName"

					Write-Host "Data Drive 2"
					$dataPool2 = "Data02"
					$dataDisks2 = Get-PhysicalDisk -FriendlyName @("PhysicalDisk3")
					New-StoragePool `
						-FriendlyName $dataPool2 `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $dataDisks2 |
						New-VirtualDisk `
							-FriendlyName $dataPool2 `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false
					
					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $poolName2"
					Write-Host "Done with $env:COMPUTERNAME"
				}
		}
		elseif ($vm.Name -eq "AZEPRDDB02")
		{
			Write-Host "Initializing $($vm.Name)..."
			RunWSManScriptBlock `
				-serviceName $sql.ServiceName `
				-vmName $vm.Name `
				-userName ($vm.Name + "\" + $sql.ServiceAccountName) `
				-password $password `
				-scriptBlock `
				{
					Write-Host "Getting DATA disks to stripe for disks..."
					Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
    
					Write-Host "Data Drive"
					$dataPool = "Data01"
					$dataDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk2", "PhysicalDisk3", "PhysicalDisk4", "PhysicalDisk5", "PhysicalDisk6", "PhysicalDisk7")
					New-StoragePool `
						-FriendlyName $dataPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $dataDisks |
						New-VirtualDisk `
							-FriendlyName $dataPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false

					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $dataPool"


					Write-Host "Index Drive"
					$indexPool = "Index01"
					$indexDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk8", "PhysicalDisk9")
					New-StoragePool `
						-FriendlyName $indexPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $indexDisks |
						New-VirtualDisk `
							-FriendlyName $indexPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false
					
					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $indexPool"


					Write-Host "Log Drive"
					$logPool = "Log01"
					$logDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk10", "PhysicalDisk11", "PhysicalDisk12", "PhysicalDisk13")
					New-StoragePool `
						-FriendlyName $logPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $logDisks |
						New-VirtualDisk `
							-FriendlyName $logPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false
					
					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $logPool"


					Write-Host "Temp Drive"
					$tempPool = "Temp01"
					$tempDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk14", "PhysicalDisk15")
					New-StoragePool `
						-FriendlyName $tempPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $tempDisks |
						New-VirtualDisk `
							-FriendlyName $tempPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false
					
					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $tempPool"


					Write-Host "Backup Drive"
					$backupPool = "Backup01"
					$backupDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk16")
					New-StoragePool `
						-FriendlyName $backupPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $backupDisks |
						New-VirtualDisk `
							-FriendlyName $backupPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false

					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $backupPool"


					Write-Host "Scratch Drive"
					$scratchPool = "Backup01"
					$scratchDisks = Get-PhysicalDisk -FriendlyName @("PhysicalDisk17")
					New-StoragePool `
						-FriendlyName $scratchPool `
						-StorageSubSystemFriendlyName "Storage Spaces*" `
						-PhysicalDisks $scratchDisks |
						New-VirtualDisk `
							-FriendlyName $scratchPool `
							-ResiliencySettingName Simple `
							-ProvisioningType Fixed `
							-AutoNumberOfColumns `
							-UseMaximumSize |
							Get-VirtualDisk | 
								Initialize-Disk	`
									-PassThru | 
									New-Partition `
										-AssignDriveLetter `
										-UseMaximumSize | 
										Format-Volume `
										-Confirm:$false

					Start-Sleep -Seconds 120
					Write-Host "Created Storage Pool $scratchPool"
					Write-Host "Done with $env:COMPUTERNAME"
				}
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
            -ErrorAction Stop
    }
    else
    {
        Invoke-Command `
            -ConnectionUri $uri.ToString() `
            -Credential $credential `
            -ArgumentList $argumentList `
            -ScriptBlock $scriptBlock `
            -ErrorAction Stop
    }
}

################## End Functions ##############################

################## Script Execution ###########################

#Call ExecuteDeployment
ExecuteDeployment

################## End Script Execution #######################