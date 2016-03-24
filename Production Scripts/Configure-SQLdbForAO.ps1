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
		[switch]$CreateStorageAccount = $false,
		[switch]$CreateNetwork = $false,
		[switch]$CreateDC = $false
	)
		
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
	
	Set-AzureSubscription `
        -SubscriptionName $subscription.SubscriptionName `
        -CurrentStorageAccount $config.Azure.StorageAccountName `
        -ErrorAction Stop |
            Out-Null
	
		
	Write-Host "Starting with adding dbs to AG"

	$sql = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "SQLServers"}
	$sqlServiceName = $sql.ServiceName
    $DBAAcct = $config.Azure.ServiceAccounts.ServiceAccount | where {$_.Type -eq "DBA"}
    $server1 = ($sql.AzureVM | where {$_.Type -eq "Primary"}).Name
    $server2 = ($sql.AzureVM | where {$_.Type -eq "Secondary"}).Name
    $serverQuorum = ($sql.AzureVM | where {$_.Type -eq "Quorum"}).Name
    $cluster = $config.Azure.SQLCluster
    
	
	foreach($database in $cluster.Databases)
    {
		 RunWSManScriptBlock `
			 -serviceName $sqlServiceName `
			 -vmName $server1 `
			 -userName $DBAAcct.UserName `
			 -password $DBAAcct.Password `
			 -credSSP $true `
			 -argumentList $server1, $server2, $serverQuorum, $cluster.AvailabilityGroup, $database.Name, $database.CreateOnPrimary, $database.BackupFromPrimary, $database.RestoreOnPrimary, $database.RestoreOnSecundary `
			 -scriptBlock `
			 {
				 param($server1, $server2, $serverQuorum, $AvailabilityGroupName, $DatabaseName, $DatabaseCreateOnPrimary, $DatabaseBackupFromPrimary, $DatabaseRestoreOnPrimary, $DatabaseRestoreOnSecundary)

				 $backupShare = "\\$serverQuorum\backup"

				 # Import SQL Server PowerShell Provider
				 Set-ExecutionPolicy RemoteSigned -Force
				 Import-Module "sqlps" -DisableNameChecking
				 
				 Write-Host " Starting with database $DatabaseName ..."
				 # Write-Host "    * DatabaseCreateOnPrimary = $DatabaseCreateOnPrimary"
				 # Write-Host "    * DatabaseBackupFromPrimary = $DatabaseBackupFromPrimary"
				 # Write-Host "    * DatabaseRestoreOnPrimary = $DatabaseRestoreOnPrimary"
				 # Write-Host "    * DatabaseRestoreOnSecundary = $DatabaseRestoreOnSecundary"
				 if($DatabaseCreateOnPrimary -eq "true")
				 {
					Write-Host " Creating database $DatabaseName on $server1"
					Invoke-SqlCmd -Query "CREATE database $DatabaseName" -ServerInstance $server1
				 }
				 if($DatabaseBackupFromPrimary -eq "true")
				 {
					 Write-Host " Creating backup from database $DatabaseName on $server1 as folder $backupShare\$DatabaseName.bak"
					 Backup-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.bak" -ServerInstance $server1
					 Backup-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.log" -ServerInstance $server1 -BackupAction Log
				 }
				 if($DatabaseRestoreOnPrimary -eq "true")
				 {
					 Write-Host " Creating restore for database $DatabaseName on $server1 from $backupShare\$DatabaseName.bak"
					 Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.bak" -ServerInstance $server1 
					 Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.log" -ServerInstance $server1 -RestoreAction Log 				 
				 }
				 if($DatabaseRestoreOnSecundary -eq "true")
				 {
					 Write-Host " Creating restore for database $DatabaseName on $server2 from $backupShare\$DatabaseName.bak" 
					 Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.bak" -ServerInstance $server2 -NoRecovery
					 Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.log" -ServerInstance $server2 -RestoreAction Log -NoRecovery 
				 }
				 Write-Host " Adding database $DatabaseName on $server1 to availability group $AvailabilityGroupName"
				 Add-SqlAvailabilityDatabase -Path "SQLSERVER:\SQL\$server1\Default\AvailabilityGroups\$AvailabilityGroupName" -Database $DatabaseName
				 
				 Write-Host " Adding database $DatabaseName on $server2 to availability group $AvailabilityGroupName"				
				 Add-SqlAvailabilityDatabase -Path "SQLSERVER:\SQL\$server2\Default\AvailabilityGroups\$AvailabilityGroupName" -Database $DatabaseName 			 
			}
	}
    Write-Host "Done with adding dbs into AG."

	Write-Verbose "Script is complete."
	# Mark the finish time of the script execution
	$finishTime = Get-Date
	# Output the time consumed in seconds
	$TotalTime = ($finishTime - $date).TotalSeconds
	Write-Output "Total time used (seconds): $TotalTime"

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