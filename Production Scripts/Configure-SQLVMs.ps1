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
	
    $clientServiceName = "TSDListenerService"

    [xml] $config = gc "$scriptFolder\Config\DeploymentConfig.xml"

    #endregion
	
	#region Creating Azure Environment
	
	Set-AzureSubscription `
        -SubscriptionName $subscription.SubscriptionName `
        -CurrentStorageAccount $config.Azure.StorageAccountName `
        -ErrorAction Stop |
            Out-Null
	
	#endregion
	
	#region Create and Configure Domain Controllers
	
	$ad = $config.Azure.ActiveDirectory
	$dc = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "DomainControllers"}
	
	#endregion
	
	#region Create and Configure VMs for WSFC Nodes
	
	$sql = $config.Azure.AzureVMGroups.VMRole | where {$_.Name -eq "SQLServers"}
    $DBAAcct = $config.Azure.ServiceAccounts.ServiceAccount | where {$_.Type -eq "DBA"}
	
	#endregion
	
	#region configure AG
	
    Write-Host "Starting AG configuration"

    $server1 = ($sql.AzureVM | where {$_.Type -eq "Primary"}).Name
    $server2 = ($sql.AzureVM | where {$_.Type -eq "Secondary"}).Name
    $serverQuorum = ($sql.AzureVM | where {$_.Type -eq "Quorum"}).Name
    $cluster = $config.Azure.SQLCluster
    $acct1 = $cluster.PrimaryServiceAccountName
    $acct2 = $cluster.SecondaryServiceAccountName
    $password1 = GetPasswordByUserName $acct1 $config.Azure.ServiceAccounts.ServiceAccount
    $password2 = GetPasswordByUserName $acct2 $config.Azure.ServiceAccounts.ServiceAccount
    RunWSManScriptBlock `
        -serviceName $sql.ServiceName `
        -vmName $server1 `
        -userName $DBAAcct.UserName `
        -password $DBAAcct.Password `
        -credSSP $true `
        -argumentList $server1, $acct1, $password1, $server2, $acct2, $password2 `
        -scriptBlock `
        {
            param($server1, $acct1, $password1, $server2, $acct2, $password2)

            $timeout = New-Object System.TimeSpan -ArgumentList 0, 0, 30
			
            # Import SQL Server PowerShell Provider
            Set-ExecutionPolicy RemoteSigned -Force
            Import-Module "sqlps" -DisableNameChecking

            Write-Host " Change the SQL Server service account for $server1 to $acct1"
            $wmi1 = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $server1
            $wmi1.services | where {$_.Type -eq 'SqlServer'} | foreach{$_.SetServiceAccount($acct1,$password1)}
            $svc1 = Get-Service -ComputerName $server1 -Name 'MSSQLSERVER'
            $svc1.Stop()
            $svc1.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,$timeout)
            $svc1.Start(); 
            $svc1.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,$timeout)

            Write-Host " Change the SQL Server service account for $server2 to $acct2"
            $wmi2 = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $server2
            $wmi2.services | where {$_.Type -eq 'SqlServer'} | foreach{$_.SetServiceAccount($acct2,$password2)}
            $svc2 = Get-Service -ComputerName $server2 -Name 'MSSQLSERVER'
            $svc2.Stop()
            $svc2.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,$timeout)
            $svc2.Start(); 
            $svc2.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,$timeout)
        }

    Write-Host "Creating the WSFC cluster"
    $clusterScript = "$scriptFolder\CreateAzureFailoverCluster.ps1"
    Unblock-File -Path $clusterScript -ErrorAction Stop
    RunWSManScriptFile `
        -serviceName $sql.ServiceName `
        -vmName $server1 `
        -userName $DBAAcct.UserName `
        -password $DBAAcct.Password `
        -credSSP $true `
        -argumentList $cluster.Name, @($server1,$server2) `
        -scriptFile $clusterScript |
            Out-Null

     RunWSManScriptBlock `
         -serviceName $sql.ServiceName `
         -vmName $serverQuorum `
         -userName $DBAAcct.UserName `
         -password $DBAAcct.Password `
         -argumentList $acct1, $acct2, ($ad.Domain + "\" + $cluster.Name) `
         -scriptBlock `
         {
             param($acct1, $acct2, $clusterAcct)
			
             $backupDir = "G:\backup"
             $quorumDir = "F:\quorum"

			 Write-Host "Create share folder for quorum configuration"
             New-Item $quorumDir -ItemType directory | Out-Null
             net share quorum=$quorumDir "/grant:Everyone,FULL"| Out-Null
             icacls.exe $quorumDir /grant:r ('Everyone:(OI)(CI)F') | Out-Null

			 Write-Host "Create backup directory and grant permissions for the SQL Server service accounts"
             New-Item $backupDir -ItemType directory | Out-Null
             net share backup=$backupDir "/grant:$acct1,FULL" "/grant:$acct2,FULL" | Out-Null
             icacls.exe $backupDir /grant:r ($acct1 + ':(OI)(CI)F') ($acct2 + ':(OI)(CI)F') | Out-Null
         }

     RunWSManScriptBlock `
         -serviceName $sql.ServiceName `
         -vmName $server1 `
         -userName $DBAAcct.UserName `
         -password $DBAAcct.Password `
         -credSSP $true `
         -argumentList $server1, $server2, $serverQuorum, $acct1, $acct2, $cluster.Name, $cluster.Database, $cluster.AvailabilityGroup `
         -scriptBlock `
         {
             param($server1, $server2, $serverQuorum, $acct1, $acct2, $clusterName, $DatabaseName, $AvailabilityGroupName)

             $timeout = New-Object System.TimeSpan -ArgumentList 0, 0, 30
             $backupShare = "\\$serverQuorum\backup"
             $quorumShare = "\\$serverQuorum\quorum"

             Write-Host "Set quorum to file share majority with $serverQuorum"
             Import-Module FailoverClusters
			  Set-ClusterQuorum -NodeAndFileShareMajority $quorumShare | Out-Null
            
			# Import SQL Server PowerShell Provider
             Set-ExecutionPolicy RemoteSigned -Force
             Import-Module "sqlps" -DisableNameChecking

             Write-Host "Enable AlwaysOn Availability Groups for $server1 and $server2"
             Enable-SqlAlwaysOn `
                 -Path SQLSERVER:\SQL\$server1\Default `
                 -Force
             Enable-SqlAlwaysOn `
                 -Path SQLSERVER:\SQL\$server2\Default `
                 -NoServiceRestart
				
             $svc2 = Get-Service -ComputerName $server2 -Name 'MSSQLSERVER'
             $svc2.Stop()
             $svc2.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,$timeout)
             $svc2.Start(); 
             $svc2.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,$timeout) 
			 
             Write-Host " Create database $DatabaseName, and restore its backups on $server2 with NO RECOVERY"
             Invoke-SqlCmd -Query "CREATE database $DatabaseName"
             Backup-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.bak" -ServerInstance $server1
             Backup-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.log" -ServerInstance $server1 -BackupAction Log
             Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.bak" -ServerInstance $server2 -NoRecovery
             Restore-SqlDatabase -Database $DatabaseName -BackupFile "$backupShare\$DatabaseName.log" -ServerInstance $server2 -RestoreAction Log -NoRecovery 

             Write-Host " Create the availability group"
             $endpoint = 
                 New-SqlHadrEndpoint MyMirroringEndpoint `
                 -Port 5022 `
                 -Path "SQLSERVER:\SQL\$server1\Default"
             Set-SqlHadrEndpoint `
                 -InputObject $endpoint `
                 -State "Started" |
                    Out-Null
            $endpoint = 
                New-SqlHadrEndpoint MyMirroringEndpoint `
                -Port 5022 `
                -Path "SQLSERVER:\SQL\$server2\Default"
            Set-SqlHadrEndpoint `
                -InputObject $endpoint `
                -State "Started" |
                    Out-Null

            Invoke-SqlCmd -Query "CREATE LOGIN [$acct2] FROM WINDOWS" -ServerInstance $server1
            Invoke-SqlCmd -Query "GRANT CONNECT ON ENDPOINT::[MyMirroringEndpoint] TO [$acct2]" -ServerInstance $server1
            Invoke-SqlCmd -Query "CREATE LOGIN [$acct1] FROM WINDOWS" -ServerInstance $server2
            Invoke-SqlCmd -Query "GRANT CONNECT ON ENDPOINT::[MyMirroringEndpoint] TO [$acct1]" -ServerInstance $server2 

            $primaryReplica = 
                New-SqlAvailabilityReplica `
                -Name $server1 `
                -EndpointURL "TCP://$server1.broadleaf.local:5022" `
                -AvailabilityMode "SynchronousCommit" `
                -FailoverMode "Automatic" `
                -Version 12 `
                -AsTemplate

            $secondaryReplica = 
                New-SqlAvailabilityReplica `
                -Name $server2 `
                -EndpointURL "TCP://$server2.broadleaf.local:5022" `
                -AvailabilityMode "SynchronousCommit" `
                -FailoverMode "Automatic" `
                -Version 12 `
                -AsTemplate

            New-SqlAvailabilityGroup `
                -Name $AvailabilityGroupName `
                -Path "SQLSERVER:\SQL\$server1\Default" `
                -AvailabilityReplica @($primaryReplica,$secondaryReplica) `
                -Database $DatabaseName |
                    Out-Null

            Join-SqlAvailabilityGroup `
                -Path "SQLSERVER:\SQL\$server2\Default" `
                -Name $AvailabilityGroupName

            Add-SqlAvailabilityDatabase `
                -Path "SQLSERVER:\SQL\$server2\Default\AvailabilityGroups\$AvailabilityGroupName" `
                -Database $DatabaseName 
        }

    Write-Host "Create the availability group listener"
    # create AG listener
    $listenerScript = "$scriptFolder\ConfigureAGListenerCloudOnly.ps1"
    Unblock-File -Path $listenerScript -ErrorAction Stop
    & $listenerScript `
        -AGName $cluster.AvailabilityGroup `
        -ListenerName $cluster.Listener `
        -ServiceName $sql.ServiceName `
        -EndpointName "SQLEndpoint" `
        -EndpointPort "1433" `
        -WSFCNodes $server1, $server2 `
        -DomainAccount $DBAAcct.UserName `
        -Password $DBAAcct.Password

    Write-Host "Done with AG configuration."

    #endregion

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

function RunWSManScriptFile (
	$serviceName,
	$vmName,
	$userName,
	$password,
	$credSSP = $false,
	$argumentList,
	$scriptFile
)
{
    $uri = Get-AzureWinRMUri -ServiceName $serviceName -Name $vmName
    $credential = New-Object System.Management.Automation.PSCredential($userName, $(ConvertTo-SecureString $password -AsPlainText -Force))
    if($credSSP)
    {
        Invoke-Command `
            -ConnectionUri $uri.ToString() `
            -Credential $credential `
            -EnableNetworkAccess `
            -Authentication Credssp `
            -ArgumentList $argumentList `
            -FilePath $scriptFile `
            -ErrorAction Stop
    }
    else
    {
        Invoke-Command `
            -ConnectionUri $uri.ToString() `
            -Credential $credential `
            -ArgumentList $argumentList `
            -FilePath $scriptFile `
            -ErrorAction Stop
    }
}

################## End Functions ##############################

################## Script Execution ###########################

#Call ExecuteDeployment
 ExecuteDeployment

################## End Script Execution #######################