# values from central cfg 
if(!$DoRetries){$DoRetries = 4 ; } ;          # attempt retries
if(!$RetrySleep){$RetrySleep = 5 ; }          # mid-retry sleep in secs
if(!$retryLimit){[int]$retryLimit=1; }        # just one retry to patch lineuri duped users and retry 1x
if(!$retryDelay){[int]$retryDelay=20; }       # secs wait time after failure
if(!$abortPassLimit){$abortPassLimit = 4;}    # maximum failed users to abort entire pass

$RootPath = $env:USERPROFILE + "\ps\"
if(!(test-path $RootPath)){ mkdir $RootPath}  ; 
$KeyPath = $Rootpath + "creds\"
if(!(test-path $KeyPath)){ mkdir $KeyPath}  ; 

#*------v Function connect-AzureRM v------
function connect-AzureRM {
    <#
    .SYNOPSIS
    connect-AzureRM.ps1 - Connect to AzureRM module
    .NOTES
    Version     : 1.6.2
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2019-02-06
    FileName    :
    License     : MIT License
    Copyright   : (c) 2019 Todd Kadrie
    Github      : https://github.com/tostka
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    #* 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    .DESCRIPTION
    .PARAMETER  ProxyEnabled
    Switch for Access Proxy in chain
    .PARAMETER  Credential
    Credential object
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .EXAMPLE
    .\connect-AzureRM.ps1
    .EXAMPLE
    .\connect-AzureRM.ps1
    .LINK
    #>
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;

    $MFA=$false ;
    # 8:32 AM 11/19/2019 torolab is mfa now, need to check
    $credDom = ($Credential.username.split("@"))[1] ;
    if(get-variable o365_*_OPDomain |Where-Object{$_.Value -eq $creddom} | Select-Object -expand Name |Where-Object{$_ -match 'o365_(.*)_OPDomain'}){
        $credVariTag = $matches[1] ;
        $MFA = (get-variable "o365_$($credVariTag)_MFA").value ;
    } else {
        throw "Failed to resolve a `$credVariTag` from populated global 'o365_*_OPDomain' variables, for credential domain:$(CredDom)" ;
    } ;

    Try {Get-AzureRmTenant -erroraction stop }
    Catch {Install-Module -Name AzureRM -Scope CurrentUser} ;
    Try {Get-AzureRmTenant -erroraction stop}
    Catch {Import-Module -Name AzureRM -MinimumVersion '4.2.1'} ;
    if (! $MFA) {
        $json = Get-ChildItem -Recurse -Include '*@*.json' -Path $KeyPath
        if ($json) {
            Write-Host   "************************************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host   "************************************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            write-verbose -verbose:$true " Select the Azure username and Click `"OK`" in lower right-hand corner"
            write-verbose -verbose:$true " Otherwise, if this is the first time using this Azure username click `"Cancel`""
            Write-Host   "************************************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host   "************************************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            $json = $json | Select-Object name | Out-GridView -PassThru -Title "Select Azure username or click Cancel to use another"
        }
        if (!($json)) {
            Try {
                #$azLogin = Login-AzureRmAccount -ErrorAction Stop
                # looks revised, even gethelp on the above returns these examples:Connect-AzureRmAccount
                $azLogin = Connect-AzureRmAccount -Credential $Credential -ErrorAction Stop
            }
            Catch [System.Management.Automation.CommandNotFoundException] {
                write-verbose -verbose:$true "Download and install PowerShell 5.1 or PowerShellGet so the AzureRM module can be automatically installed"
                write-verbose -verbose:$true "https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-4.2.0#how-to-get-powershellget"
                write-verbose -verbose:$true "or download the MSI installer and install from here: https://github.com/Azure/azure-powershell/releases"
                Break
            }
            Save-AzureRmContext -Path ($KeyPath + ($azLogin.Context.Account.Id) + ".json")
            Import-AzureRmContext -Path ($KeyPath + ($azLogin.Context.Account.Id) + ".json")
        }
        else {
            Import-AzureRmContext -Path ($KeyPath + $json.name)
        }
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        write-verbose -verbose:$true " Select Subscription and Click `"OK`" in lower right-hand corner"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription"| Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            write-verbose -verbose:$true "****************************************"
            write-verbose -verbose:$true "You have successfully connected to Azure"
            write-verbose -verbose:$true "****************************************"
        }
        Catch {
            Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            write-verbose -verbose:$true " Azure credentials have expired. Authenticate again please."
            Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
            Remove-Item ($KeyPath + $json.name)
            connect-AzureRM
        }
    } else {
        Try {
            #Login-AzureRmAccount -ErrorAction Stop
            # looks revised, even gethelp on the above returns these examples:Connect-AzureRmAccount
            Connect-AzureRmAccount -AccountID $Credential.userName ;
        }
        Catch [System.Management.Automation.CommandNotFoundException] {
            write-verbose -verbose:$true "Download and install PowerShell 5.1 or PowerShellGet so the AzureRM module can be automatically installed"
            write-verbose -verbose:$true "https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-4.2.0#how-to-get-powershellget"
            write-verbose -verbose:$true "or download the MSI installer and install from here: https://github.com/Azure/azure-powershell/releases"
            Break
        }
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        write-verbose -verbose:$true " Select Subscription and Click `"OK`" in lower right-hand corner"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        Write-Host   "*********************************************************************" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription" | Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            write-verbose -verbose:$true "****************************************"
            write-verbose -verbose:$true "You have successfully connected to Azure"
            write-verbose -verbose:$true "****************************************"
        }
        Catch {
            write-verbose -verbose:$true "There was an error selecting your subscription ID"
        }
    }
}
#*------^ END Function Connect-AzureRM ^------