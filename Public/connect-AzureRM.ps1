#*------v connect-AzureRM.ps1 v------
function connect-AzureRM {
    <#
    .SYNOPSIS
    connect-AzureRM.ps1 - Connect to AzureRM module
    .NOTES
    Version     : 1.6.2
    Author      : Kevin Blumenfeld
    Website     :	https://github.com/kevinblumenfeld/Posh365
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2019-02-06
    FileName    :
    License     : MIT License
    Copyright   : (c) 2020 Kevin Blumenfeld. All rights reserved. 
    Github      : https://github.com/kevinblumenfeld/Posh365
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 7:13 AM 7/22/2020 replaced codeblock w get-TenantTag()
    # 5:04 PM 7/21/2020 VEN support added
    # 9:19 AM 2/25/2020 updated to reflect my credential prefs
    # 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
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
    $verbose = ($VerbosePreference -eq "Continue") ; 
    $MFA = get-TenantMFARequirement -Credential $Credential ;

    $sTitleBarTag="AzRM" ;
    $TentantTag=get-TenantTag -Credential $Credential ; 
    if($TentantTag -ne 'TOR'){
        # explicitly leave this tenant (default) untagged
        $sTitleBarTag += $TentantTag ;
    } ; 

    Try {Get-AzureRmTenant -erroraction stop }
    Catch {Install-Module -Name AzureRM -Scope CurrentUser} ;
    Try {Get-AzureRmTenant -erroraction stop}
    Catch {Import-Module -Name AzureRM -MinimumVersion '4.2.1'} ;
    if (! $MFA) {
        $json = Get-ChildItem -Recurse -Include '*@*.json' -Path $CredFolder
        if ($json) {
            Write-Host " Select the Azure username and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host " Otherwise, if this is the first time using this Azure username click `"Cancel`"" -foregroundcolor "magenta" -backgroundcolor "white"
            $json = $json | select name | Out-GridView -PassThru -Title "Select Azure username or click Cancel to use another"
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
            Save-AzureRmContext -Path ($CredFolder + "\" + ($azLogin.Context.Account.Id) + ".json")
            Import-AzureRmContext -Path ($CredFolder + "\" +  + ($azLogin.Context.Account.Id) + ".json")
        }
        else {Import-AzureRmContext -Path ($CredFolder + "\" +  + $json.name)}
        Write-Host "Select Subscription and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription"| Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to AzureRm)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        }
        Catch {
            Write-Warning "Azure credentials are invalid or expired. Authenticate again please."
            if ($json.name) {Remove-Item ($CredFolder + "\" +  + $json.name) } ; 
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
        Write-Host "Select Subscription and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription" | Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to AzureRm)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        }
        Catch {
            write-verbose -verbose:$true "There was an error selecting your subscription ID"
        }
    }
}
#*------^ connect-AzureRM.ps1 ^------