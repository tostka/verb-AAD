#*------v Function Connect-MSOL v------
Function Connect-MSOL {
    <#    
    .SYNOPSIS
    Connect-MSOL - Establish authenticated session to AzureAD MSOL Module, also works as reConnect-MSOL, there is no disConnect-MSOL (have to close Powershell to clear it).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 5:06 PM 7/21/2020 added VEN supp
    * 6:11 PM 2/26/2020 moved aliases below
    * 2:08 PM 2/26/2020 converted to adv func
    * 8:50 PM 1/12/2020 expanded aliases
    * 10:55 AM 12/6/2019 Connect-MSOL:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
    * 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
    * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    * 1:32 PM 5/8/2019 switched text into pipe with explicit Write-Verbose's
    * 2:51 PM 5/2/2019 ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for aad2 module
    * 12:06 PM 12/7/2018 added Alias 'connect-msol' -> 'Connect-AAD'
    * 7:38 AM 10/5/2018 out-null the pretesting Get-MsolAccountSku into a vari (was dumping into console)
    * 9:38 AM 9/10/2018 Connect-AAD: now it's working (?.?)7 weird. Also aliased reconnect-aad -> connect-AAD()- it's the same, but easier to just cover the gap.
    * 12:27 PM 11/3/2017 nope, not working, can't authenticate yet.
    * 12:19 PM 11/3/2017 this wasn't really written, sketched it in to see how it works
    .DESCRIPTION
    Connect-MSOL - Establish authenticated session to AzureAD/MSOL, also works as reconnect-AAD, there is no disConnect-MSOL (have to close Powershell to clear it).
    No need for separate reConnect-MSOL - this self tests for connection, and reconnects if it's missing.
    No support for disConnect-MSOL, because MSOL has no command to do it, but closing powershell.
    .PARAMETER  ProxyEnabled
    Proxyied connection support
    .PARAMETER CommandPrefix
    Prefix to be appended to commands (not implemented with MSOL/AAD)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Connect-MSOL
    .LINK
    #>
    [CmdletBinding()]
    [Alias('cmsol','rmsol','Reconnect-MSOL')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()][string]$CommandPrefix,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    BEGIN { $verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $MFA = get-TenantMFARequirement -Credential $Credential ;

        # 12:10 PM 3/15/2017 disable prefix spec, unless actually blanked (e.g. centrally spec'd in profile).
        #if(!$CommandPrefix){ $CommandPrefix='aad' ; } ;

        $sTitleBarTag = "MSOL" ;
        $credDom = ($Credential.username.split("@"))[1] ;
        if($Credential.username.contains('.onmicrosoft.com')){
            # cloud-first acct
            switch ($credDom){
                "$($TORMeta['o365_TenantDomain'])" { } 
                "$($TOLMeta['o365_TenantDomain'])" {$sTitleBarTag += $TOLMeta['o365_Prefix']}
                "$($CMWMeta['o365_TenantDomain'])" {$sTitleBarTag += $CMWMeta['o365_Prefix']}
                "$($VENMeta['o365_TenantDomain'])" {$sTitleBarTag += $VENMeta['o365_Prefix']}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_TenantDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } else { 
            # OP federated domain
            switch ($credDom){
                "$($TORMeta['o365_OPDomain'])" { }
                "$($TOLMeta['o365_OPDomain'])" {$sTitleBarTag += $TOLMeta['o365_Prefix']}
                "$($CMWMeta['o365_OPDomain'])" {$sTitleBarTag += $CMWMeta['o365_Prefix']}
                "$($VENMeta['o365_OPDomain'])" {$sTitleBarTag += $VENMeta['o365_Prefix']}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_OPDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } ; 

        try { Get-MsolAccountSku -ErrorAction Stop | out-null }
        catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
            Write-Verbose "Not connected to MSOnline. Now connecting." ;
            if (!$Credential) {
                if (test-path function:\get-admincred) {
                    Get-AdminCred ;
                }
                else {
                    switch ($env:USERDOMAIN) {
                        "$($TORMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($TORMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($TORMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $TORMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($TORMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $TORMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($TOLMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($TOLMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($TOLMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $TOLMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($TOLMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $TOLMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($CMWMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($CMWMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($CMWMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $CMWMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($CMWMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $CMWMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($VENMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($VENMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($VENMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $VENMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($VENMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $VENMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        default {
                            write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                            $Credential = Get-Credential
                        } ;
                    } ;
                }  ;
            } ;
            Write-Host "Connecting to AzureAD/MSOL"  ;
            $error.clear() ;
            if (!$MFA) {
                Connect-MsolService -Credential $Credential -ErrorAction Stop ;
            }
            else {
                Connect-MsolService -ErrorAction Stop ;
            } ;
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to MSOL)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        } ;
        
    } ;
    END {} ;
} ; #*------^ END Function Connect-MSOL ^------

