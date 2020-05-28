#*------v Function Connect-AAD v------
Function Connect-AAD {
    <#
    .SYNOPSIS
    Connect-AAD - Establish authenticated session to AzureAD Graph Module (AzureAD), also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-05-27
    FileName    : Connect-AAD.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 12:11 PM 5/27/2020 updated CBH, moved aliases:'caad','raad','reconnect-AAD' win the func
    * 10:55 AM 12/6/2019 Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
    * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    * 1:39 PM 5/8/2019 Connect-AAD:tightened up the installed/imported/authenticated checks
    * 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD
    * 1:54 PM 10/8/2018 Connect-AAD:port from Connect-AAD
    .DESCRIPTION
    Connect-AAD - Establish authenticated session to AzureAD/MSOL, also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
    No need for separate reConnect-AAD - this self tests for connection, and reconnects if it's missing.
    No support for disConnect-AAD, because MSOL has no command to do it, but closing powershell.
    .PARAMETER  ProxyEnabled
    Proxyied connection support
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Connect-AAD
    .EXAMPLE
    Connect-AAD -Credential $cred
    .LINK
    #>
    [CmdletBinding()] 
    [Alias('caad','raad','reconnect-AAD')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $MFA = get-TenantMFARequirement -Credential $Credential ;

        $sTitleBarTag="AAD" ;
        $credDom = ($Credential.username.split("@"))[1] ;
        if($Credential.username.contains('.onmicrosoft.com')){
            # cloud-first acct
            switch ($credDom){
                "$($TORMeta['o365_TenantDomain'])" { }
                "$($TOLMeta['o365_TenantDomain'])" {$sTitleBarTag += "TOL"}
                "$($CMWMeta['o365_TenantDomain'])" {$sTitleBarTag +="CMW"}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_TenantDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } else { 
            # OP federated domain
            switch ($credDom){
                "$($TORMeta['o365_OPDomain'])" { }
                "$($TOLMeta['o365_OPDomain'])" {$sTitleBarTag += "TOL"}
                "$($CMWMeta['o365_OPDomain'])" {$sTitleBarTag += "CMW"}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_OPDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } ; 

        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        try { Get-AzureADTenantDetail | out-null  } # authenticated
        catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            Write-Host "You're not Authenticated to AAD: Connecting..."  ;
            Try {
                if(!$Credential){
                    if(test-path function:\get-admincred) {
                        Get-AdminCred ;
                    } else {
                        switch($env:USERDOMAIN){
                            "TORO" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($o365AdmUid ))" ;
                            if(!$bUseo365COAdminUID){
                                if($o365AdmUid ){$Credential = Get-Credential -Credential $o365AdmUid } else { $Credential = Get-Credential } ;
                            } else {
                                if($o365COAdmUid){global:o365cred = Get-Credential -Credential $o365COAdmUid} else { $Credential = Get-Credential } ;
                            } ;
                            }
                            "TORO-LAB" {
                                write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($o365LabAdmUid ))" ;
                                if(!$bUseo365COAdminUID){
                                    if($o365LabAdmUid){$Credential = Get-Credential -Credential $o365LabAdmUid} else { $Credential = Get-Credential } ;
                                } else {
                                    if($o365LabCOAdmUid){$Credential = Get-Credential -Credential $o365LabCOAdmUid} else { $Credential = Get-Credential } ;
                                } ;
                            }
                            default {
                                write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                                $Credential = Get-Credential
                            } ;
                        } ;
                    }  ;
                } ;
                if(!$MFA){Connect-AzureAD -Credential $Credential -ErrorAction Stop ;} 
                else {Connect-AzureAD -AccountID $Credential.userName ;} ;

                # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
                if ($?) { write-verbose -verbose:$true  "(connected to AzureAD ver2)" ; Add-PSTitleBar $sTitleBarTag ; } ;
                Write-Verbose -verbose:$true "(connected to AzureAD ver2)" ; 
            } Catch {
                Write-Verbose "There was an error Connecting to Azure Ad - Ensure the module is installed" ;
                Write-Verbose "Download PowerShell 5 or PowerShellGet" ;
                Write-Verbose "https://msdn.microsoft.com/en-us/powershell/wmf/5.1/install-configure" ;
            } ;
        } ;
    } ; 
    END {} ;
} ; #*------^ END Function Connect-AAD ^------