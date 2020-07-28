#*------v Connect-AAD.ps1 v------
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
    * 11:38 AM 7/28/2020 added verbose credential echo and other detail for tenant-match confirmations
    * 12:47 PM 7/24/2020 added code to test for match between get-azureadTenantDetail.VerifiedDomains list and the domain in use for the specified Credential, if no match, it triggers a full credentialed logon (working around the complete lack of an explicit disconnect-AzureAD cmdlet, for permitting changing Tenants)
    * 7:13 AM 7/22/2020 replaced codeblock w get-TenantTag()
    * 4:36 PM 7/21/2020 updated various psms for VEN tenant
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
        write-verbose "(Credential specified: $($Credential.username))" ; 
        $MFA = get-TenantMFARequirement -Credential $Credential ;

        $sTitleBarTag="AAD" ;
        $TentantTag=get-TenantTag -Credential $Credential ; 
        if($TentantTag -ne 'TOR'){
            # explicitly leave this tenant (default) untagged
            $sTitleBarTag += $TentantTag ;
        } ; 

        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        # with multitenants and changes between, instead we need ot test 'what tenant' we're connected to
        TRY { 
            $AADTenDtl = Get-AzureADTenantDetail ; # err indicates no authenticated connection
            #if connected,verify cred-specified Tenant
            if($AADTenDtl.VerifiedDomains.name.contains($Credential.username.split('@')[1].tostring())){
                write-verbose "(Authenticated to AAD:$($AADTenDtl.displayname))"
            } else { 
                write-verbose "(Disconnecting from $(AADTenDtl.displayname) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
                Disconnect-AzureAD ; 
                throw "" 
            }
        } 
        #CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        # for changing Tenant logons, we need to trigger a full credential reconnect, even if connected and not thowing AadNeedAuthenticationException
        CATCH{
            TRY {
                if(!$Credential){
                    if(get-command -Name get-admincred) {
                        Get-AdminCred ;
                    } else {
                        $credDom = ($Credential.username.split("@"))[1] ;
                        $Metas=(get-variable *meta|?{$_.name -match '^\w{3}Meta$'}) ; 
                        foreach ($Meta in $Metas){
                                if( ($credDom -eq $Meta.value.legacyDomain) -OR ($credDom -eq $Meta.value.o365_TenantDomain) -OR ($credDom -eq $Meta.value.o365_OPDomain)){
                                    if($Meta.value.o365_SIDUpn ){$Credential = Get-Credential -Credential $Meta.value.o365_SIDUpn } else { $Credential = Get-Credential } ;
                                    break ; 
                                } ; 
                        } ;
                        if(!$Credential){
                            write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                            $Credential = Get-Credential ; 
                        } ;
                    }  ;
                } ;
                Write-Host "Authenticating to AAD:$($Credential.username.split('@')[1].tostring()), w $($Credential.username)..."  ;
                if(!$MFA){
                    write-verbose "EXEC:Connect-AzureAD -Credential $($Credential.username) (no MFA, full credential)" ; 
                    Connect-AzureAD -Credential $Credential -ErrorAction Stop ;
                } else {
                    write-verbose "EXEC:Connect-AzureAD -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                    Connect-AzureAD -AccountID $Credential.userName ;
                } ;

                # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
                if ($?) { write-verbose -verbose:$true  "(connected to AzureAD ver2)" ; Add-PSTitleBar $sTitleBarTag ; } ;
            } CATCH {
                Write-Verbose "There was an error Connecting to Azure Ad - Ensure the module is installed" ;
                Write-Verbose "Download PowerShell 5 or PowerShellGet" ;
                Write-Verbose "https://msdn.microsoft.com/en-us/powershell/wmf/5.1/install-configure" ;
            } ;
        } ;
    } ; 
    END {} ;
} ; 
#*------^ Connect-AAD.ps1 ^------