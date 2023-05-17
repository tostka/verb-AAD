#*------v Connect-AAD.ps1 v------
Function Connect-AAD {
    <#
    .SYNOPSIS
    Connect-AAD - Establish authenticated session to AzureAD Graph Module (AzureAD), also works as reConnect-AAD, .
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
    * 2:59 PM 5/15/2023 simplified manual cred/tenant alignment code to simpler resolve-UserNameToUserRole  tests against token.tenantid; purged rem'd code
    * 6:27 PM 5/12/2023 fixed logic in fault ipmo block ; revised tenant/cred align validation to use resolve-UserNameToUserRole
    # 2:44 PM 5/10/2023 fixed typo in END block ($username vs $credential.username) ; drop the UPN support, all the resolution code is built to work with a full credential.username; could fake it, but safer not to support the UPN logon ; 
    if you want UPN logon use connect-azureAD -accountid UPN... ; added updated fault-tolerant load module block
    rem'd unused obso code ; MFA & CBA support updates, cross compliant with EOM310 changes & fixes: 
    Add: -UserRole & -UserPrincipalName; spec paramsets DefaultParameterSetName='UPN' ; updated UserRole to validate using global rgx; validated vaad:get-aadtoken() continues to work fine with MSAL auth lib (uses underlying )
    added CBA object resulution, leverages verb-Auth:resolve-UserNameToUserRole(), and switches auth types on rgx'd cred.Username.
    updated connect-azuread to use CBA AppID etc v AccountID (UPN)
    fixed trailing END Tenant/Cred alignmnet validator, to properly work for CBA.username (lookup the auth cert FriendlyName, from the uname, and parse out the userrole/tenorg details via resolve-UserNameToUserRole()
    # 4:45 PM 7/7/2022 workaround msal.ps bug: always ipmo it FIRST: "Get-msaltoken : The property 'Authority' cannot be found on this object. Verify that the property exists."
    * 1:24 PM 3/28/2022 fixed missing `n on #669; confirmed works fine with MFA, as long as get-TenantMFA properly returns $MFA -eq $true (uses -AccountID param & prompts for MAuth logon)
    * 9:57 AM 9/17/2021 added silent to CBH
    * 5:38 PM 8/17/2021 added -silent param
    # 3:20 PM 7/26/2021 updated add-pstitlebar
    # 1:45 PM 7/21/2021 enforce PSTitlebar tag Tenorg, no exceptions
    * 11:40 AM 5/14/2021 added -ea 0 to the gv tests (suppresses not-found error when called without logging config)
    * 12:16 PM 4/5/2021 updated w 7pswlt support ; added #Requires -Modules AzureAD
    * 2:44 PM 3/2/2021 added console TenOrg color support
    * 3:10 PM 8/8/2020 remd'd block @ #463: CATCH [Microsoft.Open.AzureAD16.Client.ApiException] causes 'Unable to find type' errors on cold load ; rewrote to leverage AzureSession checks, without need to qry Get-AzureADTenantDetail (trying to avoid sporadic VEN AAD 'Forbidden' errors)
    * 3:24 PM 8/6/2020 added CATCH block for AzureAD perms errors seeing on one tenant, also shifted only the AAD cmdlets into TRY, to isolate errs ; flip catch blocks to throw (stop) vs Exit (kill ps, when run in shell)
    * 5:17 PM 8/5/2020 strong-typed Credential; implemented get-TenantID(), captured returned objects and validated single, post-validates Credential domain AzureADTenantDetail.ValidatedDomains match.
    * 11:38 AM 7/28/2020 added verbose credential echo and other detail for tenant-match confirmations; implemented get-TenantID()
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
    .PARAMETER UserRole
    Credential User Role spec (SID|CSID|UID|B2BI|CSVC|ESVC|LSVC|ESvcCBA|CSvcCBA|SIDCBA)[-UserRole @('SIDCBA','SID','CSVC')]
    .PARAMETER silent
    Switch to suppress all non-error echos
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
    #Requires -Modules AzureAD
    [CmdletBinding(DefaultParameterSetName='UPN')]
    [Alias('caad','raad','reconnect-AAD')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter(ParameterSetName = 'Cred', HelpMessage = "Credential to use for this connection [-credential [credential obj variable]")]
            [System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(Mandatory = $false, HelpMessage = "Credential User Role spec (SID|CSID|UID|B2BI|CSVC|ESVC|LSVC|ESvcCBA|CSvcCBA|SIDCBA)[-UserRole @('SIDCBA','SID','CSVC')]")]
            # sourced from get-admincred():#182: $targetRoles = 'SID', 'CSID', 'ESVC','CSVC','UID','ESvcCBA','CSvcCBA','SIDCBA' ; 
            #[ValidateSet("SID","CSID","UID","B2BI","CSVC","ESVC","LSVC","ESvcCBA","CSvcCBA","SIDCBA")]
            # pulling the pattern from global vari w friendly err
            [ValidateScript({
                if(-not $rgxPermittedUserRoles){$rgxPermittedUserRoles = '(SID|CSID|UID|B2BI|CSVC|ESVC|LSVC|ESvcCBA|CSvcCBA|SIDCBA)'} ;
                if(-not ($_ -match $rgxPermittedUserRoles)){throw "'$($_)' doesn't match `$rgxPermittedUserRoles:`n$($rgxPermittedUserRoles.tostring())" ; } ; 
                return $true ; 
            })]
            [string[]]$UserRole = @('SID','CSVC'),
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
            [switch] $silent
    ) ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
        #if(-not (get-variable rgxCertFNameSuffix -ea 0)){$rgxCertFNameSuffix = '-([A-Z]{3})$' ; } ; 
        if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; # if it's a 40char hex string -> cert thumbprint  
        if(-not $rgxSmtpAddr){$rgxSmtpAddr = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$" ; } ; # email addr/UPN
        if(-not $rgxDomainLogon){$rgxDomainLogon = '^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$' } ; # DOMAIN\samaccountname 

        $smsg = "EXEC:get-TenantMFARequirement -Credential $($Credential.username)" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; 
        $MFA = get-TenantMFARequirement -Credential $Credential ;
        $smsg = "EXEC:get-TenantTag -Credential $($Credential.username)" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;         
        $TenantTag = $TenOrg = get-TenantTag -Credential $Credential ; 
        $sTitleBarTag = @("AAD") ;
        $sTitleBarTag += $TenantTag ;
        $TenantID = get-TenantID -Credential $Credential ;
    } ;
    PROCESS {
        # workaround msal.ps bug: always ipmo it FIRST: "Get-msaltoken : The property 'Authority' cannot be found on this object. Verify that the property exists."
        # admin/SID module auto-install code (myBoxes UID split-perm CU, all else t AllUsers)
        # Note:gmo doesn't throw an error when target isn't found, have to if/then (not try/catch); 
        # also don't if(xxx| out-null): it doesn't eval as 'true', _ever_ (capt/assign output to a vari to dump). 
        $modname = 'MSAL.PS' ;
        $smsg = "(load/install $($modname) module)" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
        $pltIMod = @{Name = $modname ; ErrorAction = 'Stop' ; verbose=$true} ;
        $error.clear() ;
        $oxmo = $null ; 
        if(-not ( $oxmo = Get-Module @pltIMod  )){
            Try {
                $smsg = "Import-Module w`n$(($pltIMod|out-string).trim())" ;
                if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                Import-Module @pltIMod ;
            } Catch {
                if(-not ($oxmo = Get-Module @pltIMod -listavailable)){
                    if($env:computername -match $rgxMyBoxW){$pltIMod.add('scope','CurrentUser')} else { $pltIMod.add('scope','AllUsers')} ;
                    $smsg = "MISSING $($modname)!: Install-Module? w`n$(($pltIMod|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $pltIMod.verbose = $true ; 
                    $bRet=Read-Host "Enter YYY to continue. Anything else will exit"  ; 
                    if ($bRet.ToUpper() -eq "YYY") {
                        Install-Module @pltIMod ; 
                    } else {
                            $smsg = "Invalid response. Exiting" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        #exit 1
                        break ; 
                    } ; #DoInstall
                } ;  # IsInstalled
            } ; # NotImportable
        } ; # IsImported

        # Note:gmo doesn't throw an error when target isn't found, have to if/then (not try/catch); 
        # also don't if(xxx| out-null): it doesn't eval as 'true', _ever_ (capt/assign output to a vari to dump). 
        $modname = 'AzureAD' ; 
        $smsg = "(load/install $($modname) module)" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
        $pltIMod = @{Name = $modname ; ErrorAction = 'Stop' ; verbose=$true} ;
        $error.clear() ;
        $oxmo = $null ; 
        if(-not ( $oxmo = Get-Module @pltIMod  )){
            Try {
                $smsg = "Import-Module w`n$(($pltIMod|out-string).trim())" ;
                if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                Import-Module @pltIMod ;
            } Catch {
                if(-not ($oxmo = Get-Module @pltIMod -listavailable)){
                    if($env:computername -match $rgxMyBoxW){$pltIMod.add('scope','CurrentUser')} else { $pltIMod.add('scope','AllUsers')} ;
                    $smsg = "MISSING $($modname)!: Install-Module? w`n$(($pltIMod|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $pltIMod.verbose = $true ; 
                    $bRet=Read-Host "Enter YYY to continue. Anything else will exit"  ; 
                    if ($bRet.ToUpper() -eq "YYY") {
                        Install-Module @pltIMod ; 
                    } else {
                            $smsg = "Invalid response. Exiting" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        #exit 1
                        break ; 
                    } ; #DoInstall
                } ;  # IsInstalled
            } ; # NotImportable
        } ; # IsImported

        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        # with multitenants and changes between, instead we need ot test 'what tenant' we're connected to
        TRY { 
            #I'm going to assume that it's due to too many repeated req's for gAADTD
            # so lets work with & eval the local AzureSession Token instead - it's got the userid, and the tenantid, both can validate the conn, wo any queries.:
            
            #$token = get-AADToken -verbose:$($verbose) ; # this actually wraps the [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens object
            <# MSAL library calls:
            $connectionDetails = @{
                'TenantId'     = 'dev.nicolonsky.ch' ;
                'ClientId'     = '453436af-5b9d-449b-82b6-22001ee3b727' ;
                'ClientSecret' = '3wD0xU571J6S70N-P-4oy_.ZtduB5JkQBC' | ConvertTo-SecureString -AsPlainText -Force ;
            } ;
            Get-MsalToken @connectionDetails ;                

            $connectionDetails = @{
                'TenantId'     = $TenantID ;
                #'ClientId'     = '453436af-5b9d-449b-82b6-22001ee3b727' ;
                # Set well-known client ID for Azure PowerShell
                ClientId  = "1950a258-227b-4e31-a9cf-717495945fc2"
                'ClientSecret' = '3wD0xU571J6S70N-P-4oy_.ZtduB5JkQBC' | ConvertTo-SecureString -AsPlainText -Force ;
            } ;
            Get-MsalToken @connectionDetails ;    
            #>
            <# Simpler to use get-aadtoken() call, which uses underlying intact obj (not ADAL or MSAL dependant); 
            works direct as well: $global:token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens  ; 
            can use direct connection status test as well:
            if ($null -eq [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens){
                Connect-AzureAD ;
            } else {
                $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens ;
                Write-Verbose "Connected to tenant: $($token.AccessToken.TenantId) with user: $($token.AccessToken.UserId)" ;
            } ;
            #>
            write-verbose "resolve-UserNameToUserRole -UserName $($Credential.username)..." ; 
            $uRoleReturn = resolve-UserNameToUserRole -UserName $Credential.username -verbose:$($VerbosePreference -eq "Continue") ; 
            #$uRoleReturn = resolve-UserNameToUserRole -Credential $Credential -verbose = $($VerbosePreference -eq "Continue") ; 
            write-verbose "get-AADToken..." ; 
            $token = get-AADToken -verbose:$($verbose) ;
            write-verbose "convert-TenantIdToTag -TenantId $(($token.AccessToken).tenantid) (`$token.AccessToken).tenantid)" ; 
            # convert token.tenantid to the 3-letter TenOrg
            $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ; 

            if( ($null -eq $token) -OR ($token.count -eq 0)){
                # not connected/authenticated
                #Connect-AzureAD -TenantId $TenantID -Credential $Credential ; 
                throw "" # gen an error to dump into generic CATCH block
            }elseif($token.count -gt 1){
                write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):MULTIPLE TOKENS RETURNED!`n$(( ($token.AccessToken) | ft -a  TenantId,UserId,LoginType |out-string).trim())" ; 
                # want to see if this winds up with a stack of parallel tokens
            } else {
                $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ;  
                if($silent){} else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
                # flip to resolve-UserNameToUserRole & direct eval the $token values:
                if( $TokenTag  -eq $uRoleReturn.TenOrg){
                    if($credential.username -match $rgxCertThumbprint){
                        $smsg = "(Authenticated to AAD:$($uRoleReturn.TenOrg) as $($uRoleReturn.FriendlyName))" ; 
                    } else { 
                        $smsg = "(Authenticated to AAD:$($uRoleReturn.TenOrg) as $(($token.AccessToken).userid))" ; 
                    } ; 
                    if($silent){} else { 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ;   
                } else { 
                    if($credential.username -match $rgxCertThumbprint){
                        $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant as $($uRoleReturn.FriendlyName)" ; 
                    } else { 
                        $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
                    } ; 
                    if($silent){} else { 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ;                    
                    Disconnect-AzureAD ; 
                    throw "AUTHENTICATED TO WRONG TENANT FOR SPECIFIED CREDENTIAL" 
                } ; 
            } ; 

        } 
        #CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        # for changing Tenant logons, we need to trigger a full credential reconnect, even if connected and not thowing AadNeedAuthenticationException
        <# 3:53 PM 8/8/2020 on a cold no-auth start, it throws up on the below
        CATCH [Microsoft.Open.AzureAD16.Client.ApiException] {
            $ErrTrpd = $_ ; 
            Write-Warning "$((get-date).ToString('HH:mm:ss')):AzureAD Tenant Permissions Error" ; 
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            throw $_ ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        }#>
        CATCH {
            
            $pltCAAD=[ordered]@{
                ErrorAction='Stop';
            }; 

            if(-not $Credential){
                if(get-command -Name get-admincred) {
                    Get-AdminCred ;
                } else {
                    # resolve suitable creds based on $credential domain specified
                    $credDom = ($Credential.username.split("@"))[1] ;
                    $Metas=(get-variable *meta|?{$_.name -match '^\w{3}Meta$'}) ; 
                    foreach ($Meta in $Metas){
                            if( ($credDom -eq $Meta.value.legacyDomain) -OR ($credDom -eq $Meta.value.o365_TenantDomain) -OR ($credDom -eq $Meta.value.o365_OPDomain)){
                                if($Meta.value.o365_SIDUpn ){$Credential = Get-Credential -Credential $Meta.value.o365_SIDUpn } else { $Credential = Get-Credential } ;
                                $TenantID = get-TenantID -Credential $Credential ;
                                break ; 
                            } ; 
                    } ;
                    if(!$Credential){
                        write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                        $Credential = Get-Credential ; 
                    } ;
                }  ;
            } ; 

            #$uRoleReturn = resolve-UserNameToUserRole -UserName $Credential.username -verbose:$($VerbosePreference -eq "Continue") ; 
            #$uRoleReturn = resolve-UserNameToUserRole -Credential $Credential -verbose = $($VerbosePreference -eq "Continue") ;

            if($credential.username -match $rgxCertThumbprint){
                $smsg =  "(UserName:Certificate Thumbprint detected)"
                if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $pltCAAD.Add("CertificateThumbprint", [string]$Credential.UserName);                    
                $pltCAAD.Add("ApplicationId", [string]$Credential.GetNetworkCredential().Password);
                if($TenantID = get-TenantID -Credential $Credential){
                    $pltCAAD.Add("TenantId", [string]$TenantID);
                } else { 
                    $smsg = "UNABLE TO RESOLVE `$TENORG:$($TenOrg) TO FUNCTIONAL `$$($TenOrg)meta.o365_TenantDomain!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                    Break ; 
                } ; 
                #$uRoleReturn = resolve-UserNameToUserRole -UserName $Credential.username -verbose:$($VerbosePreference -eq "Continue") ; 
                ##$uRoleReturn = resolve-UserNameToUserRole -Credential $Credential -verbose = $($VerbosePreference -eq "Continue") ;
                if($uRoleReturn.TenOrg){
                    $TenOrg = $uRoleReturn.TenOrg  ; 
                    #$smsg = "(using CBA:cred:$($TenOrg):$([string]$tcert.friendlyname))" ; 
                    #$smsg = "(using CBA:cred:$($TenOrg):$([string](get-childitem -path "Cert:\CurrentUser\My\$($credential.username)").FriendlyName ))" ; 
                    #$uRoleReturn.FriendlyName
                    $smsg = "(using CBA:cred:$($TenOrg):$([string]$uRoleReturn.FriendlyName))" ; 
                    if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } else {
                    $smsg = "Unable to resolve `$credential.username ($($credential.username))"
                    $smsg += "`nto a usable 'UserRole' spec!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    throw $smsg ;
                    Break ;
                } ; 
             } else { 
                <#  interactive ModernAuth -UserPrincipalName isn't supported, param is -AccountId
                    -AadAccessToken <String>
                    Specifies a Azure Active Directory Graph access token.
                    -AccountId <String>
                        Specifies the ID of an account. You must specify the UPN of the user when authenticating with a user access token.
                    -ApplicationId <String>
                        Specifies the application ID of the service principal.
                    -AzureEnvironmentName <EnvironmentName>
                        Specifies the name of the Azure environment. The acceptable values for this parameter are:
                        - AzureCloud
                        - AzureChinaCloud
                        - AzureUSGovernment
                        - AzureGermanyCloud
                        The default value is AzureCloud.
                    -CertificateThumbprint <String>
                        Specifies the certificate thumbprint of a digital public key X.509 certificate of a user account that has permission to perform
                        this action.
                    -Credential <PSCredential>
                        Specifies a PSCredential object. For more information about the PSCredential object, type Get-Help Get-Credential.
                        The PSCredential object provides the user ID and password for organizational ID credentials.
                    -InformationAction <ActionPreference>
                        Specifies how this cmdlet responds to an information event. The acceptable values for this parameter are:
                        - Continue
                        - Ignore
                        - Inquire
                        - SilentlyContinue
                        - Stop
                        - Suspend
                    -InformationVariable <String>
                        Specifies a variable in which to store an information event message.
                    -LogLevel <LogLevel>
                        Specifies the log level. The accdeptable values for this parameter are:
                        - Info
                        - Error
                        - Warning
                        - None
                        The default value is Info.
                    -MsAccessToken <String>
                        Specifies a Microsoft Graph access token.
                    -TenantId <String>
                        Specifies the ID of a tenant.
                        If you do not specify this parameter, the account is authenticated with the home tenant.
                        You must specify the TenantId parameter to authenticate as a service principal or when using Microsoft account.
                    -Confirm [<SwitchParameter>]
                        Prompts you for confirmation before running the cmdlet.
                    -WhatIf [<SwitchParameter>]
                        Shows what would happen if the cmdlet runs. The cmdlet is not run.
                    -LogFilePath <String>
                        The path where the log file for this PowerShell session is written to. Provide a value here if you need to deviate from the
                        default PowerShell log file location.
                #>
                <# original support for -userprincipalname ; too many dependancies for use of full $credential object
                if ($UserPrincipalName) {
                    #$pltCAAD.Add("UserPrincipalName", [string]$UserPrincipalName);
                    $pltCAAD.Add("AccountId", [string]$UserPrincipalName);
                    $smsg = "(using cred:$([string]$UserPrincipalName))" ; 
                    if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } elseif ($Credential -AND -not $UserPrincipalName){
                    $pltCAAD.Add("AccountId", [string]$Credential.username);
                    $smsg = "(using cred:$($credential.username))" ; 
                    if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                };
                #>
                if ($Credential){
                    $pltCAAD.Add("AccountId", [string]$Credential.username);
                    $smsg = "(using cred:$($credential.username))" ; 
                    if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } else {
                    $smsg = "Missing dependant -Credential!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    Break ; 
                } ; 
            } 

            if($uRoleReturn.UserRole -match 'CBA'){ $smsg = "Authenticating to AAD:$($uRoleReturn.TenOrg), w CBA cred:$($uRoleReturn.FriendlyName)"  }
            else {$smsg = "Authenticating to AAD:$($uRoleReturn.TenOrg), w $($Credential.username)..."  ;} ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            
            if($TenantID -AND ($pltcaad.keys -notcontains 'TenantID')){
                $smsg = "Forcing TenantID:$($TenantID)" ; 
                if($silent){} else { 
                    $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;                
                $pltCAAD.add('TenantID',[string]$TenantID) ;
            } 
            if(-not $MFA){
                #Connect-AzureAD -Credential $Credential -ErrorAction Stop ;
                $smsg = "EXEC:Connect-AzureAD -Credential $($Credential.username) (no MFA, full credential)" ; 
                if($silent){} else { 
                    $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;                
                if($Credential.username){$pltCAAD.add('Credential',$Credential)} ;
            } else {
                #Connect-AzureAD -AccountID $Credential.userName ;
                #$smsg = "EXEC:Connect-AzureAD -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                if($token.AccessToken.AccessToken){
                    if($silent){} else { 
                        $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ;                
                } ; 
                if($pltcaad.keys -notcontains 'ApplicationId' -AND $pltcaad.keys -notcontains 'CertificateThumbprint' -AND $pltcaad.keys -notcontains 'AccountId'){
                    # add UPN AccountID logon, if missing and non-CBA
                    if($Credential.username -AND ($pltCAAD.keys -notcontains 'AccountId') ){$pltCAAD.add('AccountId',$Credential.username)} ;
                } 
            } ;

            $smsg = "Connect-AzureAD w`n$(($pltCAAD|out-string).trim())" ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;             

            TRY {
                $AADConnection = Connect-AzureAD @pltCAAD ; 
                if($AADConnection -is [system.array]){
                    $smsg = "MULTIPLE TENANT CONNECTIONS RETURNED BY connect-AzureAD!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } #Error|Warn|Debug 
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    throw "MULTIPLE TENANT CONNECTIONS RETURNED BY connect-AzureAD!"
                
                } else {
                    if($silent){} else { 
                        $smsg = "(single Tenant connection returned)" 
                        # need to reqry the token for updated status
                        #$token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens ; # direct call option
                        $token = get-AADToken -verbose:$($verbose) ;
                        $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ; 
                        if($token.AccessToken.AccessToken){
                            if($silent){} else { 
                                $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } ;
                        } ; 
                    } ; 
                } ; 
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #-=-record a STATUSWARN=-=-=-=-=-=-=
                $statusdelta = ";WARN"; # CHANGE|INCOMPLETE|ERROR|WARN|FAIL ;
                if(gv passstatus -scope Script -ea 0){$script:PassStatus += $statusdelta } ;
                if(gv -Name PassStatus_$($tenorg) -scope Script -ea 0){set-Variable -Name PassStatus_$($tenorg) -scope Script -Value ((get-Variable -Name PassStatus_$($tenorg)).value + $statusdelta)} ; 
                #-=-=-=-=-=-=-=-=
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 
            
            if($silent){} else { 
                $smsg = "`n$(($AADConnection |ft -a|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor white "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { 
                #write-verbose -verbose:$true  "(connected to AzureAD ver2)" ; 
                Remove-PSTitlebar 'AAD' -verbose:$($VerbosePreference -eq "Continue") 
                # work with the current AzureSession $token instead - shift into END{}
            } ;
            
        } ; # CATCH-E # err indicates no authenticated connection
    } ;  # PROC-E
    END {
        write-verbose "get-AADToken..." ;
        $token = get-AADToken -verbose:$($verbose) ;
        write-verbose "convert-TenantIdToTag -TenantId $(($token.AccessToken).tenantid) (`$token.AccessToken).tenantid)" ;
        # convert token.tenantid to the 3-letter TenOrg
        $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ;
        if( ($null -eq $token) -OR ($token.count -eq 0)){
            $smsg = "NOT authenticated to any o365 Tenant AzureAD!" ; 
            if($credential.username -match $rgxCertThumbprint){
                $smsg = "Connecting to -Credential Tenant as $($uRoleReturn.FriendlyName)" ;
            } else {
                $smsg = "Connecting to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ;
            } ;
            if($silent){} else {
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;
            Disconnect-AzureAD ;
            Connect-AAD -Credential $Credential -verbose:$($verbose) -Silent:$false  ; 
        } else {
            $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ;
            if($silent){} else {
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;
            # flip to resolve-UserNameToUserRole & direct eval the $token values:
            if( $TokenTag  -eq $uRoleReturn.TenOrg){
                if($credential.username -match $rgxCertThumbprint){
                    $smsg = "(Authenticated to AAD:$($uRoleReturn.TenOrg) as $($uRoleReturn.FriendlyName))" ;
                } else {
                    $smsg = "(Authenticated to AAD:$($uRoleReturn.TenOrg) as $(($token.AccessToken).userid))" ;
                } ;
                if($silent){} else {
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
            } else {
                if($credential.username -match $rgxCertThumbprint){
                    $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant as $($uRoleReturn.FriendlyName)" ;
                } else {
                    $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ;
                } ;
                if($silent){} else {
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
                Disconnect-AzureAD ;
                throw "AUTHENTICATED TO WRONG TENANT FOR SPECIFIED CREDENTIAL" ;
            } ;
        } ; 

    } ; # END-E
}
#*------^ Connect-AAD.ps1 ^------