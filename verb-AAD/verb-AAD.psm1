﻿# verb-AAD.psm1


<#
.SYNOPSIS
verb-AAD - Azure AD-related generic functions
.NOTES
Version     : 1.2.1
Author      : Todd Kadrie
Website     :	https://www.toddomation.com
Twitter     :	@tostka
CreatedDate : 12/17/2019
FileName    : verb-AAD.psm1
License     : MIT
Copyright   : (c) 12/17/2019 Todd Kadrie
Github      : https://github.com/tostka
AddedCredit : REFERENCE
AddedWebsite:	REFERENCEURL
AddedTwitter:	@HANDLE / http://twitter.com/HANDLE
REVISIONS
* 3:45 PM 3/15/2021 disabled console coloring (psreadline breaking changes make it too hard to work everywhere)
* 11:06 AM 2/25/2020 1.0.3 connect-azrm updated to reflect my credential prefs, broad updates and tightening across, also abstracted literals & constants out. Validated functions work post chgs
* 12/17/2019 - 1.0.0
* 10:55 AM 12/6/2019 Connect-MSOL & Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
* 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
* 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA, splits specified credential and picks up on global o365_TAG_MFA/o365_TAG_OPDomain varis matching the credential domain. also added Add-PSTitleBar 'XXX' for msol & aad ;
* 2:18 PM 5/14/2019 added Build-AADSignErrorsHash 
* 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD ; ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for AzureAD module
* 11:56 AM 12/7/2018 init version, added Alias connect-msol -> connect-aad
.DESCRIPTION
verb-AAD - Azure AD-related generic functions
.LINK
https://github.com/tostka/verb-AAD
#>


$script:ModuleRoot = $PSScriptRoot ;
$script:ModuleVersion = (Import-PowerShellDataFile -Path (get-childitem $script:moduleroot\*.psd1).fullname).moduleversion ;

#*======v FUNCTIONS v======



#*------v Add-ADALType.ps1 v------
function Add-ADALType {
    <#
    .SYNOPSIS
    Add-ADALType - Path & Load the AzureAD 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Add-ADALType
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 1:53 PM 6/16/2021 flip fr static rev to latest rev of azuread mod
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Add-ADALType - Path & Load the AzureAD 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    .EXAMPLE
    Add-ADALType ; 
    Ensure our ADAL types are loaded and available
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param([Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        #$path = join-path (split-path (Get-Module azuread -ListAvailable | Where-Object { $_.Version -eq '2.0.2.16' }).Path -parent) 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll' ; 
        # hardcode fails, if vers not present; flip to latest of list
        $path = join-path (split-path (Get-Module azuread -ListAvailable | sort Version | select -last 1).Path -parent) 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll' ; 
        Add-Type -Path $path ; 
    } ; 
    END{} ;
}

#*------^ Add-ADALType.ps1 ^------

#*------v caadCMW.ps1 v------
function caadCMW {Connect-AAD -cred $credO365CMWCSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ caadCMW.ps1 ^------

#*------v caadTOL.ps1 v------
function caadtol {Connect-AAD -cred $credO365TOLSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ caadTOL.ps1 ^------

#*------v caadTOR.ps1 v------
function caadTOR {Connect-AAD -cred $credO365TORSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ caadTOR.ps1 ^------

#*------v caadVEN.ps1 v------
function caadVEN {Connect-AAD -cred $credO365VENCSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ caadVEN.ps1 ^------

#*------v cmsolCMW.ps1 v------
function cmsolcmw {Connect-MSOL -cred $credO365CMWCSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ cmsolCMW.ps1 ^------

#*------v cmsolTOL.ps1 v------
function cmsolTOL {Connect-MSOL -cred $credO365TOLSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ cmsolTOL.ps1 ^------

#*------v cmsolTOR.ps1 v------
function cmsolTOR {Connect-MSOL -cred $credO365TORSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ cmsolTOR.ps1 ^------

#*------v cmsolVEN.ps1 v------
function cmsolVEN {Connect-MSOL -cred $credO365VENCSID -Verbose:($VerbosePreference -eq 'Continue') ; }

#*------^ cmsolVEN.ps1 ^------

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
    [CmdletBinding()] 
    [Alias('caad','raad','reconnect-AAD')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
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
        $TenantTag=$TenOrg = get-TenantTag -Credential $Credential ; 
        $sTitleBarTag = @("AAD") ;
        $sTitleBarTag += $TenantTag ;
        $TenantID = get-TenantID -Credential $Credential ;
    } ;
    PROCESS {
        $smsg = "(Check for/install AzureAD module)" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;         Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        $smsg = "Import-Module -Name AzureAD -MinimumVersion '2.0.0.131'" ; 
        if($silent){} else { 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;  
       Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        # with multitenants and changes between, instead we need ot test 'what tenant' we're connected to
        TRY { 
            #I'm going to assume that it's due to too many repeated req's for gAADTD
            # so lets work with & eval the local AzureSession Token instead - it's got the userid, and the tenantid, both can validate the conn, wo any queries.:
            $token = get-AADToken -verbose:$($verbose) ; 
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
                #if connected,verify cred-specified Tenant
                #if($AADTenDtl.VerifiedDomains.name.contains($Credential.username.split('@')[1].tostring())){
                if(($token.AccessToken).userid -eq $Credential.username){
                    $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid ;                    
                    #$smsg = "(Authenticated to AAD:$($AADTenDtl.displayname))"
                    $smsg = "(Authenticated to AAD:$($TokenTag) as $(($token.AccessToken).userid)" ; 
                    if($silent){} else { 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ;                    
                } else { 
                    $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ; 
                    $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
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
            
            if(!$Credential){
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

            $smsg = "Authenticating to AAD:$($Credential.username.split('@')[1].tostring()), w $($Credential.username)..."  ;
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            $pltCAAD=[ordered]@{
                    ErrorAction='Stop';
            }; 
            if($TenantID){
                $smsg = "Forcing TenantID:$($TenantID)" ; 
                if($silent){} else { 
                    $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;                
                $pltCAAD.add('TenantID',$TenantID) ;
            } 
            if(!$MFA){
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
                $smsg = "EXEC:Connect-AzureAD -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                if($silent){} else { 
                    $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;                

                if($Credential.username){$pltCAAD.add('AccountId',$Credential.username)} ;
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
                        if($silent){} else { 
                            $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
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
                $smsg = "$(($AADConnection |ft -a|out-string).trim())" ;
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
        $token = get-AADToken -verbose:$($verbose) ; 
        if( ($null -eq $token) -OR ($token.count -eq 0)){
            # not connected/authenticated
            #Connect-AzureAD -TenantId $TenantID -Credential $Credential ; 
            #throw "" # gen an error to dump into generic CATCH block
        } else { 
            <# borked by psreadline v1/v2 breaking changes
            if(($PSFgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSFgColor) -AND ($PSBgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSBgColor)){
                $smsg = "(setting console colors:$($TenOrg)Meta.PSFgColor:$($PSFgColor),PSBgColor:$($PSBgColor))" ; 
                $Host.UI.RawUI.BackgroundColor = $PSBgColor
                $Host.UI.RawUI.ForegroundColor = $PSFgColor ; 
            } ;
            #>
            if($silent){} else { 
                $smsg = "Connected to Tenant:`n$(($token.AccessToken | ft -a TenantId,UserId,LoginType|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ $smsg = "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            if(($token.AccessToken).userid -eq $Credential.username){
                $TokenTag = convert-TenantIdToTag -TenantId $TenantId ;                    
                $smsg = "(Authenticated to AAD:$($TokenTag) as $(($token.AccessToken).userid)" ; 
                if($silent){} else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ $smsg = "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
                $TenOrg=get-TenantTag -Credential $Credential ; 
                $sTitleBarTag = @("AAD") ;
                $sTitleBarTag +=  $TokenTag ;# $TenOrg ;
                Add-PSTitleBar $sTitleBarTag -verbose:$($VerbosePreference -eq "Continue");
            } else { 
                $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).TenantID  -verbose:$($verbose) ; 
                $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ $smsg = "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                Disconnect-AzureAD ; 
                throw "AUTHENTICATED TO WRONG TENANT FOR SPECIFIED CREDENTIAL" 
            } ; 
        } ; 
    } ; # END-E
}

#*------^ Connect-AAD.ps1 ^------

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
    * 5:17 PM 8/5/2020 strong-typed Credential
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
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
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
            Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
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

#*------v Connect-MSOL.ps1 v------
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
    * 9:40 AM 9/17/2021 had missed an echo past -silent
    * 1:17 PM 8/24/2021 remove unused ProxyEnabled param (causing arg transf errs
    * 1:17 PM 8/17/2021 added -silent param
    # 3:23 PM 7/26/2021 ADD PSTITLEBAR TAG
    # 1:45 PM 7/21/2021 enforce PSTitlebar tag Tenorg, no exceptions
    * 12:16 PM 4/5/2021 updated w 7pswlt support ;replaced hard-coded cred with proper $Credential.username ref
    * 11:36 AM 3/5/2021 updated colorcode, subed wv -verbose with just write-verbose, added cred.uname echo
    * 2:44 PM 3/2/2021 added console TenOrg color support
    * 3:40 PM 8/8/2020 updated to match caad's options, aside from msol's lack of AzureSession token support - so this uses Get-MsolDomain & Get-MsolCompanyInformation to handle the new post-connect cred->tenant match validation
    * 5:17 PM 8/5/2020 strong-typed Credential, swapped in get-TenantTag()
    * 1:28 PM 7/27/2020 restored deleted file (was fat-thumbed 7/22)
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
    Also an msol connectoin doesn't yield the same token - (([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens).AccessToken) | fl * ;  - AAD does, though an AAD token can be used to authenticate (through -MsGraphAccessToken or -AdGraphAccessToken?)
    .PARAMETER CommandPrefix
    Prefix to be appended to commands (not implemented with MSOL/AAD)
    .PARAMETER Credential
    Credential to be used for connection
    .PARAMETER silent
    Switch to suppress all non-error echos
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Connect-MSOL
    .LINK
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()]
    [Alias('cmsol','rmsol','Reconnect-MSOL')]
    Param(
        [Parameter()][string]$CommandPrefix,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    BEGIN { 
        $verbose = ($VerbosePreference -eq "Continue") ;
        $tmod = "MSOnline" ; 
        write-verbose "(Check for/install $($tmod) module)" ; 
        Try {Get-Module $tmod -listavailable -ErrorAction Stop | out-null } Catch {Install-Module $tmod -scope AllUsers ; } ;                 # installed
        write-verbose "Import-Module -Name $($tmod)" ; 
        Try {Get-Module $tmod -ErrorAction Stop | out-null } Catch {Import-Module -Name $tmod -ErrorAction Stop  } ; # imported
    } ;
    PROCESS {
        $MFA = get-TenantMFARequirement -Credential $Credential ;
        # msol doesn't support the -TenantID, it's imputed from the credential

        # 12:10 PM 3/15/2017 disable prefix spec, unless actually blanked (e.g. centrally spec'd in profile).
        #if(!$CommandPrefix){ $CommandPrefix='aad' ; } ;

        $TenantTag=$TenOrg = get-TenantTag -Credential $Credential ; 
        $sTitleBarTag = @("MSOL") ;
        $sTitleBarTag += $TenOrg ;

        try { Get-MsolAccountSku -ErrorAction Stop | out-null }
        catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
            $smsg = "Not connected to MSOnline. Now connecting." ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            if (!$Credential) {
                if(get-command -Name get-admincred) {
                    Get-AdminCred -Verbose:($VerbosePreference -eq 'Continue') -silent ; 
                } else {
                    # resolve suitable creds based on $credential domain specified
                    $credDom = ($Credential.username.split("@"))[1] ;
                    $Metas=(get-variable *meta|?{$_.name -match '^\w{3}Meta$'}) ; 
                    foreach ($Meta in $Metas){
                            if( ($credDom -eq $Meta.value.legacyDomain) -OR ($credDom -eq $Meta.value.o365_TenantDomain) -OR ($credDom -eq $Meta.value.o365_OPDomain)){
                                if($Meta.value.o365_SIDUpn ){$Credential = Get-Credential -Credential $Meta.value.o365_SIDUpn } else { $Credential = Get-Credential } ;
                                #$TenantID = get-TenantID -Credential $Credential ;
                                break ; 
                            } ; 
                    } ;
                    if(!$Credential){
                        write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                        $Credential = Get-Credential ; 
                    } ;
                }  ;
            } ;
            Write-Host "Connecting to MSOL"  ;
            $pltCMSOL=[ordered]@{
                ErrorAction='Stop';
            }; 
            $error.clear() ;
            if (!$MFA) {
                $smsg = "EXEC:Connect-MsolService -Credential $($Credential.username) (no MFA, full credential)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                if($Credential.username){
                    $pltCMSOL.add('Credential',$Credential) ; 
                    $smsg = "(using cred:$($credential.username))" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
                #Connect-MsolService -Credential $Credential -ErrorAction Stop ;
            }
            else {
                $smsg = "EXEC:Connect-MsolService -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #if($Credential.username){$pltCMSOL.add('AccountId',$Credential.username)} ;
                #Connect-MsolService -ErrorAction Stop ;
            } ;

            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Connect-MsolService w`n$(($pltCMSOL|out-string).trim())" ; 
            TRY {
                Connect-MsolService @pltCMSOL ; 
            } CATCH {
                $smsg = "Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                throw $_ #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 

            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { 
                add-PSTitlebar 'MSOL' -verbose:$($VerbosePreference -eq "Continue") ; 
                if($silent){} else { 
                    $smsg = "(Connected to MSOL)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ; 
            } ;
        } ;
        
    } ;
    END {
        $smsg = "EXEC:Get-MsolDomain" ; 
        if(!$silent){
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; 
        TRY {
            $MSOLDoms = Get-MsolDomain ; # err indicates no authenticated connection ; 
            $MsolCoInf = Get-MsolCompanyInformation ; 
        } CATCH [Microsoft.Open.AzureAD16.Client.ApiException] {
            $ErrTrpd = $_ ; 
            Write-Warning "$((get-date).ToString('HH:mm:ss')):AzureAD Tenant Permissions Error" ; 
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            throw $ErrTrpd ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            throw $_ ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 

        #if connected,verify cred-specified Tenant
        if( $msoldoms.name.contains($Credential.username.split('@')[1].tostring()) ){
            <# borked by psreadline v1/v2 breaking changes
            if(($PSFgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSFgColor) -AND ($PSBgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSBgColor)){
                $Host.UI.RawUI.BackgroundColor = $PSBgColor
                $Host.UI.RawUI.ForegroundColor = $PSFgColor ; 
            } ;
            #>
            if($silent){} else { 
                $smsg = "(Authenticated to MSOL:$($MsolCoInf.DisplayName))" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            $sTitleBarTag = @("MSOL") ;
            $sTitleBarTag +=  $TenantTag ; 
            Add-PSTitleBar $sTitleBarTag -verbose:$($VerbosePreference -eq "Continue");
        } else { 
            #$smsg = "(Disconnecting from $(AADTenDtl.displayname) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
            #Disconnect-AzureAD ; 
            throw "MSOLSERVICE IS CONNECTED TO WRONG TENANT!:$($MsolCoInf.DisplayName)" ;
        } ;             
    } ;
}

#*------^ Connect-MSOL.ps1 ^------

#*------v convert-AADUImmuntableIDToADUObjectGUID.ps1 v------
Function convert-AADUImmuntableIDToADUObjectGUID {
    <#
    .SYNOPSIS
    convert-AADUImmuntableIDToADUObjectGUID - Convert an AzureADUser.ImmuntableID to the equivelent ADUser.objectGuid (via Base64 conversion).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-12-06
    FileName    : convert-AADUImmuntableIDToADUObjectGUID.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,AzureAD,ActiveDirectory,Conversion
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 10:29 AM 12/6/2021 init
    .DESCRIPTION
    convert-AADUImmuntableIDToADUObjectGUID - Convert an AzureADUser.ImmuntableID to the equivelent ADUser.objectGuid (via Base64 conversion).
    .PARAMETER immutableID
immutableID string to be converted[-immutableID 'SAMPLEINPUT']
    .PARAMETER silent
    Switch to suppress all non-error echos
    .INPUTS
    System.string
    Microsoft.Open.AzureAD.Model.User
    Accepts pipeline input.
    .OUTPUTS
    System.Guid
    .EXAMPLE
    $ObjectGuid = (convert-AADUImmuntableIDToADUObjectGUID -immutableID 'fxTjHP+7AkiDxhZ+afyOEA==' -verbose).guid ; 
    
    Directly convert specified -immutableID string to guid object, and assign to a variable, with verbose output.
    .EXAMPLE
    get-AzureAdUser -objectname fname.lname@domain.tld | convert-AADUImmuntableIDToADUObjectGUID | foreach-object {get-aduser -identity $_.guid} ;
    Pipeline example demoing retrieval of an AzureADUser, conversion to guid mid-pipeline, and retrieval of matching ADUser for the converted immutableID/guid.
    .LINK
    https://github.com/tostka/verb-aad
    #>
    #Requires -Modules AzureAD,ActiveDirectory
    [CmdletBinding()] 
    [Alias('convert-ImmuntableIDToGUID')]
    Param(
         [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="immutableID string to be converted[-immutableID 'SAMPLEINPUT']")]
        [String]$immutableID,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    BEGIN {} ;
    PROCESS {
        $error.clear() ;
        TRY {
            $smsg = "convert (AADU.)immutableID:$($immutableID)" ; 
            $smsg += " to (ExchOP.)objectGuid..." ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ; 
            [guid]$guid=New-Object -TypeName guid (,[System.Convert]::FromBase64String($immutableid)) ;
            $smsg = "(returning to pipeline, converted [guid]:$($guid)" ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ; 
            $guid | write-output ; 
        } CATCH {
            $ErrTrapd=$Error[0] ;
            $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
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
        
    } ;  # PROC-E
    END {} ; 
}

#*------^ convert-AADUImmuntableIDToADUObjectGUID.ps1 ^------

#*------v convert-ADUObjectGUIDToAADUImmuntableID.ps1 v------
Function convert-ADUObjectGUIDToAADUImmuntableID {
    <#
    .SYNOPSIS
    convert-ADUObjectGUIDToAADUImmuntableID - Convert an ADUser.objectGuid to the equivelent AzureADUser.ImmuntableID (via Base64 conversion).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-12-06
    FileName    : convert-ADUObjectGUIDToAADUImmuntableID.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,AzureAD,ActiveDirectory,Conversion
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 11:20 AM 12/6/2021 init
    .DESCRIPTION
    convert-ADUObjectGUIDToAADUImmuntableID - Convert an ADUser.objectGuid to the equivelent AzureADUser.ImmuntableID (via Base64 conversion).
    .PARAMETER  Guid
    Guid to be converted[-guid '24bf3cb0-65b6-4ab7-ba2f-7d60f2a7a76a']
    .PARAMETER silent
    Switch to suppress all non-error echos
    .INPUTS
    System.string
    System.Guid
    Microsoft.ActiveDirectory.Management.ADUser
    .OUTPUTS
    System.string
    .EXAMPLE
    convert-ADUObjectGUIDToAADUImmuntableID -guid '73f3ee61-4d95-451b-80a1-089536361a16' -verbose ; 
    Directly convert specified -immutableID string to guid object, with verbose output
    .EXAMPLE
    get-AdUser -id someSamAccountName | convert-ADUObjectGUIDToAADUImmuntableID | foreach-object {get-AzureAdUser -objectid $_} ;
    Pipeline example demoing retrieval of an AzureADUser, conversion to guid mid-pipeline, and retrieval of matching ADUser for the converted immutableID/guid.
    .LINK
    https://github.com/tostka/verb-aad
    #>
    #Requires -Modules AzureAD,ActiveDirectory
    [CmdletBinding()] 
    [Alias('convert-GUIDToImmuntableID')]
    Param(
         [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Guid to be converted[-guid '24bf3cb0-65b6-4ab7-ba2f-7d60f2a7a76a']")]
        [Alias('objectGuid')]
        [String]$Guid,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    BEGIN {} ;
    PROCESS {
        <#
        # going from msoluser.immutableid -> ad.objectguid:
        [System.Convert]::ToBase64String($guid.ToByteArray()) ;
        #>
        $error.clear() ;
        TRY {
            $smsg = "convert (ADU.)guid:$($guid)" ; 
            $smsg += " to (AADU.)immutableID..."
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            
            [string]$immutableID=[System.Convert]::ToBase64String($guid.ToByteArray()) ;
            
            $smsg = "(returning to pipeline, converted ImmutableID string:$($immutableID)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            $immutableID | write-output ; 
        } CATCH {
            $ErrTrapd=$Error[0] ;
            $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
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
        
    } ;  # PROC-E
    END {
        
    } ; # END-E
}

#*------^ convert-ADUObjectGUIDToAADUImmuntableID.ps1 ^------

#*------v Disconnect-AAD.ps1 v------
Function Disconnect-AAD {
    <#
    .SYNOPSIS
    Disconnect-AAD - Disconnect current authenticated session to Azure Active Directory tenant via AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does (wraps new underlying disconnect-azuread())
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-07-27
    FileName    : Disconnect-AAD.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 3:28 PM 7/26/2021 pstitlebar update
    * 10:58 AM 3/16/2021 updated cbh & new try-catch to accomodate non-existing 
    * 2:44 PM 3/2/2021 added console TenOrg color support
    * 3:03 PM 8/8/2020 rewrote to leverage AzureSession checks, without need to qry Get-AzureADTenantDetail (trying to avoid sporadic VEN AAD 'Forbidden' errors)
    * 3:24 PM 8/6/2020 added CATCH block for AzureAD perms errors seeing on one tenant, also shifted only the AAD cmdlets into TRY, to isolate errs
    * 5:17 PM 8/5/2020 strong-typed Credential;added verbose outputs, try/catch, and catch targeting unauthenticated status, added missing Disconnect-AzureAD (doh)
    * 3:15 PM 7/27/2020 init vers
    .DESCRIPTION
    Disconnect-AAD - Disconnect authenticated session to AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Disconnect-AAD
    .EXAMPLE
    Disconnect-AAD -Credential $cred
    .LINK
    https://docs.microsoft.com/en-us/powershell/module/azuread/disconnect-azuread?view=azureadps-2.0
    #>
    [CmdletBinding()] 
    [Alias('daad')]
    Param() ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        write-verbose "(Check for/install AzureAD module)" ; 
        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        write-verbose "Import-Module -Name AzureAD -MinimumVersion '2.0.0.131'" ; 
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        write-verbose "get-command disconnect-AzureAD" ; 
        if(get-command disconnect-AzureAD){
            $sTitleBarTag = @("AAD") ;
            $error.clear() ;
            TRY {
                <# old code
                write-verbose "Checking for existing AzureADTenantDetail (AAD connection)" ; 
                $AADTenDtl = Get-AzureADTenantDetail ; 
                if($AADTenDtl){
                    write-host "(disconnect-AzureAD from:$($AADTenDtl.displayname))" ;
                    disconnect-AzureAD ; 
                    write-verbose "Remove-PSTitleBar -Tag $($sTitleBarTag)" ; 
                    Remove-PSTitleBar -Tag $sTitleBarTag ; 
                } else { write-host "(No existing AAD tenant connection)" } ;
                #>
                try{
                    Disconnect-AzureAD -EA SilentlyContinue -ErrorVariable AADError ;
                    Write-Host -ForegroundColor green ("Azure Active Directory - Disconnected") ;
                    remove-PSTitleBar $sTitleBarTag -verbose:$($VerbosePreference -eq "Continue");
                }
                catch  {
                    $ErrTrpd = $Error[0] ; 
                    if($AADError.Exception.Message -eq "Object reference not set to an instance of an object."){
                        Write-Host -foregroundcolor yellow "Azure AD - No active Azure Active Directory Connections" ;
                    }else{
                        Write-Host -foregroundcolor "Azure Active Directory - $($ErrTrpd.Exception.Message)" ;
                        $error.clear() ;
                        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($ErrTrpd.Exception.ItemName). `nError Message: $($ErrTrpd.Exception.Message)`nError Details: $($ErrTrpd)" ;
                        $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($Error[0].Exception.GetType().FullName)]{" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ; 
        
                } ;
                # shift to AzureSession token checks
                $token = get-AADToken -verbose:$($verbose) ;
                if( ($null -eq $token) -OR ($token.count -eq 0)){
                    # not connected/authenticated
                    #Connect-AzureAD -TenantId $TenantID -Credential $Credential ;
                    #throw "" # gen an error to dump into generic CATCH block
                } else {
                    write-verbose "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ;
                    $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).TenantID  -verbose:$($verbose) ; 
                    write-host "(disconnect-AzureAD from:$($TokenTag))" ;
                    disconnect-AzureAD ; 
                    write-verbose "Remove-PSTitleBar -Tag $($sTitleBarTag)" ; 
                    Remove-PSTitlebar $sTitleBarTag -verbose:$($VerbosePreference -eq "Continue") 
                    # should pull TenOrg if no other mounted 
                    <#$sXopDesig = 'xp' ;
                    $sXoDesig = 'xo' ;
                    #>
                    #$xxxMeta.rgxOrgSvcs - $ExchangeServer = (Get-Variable  -name "$($TenOrg)Meta").value.Ex10Server|get-random ;
                    # normally would be org specific, but we don't have a cred or a TenOrg ref to resolve, so just check xx's version
                    # -replace 'EMS','' -replace '\(\|','(' -replace '\|\)',')'
                    #if($host.ui.RawUI.WindowTitle -notmatch ((Get-Variable  -name "TorMeta").value.rgxOrgSvcs-replace 'EMS','' -replace '\(\|','(' -replace '\|\)',')' )){
                    # drop the current tag being removed from the rgx...
                    [regex]$rgxsvcs = ('(' + (((Get-Variable  -name "TorMeta").value.OrgSvcs |?{$_ -ne 'AAD'} |%{[regex]::escape($_)}) -join '|') + ')') ;
                    if($host.ui.RawUI.WindowTitle -notmatch $rgxsvcs){
                        write-verbose "(removing TenOrg reference from PSTitlebar)" ; 
                        # in this case as we need to remove all Orgs, have to build a full list from $xxxmeta
                        #Remove-PSTitlebar $TenOrg ;
                        if(!$TokenTag){
                            # if don't have TenOrg known, full remove:
                            # split the rgx into an array of tags
                            #sTitleBarTag = (((Get-Variable  -name "TorMeta").value.rgxOrgSvcs) -replace '(\\s\(|\)\\s)','').split('|') ; 
                            # no remove all meta tenorg tags , if no other services(??)
                            $Metas=(get-variable *meta|?{$_.name -match '^\w{3}Meta$'}) ; 
                            $sTitleBarTag = $metas.name.substring(0,3) ; 
                            $sTitleBarTag += 'AAD' ; 
                        } else { 
                            # TokenTag already resolved the 3-letter TenOrg, use it
                            $sTitleBarTag = $TokenTag
                            $sTitleBarTag += 'AAD' ; 
                        } ; 
                        Remove-PSTitlebar $sTitleBarTag ;
                    } else {
                        write-verbose "(detected matching OrgSvcs in PSTitlebar: *not* removing TenOrg reference)" ; 
                    } ; 
                    #[console]::ResetColor()  # reset console colorscheme
                } ; 
            
            } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]{
                write-host "(No existing AAD tenant connection)"
            } CATCH [Microsoft.Open.AzureAD16.Client.ApiException] {
                $ErrTrpd = $_ ; 
                Write-Warning "$((get-date).ToString('HH:mm:ss')):AzureAD Tenant Permissions Error" ; 
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                throw $ErrTrpd ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } CATCH {
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                throw $_ ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 
        } else {write-host "(The AzureAD module isn't currently loaded)" } ; 
    } ; 
    END {} ;
}

#*------^ Disconnect-AAD.ps1 ^------

#*------v get-AADBearerToken.ps1 v------
function get-AADBearerToken {
    <#
    .SYNOPSIS
    get-AADBearerToken.ps1 - generates a header from a Bearer token.
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : get-AADBearerToken.ps1
    License     : 
    Copyright   : 
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs,Azure,AzureAD,Token,RestAPI
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    # [does not contain a method named 'AcquireToken' Â· Issue #29108 Â· MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs/issues/29108)
    reports a fix:(untested, moved to native auth via certs)
    TomBertie commented Apr 13, 2019 â€¢
    I think I've got it working with AcquireTokenAsync by changing RESTAPI-Auth to:
    #-=-=-=-=-=-=-=-=
    Function RESTAPI-Auth {
        $global:SubscriptionID = $Subscription.Subscription.Id
        # Set Resource URI to Azure Service Management API
        $resourceAppIdURIARM=$ARMResource
        # Authenticate and Acquire Token
        # Create Authentication Context tied to Azure AD Tenant
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
        # Acquire token
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $global:authResultARM = $authContext.AcquireTokenAsync($resourceAppIdURIARM, $clientId, $redirectUri, $platformParameters)
        $global:authResultARM.Wait()
        $authHeader = $global:authResultARM.result.CreateAuthorizationHeader()
        $authHeader
    }
    #-=-=-=-=-=-=-=-=
    REVISIONS   :
    * 1:45 PM 6/16/2021 added logging (although borked, maybe they'll restore function later)
    5:41 PM 1/30/2020 BROKEN - whole concept of Bearer token pull: ADAL Azure mod dll no longer has an 'AcquireToken' method (revised away)
    .PARAMETER tenantId
    AAD TenantID (defaulted TOR) [-TenantID (guid)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADBearerToken ;
    Obtain a token
    .EXAMPLE
    $token=get-AADBearerToken -tenantId:$($tenantId) ;
    Specing a non-default Tenant
    .EXAMPLE
    $authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
    $token = $authResult.AccessToken
    $AADTokenHeaders = get-AADBearerTokenHeaders($token)
    Token rnewal example
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    [CmdletBinding()]
    Param(
        [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
        [string]$tenantId = "549366ae-e80a-44b9-8adc-52d0c29ba08b",
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug,
        [Parameter(HelpMessage = "Whatif Flag  [-whatIf]")]
        [switch] $whatIf
    ) # PARAM BLOCK END ;

    $authority = "https://login.microsoftonline.com/$tenantId"
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    write-verbose "`$authContext:`n$(($authContext|out-string).trim())" ;
    $authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Always")
    write-verbose "`$authResult:`n$(($authResult|out-string).trim())" ;
    # but as of 9:48 AM 1/28/2020 it's working again in ISE (facepalm)
    <# 3:13 PM 1/27/2020 new error:
    get-AADBearerToken : Method invocation failed because [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext] does not contain a method named 'AcquireToken'.
At C:\usr\work\o365\scripts\Pull-AADSignInReports.ps1:434 char:8
+ $token=get-AADBearerToken ;
+        ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [get-AADBearerToken], RuntimeException
    + FullyQualifiedErrorId : MethodNotFound,get-AADBearerToken
    #>
    $token = $authResult.AccessToken
    write-verbose "`$token:`n$(($token|out-string).trim())" ;
    if ($token -eq $null) {
        $smsg = "ERROR: Failed to get an Access Token" ; ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        break ;
    }
    else { $token | write-output }
}

#*------^ get-AADBearerToken.ps1 ^------

#*------v get-AADBearerTokenHeaders.ps1 v------
Function get-AADBearerTokenHeaders {
    <#
    .SYNOPSIS
    get-AADBearerTokenHeaders.ps1 - generates a header from a Bearer token.
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : get-AADBearerTokenHeaders.ps1
    License     : 
    Copyright   : 
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs,Azure,AzureAD,Token,RestAPI
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS   :
    5:41 PM 1/30/2020 BROKEN - whole concept of Bearer token pul: ADAL Azure mod dll no longer has an 'AcquireToken' method
    .PARAMETER tenantId
    AAD TenantID (defaulted TOR) [-TenantID (guid)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADBearerTokenHeaders ;
    Obtain a token
    .EXAMPLE
    $token=get-AADBearerTokenHeaders -tenantId:$($tenantId) ;
    Specing a non-default Tenant
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    [CmdletBinding()]
    param( $token )
    Return @{
        "Authorization" = ("Bearer {0}" -f $token);
        "Content-Type"  = "application/json";
    }
}

#*------^ get-AADBearerTokenHeaders.ps1 ^------

#*------v get-AADCertToken.ps1 v------
function get-AADCertToken {
    <#
    .SYNOPSIS
     get-AADCertToken - Obtain a certificate-authenticated Azure access token
    .NOTES
    Version     : 1.0.0
    Author      : Alex Asplund
    Website     : https://automativity.com
    Twitter     : @AlexAsplund
    CreatedDate : 2019-08-12
    FileName    : get-AADCertToken.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	
    REVISIONS
    * 1:13 PM 6/16/2021 logging: swapped wl for write-* ; swapped $XXXmeta. props for driver vari's
    * 3:16 PM 6/14/2021 fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out rednund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
* 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
    * 8:51 AM 1/30/2020
    * 2019-08-12 posted version 
    .DESCRIPTION
     get-AADCertToken - Obtain a certificate-authenticated AADApp Azure access token
     As written, it Authenticates with a certificate (thumbprint matchese $global:TOR_AAD_App_Audit_CertThumb), 
     stored in Cert:\CurrentUser\My\ (see 4a) for process to export and import into new machines and account profiles)
     Uses code Alex Asplund demo'd at link below, wrapped into a func
     Configure parameter defaults as follows
        |param|info source|
        |---|---|
        |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
        |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
        |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
        |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|

        This script uses RestAPI calls to authenticate and query GraphAPI. 

        ##Prereqs:
        1) **Verify AAD Premium P1 tenant license:**
          - [https://admin.microsoft.com/Adminportal/](https://admin.microsoft.com/Adminportal/) : *Billing >* appears at top: *Azure Active Directory Premium P1*
          - or [https://portal.azure.com](https://portal.azure.com) ; *AAD *> main overview page, it appear right below* 'The Toro Company'* on the graph: *Azure AD Premium P1*
        2) **Create an Application Identity**
        [https://portal.azure.com](https://portal.azure.com) > *Azure Active Directory* > *Manage pane:* *App Registrations* > **[+]New Registration**
        **Register an application screen**:
        - **Displayname**: `AuditGraphAccessMessaging`
        - **Supported account types**:
        (x) **Accounts in this organizational directory only (COMPANY - Single tenant)**</br>
        ( ) *Accounts in any organizational directory (Any Azure AD directory - Multitenant)*</br>
        ( ) *Accounts in any organizational directory (Any Azure AD directory - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)*</br>
        - Click **Register**
        - Above refreshes to the details of the new App: upper right: click **Add a Redirect URI**
            - **Type**: ***Web***, **Redirect URI**: `https://localhost` </br>
            *(can set anything here, doesn't need to be functional)*
            - click **Save** *(top left, note the redirect url created)*
        - Record the **Application (client ID)** *(guid)* for future reference.
         2a) Expired Cert or Secret:
                    This also *expires* (visible by browsing below and checking status)
                    [https://portal.azure.com](https://portal.azure.com) > *Azure Active Directory* > *Manage pane:* *App Registrations*
                    Search 'AuditGraphAccessMessaging'
                    Returns 'A certificate or secret has expired. Create a new one ->', click _->_
                    Sections:
                        Certificates:
                        |Thumb|from|to|id|
                        |7C7D6CA274D687693340918E8CB07D22F2FE4AC4| 1/28/2020| 1/28/2022 |416f6bc7-2e19-4ca8-8f22-2995ed0fbc99|
                        - is still valid
                        Client secrets
                        |Description|Expires|Value|ID|
                        |AudGrphAccMsgKey|4/23/2020|Hidden|195bc9ce-adb7-4b38-8873-ef7d694406fe|
                        - above expired, click _+New Client Secret_
                        Desc: AudGrphAccMsgKey rollover 3:51 PM 20210114-0351PM 2yrs
                        _Add_,
                        "Copy the new client secret value. You won't be able to retrieve it after you perform another operation or leave this blade"
                        click the [copy] btn at right of the secret. The copied material is the 'Value' column (which on the prior, or after leaving this page, displays as 'Hidden')
                        "[looks like a guid]"
                        Also record the Secret's expiration date : 1/14/2023
        3) **Grant necessary App Permissions**
            - If necessary, return to: *AADPortal > App Registrations* > [find and click your new App]
            - Left pane: Click **Api permisions**
                - ***For Audit Log Sign-in Activity, it needs:***
                |Permission type |Permissions (from least to most privileged)|
                |---|---|
                |Delegated (work or school account) |AuditLog.Read.All, Directory.Read.All|
                |Delegated (personal Microsoft account) |Not supported|
                |Application |AuditLog.Read.All, Directory.Read.All|
            - click **Add a permission** btn
                - **Request API Permissions** blade: **Microsoft Graph**
                - click **Application permissions** *(don't require a logged on user to be present to run)*
                - *Type to search*: [*type out one of the permisison names above*]
                - when the matching entry appears **[x]** (e.g. AuditLog.Read.All)
                - click **Add permission** to commit the change. (refreshes back to the *Configured permissions* screen)
                - Repeat the process above for each additional permission to be added
            - When all permisisons are added & displayed, click the **Grant admin consent for TENANT** button, **Yes**
        4) **Create a self-signed certificate to handle authentication:**
          - Configure values to suite Tenant and App Name.
        ```powershell
        # gens a self-signed cert for AAD auth of the AAD AuditGraphAccessMessaging API Access secprinc
        # below is displayed by: (Get-AzureADTenantDetail).VerifiedDomain
        # revised out:
        #$TenantName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain ;
        #$StoreLocation = "Cert:\CurrentUser\My" ;
        #$ExpirationDate = (Get-Date).AddYears(2) ;
        #
        $TenOrg = 'CMW' ;
        $CertName = "AuditGraphAccessMessaging$($TenOrg)" ;
        $CerOutputPath = "C:\usr\work\o365\certs\$($CertName)-$($TenOrg).cer" ;
        $PfxOutputPath = $CerOutputPath.replace('.cer','.pfx') ;
        $pltNewSSCert = @{
            FriendlyName = $CertName ;
            DnsName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain ; ;
            CertStoreLocation = "Cert:\CurrentUser\My" ;
            NotAfter = (Get-Date).AddYears(2) ;
            KeyExportPolicy = "Exportable" ;
            KeySpec = "Signature" ;
            Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider" ;
            HashAlgorithm = "SHA256" ;
        } ;
        TRY {$cert = New-SelfSignedCertificate @pltNewSSCert ;} CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
        $certPath = Join-Path -Path $pltNewSSCert.CertStoreLocation -ChildPath $cert.Thumbprint ;
        $pltExCER = [ordered]@{
          Cert = $certPath ;
          FilePath = $CerOutputPath ;
          Type = 'CERT' ;
        } ;
        TRY {$exportedCER = Export-Certificate @pltExCER } CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
        $exportedCER.fullname ;
        $cerDtls = gci $certPath ; $cerDtls ;$cerDtls | fl fullname,length;
        ```
        4a) Export the cert to another machine (jumpbox)
            # find it via the thumbprint (stored under Meta and reg global):$tormeta.AAD_App_Audit_CertThumb/$global:TOR_AAD_App_Audit_CertThumb
            # prior CER export lacks the private key (cer's always do) - sufficient for uploading to AAD, to register for auth, but not for moving cert bewteen hosts & accts.
            # export cert with privkey, into pfx file
            #$cert = Get-Item "Cert:\CurrentUser\My\$($global:TORMeta.AAD_App_Audit_CertThumb)" ;
            # dyn path
            #$cert = Get-Item "Cert:\CurrentUser\My\$((gv -name "$($TenOrg)meta").value.AAD_App_Audit_CertThumb)" ;
            # using $pltExCER.Cert
            $pfxcred=(Get-Credential -credential dummy) ;
            if($cert -AND $pfxcred.password){
                $pltExPfx=[ordered]@{
                    Cert=$certPath ;
                    FilePath = $CerOutputPath.replace('.cer','.pfx') ;
                    Password = $pfxcred.password
                };
                TRY {$exportedPFX = Export-PfxCertificate @pltExPfx  } CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
                $exportedPfx.fullname ;
                gci $exportedPfx.fullname| fl fullname,length;
                #Copy the pfx to the target machine, and use Certs.msc to import it into hkcu\My. repeat it for each acct that needs to use the cert
                if($exportedPfx.fullname){
                    $smsg = "# cp to target machine (over rdp, from desktop):`ngci $($exportedPfx.fullname -REPLACE "^([A-Za-z]):\\",'\\tsclient\$1\') | cp -Destination d:\scripts\cert\ -whatif ;" ; 
                    $smsg += "`n# import ON targmach:`n"  ; 
                    $smsg += "`$pfxcred = (Get-Credential -credential dummy)`n" ;
                    $smsg += "Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My -FilePath d:\scripts\cert\$(split-path $exportedPfx.fullname -leaf) -Password `$pfxcred.password" ; 
                    write-host $smsg ;
                } ; 
            } else { throw "Missing either `$cert or `$$pfxcred.password!" } ;   
            
        5) **Configure App with Certificate Authentication:**
        - From the registered apps's summary page, click left menu: **Certificates & secrets**  > **Upload certificate**, click folder icon, (*browse .cer*, in PS above, it's stored in $exportedcer.fullname) , **Add**
        - **while we're here lets add a Secret (password) as well:**
          - **Certificates & secrets**  > **New client secret**
          - *Description*: 'For SigninActivity review scripts'
          - *Expires*: **(x) in 24 mos**
          - click **Add**
          - The newly generated secret (password) string will *only* be displayed *once* on this page. Record it & the expiration date for permanent reference: (put the secret value into the password field on the KP entry)
        -
        6) **Script configuration:**
        - Update the following parameter default values to your target Tenants values:
        |param|info source|
        |---|---|
        |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
        |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
        |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
        |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|
        #-=-=-=-=-=-=-=-=


        The script queries the Azure AD Audit Graph endpoint for Sign In report entries.
        More information about the filtering options and the data returned can
        be found online at this link:
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

        Refs: 
        #-=-=-=-=-=-=-=-=
        List signIns - Microsoft Graph beta | Microsoft Docs - https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta
        [List signIns - Microsoft Graph beta | Microsoft Docs](https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta&tabs=http)
        Permissions
        One of the following permissions is required to call this API. To learn more, including how to choose permissions, see Permissions.
        |Permission type |Permissions (from least to most privileged)|
        |---|---|
        |Delegated (work or school account) |AuditLog.Read.All, Directory.Read.All|
        |Delegated (personal Microsoft account) |Not supported|
        |Application |AuditLog.Read.All, Directory.Read.All|
        (TSK: as of 11/5/19 rev: application now needs Directory.Read.All, in addition to AuditLog.Read.All)
        Set/Review: AzPortal (https://portal.azure.com): App registrations > search for the app name & click match > click _API permissions_, _Yes_
        Had:
            AAD Graph:
                User.Read  Delegated
            Microsoft Graph:
                AuditLog.Read.All  Application
        Need to add: Directory.Read.All: click _Add a Permission_ > Microsoft Graph > Application permissions > Search: Directory.Read.All: [x]Directory.Read.All, click _Add permissions_.
        back on API perms page: review that the perms list is now complete, then click _Grant admin consent for the Toro Company (only globals can do)
        #-=-=-=-=-=-=-=-=
    .PARAMETER  tenantName
    AAD TenantID [-TenantID (guid)]]
    .PARAMETER  AppID
    AAD AppID [-AppID (guid)]]
    .PARAMETER  Certificate
    Certificate Thumbprint [-Certificate (thumbprint)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADCertToken ;
    Obtain a token, using default params
    .EXAMPLE
    $token=get-AADCertToken -tenantName "[tenant].onmicrosoft.com" -AppID "[appid guid]" -Certificate "7C7D6...[thumbprint]";
    Specing a Token with non-defaults explicits
    .EXAMPLE
    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token =get-AADCertToken @pltAADCertToken ; 
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue') ; 
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns" ; 
    $myReportRequest = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json") ; 
    $myReport = @()
    $myReport += $myReportRequest.value
    Do {
        $myReportRequest = Invoke-RestMethod -Uri $AuditLogRequest.'@odata.nextLink' -Headers $Header -Method Get -ContentType "application/json"
        $myReport += $myReportRequest.value
    } while($myReportRequest.'@odata.nextLink' -ne $null) ; 
    .EXAMPLE
    $pltAADCertToken=[ordered]@{
        tenantName= $TOLMeta.o365_TenantDomain ; AppID= $TOLMeta.AAD_App_Audit_ID ; Certificate= $TOLMeta.AAD_App_Audit_CertThumb ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token = get-AADCertToken @pltAADCertToken ;
    ...
    TOL example
    .EXAMPLE
    # CertToken version
    #$Request = get-AADCertToken -Verbose:($VerbosePreference -eq 'Continue') ; 
    $tenantName = $global:$XXXMeta.o365_TenantDomain ;
    $AppID = $global:XXXMeta.AAD_App_Audit_ID ;
    $Certificate = $global:XXXmeta.AAD_App_Audit_CertThumb ;
    # leverage the params:
    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose -Verbose:$verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token =get-AADCertToken @pltAADCertToken ; 
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
    Streamlined example
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    #>
    [CmdletBinding()]
    Param(
        [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
        [string]$tenantName = $global:TorMeta.o365_TenantDomain,
        [Parameter(HelpMessage = "AAD AppID [-AppID (guid)]]")]
        [string]$AppID = $global:TORMeta.AAD_App_Audit_I,
        [Parameter(HelpMessage = "Certificate Thumbprint [-Certificate (thumbprint)]]")]
        $Certificate = $global:tormeta.AAD_App_Audit_CertThumb,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ;
    if($Certificate = Get-Item Cert:\CurrentUser\My\$Certificate){ 
        $smsg = "Cert:$($Certificate.thumbprint):`n$(($certificate| fl Subject,DnsNameList,FriendlyName,Not*,Thumbprint|out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        if(((get-date $Certificate.NotBefore) -lt (get-date)) -AND ((get-date) -lt (get-date $Certificate.NotAfter))){
            $smsg = "(cert is in valid date window)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else { 
            $smsg = "$(($Certificate.pspath.tostring() -split '::')[1]) *IS EXPIRED!*`n" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; 
        if(!$MSGraphScope){$MSGraphScope = 'https://graph.microsoft.com'} ; 
        #$Scope = "https://graph.microsoft.com/.default" ;
        $Scope = "$($MSGraphScope)/.default" ;
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) ;
        # Create JWT timestamp for expiration
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime() ;
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0) ;
        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0) ;
        # Create JWT header
        $JWTHeader = @{
            alg = "RS256" ;
            typ = "JWT" ;
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '=' ;
        } ;
        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantName/oauth2/token" ;
            # Expiration timestamp
            exp = $JWTExpiration ;
            # Issuer = your application
            iss = $AppId ;
            # JWT ID: random guid
            jti = [guid]::NewGuid() ;
            # Not to be used before
            nbf = $NotBefore ;
            # JWT Subject
            sub = $AppId ;
        } ;
        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json)) ;
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte) ;
        $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json)) ;
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte) ;
        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + "." + $EncodedPayload ;
        # Get the private key object of your certificate
        if(!$Certificate.PrivateKey){
            $smsg = "Specified Certificate... $($Certificate.thumbprint)`nis *MISSING* its PRIVATE KEY!`nYou must export the key - in PFX format - when moving the cert between hosts & accounts!`n(see get-help $($CmdletName) -detail for sample export code)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            break ; 
        } else { 
            $PrivateKey = $Certificate.PrivateKey ;
            # Define RSA signature and hashing algorithm
            $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1 ;
            $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256 ; 
            # Create a signature of the JWT
            $Signature = [Convert]::ToBase64String(
                $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding) 
            ) -replace '\+','-' -replace '/','_' -replace '=' ;
            # Join the signature to the JWT with "."
            $JWT = $JWT + "." + $Signature ;
            # Create a hash with body parameters
            $Body = @{
                client_id = $AppId ;
                client_assertion = $JWT ;
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ;
                scope = $Scope ;
                grant_type = "client_credentials" ;
            } ;
            $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" ;
            # Use the self-generated JWT as Authorization
            $Header = @{Authorization = "Bearer $JWT" } ;
            $pltPost = @{
                ContentType = 'application/x-www-form-urlencoded' ;
                Method = 'POST' ;
                Body = $Body ;
                Uri = $Url ;
                Headers = $Header ;
            } ;
            $smsg = "Obtain Token:Invoke-RestMethod w`n$(($pltPost|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            $token = Invoke-RestMethod @pltPost ; 
        } ;
    } else { 
        $smsg = "Unable to:Get-Item Cert:\CurrentUser\My\$($Certificate)" 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        Break;
    } ; 

    $smsg = "`$token:`n$(($token|out-string).trim())" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    if ($token -eq $null) {
        $smsg = "ERROR: Failed to get an Access Token" ; ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        break ;
    } else { $token | write-output }
}

#*------^ get-AADCertToken.ps1 ^------

#*------v get-AADLastSync.ps1 v------
Function get-AADLastSync {
  <#
    .SYNOPSIS
    get-AADLastSync - Get specific user's last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Author      : Todd Kadrie
    Website     :	https://www.toddomation.com
    Twitter     :	@tostka
    REVISIONS   :
    * 4:08 PM 7/24/2020 added full multi-ten cred support
    * 1:03 PM 5/27/2020 moved alias: get-MsolLastSync win func
    * 9:51 AM 2/25/2020 condenced output
    * 8:50 PM 1/12/2020 expanded aliases
    * 9:17 AM 10/9/2018 get-AADLastSync:simplified the collection, and built a Cobj returned in GMT & local timezone
    * 12:30 PM 11/3/2017 initial version
    .DESCRIPTION
    get-AADLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-AADLastSync
    .LINK
    #>
    [CmdletBinding()]
    [Alias('get-MsolLastSync')]
    Param([Parameter()]$Credential = $global:credo365TORSID) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
      "Not connected to MSOnline. Now connecting to $($credo365.username.split('@')[1])." ;
      $MFA = get-TenantMFARequirement -Credential $Credential ;
      if($MFA){ Connect-MsolService }
      else {Connect-MsolService -Credential $Credential ;}
    } ;
    $LastDirSyncTime = (Get-MsolCompanyInformation).LastDirSyncTime ;
    New-Object PSObject -Property @{
      TimeGMT   = $LastDirSyncTime  ;
      TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
}

#*------^ get-AADLastSync.ps1 ^------

#*------v get-AADlicensePlanList.ps1 v------
function get-AADlicensePlanList {
    <#
    .SYNOPSIS
    get-AADlicensePlanList - Resolve Get-AzureADSubscribedSku into an indexed hash of Tenant License detailed specs
    .NOTES
    Version     : 1.0.0.1
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-10
    FileName    : get-AADlicensePlanList
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/
    REVISIONS
    * 11:05 AM 9/16/2021 fixed Examples to functional 
    * 2:06 PM 10/12/2020 ported to verb-AAD
    * 9:03 AM 8/10/2020 init
    .DESCRIPTION
    get-AADlicensePlanList - Resolve Get-AzureADSubscribedSku into an indexed hash of Tenant License detailed specs
    .PARAMETER Credential
    Credential to be used for connection
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> $pltGLPList=[ordered]@{
        TenOrg= $TenOrg;
        verbose=$($verbose) ;
        credential=(Get-Variable -name cred$($tenorg) ).value ;
    } ;
    $smsg = "$($tenorg):get-AADlicensePlanList w`n$(($pltGLPList|out-string).trim())" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $objRet = $null ;
    $objRet = get-AADlicensePlanList @pltGLPList ;
    switch ($objRet.GetType().FullName){
        "System.Collections.Hashtable" {
            if( ($objRet|Measure-Object).count ){
                $smsg = "get-AADlicensePlanList:$($tenorg):returned populated LicensePlanList" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $licensePlanListHash = $objRet ; 
            } else {
                $smsg = "get-AADlicensePlanList:$($tenorg):FAILED TO RETURN populated LicensePlanList" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;
        } 
        default {
            $smsg = "get-AADlicensePlanList:$($tenorg):RETURNED UNDEFINED OBJECT TYPE!" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } #Error|Warn|Debug
            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            Exit ; 
        } ; 
    } ;  # SWITCH-E    
    $aadu = get-azureaduser -obj someuser@domain.com ; 
    $userList = $aadu | Select -ExpandProperty AssignedLicenses | Select SkuID  ;
    $userLicenses=@() ;
    $userList | ForEach {
        $sku=$_.SkuId ;
        $userLicenses+=$licensePlanListHash[$sku].SkuPartNumber ;
    } ;
    .LINK
    https://github.com/tostka
    #>
    ##ActiveDirectory, MSOnline, 
    #Requires -Version 3
    ##requires -PSEdition Desktop
    #Requires -Modules AzureAD, verb-Text
    #Requires -RunasAdministrator
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("(lyn|bcc|spb|adl)ms6(4|5)(0|1).(china|global)\.ad\.toro\.com")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Tenant Tag to be processed[-PARAM 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$TenOrg,
        [Parameter(Mandatory=$True,HelpMessage="Credentials [-Credentials [credential object]]")]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(HelpMessage="The ManagedBy parameter specifies an owner for the group [-ManagedBy alias]")]
        $ManagedBy,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug,
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
        [switch] $whatIf=$true
    ) ;
    BEGIN {
        #${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        # Get parameters this function was invoked with
        #$PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        $Verbose = ($VerbosePreference -eq 'Continue') ;
        #$script:PassStatus = $null ;
        #if(!$GroupSpecifications ){$GroupSpecifications = "ENT-SEC-Guest-TargetUsers;AzureAD Guest User Population","ENT-SEC-Guest-BlockedUsers;AzureAD Guest Blocked Users","ENT-SEC-Guest-AlwaysUsers;AzureAD Guest Force-include Users" ; } ;
    } ;
    PROCESS {
        $Error.Clear() ;
        #$ObjReturn=@() ; 
        <#$hshRet=[ordered]@{
            Cred=$null ; 
            credType=$null ; 
        } ; 
        #>
        $smsg = "$($TenOrg):Retrieving licensePlanList..." ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $licensePlanList = $null ; 

        Connect-AAD -Credential:$Credential -verbose:$($verbose) ;

        $error.clear() ;
        TRY {
            $licensePlanList = Get-AzureADSubscribedSku ;
        } CATCH {
            $ErrTrapd=$Error[0] ;
            Start-Sleep -Seconds $RetrySleep ;
            $Exit ++ ;
            $smsg= "Failed to exec cmd because: $($ErrTrapd)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error} ; #Error|Warn
            $smsg= "Try #: $($Exit)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error} ; #Error|Warn
            $script:PassStatus += ";ERROR";
            $smsg= "Unable to exec cmd!" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error} ; #Error|Warn
            Exit ;#Continue/Exit/Stop
        } ; 

        $smsg = "(converting `$licensePlanList to `$licensePlanListHash indexed hash)..." ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        # can't use convert-ObjectToIndexedHash as the key/index is a split version of a property, rather than the entire property
        $swMstr = [Diagnostics.Stopwatch]::StartNew();
        $licensePlanListHash = @{} ;
        foreach($lic in $licensePlanList) {
            # target SKUid is the 2nd half of the SubscribedSKU.objectid, split at the _
            $licensePlanListHash[$lic.objectid.split('_')[1]] = $lic ;
        } ;
    
        $swMstr.Stop() ;
        $smsg = "($(($licensePlanList|measure).count) records converted in $($swMstr.Elapsed.ToString()))" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        # purge the original (reduce mem)
        $licensePlanList = $null ; 
        #now can lookup user AssignedLicense.SKUID's eqiv licName as $licensePlanListHash[$skuid].skupartnumber

    } ;  # PROC-E
    END{
        $licensePlanListHash | write-output ; 
    } ;
}

#*------^ get-AADlicensePlanList.ps1 ^------

#*------v get-AADToken.ps1 v------
function get-AADToken {
    <#
    .SYNOPSIS
    get-AADToken - Retrieve and summarize [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : get-AADToken
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 8:50 AM 3/16/2021 added extra catchblock on expired token, but found that MS had massive concurrent Auth issues, so didn't finish - isolated event, not a normal fail case
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    get-AADToken - Retrieve and summarize [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens
    .EXAMPLE
    $token = get-AADToken ; 
    if( ($null -eq $token) -OR ($token.count -eq 0)){
        # not connected/authenticated
        Connect-AzureAD ; 
    } else { 
        write-verbose "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
    } ; 
    Retrieve and evaluate status of AzureSession token
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param([Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $token = $false ;
        $error.clear() ;
        TRY {
            $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens ; 
            # 3:50 PM 3/15/2021: I'm getting a token, but it's *expired*, need another test - actually MS was having massive auth issues concurrent w the error. Likely transitory
        } CATCH [System.Management.Automation.RuntimeException] {
            # pre connect it throws this
            <#
                Unable to find type [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession].
                At line:1 char:10
                + $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::Access ...
                +          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    + CategoryInfo          : InvalidOperation: (Microsoft.Open....ry.AzureSession:TypeName) [], RuntimeException
                    + FullyQualifiedErrorId : TypeNotFound
            #>
            write-verbose "(No authenticated connection found)"
            #$token = $false ; 
        } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            # reflects unauthenticated
            <#
                At line:2 char:11
            +  $myVar = Get-AzureADTenantDetail
            +           ~~~~~~~~~~~~~~~~~~~~~~~
                + CategoryInfo          : NotSpecified: (:) [Get-AzureADTenantDetail], AadNeedAuthenticationException
                + FullyQualifiedErrorId : Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException,Microsoft.Open.AzureAD16.PowerShell.GetTenantDetails 
            #>
            write-verbose "(requires AAD authentication)"
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ;  
    } ; 
    END{ 
        if($token.count -gt 1){
            write-verbose "(returning $(($token|measure).count) tokens)" ; 
        } ; 
        write-verbose "(Connected to tenant: $($token.AccessToken.TenantId) with user: $($token.AccessToken.UserId)" ; 
        $token | Write-Output 
    } ;
}

#*------^ get-AADToken.ps1 ^------

#*------v get-AADTokenHeaders.ps1 v------
Function get-AADTokenHeaders {
    <#
    .SYNOPSIS
    get-AADTokenHeaders - Construct headers for an Azure access token
    .NOTES
    Version     : 1.0.0
    Author      : Alex Asplund
    Website     :	https://automativity.com
    Twitter     :	@AlexAsplund
    CreatedDate : 2019-08-12
    FileName    : 
    License     :
    Copyright   : 
    Github      : 
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	
    REVISIONS
    * 2019-08-12 posted version 
    .DESCRIPTION
    get-AADTokenHeaders - Construct Azure access token headers
    Uses code Alex Asplund demo'd at link below, wrapped into a func
    .PARAMETER  token
    Token[-Token (token obj)]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a header hashtable
    .EXAMPLE
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Token[-Token (token obj)]")]
        [ValidateNotNullOrEmpty()]$token,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    write-verbose "$((get-date).ToString('HH:mm:ss')):Provided token:`n$(($token|out-string).trim())" ; 
    $Header = @{
        Authorization = "$($token.token_type) $($token.access_token)"
    }
    write-verbose "$((get-date).ToString('HH:mm:ss')):Generated `$Header:`n$(($Header|out-string).trim())" ; 
    $Header | write-output ; 
}

#*------^ get-AADTokenHeaders.ps1 ^------

#*------v get-AADUser.ps1 v------
function get-aaduser {
    <#
    .SYNOPSIS
    get-aaduser.ps1 - query and return Get-AzureADUser (canning up the bp & error handling, to avoid rampant duplication in functions).
    .NOTES
    Version     : 1.0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-12-10
    FileName    : get-aaduser.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-AAD
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 8:35 AM 12/10/2021 init 
    .DESCRIPTION
    get-aaduser.ps1 - query and return Get-AzureADUser (canning up the bp & error handling, to avoid rampant duplication in functions).
    .PARAMETER ObjectId
    Specifies the ID (as a UPN or ObjectId) of a user in Azure AD.[-ObjectID upn@domain.com
    .PARAMETER Filter
    Specifies an oData v3.0 filter statement. This parameter controls which objects are returned. Details on querying wit oData can be found here. http://www.odata.org/documentation/odata-version-3-0/odata-version-3-0-core-protocol/#queryingcollections[-filter 'proxyAddresses/any(c:c eq 'smtp:user@domain.com')'
    .PARAMETER All
    If true, return all users. If false, return the number of objects specified by the Top parameter[-credential [credential obj variable]
    .PARAMETER Top
    Specifies the maximum number of records to return.[-Top 3]
    .PARAMETER Credential
    Credential to use for this connection [-credential [credential obj variable]
    .PARAMETER silent
    Silent output (suppress status echos)[-silent]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .EXAMPLE
    PS> $AADUs = get-aaduser -objectid upn@domain.com -credential $cred
    Example querying a UPN, with a specified credential object
    .EXAMPLE
    PS> $AADUs = get-aaduser -objectid upn@domain.com -credential $cred
    Example querying a UPN, with a specified credential object
    .EXAMPLE
    PS> $AADUs = get-aaduser -filter "proxyAddresses/any(c:c eq 'smtp:user@domain.com')"
    Example querying an OData filter for matches within the proxyAddresses field
    .EXAMPLE
    PS> $AADUs = get-aaduser -filter 'accountEnabled eq false' ; 
    Example querying an OData filter for AAD disabled accounts
    .EXAMPLE
    PS> $AADUs = get-aaduser -filter "contains(CompanyName,'Alfreds')" ; 
    Example querying an OData filter for Company field containing the specified substring (e.g. 'like')
    .LINK
    https://github.com/tostka/verb-AAD
    .LINK
    #>
    ###Requires -Version 5
    #Requires -Modules MSOnline, AzureAD, verb-Text, verb-IO
    #Requires -RunasAdministrator
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("(lyn|bcc|spb|adl)ms6(4|5)(0|1).(china|global)\.ad\.toro\.com")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ##[Alias('somealias')]
    PARAM(
        [Parameter(ParameterSetName='Obj',Position=0,Mandatory=$False,ValueFromPipeline=$true,HelpMessage="Specifies the ID (as a UPN or ObjectId) of a user in Azure AD.[-ObjectID upn@domain.com")]
        #[ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string[]]$ObjectId,
        [Parameter(ParameterSetName='Filter',Mandatory=$False,HelpMessage="Specifies an oData v3.0 filter statement. This parameter controls which objects are returned. Details on querying wit oData can be found here. http://www.odata.org/documentation/odata-version-3-0/odata-version-3-0-core-protocol/#queryingcollections[-filter 'proxyAddresses/any(c:c eq 'smtp:user@domain.com')'")]
        #[ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$Filter,
        [Parameter(ParameterSetName='All',HelpMessage = "If true, return all users. If false, return the number of objects specified by the Top parameter[-credential [credential obj variable]")]
        [boolean]$All,
        [Parameter(HelpMessage = "Specifies the maximum number of records to return.[-Top 3]")]
        [boolean]$Top = 25,
        [Parameter(HelpMessage = "Credential to use for this connection [-credential [credential obj variable]")]
        [System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    
    <# #-=-=-=MUTUALLY EXCLUSIVE PARAMS OPTIONS:-=-=-=-=-=
# designate a default paramset, up in cmdletbinding line
[CmdletBinding(DefaultParameterSetName='SETNAME')]
  # * set blank, if none of the sets are to be forced (eg optional mut-excl params)
  # * force exclusion by setting ParameterSetName to a diff value per exclusive param

# example:single $Computername param with *multiple* ParameterSetName's, and varying Mandatory status per set
    [Parameter(ParameterSetName='LocalOnly', Mandatory=$false)]
    $LocalAction,
    [Parameter(ParameterSetName='Credential', Mandatory=$true)]
    [Parameter(ParameterSetName='NonCredential', Mandatory=$false)]
    $ComputerName,
    # $Credential as tied exclusive parameter
    [Parameter(ParameterSetName='Credential', Mandatory=$false)]
    $Credential ;    
    # effect: 
    -computername is mandetory when credential is in use
    -when $localAction param (w localOnly set) is in use, neither $Computername or $Credential is permitted
    write-verbose -verbose:$verbose "ParameterSetName:$($PSCmdlet.ParameterSetName)"
    Can also steer processing around which ParameterSetName is in force:
    if ($PSCmdlet.ParameterSetName -eq 'LocalOnly') {
        return "some localonly stuff" ; 
    } ;    
# 
#-=-reports on which parameters can be used in each parameter set.=-=-=-=-=-=-=
(gcm SCRIPT.ps1).ParameterSets | Select-Object -Property @{n='ParameterSetName';e={$_.name}}, @{n='Parameters';e={$_.ToString()}} ;
#-=-=-=-=-=-=-=-=
#>
    BEGIN{
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        $MaxRecips = 25 ; # max number of objects to permit on a return resultsize/,ResultSetSize, to prevent empty set return of everything in the addressspace

        $pltCAAD=[ordered]@{
            Credential= $Credential ;
            silent =:$($silent) ;
            verbose = $($VerbosePreference -eq "Continue") ;
        } ;
 
        Connect-AAD @pltCAAD ; 
        
        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        }
        else {
            write-verbose "Data received from parameter input: '$($InputObject)'" ; 
        }
    } 
    # loop bound pipeline elements in process{}
    PROCESS{
        $Error.Clear() ; 
        $pltCAAD.silent = $false ;  # suppress looping reconnect echos
        # foreach -objectid named-params in foreach
        foreach($id in $objectid) {
            
            # put your real processing in here, and assume everything that needs to happen per loop pass is within this section.
            # that way every pipeline or named variable param item passed will be processed through. 
            $error.clear() ;
            TRY {
                Connect-AAD @pltCAAD ; 
                write-verbose "OPRcp:Mailuser, ensure GET-ADUSER pulls AADUser.matched object for cloud recipient:`nfallback:get-AzureAdUser  -objectid $($hsum.xoRcp.ExternalDirectoryObjectId)" ;
                # have to postfilter, if want specific count -maxresults catch's with no $error[0]
                $pltGaadu=[ordered]@{
                    ErrorAction = 'STOP' ;
                } ; 
                if($objectID){ pltGaadu.add('objectid',$id)}  ;
                if($filter){ pltGaadu.add('filter',$filter)}  ;
                if($all){ pltGaadu.add('All',$true)}  ;
                $smsg = "get-AzureAdUser w`n$(($pltGaadu|out-string).trim())" ; 
                if($silent){} else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ; 
                if(-not $All -OR ($Top -ne $MaxRecips)){
                    # run unrestricted, or solely restricted by -Top
                    $returns = get-AzureAdUser  @pltGaadu ;
                } else {
                    $returns= get-AzureAdUser  @pltGaadu | select -first $MaxRecips;  ;
                } ; 
                if($returns){
                    $smsg = "(returning $(($results|measure).count) matched results to pipeline)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    $aadu | write-output ; 
                } else {
                    $smsg = "(no matching results found!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } ; 
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
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
        } ; # foreach($id in $objectid) 
    } ;  # if-E PROC
    END{}
}

#*------^ get-AADUser.ps1 ^------

#*------v Get-DsRegStatus .ps1 v------
function Get-DsRegStatus {
    <#
    .SYNOPSIS
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject. 
    .NOTES
    Version     : 0.1.17
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / ttps://github.com/tostka/verb-aad
    CreatedDate : 2021-06-23
    FileName    : Get-DsRegStatus
    License     : (none asserted)
    Copyright   : (c) 2019 Thomas Kurth. All rights reserved.
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Thomas Kurth
    AddedWebsite: https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions/Get-DsRegStatus.ps1
    AddedTwitter: 
    REVISIONS
    * 9:15 AM 6/28/2021 updated CBH
    * 9:54 AM 6/23/2021 added to verb-aad
    * 12:21 PM 8/8/2020 init; added CBH
    .DESCRIPTION
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject. 
    Returns the output of dsregcmd /status as a PSObject. All returned values are accessible by their property name.
    Lifted from [PowerShell Gallery | Functions/Get-DsRegStatus.ps1 0.1.3 - www.powershellgallery.com/](https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions%5CGet-DsRegStatus.ps1)
    Alt to manual cmdline parsing:
    ```powershell
    $results = dsregcmd /status;
    $results|sls azureadjoined ; $results | sls domainjoined ; $results | sls workplacejoined ;
    ```
    Or remote exec: 
    ```powershell
     Invoke-Command -ComputerName MyComputerName -ScriptBlock {dsregcmd /status}
    ```
    .OUTPUTS
    List of the information in the token cache. 
    .Example
    Get-DsRegStatus 
    Displays a full output of dsregcmd / status.
    .LINK
    https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions%5CGet-DsRegStatus.ps1
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param() ;
    PROCESS {
        $dsregcmd = dsregcmd /status
        $o = New-Object -TypeName PSObject
        foreach($line in $dsregcmd){
            if($line -like "| *"){
                 if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
                      Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
                 }
                 $currentSection = $line.Replace("|","").Replace(" ","").Trim()
                 $so = New-Object -TypeName PSObject
            } elseif($line -match " *[A-z]+ : [A-z0-9\{\}]+ *"){
                 Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
            }
        }
        if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
            Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
        }
        return $o
    } ; 
}

#*------^ Get-DsRegStatus .ps1 ^------

#*------v Get-MsolDisabledPlansForSKU.ps1 v------
Function Get-MsolDisabledPlansForSKU {
    <#
    .SYNOPSIS
    Get-MsolDisabledPlansForSKU - AzureAD produces a list of disabled service plan names for a set of plans we want to leave enabled.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolDisabledPlansForSKU.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 8:17 AM 8/18/2021 populated example
    * 9:23 AM 4/27/2021 renamed 'GetDisabledPlansForSKU()' -> Get-MsolDisabledPlansForSKU; put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolDisabledPlansForSKU - AzureAD produces a list of disabled service plan names for a set of plans we want to leave enabled.
    .PARAMETER  skuId
    .PARAMETER enabledPlans
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    $disabledplans = Get-MsolDisabledPlansForSKU -skuid $skuid -enabledplans $enabledplans ; 
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [string]$skuId, 
        [string[]]$enabledPlans
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        $allPlans = Get-MsolAccountSku | where {$_.AccountSkuId -ieq $skuId} | Select -ExpandProperty ServiceStatus | Where {$_.ProvisioningStatus -ine "PendingActivation" -and $_.ServicePlan.TargetClass -ieq "User"} | Select -ExpandProperty ServicePlan | Select -ExpandProperty ServiceName ; 
        $disabledPlans = $allPlans | Where {$enabledPlans -inotcontains $_} ; 
        return $disabledPlans
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ Get-MsolDisabledPlansForSKU.ps1 ^------

#*------v Get-MsolUnexpectedEnabledPlansForUser.ps1 v------
Function Get-MsolUnexpectedEnabledPlansForUser {
    <#
    .SYNOPSIS
    Get-MsolUnexpectedEnabledPlansForUser - AzureAD produces a list of enabled service plan names that are not present in the list specified by the -expectedDisabledPlans param.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolUnexpectedEnabledPlansForUser.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed 'GetDisabledPlansForSKU()' -> Get-MsolUnexpectedEnabledPlansForUser; put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolUnexpectedEnabledPlansForUser - AzureAD produces a list of enabled service plan names that are not present in the list specified by the -expectedDisabledPlans param.
    .PARAMETER  user
    .PARAMETER skuId
    .PARAMETER expectedDisabledPlans
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $extraPlans = Get-MsolUnexpectedEnabledPlansForUser $user $skuId $expectedDisabledPlans ; 
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Microsoft.Online.Administration.User]$user, 
        [string]$skuId, 
        [string[]]$expectedDisabledPlans
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        $license = Get-MsolUserLicense $user $skuId ;
        $extraPlans = @();
        if($license -ne $null){
            $userDisabledPlans = $license.ServiceStatus | where {$_.ProvisioningStatus -ieq "Disabled"} | Select -ExpandProperty ServicePlan | Select -ExpandProperty ServiceName ;
            $extraPlans = $expectedDisabledPlans | where {$userDisabledPlans -notcontains $_} ;
        } ;
        return $extraPlans ;
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ Get-MsolUnexpectedEnabledPlansForUser.ps1 ^------

#*------v get-MsolUserLastSync.ps1 v------
Function get-MsolUserLastSync {
    <#
    .SYNOPSIS
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 5:17 PM 8/5/2020 strong-typed Credential
    * 4:21 PM 7/24/2020 added verbose
    * 9:51 AM 2/25/2020 condenced output
    * 8:50 PM 1/12/2020 expanded aliases
    * 11:23 AM 10/18/2018 ported from get-MsolUserLastSync()
    .DESCRIPTION
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLastSync
    .LINK
    #>
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "MSolUser UPN")][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        write-verbose -verbose:$true "$((get-date).ToString('HH:mm:ss')):Not connected to MSOnline. Now connecting." ;
        Connect-MsolService -credential $Credential ;
    } ;
    $LastDirSyncTime = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
    New-Object PSObject -Property @{
        TimeGMT   = $LastDirSyncTime  ;
        TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
}

#*------^ get-MsolUserLastSync.ps1 ^------

#*------v Get-MsolUserLicense.ps1 v------
Function Get-MsolUserLicense {
    <#
    .SYNOPSIS
    Get-MsolUserLicense - AzureAD Returns the license object corresponding to the skuId. Returns NULL if not found.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolUserLicense.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 8:14 AM 8/18/2021 cbh: populated example
    * 9:23 AM 4/27/2021 renamed 'GetUserLicense()' -> Get-MsolUserLicense(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolUserLicense - AzureAD Returns the license object corresponding to the skuId. Returns NULL if not found.
    .PARAMETER user, 
    .PARAMETER groupId
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    $license = Get-MsolUserLicense $user $skuId ;
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Microsoft.Online.Administration.User]$user,
        [string]$skuId, [Guid]$groupId
    )
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        #we look for the specific license SKU in all licenses assigned to the user
        foreach($license in $user.Licenses) {
            if ($license.AccountSkuId -ieq $skuId){return $license } ; 
        } ; 
        return $null ; 
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ Get-MsolUserLicense.ps1 ^------

#*------v get-MsolUserLicenseDetails.ps1 v------
Function get-MsolUserLicenseDetails {
    <#
    .SYNOPSIS
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Based on work by :Brad Wyatt
    Website: https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    REVISIONS   :
    * 11:01 AM 9/16/2021 cleaned up stings
    * 1:24 PM 8/20/2020 added a raft from the guest work, including collab-related items fr https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference
    * 5:17 PM 8/5/2020 strong-typed Credential
    * 4:22 PM 7/24/2020 added verbose
    * 8:50 PM 1/12/2020 expanded aliases
    # 11:13 AM 1/9/2019: SPE_F1 isn't in thlist, 'SPE'=="Secure Productive Enterprise (SPE) Licensing Bundle"
    # 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    * 12:00 PM 1/9/2019 replaced broken aggreg with simpler cobj -prop $hash set, now returns proper mult lics
    * 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    * 11:33 AM 1/9/2019 add SPE_F1 lic spec, and export the aggreg, NewObject02 was never more than a single lic (eg. support mult lics)
    * 3:47 PM 12/7/2018 works in prod for single-licenses users, haven't tested on multis yet.
    * 3:17 PM 12/7/2018 added showdebug, updated pshelp
    * 2:58 PM 12/7/2018 initial version
    .DESCRIPTION
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    Based on the core lic hash & lookup code in Brad's "Get Friendly License Name for all Users in Office 365 Using PowerShell" script
    .PARAMETER UPNs
    Array of Userprincipalnames to be looked up
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLicenseDetails -UPNs fname.lname@domain.com ;
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = get-MsolUserLicenseDetails -UPNs $exombx.userprincipalname -showdebug:$($showdebug)
    Retrieve MSOL License details on specified UPN, with showdebug specified
    .LINK
    https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    #>
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "An array of MSolUser objects")][ValidateNotNullOrEmpty()]
        [string]$UPNs,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")][switch] $showDebug
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ;
    $Retries = 4 ;
    $RetrySleep = 5 ;
    #Connect-AAD ;
    # 2:45 PM 11/15/2019
    Connect-Msol ;

    # [Product names and service plan identifiers for licensing in Azure Active Directory | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference)

    <# whatis an F1 lic: Office 365 F1 is designed to enable Firstline Workers to do their best work.
    Office 365 F1 provides easy-to-use tools and services to help these workers
    easily create, update, and manage schedules and tasks, communicate and work
    together, train and onboard, and quickly receive company news and announcements.
    #>

    # updating sort via text: gc c:\tmp\list.txt | sort ;
    $Sku = @{
        "AAD_BASIC"                          = "Azure Active Directory Basic"
        "AAD_PREMIUM"                        = "Azure Active Directory Premium"
        "ATA"                                = "Advanced Threat Analytics"
        "ATP_ENTERPRISE"                     = "Exchange Online Advanced Threat Protection"
        "BI_AZURE_P1"                        = "Power BI Reporting and Analytics"
        "CRMIUR"                             = "CMRIUR"
        "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
        "DESKLESSPACK"                       = "Office 365 (Plan K1)"
        "DESKLESSPACK_GOV"                   = "Microsoft Office 365 (Plan K1) for Government"
        "DESKLESSWOFFPACK"                   = "Office 365 (Plan K2)"
        "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
        "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
        "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
        "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
        "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
        "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
        "ECAL_SERVICES"                      = "ECAL"
        "EMS"                                = "Enterprise Mobility Suite"
        "ENTERPRISEPACK"                     = "Enterprise Plan E3"
        "ENTERPRISEPACK_B_PILOT"             = "Office 365 (Enterprise Preview)"
        "ENTERPRISEPACK_FACULTY"             = "Office 365 (Plan A3) for Faculty"
        "ENTERPRISEPACK_GOV"                 = "Microsoft Office 365 (Plan G3) for Government"
        "ENTERPRISEPACK_STUDENT"             = "Office 365 (Plan A3) for Students"
        "ENTERPRISEPACKLRG"                  = "Enterprise Plan E3"
        "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
        "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
        "ENTERPRISEWITHSCAL"                 = "Enterprise Plan E4"
        "ENTERPRISEWITHSCAL_FACULTY"         = "Office 365 (Plan A4) for Faculty"
        "ENTERPRISEWITHSCAL_GOV"             = "Microsoft Office 365 (Plan G4) for Government"
        "ENTERPRISEWITHSCAL_STUDENT"         = "Office 365 (Plan A4) for Students"
        "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
        "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
        "ESKLESSWOFFPACK_GOV"                = "Microsoft Office 365 (Plan K2) for Government"
        "EXCHANGE_L_STANDARD"                = "Exchange Online (Plan 1)"
        "EXCHANGE_S_ARCHIVE_ADDON_GOV"       = "Exchange Online Archiving"
        "EXCHANGE_S_DESKLESS"                = "Exchange Online Kiosk"
        "EXCHANGE_S_DESKLESS_GOV"            = "Exchange Kiosk"
        "EXCHANGE_S_ENTERPRISE_GOV"          = "Exchange Plan 2G"
        "EXCHANGE_S_ESSENTIALS"              = "Exchange Online Essentials   "
        "EXCHANGE_S_STANDARD_MIDMARKET"      = "Exchange Online (Plan 1)"
        "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
        "EXCHANGEDESKLESS"                   = "Exchange Online Kiosk"
        "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
        "EXCHANGEENTERPRISE_GOV"             = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
        "EXCHANGEESSENTIALS"                 = "Exchange Online Essentials"
        "EXCHANGESTANDARD"                   = "Office 365 Exchange Online Only"
        "EXCHANGESTANDARD_GOV"               = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
        "EXCHANGESTANDARD_STUDENT"           = "Exchange Online (Plan 1) for Students"
        "FLOW_FREE"                          = "Microsoft Flow Free"
        "FLOW_P1"                            = "Microsoft Flow Plan 1"
        "FLOW_P2"                            = "Microsoft Flow Plan 2"
        "INTUNE_A"                           = "Windows Intune Plan A"
        "LITEPACK"                           = "Office 365 (Plan P1)"
        "LITEPACK_P2"                        = "Office 365 Small Business Premium"
        "M365_F1"                            = "Microsoft 365 F1"
        "MCOEV"                              = "Microsoft Phone System"
        "MCOLITE"                            = "Lync Online (Plan 1)"
        "MCOMEETACPEA"                       = "Pay Per Minute Audio Conferencing"
        "MCOMEETADD"                         = "Audio Conferencing"
        "MCOMEETADV"                         = "PSTN conferencing"
        "MCOPSTN1"                           = "Domestic Calling Plan (3000 min US / 1200 min EU plans)"
        "MCOPSTN2"                           = "International Calling Plan"
        "MCOPSTN5"                           = "Domestic Calling Plan (120 min calling plan)"
        "MCOPSTN6"                           = "Domestic Calling Plan (240 min calling plan) Note: Limited Availability"
        "MCOPSTNC"                           = "Communications Credits"
        "MCOPSTNPP"                          = "Communications Credits"
        "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
        "MCOSTANDARD_GOV"                    = "Lync Plan 2G"
        "MCOSTANDARD_MIDMARKET"              = "Lync Online (Plan 1)"
        "MFA_PREMIUM"                        = "Azure Multi-Factor Authentication"
        "MIDSIZEPACK"                        = "Office 365 Midsize Business"
        "MS_TEAMS_IW"                        = "Microsoft Teams Trial"
        "O365_BUSINESS"                      = "Office 365 Business"
        "O365_BUSINESS_ESSENTIALS"           = "Office 365 Business Essentials"
        "O365_BUSINESS_PREMIUM"              = "Office 365 Business Premium"
        "OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ" = "Office ProPlus"
        "OFFICESUBSCRIPTION"                 = "Office ProPlus"
        "OFFICESUBSCRIPTION_GOV"             = "Office ProPlus"
        "OFFICESUBSCRIPTION_STUDENT"         = "Office ProPlus Student Benefit"
        "PLANNERSTANDALONE"                  = "Planner Standalone"
        "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
        "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
        "POWER_BI_PRO"                       = "Power BI Pro"
        "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
        "POWER_BI_STANDARD"                  = "Power-BI Standard"
        "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
        "PROJECTCLIENT"                      = "Project Professional"
        "PROJECTESSENTIALS"                  = "Project Lite"
        "PROJECTONLINE_PLAN_1"               = "Project Online"
        "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
        "ProjectPremium"                     = "Project Online Premium"
        "PROJECTPROFESSIONAL"                = "Project Professional"
        "PROJECTWORKMANAGEMENT"              = "Office 365 Planner Preview"
        "RIGHTSMANAGEMENT"                   = "Rights Management"
        "RIGHTSMANAGEMENT_ADHOC"             = "Windows Azure Rights Management"
        "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
        "RMS_S_ENTERPRISE_GOV"               = "Windows Azure Active Directory Rights Management"
        "SHAREPOINTDESKLESS"                 = "SharePoint Online Kiosk"
        "SHAREPOINTDESKLESS_GOV"             = "SharePoint Online Kiosk"
        "SHAREPOINTENTERPRISE"               = "Sharepoint Online (Plan 2)"
        "SHAREPOINTENTERPRISE_GOV"           = "SharePoint Plan 2G"
        "SHAREPOINTENTERPRISE_MIDMARKET"     = "SharePoint Online (Plan 1)"
        "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
        "SHAREPOINTSTANDARD"                 = "Sharepoint Online (Plan 1)"
        "SHAREPOINTSTORAGE"                  = "SharePoint storage"
        "SHAREPOINTWAC"                      = "Office Online"
        "SHAREPOINTWAC_GOV"                  = "Office Online for Government"
        "SMB_BUSINESS"                       = "Microsoft 365 Apps For Business"
        "SMB_BUSINESS_ESSENTIALS"            = "Microsoft 365 Business Basic       "
        "SMB_BUSINESS_PREMIUM"               = "Microsoft 365 Business Standard"
        "SPB"                                = "Microsoft 365 Business Premium"
        "SPE_E3"                             = "Microsoft 365 E3"
        "SPE_E5"                             = "Microsoft 365 E5"
        "SPE_F1"                             = "Office 365 F1"
        "SPZA_IW"                            = "App Connect"
        "STANDARD_B_PILOT"                   = "Office 365 (Small Business Preview)"
        "STANDARDPACK"                       = "Enterprise Plan E1"
        "STANDARDPACK_FACULTY"               = "Office 365 (Plan A1) for Faculty"
        "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
        "STANDARDPACK_STUDENT"               = "Office 365 (Plan A1) for Students"
        "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
        "STANDARDWOFFPACK_FACULTY"           = "Office 365 Education E1 for Faculty"
        "STANDARDWOFFPACK_GOV"               = "Microsoft Office 365 (Plan G2) for Government"
        "STANDARDWOFFPACK_IW_FACULTY"        = "Office 365 Education for Faculty"
        "STANDARDWOFFPACK_IW_STUDENT"        = "Office 365 Education for Students"
        "STANDARDWOFFPACK_STUDENT"           = "Microsoft Office 365 (Plan A2) for Students"
        "STANDARDWOFFPACKPACK_FACULTY"       = "Office 365 (Plan A2) for Faculty"
        "STANDARDWOFFPACKPACK_STUDENT"       = "Office 365 (Plan A2) for Students"
        "TEAMS_COMMERCIAL_TRIAL"             = "Teams Commercial Trial"
        "TEAMS_EXPLORATORY"                  = "Teams Exploratory"
        "VIDEO_INTEROP"                      = "Polycom Skype Meeting Video Interop for Skype for Business"
        "VISIOCLIENT"                        = "Visio Pro Online"
        "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
        "WINDOWS_STORE"                      = "Windows Store for Business"
        "YAMMER_ENTERPRISE"                  = "Yammer for the Starship Enterprise"
        "YAMMER_MIDSIZE"                     = "Yammer"
    }

    Foreach ($User in $UPNs) {
        if ($showdebug) { write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Getting all licenses for $($User)..."  ; } ;

        $Exit = 0 ;
        Do {
            Try {
                $MsolU = Get-MsolUser -UserPrincipalName $User ;
                $Licenses = $MsolU.Licenses.AccountSkuID
                $Exit = $Retries ;
            } Catch {
                Start-Sleep -Seconds $RetrySleep ;
                $Exit ++ ;
                Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                Write-Verbose "Try #: $Exit" ;
                If ($Exit -eq $Retries) { Write-Warning "Unable to exec cmd!" } ;
            }  ;
        } Until ($Exit -eq $Retries) ;

        $AggregLics = $null
        $AggregLics = @() ;
        If (($Licenses).Count -gt 1) {
            Foreach ($License in $Licenses) {
                if ($showdebug) { Write-Host "Finding $License in the Hash Table..." -ForegroundColor White }
                $LicenseItem = $License -split ":" | Select-Object -Last 1
                $TextLic = $Sku.Item("$LicenseItem")
                If (!($TextLic)) {
                    $smsg = "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!"
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error }
                    else { write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $LicenseFallBackName = $License.AccountSkuId

                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName         = $MsolU.DisplayName ;
                        UserPrincipalName   = $MsolU.Userprincipalname
                        LicAccountSkuID     = $License
                        LicenseFriendlyName = $LicenseFallBackName
                    };
                    $AggregLics += $LicSummary ;

                } Else {
                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName         = $MsolU.DisplayName
                        UserPrincipalName   = $MsolU.Userprincipalname
                        LicAccountSkuID     = $License
                        LicenseFriendlyName = $TextLic
                    };
                    $AggregLics += $LicSummary ;
                } # if-E
            } # loop-E
        } Else {
            if ($showdebug) { Write-Host "Finding $Licenses in the Hash Table..." -ForegroundColor White } ;
            $Exit = 0 ;
            Do {
                Try {
                    #$LicenseItem = ((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID -split ":" | Select-Object -Last 1
                    $LicenseID = ((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID
                    $LicenseItem = $LicenseID -split ":" | Select-Object -Last 1
                    $Exit = $Retries ;
                } Catch {
                    Start-Sleep -Seconds $RetrySleep ;
                    $Exit ++ ;
                    Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                    Write-Verbose "Try #: $Exit" ;
                    If ($Exit -eq $Retries) { Write-Warning "Unable to exec cmd!" } ;
                }  ;
            } Until ($Exit -eq $Retries) ;
            $TextLic = $Sku.Item("$LicenseItem")
            If (!($TextLic)) {
                $smsg = "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!"
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error }
                else { write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $LicenseFallBackName = $License.AccountSkuId
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName         = $MsolU.DisplayName
                    UserPrincipalName   = $MsolU.Userprincipalname
                    LicAccountSkuID     = $LicenseID
                    LicenseFriendlyName = $LicenseFallBackName
                };
                $AggregLics += $LicSummary ;
            } Else {
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName         = $MsolU.DisplayName
                    UserPrincipalName   = $MsolU.Userprincipalname
                    LicAccountSkuID     = $LicenseID
                    LicenseFriendlyName = "$TextLic"
                };
                $AggregLics += $LicSummary ;
            }
        } # if-E
    } # loop-E

    $AggregLics | write-output ; # 11:33 AM 1/9/2019 export the aggreg, NewObject02 was never more than a single lic
}

#*------^ get-MsolUserLicenseDetails.ps1 ^------

#*------v Get-ServiceToken.ps1 v------
function Get-ServiceToken {
    <#
    .SYNOPSIS
    Get-ServiceToken - Get a token for a given Microsoft Cloud Service 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Get-ServiceToken
    License     : MIT License
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Get-ServiceToken - Get a token for a given Microsoft Cloud Service 
    Returns an ADAL token for a given Microsoft Cloud Service
    Will attempt to acquire the token silently (refresh) if possible 
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    # References https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/AcquireTokenSilentAsync-using-a-cached-token
     https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/tree/adalv3/dev
    .OUTPUTS
    Returns a token object for the requested cloud service
    .EXAMPLE
    Get-ServiceToken -Service EXO
    Returns a token for the Exchange Online Service.
    .LINK
    https://github.com/Canthv0/CloudAuthModule 
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateSet("EXO","AzureGraph")]
        [string]
        $Service
    ) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        # Ensure our ADAL types are loaded and availble
        Add-ADALType ; 

        switch ($Service) {
            exo {
                # EXO Powershell Client ID
                $clientId = "a0c73c16-a7e3-4564-9a95-2bdf47383716"  ; 
                # Set redirect URI for PowerShell
                $redirectUri = "urn:ietf:wg:oauth:2.0:oob" ; 
                # Set Resource URI to EXO endpoint
                $resourceAppIdURI = "https://outlook.office365.com" ; 
                # Set Authority to Azure AD Tenant
                $authority = "https://login.windows.net/common" ; 
            } ; 
            AzureGraph {
                # Azure PowerShell Client ID
                $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" ; 
                # Set redirect URI for PowerShell
                $redirectUri = "urn:ietf:wg:oauth:2.0:oob" ; 
                # Set Resource URI to EXO endpoint
                $resourceAppIdURI = "https://graph.windows.net" ; 
                # Set Authority to Azure AD Tenant
                $authority = "https://login.windows.net/common"             ; 
            } ; 
            Default { Write-Error "Service Not Implemented" -ErrorAction Stop } ; 
        } ; 

        # Create AuthenticationContext tied to Azure AD Tenant
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority ; 

        # Create platform Options, we want it to prompt if it needs to.
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always" ; 

        # Acquire token, this will place it in the token cache
        # $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters)

        Write-Debug "Looking in token cache" ; 
        $Result = $authContext.AcquireTokenSilentAsync($resourceAppIdURI, $clientId) ; 

        while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "silent sleep" }

        # Check if we failed to get the token
        if (!($Result.IsFaulted -eq $false)) {
             
            Write-Debug "Acquire token silent failed" ; 
            switch ($Result.Exception.InnerException.ErrorCode) {
                failed_to_acquire_token_silently { 
                    # do nothing since we pretty much expect this to fail
                    Write-Information "Cache miss, asking for credentials" ; 
                    $Result = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters) ; 
                    
                    while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "sleep" }
                } ; 
                multiple_matching_tokens_detected {
                    # we could clear the cache here since we don't have a UPN, but we are just going to move on to prompting
                    Write-Information "Multiple matching entries found, asking for credentials" ; 
                    $Result = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters) ; 
                    
                    while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "sleep" }
                } ; 
                Default { Write-Error -Message "Unknown Token Error $Result.Exception.InnerException.ErrorCode" -ErrorAction Stop } ; 
            } ; 
        }    ; 

        Return $Result ; 
    } ;  # PROC-E
    END{} ;
}

#*------^ Get-ServiceToken.ps1 ^------

#*------v Get-TokenCache.ps1 v------
function Get-TokenCache {
    <#
    .SYNOPSIS
    Get-TokenCache - Returns the current contents of the token cache 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Get-TokenCache
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 1:58 PM 6/16/2021 fixed typo (spurious ;)
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Get-TokenCache - Returns the current contents of the token cache 
    Returns basic properties about the objects currently in the token cache.
    Returns the local time that the token will expire. 
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    .OUTPUTS
    List of the information in the token cache. 
    .EXAMPLE
    Get-TokenCache
    Displays the information currently in the token cache. 
    .LINK
    https://github.com/Canthv0/CloudAuthModule 
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param() ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        # Ensure our ADAL types are loaded and availble
        Add-ADALType ;
        $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared ;
        if ($full){
            Return $Cache.ReadItems() ;
        } else {
            $cache.ReadItems() | Select-Object DisplayableId, Authority, ClientId, Resource, @{Name = "ExpiresOn"; Expression = { $_.ExpiresOn.localdatetime } } ;
        } ;
    } ; 
    END{} ;
}

#*------^ Get-TokenCache.ps1 ^------

#*------v Initialize-AADSignErrorsHash.ps1 v------
function Initialize-AADSignErrorsHash {
    <#
    .SYNOPSIS
    Initialize-AADSignErrorsHash - Builds a hash object containing AzureAD Sign-on Error codes & matching description
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-06-15
    FileName    : Initialize-AADSignErrorsHash.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-AAD
    Tags        : Powershell,AzureAD,Errors,Reference
    AddedCredit : Sign-in activity report error codes in the Azure Active Directory portal
    AddedWebsite: https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
    AddedTwitter: URL
    REVISIONS   :
    * 11:01 AM 6/15/2021 Ren'd Build-AADSignErrorsHash -> Initialize-AADSignErrorsHash (compliant verb) ; copied over vers from profile-AAD-Signons.ps1 ; kept updated CBH. 
    * 8:50 PM 1/12/2020 expanded aliases
    * 9:53 AM 8/29/2019 amended 50135, 50125, with MS support comments, and reserached 50140 a bit
    * 2:49 PM 8/27/2019 updated errornumber 0 to be (undocumented - successful), as it is the code on a non-error logon
    * 10:41 AM 5/13/2019 init vers
    .DESCRIPTION
    Build-AADSignErrorsHas.ps1 - Builds a hash object containing AzureAD Sign-on Error codes & matching description: [Sign-in activity report error codes in the Azure Active Directory portal | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a populated hashtable of AAD signon error codes & descriptions
    .EXAMPLE
    $AADSignOnErrors = Initialize-AADSignErrorsHash ; 
    $ErrDetail = $AADSignOnErrors[$errorCode] ; 
    Populate hash and lookup errorcode
    .LINK
    https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
    #>
    [CmdletBinding()]
    [Alias('Build-AADSignErrorsHash')]
    PARAM() ;
     #Error 	Description
    $AADSignOnError = [ordered]@{ } ;
    $AADSignOnError.add("0", "(undocumented - ((Successful)))") ;
    $AADSignOnError.add("16000", "This is an internal implementation detail and not an error condition. You can safely ignore this reference.") ;
    $AADSignOnError.add("20001", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("20012", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("20033", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40008", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40009", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40014", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("50000", "There is an issue with our sign-in service. Open a support ticket to resolve this issue.") ;
    $AADSignOnError.add("50001", "The service principal name was not found in this tenant. This can happen if the application has not been installed by the administrator of the tenant, or if the resource principal was not found in the directory or is invalid.") ;
    $AADSignOnError.add("50002", "Sign-in failed due to restricted proxy access on tenant. If its your own tenant policy, you can change your restricted tenant settings to fix this issue.") ;
    $AADSignOnError.add("50003", "Sign-in failed due to missing signing key or certificate. This might be because there was no signing key configured in the application. Check out the resolutions outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#certificate-or-key-not-configured. If the issue persists, contact the application owner or the application administrator.") ;
    $AADSignOnError.add("50005", "User tried to login to a device from a platform thats currently not supported through conditional access policy.") ;
    $AADSignOnError.add("50006", "Signature verification failed due to invalid signature. Check out the resolution outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery. If the issue persists, contact the application owner or application administrator.") ;
    $AADSignOnError.add("50007", "Partner encryption certificate was not found for this application. Open a support ticket with Microsoft to get this fixed.") ;
    $AADSignOnError.add("50008", "SAML assertion is missing or misconfigured in the token. Contact your federation provider.") ;
    $AADSignOnError.add("50010", "Audience URI validation for the application failed since no token audiences were configured. Contact the application owner for resolution.") ;
    $AADSignOnError.add("50011", "The reply address is missing, misconfigured, or does not match reply addresses configured for the application. Try the resolution listed at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#the-reply-address-does-not-match-the-reply-addresses-configured-for-the-application. If the issue persists, contact the application owner or application administrator.") ;
    $AADSignOnError.add("50012", "This is a generic error message that indicates that authentication failed. This can happen for reasons such as missing or invalid credentials or claims in the request. Ensure that the request is sent with the correct credentials and claims.") ;
    $AADSignOnError.add("50013", "Assertion is invalid because of various reasons. For instance, the token issuer doesnt match the api version within its valid time range, the token is expired or malformed, or the refresh token in the assertion is not a primary refresh token.") ;
    $AADSignOnError.add("50017", "Certification validation failed, reasons for the following reasons:, Cannot find issuing certificate in trusted certificates list , Unable to find expected CrlSegment , Cannot find issuing certificate in trusted certificates list , Delta CRL distribution point is configured without a corresponding CRL distribution point , Unable to retrieve valid CRL segments due to timeout issue , Unable to download CRL , Contact the tenant administrator.") ;
    $AADSignOnError.add("50020", "The user is unauthorized for one of the following reasons. The user is attempting to login with an MSA account with the v1 endpoint , The user doesnt exist in the tenant. , Contact the application owner.") ;
    $AADSignOnError.add("50027", "Invalid JWT token due to the following reasons:, doesnt contain nonce claim, sub claim , subject identifier mismatch , duplicate claim in idToken claims , unexpected issuer , unexpected audience , not within its valid time range , token format is not proper , External ID token from issuer failed signature verification. , Contact the application owner , ") ;
    $AADSignOnError.add("50029", "Invalid URI - domain name contains invalid characters. Contact the tenant administrator.") ;
    $AADSignOnError.add("50034", "User does not exist in directory. Contact your tenant administrator.") ;
    $AADSignOnError.add("50042", "The salt required to generate a pairwise identifier is missing in principle. Contact the tenant administrator.") ;
    $AADSignOnError.add("50048", "Subject mismatches Issuer claim in the client assertion. Contact the tenant administrator.") ;
    $AADSignOnError.add("50050", "Request is malformed. Contact the application owner.") ;
    $AADSignOnError.add("50053", "Account is locked because the user tried to sign in too many times with an incorrect user ID or password.") ;
    $AADSignOnError.add("50055", "Invalid password, entered expired password.") ;
    $AADSignOnError.add("50056", "Invalid or null password - Password does not exist in store for this user.") ;
    $AADSignOnError.add("50057", "User account is disabled. The account has been disabled by an administrator.") ;
    $AADSignOnError.add("50058", "The application tried to perform a silent sign in and the user could not be silently signed in. The application needs to start an interactive flow giving users an option to sign-in. Contact application owner.") ;
    $AADSignOnError.add("50059", "User does not exist in directory. Contact your tenant administrator.") ;
    $AADSignOnError.add("50061", "Sign-out request is invalid. Contact the application owner.") ;
    $AADSignOnError.add("50072", "User needs to enroll for two-factor authentication (interactive).") ;
    $AADSignOnError.add("50074", "User did not pass the MFA challenge.") ;
    $AADSignOnError.add("50076", "User did not pass the MFA challenge (non interactive).") ;
    $AADSignOnError.add("50079", "User needs to enroll for two factor authentication (non-interactive logins).") ;
    $AADSignOnError.add("50085", "Refresh token needs social IDP login. Have user try signing-in again with their username and password.") ;
    $AADSignOnError.add("50089", "Flow token expired - Authentication failed. Have user try signing-in again with their username and password") ;
    $AADSignOnError.add("50097", "Device Authentication Required. This could occur because the DeviceId or DeviceAltSecId claims are null, or if no device corresponding to the device identifier exists.") ;
    $AADSignOnError.add("50099", "JWT signature is invalid. Contact the application owner.") ;
    $AADSignOnError.add("50105", "The signed in user is not assigned to a role for the signed in application. Assign the user to the application. For more information: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#user-not-assigned-a-role") ;
    $AADSignOnError.add("50107", "Requested federation realm object does not exist. Contact the tenant administrator.") ;
    $AADSignOnError.add("50120", "Issue with JWT header. Contact the tenant administrator.") ;
    $AADSignOnError.add("50124", "Claims Transformation contains invalid input parameter. Contact the tenant administrator to update the policy.") ;
    $AADSignOnError.add("50125", "Sign-in was interrupted due to a password reset or password registration entry.(This error may come up due to an interruption in the network while the password was being changed/reset)") ;
    $AADSignOnError.add("50126", "Invalid username or password, or invalid on-premises username or password.") ;
    $AADSignOnError.add("50127", "User needs to install a broker application to gain access to this content.") ;
    $AADSignOnError.add("50128", "Invalid domain name - No tenant-identifying information found in either the request or implied by any provided credentials.") ;
    $AADSignOnError.add("50129", "Device is not workplace joined - Workplace join is required to register the device.") ;
    $AADSignOnError.add("50130", "Claim value cannot be interpreted as known auth method.") ;
    $AADSignOnError.add("50131", "Used in various conditional access errors. E.g. Bad Windows device state, request blocked due to suspicious activity, access policy, and security policy decisions.") ;
    $AADSignOnError.add("50132", "Credentials have been revoked due to the following reasons: , SSO Artifact is invalid or expired , Session not fresh enough for application , A silent sign-in request was sent but the users session with Azure AD is invalid or has expired. , ") ;
    $AADSignOnError.add("50133", "Session is invalid due to expiration or recent password change.`n(Once a Password is changed, it is advised to close all the open sessions and re-login with the new password, else this error might pop-up)") ;
    $AADSignOnError.add("50135", "Password change is required due to account risk.") ;
    $AADSignOnError.add("50136", "Redirect MSA session to application - Single MSA session detected.") ;
    $AADSignOnError.add("50140", "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.`n(if user is functional, this error may be a log anomaly that can be safely ignored)") ;
    $AADSignOnError.add("50143", "Session mismatch - Session is invalid because user tenant does not match the domain hint due to different resource. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.") ;
    $AADSignOnError.add("50144", "Users Active Directory password has expired. Generate a new password for the user or have the end user using self-service reset tool.") ;
    $AADSignOnError.add("50146", "This application is required to be configured with an application-specific signing key. It is either not configured with one, or the key has expired or is not yet valid. Contact the application owner.") ;
    $AADSignOnError.add("50148", "The code_verifier does not match the code_challenge supplied in the authorization request for PKCE. Contact the application developer.") ;
    $AADSignOnError.add("50155", "Device authentication failed for this user.") ;
    $AADSignOnError.add("50158", "External security challenge was not satisfied.") ;
    $AADSignOnError.add("50161", "Claims sent by external provider is not sufficient, or missing claim requested to external provider.") ;
    $AADSignOnError.add("50166", "Failed to send request to claims provider.") ;
    $AADSignOnError.add("50169", "The realm is not a configured realm of the current service namespace.") ;
    $AADSignOnError.add("50172", "External claims provider is not approved. Contact the tenant administrator") ;
    $AADSignOnError.add("50173", "Fresh auth token is needed. Have the user sign-in again using fresh credentials.") ;
    $AADSignOnError.add("50177", "External challenge is not supported for passthrough users.") ;
    $AADSignOnError.add("50178", "Session Control is not supported for passthrough users.") ;
    $AADSignOnError.add("50180", "Windows Integrated authentication is needed. Enable the tenant for Seamless SSO.") ;
    $AADSignOnError.add("51001", "Domain Hint is not present with On-Premises Security Identifier - On-Premises UPN.") ;
    $AADSignOnError.add("51004", "User account doesnt exist in the directory.") ;
    $AADSignOnError.add("51006", "Windows Integrated authentication is needed. User logged in using session token that is missing via claim. Request the user to re-login.") ;
    $AADSignOnError.add("52004", "User has not provided consent for access to LinkedIn resources.") ;
    $AADSignOnError.add("53000", "Conditional Access policy requires a compliant device, and the device is not compliant. Have the user enroll their device with an approved MDM provider like Intune.") ;
    $AADSignOnError.add("53001", "Conditional Access policy requires a domain joined device, and the device is not domain joined. Have the user use a domain joined device.") ;
    $AADSignOnError.add("53002", "Application used is not an approved application for conditional access. User needs to use one of the apps from the list of approved applications to use in order to get access.") ;
    $AADSignOnError.add("53003", "Access has been blocked due to conditional access policies.") ;
    $AADSignOnError.add("53004", "User needs to complete Multi-factor authentication registration process before accessing this content. User should register for multi-factor authentication.") ;
    $AADSignOnError.add("65001", "Application X doesnt have permission to access application Y or the permission has been revoked. Or The user or administrator has not consented to use the application with ID X. Send an interactive authorization request for this user and resource. Or The user or administrator has not consented to use the application with ID X. Send an authorization request to your tenant admin to act on behalf of the App : Y for Resource : Z.") ;
    $AADSignOnError.add("65004", "User declined to consent to access the app. Have the user retry the sign-in and consent to the app") ;
    $AADSignOnError.add("65005", "The application required resource access list does not contain applications discoverable by the resource or The client application has requested access to resource, which was not specified in its required resource access list or Graph service returned bad request or resource not found. If the application supports SAML, you may have configured the application with the wrong Identifier (Entity). Try out the resolution listed for SAML using the link below: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery?/?WT.mc_id=DMC_AAD_Manage_Apps_Troubleshooting_Nav#no-resource-in-requiredresourceaccess-list") ;
    $AADSignOnError.add("70000", "Invalid grant due to the following reasons:, Requested SAML 2.0 assertion has invalid Subject Confirmation Method , App OnBehalfOf flow is not supported on V2 , Primary refresh token is not signed with session key , Invalid external refresh token , The access grant was obtained for a different tenant. , ") ;
    $AADSignOnError.add("70001", "The application named X was not found in the tenant named Y. This can happen if the application with identifier X has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have misconfigured the Identifier value for the application or sent your authentication request to the wrong tenant.") ;
    $AADSignOnError.add("70002", "The application returned invalid client credentials. Contact the application owner.") ;
    $AADSignOnError.add("70003", "The application returned an unsupported grant type. Contact the application owner.") ;
    $AADSignOnError.add("70004", "The application returned an invalid redirect URI. The redirect address specified by the client does not match any configured addresses or any addresses on the OIDC approve list. Contact the application owner.") ;
    $AADSignOnError.add("70005", "The application returned an unsupported response type due to the following reasons: , response type token is not enabled for the application , response type id_token requires the OpenID scope -contains an unsupported OAuth parameter value in the encoded wctx , Contact the application owner.") ;
    $AADSignOnError.add("70007", "The application returned an unsupported value of response_mode when requesting a token. Contact the application owner.") ;
    $AADSignOnError.add("70008", "The provided authorization code or refresh token is expired or has been revoked. Have the user retry signing in.") ;
    $AADSignOnError.add("70011", "The scope requested by the application is invalid. Contact the application owner.") ;
    $AADSignOnError.add("70012", "A server error occurred while authenticating an MSA (consumer) user. Retry the sign-in, and if the issue persists, open a support ticket") ;
    $AADSignOnError.add("70018", "Invalid verification code due to User typing in wrong user code for device code flow. Authorization is not approved.") ;
    $AADSignOnError.add("70019", "Verification code expired. Have the user retry the sign-in.") ;
    $AADSignOnError.add("70037", "Incorrect challenge response provided. Remote auth session denied.") ;
    $AADSignOnError.add("75001", "An error occurred during SAML message binding.") ;
    $AADSignOnError.add("75003", "The application returned an error related to unsupported Binding (SAML protocol response cannot be sent via bindings other than HTTP POST). Contact the application owner.") ;
    $AADSignOnError.add("75005", "Azure AD doesnt support the SAML Request sent by the application for Single Sign-on. Contact the application owner.") ;
    $AADSignOnError.add("75008", "The request from the application was denied since the SAML request had an unexpected destination. Contact the application owner.") ;
    $AADSignOnError.add("75011", "Authentication method by which the user authenticated with the service doesnt match requested authentication method. Contact the application owner.") ;
    $AADSignOnError.add("75016", "SAML2 Authentication Request has invalid NameIdPolicy. Contact the application owner.") ;
    $AADSignOnError.add("80001", "Authentication Agent unable to connect to Active Directory. Make sure the authentication agent is installed on a domain-joined machine that has line of sight to a DC that can serve the users login request.") ;
    $AADSignOnError.add("80002", "Internal error. Password validation request timed out. We were unable to either send the authentication request to the internal Hybrid Identity Service. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80003", "Invalid response received by Authentication Agent. An unknown error occurred while attempting to authentication against Active Directory on-premises. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80005", "Authentication Agent: An unknown error occurred while processing the response from the Authentication Agent. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80007", "Authentication Agent unable to validate users password.") ;
    $AADSignOnError.add("80010", "Authentication Agent unable to decrypt password.") ;
    $AADSignOnError.add("80011", "Authentication Agent unable to retrieve encryption key.") ;
    $AADSignOnError.add("80012", "The users attempted to log on outside of the allowed hours (this is specified in AD).") ;
    $AADSignOnError.add("80013", "The authentication attempt could not be completed due to time skew between the machine running the authentication agent and AD. Fix time sync issues") ;
    $AADSignOnError.add("80014", "Authentication agent timed out. Open a support ticket with the error code, correlation ID, and Datetime to get more details on this error.") ;
    $AADSignOnError.add("81001", "Users Kerberos ticket is too large. This can happen if the user is in too many groups and thus the Kerberos ticket contains too many group memberships. Reduce the users group memberships and try again.") ;
    $AADSignOnError.add("81005", "Authentication Package Not Supported.") ;
    $AADSignOnError.add("81007", "Tenant is not enabled for Seamless SSO.") ;
    $AADSignOnError.add("81012", "This is not an error condition. It indicates that user trying to sign in to Azure AD is different from the user signed into the device. You can safely ignore this code in the logs.") ;
    $AADSignOnError.add("90010", "The request is not supported for various reasons. For example, the request is made using an unsupported request method (only POST method is supported) or the token signing algorithm that was requested is not supported. Contact the application developer.") ;
    $AADSignOnError.add("90014", "A required field for a protocol message was missing, contact the application owner. If you are the application owner, ensure that you have all the necessary parameters for the login request.") ;
    $AADSignOnError.add("90051", "Invalid Delegation Token. Invalid national Cloud ID ({cloudId}) is specified.") ;
    $AADSignOnError.add("90072", "The account needs to be added as an external user in the tenant first. Sign-out and sign-in again with a different Azure AD account.") ;
    $AADSignOnError.add("90094", "The grant requires administrator permissions. Ask your tenant administrator to provide consent for this application.") ;
    $AADSignOnError.add("500021", "Tenant is restricted by company proxy. Denying the resource access.") ;
    $AADSignOnError.add("500121", "Authentication failed during strong authentication request.") ;
    $AADSignOnError.add("500133", "The assertion is not within its valid time range. Ensure that the access token is not expired before using it for user assertion, or request a new token.") ;
    $AADSignOnError.add("530021", "Application does not meet the conditional access approved app requirements.") ;
    $AADSignOnError | write-output ;
}

#*------^ Initialize-AADSignErrorsHash.ps1 ^------

#*------v profile-AAD-Signons.ps1 v------
Function profile-AAD-Signons {
    <#
    .SYNOPSIS
    profile-AAD-Signons.ps1 - profile AAD Sign-ons Activity JSON dump Splitbrain and outline remediation steps
    .NOTES
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Additional Credits: REFERENCE
    Website:	URL
    Twitter:	URL
    REVISIONS   : 
    * 11:18 AM 9/16/2021 string cleaning
    * 3:04 PM 6/16/2021, shifted to standard start-log mod support, conditioned helper funcs, added test for events in target file, echo on gap
    * 11:11 AM 6/15/2021 Ren'd Build-AADSignErrorsHash() -> Initialize-AADSignErrorsHash (compliant verb) ; sync'd copy & set it to defer to the verb-AAD mod version
    # 10:46 AM 6/2/2021 sub'd verb-logging for v-trans
    * 9:19 AM 8/29/2019 fixed $filterdesc's, alot didn't match the actual filters, added device.displayname (workstation name, blank on a lot of browsers too), also added correlid, requsestidto fail dumps, as some error recommend a ticket with those values and the errornumber
    * * 2:49 PM 8/27/2019 updated errornumber 0 to be (undocumented - successful), as it is the code on a non-error logon
    * 12:22 PM 8/26/2019 hybrid in a *lot* of code and color-coding (get-colorcombo) from older 5/19 profile-AADSignOnsJson.ps1 (forgotten I had it), which resolves the error codes into useful descriptions
    * 1:48 PM 8/20/2019 v0.1.1 reworked outputs to cleanup and hibrid, delimted the trailing evt dumps too.
    * 1:01 PM 8/20/2019 v0.1.0 init vers (converted check-ExosplitBrain.ps1), subbed in write-log from verb-transcript (debug support)
    .DESCRIPTION
    profile-AAD-Signons.ps1 - profile AAD Sign-ons Activity JSON dump Splitbrain and outline remediation steps
    .PARAMETER  UPNs
    User Userprincipalnames (array)[-UPNs]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    .\profile-AAD-Signons.ps1 -Files "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json";
    Process a single json AAD signon log
    .EXAMPLE
    .\profile-AAD-Signons.ps1 -Files "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json","c:\usr\work\incid\todd.USER-SignIns__2019-07-07__2019-08-06b.csv.json" ;
    Process an array of json AAD signon logs
    .LINK
    #>

    ### Note: vers 2: #Requires -Version 2.0
    #Requires -Modules ActiveDirectory
    #Requires -Version 3


    Param(
        [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Files [-file c:\path-to\file.ext]")]
        [array]$Files,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) # PARAM BLOCK END

    $whatif=$true ;
    #region INIT; # ------
    #*======v SCRIPT/DOMAIN/MACHINE/INITIALIZATION-DECLARE-BOILERPLATE v======
    # SCRIPT-CONFIG MATERIAL TO SET THE UNDERLYING $DBGPREF:
    if ($ShowDebug) { $DebugPreference = "Continue" ; write-debug "(`$showDebug:$showDebug ;`$DebugPreference:$DebugPreference)" ; };
    if ($Whatif){Write-Verbose -Verbose:$true "`$Whatif is TRUE (`$whatif:$($whatif))" ; };
    if($showDebug){$ErrorActionPreference = 'Stop' ; write-debug "(Setting `$ErrorActionPreference:$ErrorActionPreference;"};
    # If using WMI calls, push any cred into WMI:
    #if ($Credential -ne $Null) {$WmiParameters.Credential = $Credential }  ;

    # scriptname with extension
    $ScriptDir=(Split-Path -parent $MyInvocation.MyCommand.Definition) + "\" ;
    $ScriptBaseName = (Split-Path -Leaf ((&{$myInvocation}).ScriptName))  ;
    $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;
    $ComputerName = $env:COMPUTERNAME ;
    $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
    #$smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
    $smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;
    $smtpTo=$TORMeta['NotificationAddr1'] ;
    $sQot = [char]34 ; $sQotS = [char]39 ;
    $NoProf=[bool]([Environment]::GetCommandLineArgs() -like '-noprofile'); # if($NoProf){# do this};
    $MyBox="LYN-3V6KSY1","TIN-BYTEIII","TIN-BOX","TINSTOY","LYN-8DCZ1G2" ;
    $DomainWork = "TORO";
    $DomHome = "REDBANK";
    $DomLab="TORO-LAB";
    #$ProgInterval= 500 ; # write-progress wait interval in ms
    # 12:23 PM 2/20/2015 add gui vb prompt support
    #[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null ;
    # 11:00 AM 3/19/2015 should use Windows.Forms where possible, more stable



    #*======v FUNCTIONS v======

    #*------v Function Write-Log v-----
    if(test-path function:Write-Log){
        "(deferring to `$script:Write-Log())" ;
    } else {
        "(using default verb-logging:Write-Log())" ;
        function Write-Log {
            <#
            .SYNOPSIS
            Write-Log.ps1 - Write-Log writes a message to a specified log file with the current time stamp, and write-verbose|warn|error's the matching msg.
            .NOTES
            Author: Jason Wasser @wasserja
            Website:	https://www.powershellgallery.com/packages/MrAADAdministration/1.0/Content/Write-Log.ps1
            Twitter:	@wasserja
            Updated By: Todd Kadrie
            Website:	http://www.toddomation.com
            Twitter:	@tostka, http://twitter.com/tostka
            Additional Credits: REFERENCE
            Website:	URL
            Twitter:	URL
            REVISIONS   :
            * 11:34 AM 8/26/2019 fixed missing noecho parameter desig in comment help
            * 9:31 AM 2/15/2019:Write-Log: added Level:Debug support, and broader init
                block example with $whatif & $ticket support, added -NoEcho to suppress console
                echos and just use it for writing logged output
            * 8:57 PM 11/25/2018 Write-Log:shifted copy to verb-logging, added defer to scope $script versions
            * 2:30 PM 10/18/2018 added -useHost to have it issue color-keyed write-host commands vs write-(warn|error|verbose)
                switched timestamp into the function (as $echotime), rather than redundant code in the $Message contstruction.
            * 10:18 AM 10/18/2018 cleanedup, added to pshelp, put into OTB fmt, added trailing semis, parame HelpMessages, and -showdebug param
            * Code simplification and clarification - thanks to @juneb_get_help  ;
            * Added documentation.
            * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks  ;
            * Revised the Force switch to work as it should - thanks to @JeffHicks  ;

            To Do:  ;
            * Add error handling if trying to create a log file in a inaccessible location.
            * Add ability to write $Message to $Verbose or $Error pipelines to eliminate  ;
                duplicates.
            .DESCRIPTION
            The Write-Log function is designed to add logging capability to other scripts.
            In addition to writing output and/or verbose you can write to a log file for  ;
            later debugging.
            .PARAMETER Message  ;
            Message is the content that you wish to add to the log file.
            .PARAMETER Path  ;
            The path to the log file to which you would like to write. By default the function will create the path and file if it does not exist.
            .PARAMETER Level  ;
            Specify the criticality of the log information being written to the log defaults Info: (Error|Warn|Info)  ;
            .PARAMETER useHost  ;
            Switch to use write-host rather than write-[verbose|warn|error] [-useHost]
            .PARAMETER NoEcho
            Switch to suppress console echos (e.g log to file only [-NoEcho]
            .PARAMETER NoClobber  ;
            Use NoClobber if you do not wish to overwrite an existing file.
            .PARAMETER ShowDebug
            Parameter to display Debugging messages [-ShowDebug switch]
            .INPUTS
            None. Does not accepted piped input.
            .OUTPUTS
            Writes output to the specified Path.
            .EXAMPLE
            Write-Log -Message 'Log message'   ;
            Writes the message to c:\Logs\PowerShellLog.log.
            .EXAMPLE
            Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
            Writes the content to the specified log file and creates the path and file specified.
            .EXAMPLE
            Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error  ;
            Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
            .EXAMPLE
            # init content in script context ($MyInvocation is blank in function scope)
            $logfile = join-path -path $ofile -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-LOG.txt"  ;
            $logging = $True ;
            # ...
            $sBnr="#*======v `$tmbx:($($Procd)/$($ttl)):$($tmbx) v======" ;
            $smsg="$($sBnr)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } ; #Error|Warn
            Example that uses a variable and the -useHost switch, to trigger write-host use
            .EXAMPLE
            $transcript = join-path -path (Split-Path -parent $MyInvocation.MyCommand.Definition) -ChildPath "logs" ;
            if(!(test-path -path $transcript)){ "Creating missing log dir $($transcript)..." ; mkdir $transcript  ; } ;
            $transcript=join-path -path $transcript -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))"  ;
            $transcript+= "-Transcript-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-trans-log.txt"  ;
            # add log file variant as target of Write-Log:
            $logfile=$transcript.replace("-Transcript","-LOG").replace("-trans-log","-log")
            if($whatif){
                $logfile=$logfile.replace("-BATCH","-BATCH-WHATIF") ;
                $transcript=$transcript.replace("-BATCH","-BATCH-WHATIF") ;
            } else {
                $logfile=$logfile.replace("-BATCH","-BATCH-EXEC") ;
                $transcript=$transcript.replace("-BATCH","-BATCH-EXEC") ;
            } ;
            if($Ticket){
                $logfile=$logfile.replace("-BATCH","-$($Ticket)") ;
                $transcript=$transcript.replace("-BATCH","-$($Ticket)") ;
            } else {
                $logfile=$logfile.replace("-BATCH","-nnnnnn") ;
                $transcript=$transcript.replace("-BATCH","-nnnnnn") ;
            } ;
            $logging = $True ;

            $sBnr="#*======v START PASS:$($ScriptBaseName) v======" ;
            $smsg= "$($sBnr)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } ; #Error|Warn
            More complete boilerplate including $whatif & $ticket
            .LINK
            https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0  ;
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "Message is the content that you wish to add to the log file")]
                [ValidateNotNullOrEmpty()][Alias("LogContent")]
                [string]$Message,
                [Parameter(Mandatory = $false, HelpMessage = "The path to the log file to which you would like to write. By default the function will create the path and file if it does not exist.")][Alias('LogPath')]
                [string]$Path = 'C:\Logs\PowerShellLog.log',
                [Parameter(Mandatory = $false, HelpMessage = "Specify the criticality of the log information being written to the log defaults Info: (Error|Warn|Info)")][ValidateSet("Error", "Warn", "Info", "Debug")]
                [string]$Level = "Info",
                [Parameter(HelpMessage = "Switch to use write-host rather than write-[verbose|warn|error] [-useHost]")]
                [switch] $useHost,
                [Parameter(HelpMessage = "Switch to suppress console echos (e.g log to file only [-NoEcho]")]
                [switch] $NoEcho,
                [Parameter(Mandatory = $false, HelpMessage = "Use NoClobber if you do not wish to overwrite an existing file.")]
                [switch]$NoClobber,
                [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
                [switch] $showDebug
            )  ;

            Begin {
                $VerbosePreference = 'Continue'  ; # Set VerbosePreference to Continue so that verbose messages are displayed.
            }  ;
            Process {
                # If the file already exists and NoClobber was specified, do not write to the log.
                if ((Test-Path $Path) -AND $NoClobber) {
                    Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."  ;
                    Return  ;
                }
                elseif (!(Test-Path $Path)) {
                    # create the file including the path when missing.
                    Write-Verbose "Creating $Path."  ;
                    $NewLogFile = New-Item $Path -Force -ItemType File  ;
                }
                else {
                    # Nothing to see here yet.
                }  ;

                $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"  ;
                $EchoTime = "$((get-date).ToString('HH:mm:ss')):" ;

                # Write message to error, warning, or verbose pipeline and specify $LevelText
                switch ($Level) {
                    'Error' {
                        if ($useHost) {
                            write-host -foregroundcolor red ($EchoTime + $Message)   ;
                        }
                        else {
                            if (!$NoEcho) { Write-Error ($EchoTime + $Message) } ;
                        } ;
                        $LevelText = 'ERROR:'  ;
                    }
                    'Warn' {
                        if ($useHost) {
                            write-host -foregroundcolor yellow ($EchoTime + $Message)    ;
                        }
                        else {
                            if (!$NoEcho) { Write-Warning ($EchoTime + $Message) } ;
                        } ;
                        $LevelText = 'WARNING:'  ;
                    }
                    'Info' {
                        if ($useHost) {
                            write-host -foregroundcolor green ($EchoTime + $Message)   ;
                        }
                        else {
                            if (!$NoEcho) { Write-Verbose ($EchoTime + $Message) } ;
                        } ;
                        $LevelText = 'INFO:'  ;
                    }
                    'Debug' {
                        if (!$NoEcho) { Write-Debug -Verbose:$true ($EchoTime + $Message) }  ;
                        $LevelText = 'DEBUG:'  ;
                    }
                } ;

                # Write log entry to $Path
                "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append  ;
            }  ; # PROC-E
            End {
            }  ;
        } ;
    } ; #*------^ END Function Write-Log ^------

    #*------v Function get-colorcombo v------
    function get-colorcombo {
        <#
        .SYNOPSIS
        get-colorcombo - Return a readable console fg/bg color combo (commonly for use with write-host blocks to id variant datatypes across a series of tests)
        .NOTES
        Author: Todd Kadrie
        Website:	http://www.toddomation.com
        Twitter:	@tostka, http://twitter.com/tostka
        REVISIONS   :
        * 1:22 PM 5/10/2019 init version
        .DESCRIPTION
        .PARAMETER  Combo
        Combo Number (0-73)[-Combo 65]
        .PARAMETER Random
        Returns a random Combo [-Random]
        .PARAMETER  Demo
        Dumps a table of all combos for review[-Demo]
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.Collections.Hashtable
        .EXAMPLE
        $plt=get-colorcombo 70 ;
        write-host @plt "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" ;
        Pull and use get-colorcombo 72 in a write-host ;
        .EXAMPLE
        get-colorcombo -demo ;
        .EXAMPLE
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Pull Random get-colorcombo" ;
        $plt=get-colorcombo -Rand ; write-host  @plt "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" ;
        Run a demo
        .LINK
        #>

        Param(
            [Parameter(Position=0,HelpMessage="Combo Number (0-73)[-Combo 65]")][int]$Combo,
            [Parameter(HelpMessage="Returns a random Combo [-Random]")][switch]$Random,
            [Parameter(HelpMessage="Dumps a table of all combos for review[-Demo]")][switch]$Demo
        )
        if(-not($Demo) -AND -not($Combo) -AND -not($Random)){
            throw "No -Combo integer specified, no -Random, and no -Demo param. One of these must be specified" ;
            Exit ;
        } ;

        $colorcombo=[ordered]@{} ;
        $schemes="Black;DarkYellow","Black;Gray","Black;Green","Black;Cyan","Black;Red","Black;Yellow","Black;White","DarkGreen;Gray","DarkGreen;Green","DarkGreen;Cyan","DarkGreen;Magenta","DarkGreen;Yellow","DarkGreen;White","White;DarkGray","DarkRed;Gray","White;Blue","White;DarkRed","DarkRed;Green","DarkRed;Cyan","DarkRed;Magenta","DarkRed;Yellow","DarkRed;White","DarkYellow;Black","White;DarkGreen","DarkYellow;Blue","DarkYellow;Green","DarkYellow;Cyan","DarkYellow;Yellow","DarkYellow;White","Gray;Black","Gray;DarkGreen","Gray;DarkMagenta","Gray;Blue","Gray;White","DarkGray;Black","DarkGray;DarkBlue","DarkGray;Gray","DarkGray;Blue","Yellow;DarkGreen","DarkGray;Green","DarkGray;Cyan","DarkGray;Yellow","DarkGray;White","Blue;Gray","Blue;Green","Blue;Cyan","Blue;Red","Blue;Magenta","Blue;Yellow","Blue;White","Green;Black","Green;DarkBlue","White;Black","Green;Blue","Green;DarkGray","Yellow;DarkGray","Yellow;Black","Cyan;Black","Yellow;Blue","Cyan;Blue","Cyan;Red","Red;Black","Red;DarkGreen","Red;Blue","Red;Yellow","Red;White","Magenta;Black","Magenta;DarkGreen","Magenta;Blue","Magenta;DarkMagenta","Magenta;Blue","Magenta;Yellow","Magenta;White" ;
        $i=0 ;
        foreach($scheme in $schemes){
            $colorcombo["$($i)"]=@{BackgroundColor=$scheme.split(";")[0] ; foregroundcolor=$scheme.split(";")[1] ; } ;
            $i++ ;
        } ;
        if($Demo){
            write-verbose -verbose:$true  "-Demo specified: Dumping a table of range from Combo 0 to $($colorcombo.count)" ;
            $a=00 ;
            Do {
                $plt=$colorcombo[$a].clone() ;
                write-host -object "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" @plt ;
                $a++ ;
            }  While ($a -lt $colorcombo.count) ;
        } elseif ($Random){
            $colorcombo[(get-random -minimum 0 -maximum $colorcombo.count)] | write-output ;
        } else {
            $colorcombo[$Combo] | write-output ;
        } ;
    } ; #*------^ END Function get-colorcombo() ^------

    if(!(get-command Initialize-AADSignErrorsHash -ea 0)){
        #*------v Initialize-AADSignErrorsHash.ps1 v------
        function Initialize-AADSignErrorsHash {
            <#
            .SYNOPSIS
            Initialize-AADSignErrorsHash - Builds a hash object containing AzureAD Sign-on Error codes & matching description
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2021-06-15
            FileName    : Initialize-AADSignErrorsHash.ps1
            License     : MIT License
            Copyright   : (c) 2020 Todd Kadrie
            Github      : https://github.com/tostka/verb-AAD
            Tags        : Powershell,AzureAD,Errors,Reference
            AddedCredit : Sign-in activity report error codes in the Azure Active Directory portal
            AddedWebsite: https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
            AddedTwitter: URL
            REVISIONS   :
            * 11:01 AM 6/15/2021 Ren'd Build-AADSignErrorsHash -> Initialize-AADSignErrorsHash (compliant verb) ; copied over vers from profile-AAD-Signons.ps1 ; kept updated CBH. 
            * 8:50 PM 1/12/2020 expanded aliases
            * 9:53 AM 8/29/2019 amended 50135, 50125, with MS support comments, and reserached 50140 a bit
            * 2:49 PM 8/27/2019 updated errornumber 0 to be (undocumented - successful), as it is the code on a non-error logon
            * 10:41 AM 5/13/2019 init vers
            .DESCRIPTION
            Build-AADSignErrorsHas.ps1 - Builds a hash object containing AzureAD Sign-on Error codes & matching description: [Sign-in activity report error codes in the Azure Active Directory portal | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
            .INPUTS
            None. Does not accepted piped input.
            .OUTPUTS
            Returns a populated hashtable of AAD signon error codes & descriptions
            .EXAMPLE
            $AADSignOnErrors = Initialize-AADSignErrorsHash ; 
            $ErrDetail = $AADSignOnErrors[$errorCode] ; 
            Populate hash and lookup errorcode
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
            #>
            [CmdletBinding()]
            [Alias('Build-AADSignErrorsHash')]
            PARAM() ;
             #Error 	Description
            $AADSignOnError = [ordered]@{ } ;
            $AADSignOnError.add("0", "(undocumented - ((Successful)))") ;
            $AADSignOnError.add("16000", "This is an internal implementation detail and not an error condition. You can safely ignore this reference.") ;
            $AADSignOnError.add("20001", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("20012", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("20033", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40008", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40009", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40014", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("50000", "There is an issue with our sign-in service. Open a support ticket to resolve this issue.") ;
            $AADSignOnError.add("50001", "The service principal name was not found in this tenant. This can happen if the application has not been installed by the administrator of the tenant, or if the resource principal was not found in the directory or is invalid.") ;
            $AADSignOnError.add("50002", "Sign-in failed due to restricted proxy access on tenant. If its your own tenant policy, you can change your restricted tenant settings to fix this issue.") ;
            $AADSignOnError.add("50003", "Sign-in failed due to missing signing key or certificate. This might be because there was no signing key configured in the application. Check out the resolutions outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#certificate-or-key-not-configured. If the issue persists, contact the application owner or the application administrator.") ;
            $AADSignOnError.add("50005", "User tried to login to a device from a platform thats currently not supported through conditional access policy.") ;
            $AADSignOnError.add("50006", "Signature verification failed due to invalid signature. Check out the resolution outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery. If the issue persists, contact the application owner or application administrator.") ;
            $AADSignOnError.add("50007", "Partner encryption certificate was not found for this application. Open a support ticket with Microsoft to get this fixed.") ;
            $AADSignOnError.add("50008", "SAML assertion is missing or misconfigured in the token. Contact your federation provider.") ;
            $AADSignOnError.add("50010", "Audience URI validation for the application failed since no token audiences were configured. Contact the application owner for resolution.") ;
            $AADSignOnError.add("50011", "The reply address is missing, misconfigured, or does not match reply addresses configured for the application. Try the resolution listed at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#the-reply-address-does-not-match-the-reply-addresses-configured-for-the-application. If the issue persists, contact the application owner or application administrator.") ;
            $AADSignOnError.add("50012", "This is a generic error message that indicates that authentication failed. This can happen for reasons such as missing or invalid credentials or claims in the request. Ensure that the request is sent with the correct credentials and claims.") ;
            $AADSignOnError.add("50013", "Assertion is invalid because of various reasons. For instance, the token issuer doesnt match the api version within its valid time range, the token is expired or malformed, or the refresh token in the assertion is not a primary refresh token.") ;
            $AADSignOnError.add("50017", "Certification validation failed, reasons for the following reasons:, Cannot find issuing certificate in trusted certificates list , Unable to find expected CrlSegment , Cannot find issuing certificate in trusted certificates list , Delta CRL distribution point is configured without a corresponding CRL distribution point , Unable to retrieve valid CRL segments due to timeout issue , Unable to download CRL , Contact the tenant administrator.") ;
            $AADSignOnError.add("50020", "The user is unauthorized for one of the following reasons. The user is attempting to login with an MSA account with the v1 endpoint , The user doesnt exist in the tenant. , Contact the application owner.") ;
            $AADSignOnError.add("50027", "Invalid JWT token due to the following reasons:, doesnt contain nonce claim, sub claim , subject identifier mismatch , duplicate claim in idToken claims , unexpected issuer , unexpected audience , not within its valid time range , token format is not proper , External ID token from issuer failed signature verification. , Contact the application owner , ") ;
            $AADSignOnError.add("50029", "Invalid URI - domain name contains invalid characters. Contact the tenant administrator.") ;
            $AADSignOnError.add("50034", "User does not exist in directory. Contact your tenant administrator.") ;
            $AADSignOnError.add("50042", "The salt required to generate a pairwise identifier is missing in principle. Contact the tenant administrator.") ;
            $AADSignOnError.add("50048", "Subject mismatches Issuer claim in the client assertion. Contact the tenant administrator.") ;
            $AADSignOnError.add("50050", "Request is malformed. Contact the application owner.") ;
            $AADSignOnError.add("50053", "Account is locked because the user tried to sign in too many times with an incorrect user ID or password.") ;
            $AADSignOnError.add("50055", "Invalid password, entered expired password.") ;
            $AADSignOnError.add("50056", "Invalid or null password - Password does not exist in store for this user.") ;
            $AADSignOnError.add("50057", "User account is disabled. The account has been disabled by an administrator.") ;
            $AADSignOnError.add("50058", "The application tried to perform a silent sign in and the user could not be silently signed in. The application needs to start an interactive flow giving users an option to sign-in. Contact application owner.") ;
            $AADSignOnError.add("50059", "User does not exist in directory. Contact your tenant administrator.") ;
            $AADSignOnError.add("50061", "Sign-out request is invalid. Contact the application owner.") ;
            $AADSignOnError.add("50072", "User needs to enroll for two-factor authentication (interactive).") ;
            $AADSignOnError.add("50074", "User did not pass the MFA challenge.") ;
            $AADSignOnError.add("50076", "User did not pass the MFA challenge (non interactive).") ;
            $AADSignOnError.add("50079", "User needs to enroll for two factor authentication (non-interactive logins).") ;
            $AADSignOnError.add("50085", "Refresh token needs social IDP login. Have user try signing-in again with their username and password.") ;
            $AADSignOnError.add("50089", "Flow token expired - Authentication failed. Have user try signing-in again with their username and password") ;
            $AADSignOnError.add("50097", "Device Authentication Required. This could occur because the DeviceId or DeviceAltSecId claims are null, or if no device corresponding to the device identifier exists.") ;
            $AADSignOnError.add("50099", "JWT signature is invalid. Contact the application owner.") ;
            $AADSignOnError.add("50105", "The signed in user is not assigned to a role for the signed in application. Assign the user to the application. For more information: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#user-not-assigned-a-role") ;
            $AADSignOnError.add("50107", "Requested federation realm object does not exist. Contact the tenant administrator.") ;
            $AADSignOnError.add("50120", "Issue with JWT header. Contact the tenant administrator.") ;
            $AADSignOnError.add("50124", "Claims Transformation contains invalid input parameter. Contact the tenant administrator to update the policy.") ;
            $AADSignOnError.add("50125", "Sign-in was interrupted due to a password reset or password registration entry.(This error may come up due to an interruption in the network while the password was being changed/reset)") ;
            $AADSignOnError.add("50126", "Invalid username or password, or invalid on-premises username or password.") ;
            $AADSignOnError.add("50127", "User needs to install a broker application to gain access to this content.") ;
            $AADSignOnError.add("50128", "Invalid domain name - No tenant-identifying information found in either the request or implied by any provided credentials.") ;
            $AADSignOnError.add("50129", "Device is not workplace joined - Workplace join is required to register the device.") ;
            $AADSignOnError.add("50130", "Claim value cannot be interpreted as known auth method.") ;
            $AADSignOnError.add("50131", "Used in various conditional access errors. E.g. Bad Windows device state, request blocked due to suspicious activity, access policy, and security policy decisions.") ;
            $AADSignOnError.add("50132", "Credentials have been revoked due to the following reasons: , SSO Artifact is invalid or expired , Session not fresh enough for application , A silent sign-in request was sent but the users session with Azure AD is invalid or has expired. , ") ;
            $AADSignOnError.add("50133", "Session is invalid due to expiration or recent password change.`n(Once a Password is changed, it is advised to close all the open sessions and re-login with the new password, else this error might pop-up)") ;
            $AADSignOnError.add("50135", "Password change is required due to account risk.") ;
            $AADSignOnError.add("50136", "Redirect MSA session to application - Single MSA session detected.") ;
            $AADSignOnError.add("50140", "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.`n(if user is functional, this error may be a log anomaly that can be safely ignored)") ;
            $AADSignOnError.add("50143", "Session mismatch - Session is invalid because user tenant does not match the domain hint due to different resource. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.") ;
            $AADSignOnError.add("50144", "Users Active Directory password has expired. Generate a new password for the user or have the end user using self-service reset tool.") ;
            $AADSignOnError.add("50146", "This application is required to be configured with an application-specific signing key. It is either not configured with one, or the key has expired or is not yet valid. Contact the application owner.") ;
            $AADSignOnError.add("50148", "The code_verifier does not match the code_challenge supplied in the authorization request for PKCE. Contact the application developer.") ;
            $AADSignOnError.add("50155", "Device authentication failed for this user.") ;
            $AADSignOnError.add("50158", "External security challenge was not satisfied.") ;
            $AADSignOnError.add("50161", "Claims sent by external provider is not sufficient, or missing claim requested to external provider.") ;
            $AADSignOnError.add("50166", "Failed to send request to claims provider.") ;
            $AADSignOnError.add("50169", "The realm is not a configured realm of the current service namespace.") ;
            $AADSignOnError.add("50172", "External claims provider is not approved. Contact the tenant administrator") ;
            $AADSignOnError.add("50173", "Fresh auth token is needed. Have the user sign-in again using fresh credentials.") ;
            $AADSignOnError.add("50177", "External challenge is not supported for passthrough users.") ;
            $AADSignOnError.add("50178", "Session Control is not supported for passthrough users.") ;
            $AADSignOnError.add("50180", "Windows Integrated authentication is needed. Enable the tenant for Seamless SSO.") ;
            $AADSignOnError.add("51001", "Domain Hint is not present with On-Premises Security Identifier - On-Premises UPN.") ;
            $AADSignOnError.add("51004", "User account doesnt exist in the directory.") ;
            $AADSignOnError.add("51006", "Windows Integrated authentication is needed. User logged in using session token that is missing via claim. Request the user to re-login.") ;
            $AADSignOnError.add("52004", "User has not provided consent for access to LinkedIn resources.") ;
            $AADSignOnError.add("53000", "Conditional Access policy requires a compliant device, and the device is not compliant. Have the user enroll their device with an approved MDM provider like Intune.") ;
            $AADSignOnError.add("53001", "Conditional Access policy requires a domain joined device, and the device is not domain joined. Have the user use a domain joined device.") ;
            $AADSignOnError.add("53002", "Application used is not an approved application for conditional access. User needs to use one of the apps from the list of approved applications to use in order to get access.") ;
            $AADSignOnError.add("53003", "Access has been blocked due to conditional access policies.") ;
            $AADSignOnError.add("53004", "User needs to complete Multi-factor authentication registration process before accessing this content. User should register for multi-factor authentication.") ;
            $AADSignOnError.add("65001", "Application X doesnt have permission to access application Y or the permission has been revoked. Or The user or administrator has not consented to use the application with ID X. Send an interactive authorization request for this user and resource. Or The user or administrator has not consented to use the application with ID X. Send an authorization request to your tenant admin to act on behalf of the App : Y for Resource : Z.") ;
            $AADSignOnError.add("65004", "User declined to consent to access the app. Have the user retry the sign-in and consent to the app") ;
            $AADSignOnError.add("65005", "The application required resource access list does not contain applications discoverable by the resource or The client application has requested access to resource, which was not specified in its required resource access list or Graph service returned bad request or resource not found. If the application supports SAML, you may have configured the application with the wrong Identifier (Entity). Try out the resolution listed for SAML using the link below: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery?/?WT.mc_id=DMC_AAD_Manage_Apps_Troubleshooting_Nav#no-resource-in-requiredresourceaccess-list") ;
            $AADSignOnError.add("70000", "Invalid grant due to the following reasons:, Requested SAML 2.0 assertion has invalid Subject Confirmation Method , App OnBehalfOf flow is not supported on V2 , Primary refresh token is not signed with session key , Invalid external refresh token , The access grant was obtained for a different tenant. , ") ;
            $AADSignOnError.add("70001", "The application named X was not found in the tenant named Y. This can happen if the application with identifier X has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have misconfigured the Identifier value for the application or sent your authentication request to the wrong tenant.") ;
            $AADSignOnError.add("70002", "The application returned invalid client credentials. Contact the application owner.") ;
            $AADSignOnError.add("70003", "The application returned an unsupported grant type. Contact the application owner.") ;
            $AADSignOnError.add("70004", "The application returned an invalid redirect URI. The redirect address specified by the client does not match any configured addresses or any addresses on the OIDC approve list. Contact the application owner.") ;
            $AADSignOnError.add("70005", "The application returned an unsupported response type due to the following reasons: , response type token is not enabled for the application , response type id_token requires the OpenID scope -contains an unsupported OAuth parameter value in the encoded wctx , Contact the application owner.") ;
            $AADSignOnError.add("70007", "The application returned an unsupported value of response_mode when requesting a token. Contact the application owner.") ;
            $AADSignOnError.add("70008", "The provided authorization code or refresh token is expired or has been revoked. Have the user retry signing in.") ;
            $AADSignOnError.add("70011", "The scope requested by the application is invalid. Contact the application owner.") ;
            $AADSignOnError.add("70012", "A server error occurred while authenticating an MSA (consumer) user. Retry the sign-in, and if the issue persists, open a support ticket") ;
            $AADSignOnError.add("70018", "Invalid verification code due to User typing in wrong user code for device code flow. Authorization is not approved.") ;
            $AADSignOnError.add("70019", "Verification code expired. Have the user retry the sign-in.") ;
            $AADSignOnError.add("70037", "Incorrect challenge response provided. Remote auth session denied.") ;
            $AADSignOnError.add("75001", "An error occurred during SAML message binding.") ;
            $AADSignOnError.add("75003", "The application returned an error related to unsupported Binding (SAML protocol response cannot be sent via bindings other than HTTP POST). Contact the application owner.") ;
            $AADSignOnError.add("75005", "Azure AD doesnt support the SAML Request sent by the application for Single Sign-on. Contact the application owner.") ;
            $AADSignOnError.add("75008", "The request from the application was denied since the SAML request had an unexpected destination. Contact the application owner.") ;
            $AADSignOnError.add("75011", "Authentication method by which the user authenticated with the service doesnt match requested authentication method. Contact the application owner.") ;
            $AADSignOnError.add("75016", "SAML2 Authentication Request has invalid NameIdPolicy. Contact the application owner.") ;
            $AADSignOnError.add("80001", "Authentication Agent unable to connect to Active Directory. Make sure the authentication agent is installed on a domain-joined machine that has line of sight to a DC that can serve the users login request.") ;
            $AADSignOnError.add("80002", "Internal error. Password validation request timed out. We were unable to either send the authentication request to the internal Hybrid Identity Service. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80003", "Invalid response received by Authentication Agent. An unknown error occurred while attempting to authentication against Active Directory on-premises. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80005", "Authentication Agent: An unknown error occurred while processing the response from the Authentication Agent. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80007", "Authentication Agent unable to validate users password.") ;
            $AADSignOnError.add("80010", "Authentication Agent unable to decrypt password.") ;
            $AADSignOnError.add("80011", "Authentication Agent unable to retrieve encryption key.") ;
            $AADSignOnError.add("80012", "The users attempted to log on outside of the allowed hours (this is specified in AD).") ;
            $AADSignOnError.add("80013", "The authentication attempt could not be completed due to time skew between the machine running the authentication agent and AD. Fix time sync issues") ;
            $AADSignOnError.add("80014", "Authentication agent timed out. Open a support ticket with the error code, correlation ID, and Datetime to get more details on this error.") ;
            $AADSignOnError.add("81001", "Users Kerberos ticket is too large. This can happen if the user is in too many groups and thus the Kerberos ticket contains too many group memberships. Reduce the users group memberships and try again.") ;
            $AADSignOnError.add("81005", "Authentication Package Not Supported.") ;
            $AADSignOnError.add("81007", "Tenant is not enabled for Seamless SSO.") ;
            $AADSignOnError.add("81012", "This is not an error condition. It indicates that user trying to sign in to Azure AD is different from the user signed into the device. You can safely ignore this code in the logs.") ;
            $AADSignOnError.add("90010", "The request is not supported for various reasons. For example, the request is made using an unsupported request method (only POST method is supported) or the token signing algorithm that was requested is not supported. Contact the application developer.") ;
            $AADSignOnError.add("90014", "A required field for a protocol message was missing, contact the application owner. If you are the application owner, ensure that you have all the necessary parameters for the login request.") ;
            $AADSignOnError.add("90051", "Invalid Delegation Token. Invalid national Cloud ID ({cloudId}) is specified.") ;
            $AADSignOnError.add("90072", "The account needs to be added as an external user in the tenant first. Sign-out and sign-in again with a different Azure AD account.") ;
            $AADSignOnError.add("90094", "The grant requires administrator permissions. Ask your tenant administrator to provide consent for this application.") ;
            $AADSignOnError.add("500021", "Tenant is restricted by company proxy. Denying the resource access.") ;
            $AADSignOnError.add("500121", "Authentication failed during strong authentication request.") ;
            $AADSignOnError.add("500133", "The assertion is not within its valid time range. Ensure that the access token is not expired before using it for user assertion, or request a new token.") ;
            $AADSignOnError.add("530021", "Application does not meet the conditional access approved app requirements.") ;
            $AADSignOnError | write-output ;
        }
        #*------^ Initialize-AADSignErrorsHash.ps1 ^------
    }

    #-------v Function Cleanup v-------
    function Cleanup {
        # clear all objects and exit
        # Clear-item doesn't seem to work as a variable release

        # 12:40 PM 10/23/2018 added write-log trainling bnr
        # 2:02 PM 9/21/2018 missing $timestampnow, hardcode
        # 8:45 AM 10/13/2015 reset $DebugPreference to default SilentlyContinue, if on
        # # 8:46 AM 3/11/2015 at some time from then to 1:06 PM 3/26/2015 added ISE Transcript
        # 8:39 AM 12/10/2014 shifted to stop-transcriptLog function
        # 7:43 AM 1/24/2014 always stop the running transcript before exiting
        if ($showdebug) {"CLEANUP"}
        #stop-transcript
        # 11:16 AM 1/14/2015 aha! does this return a value!??
        if($host.Name -eq "Windows PowerShell ISE Host"){
            # 8:46 AM 3/11/2015 shift the logfilename gen out here, so that we can arch it
            #$Logname= (join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + (get-date -uformat "%Y%m%d-%H%M" ) + "-ISEtrans.log")) ;
            # 2:16 PM 4/27/2015 shift to static timestamp $timeStampNow
            #$Logname= (join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + $timeStampNow + "-ISEtrans.log")) ;
            # 2:02 PM 9/21/2018 missing $timestampnow, hardcode
            $Logname=(join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + (get-date -format 'yyyyMMdd-HHmmtt') + "-ISEtrans.log")) ;
            write-host "`$Logname: $Logname";
            Start-iseTranscript -logname $Logname ;
            #Archive-Log $Logname ;
            # 1:23 PM 4/23/2015 standardize processing file so that we can send a link to open the transcript for review
            $transcript = $Logname
        } else {
            if($showdebug){ write-debug "$(get-timestamp):Stop Transcript" };
            Stop-TranscriptLog ;
            #if($showdebug){ write-debug "$(get-timestamp):Archive Transcript" };
            #Archive-Log $transcript ;
        } # if-E

        # 4:05 PM 10/11/2018 add trailing notifc
        # 12:09 PM 4/26/2017 need to email transcript before archiving it
        if($showdebug){ write-host -ForegroundColor Yellow "Mailing Report" };

        #$smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;

        #Load as an attachment into the body text:
        #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
        #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
        # 4:07 PM 10/11/2018 giant transcript, no send
        #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
        $SmtpBody += "Pass Completed $([System.DateTime]::Now)`nTranscript:($transcript)" ;
        $SmtpBody += "`n$('-'*50)" ;
        #$SmtpBody += (gc $outtransfile | ConvertTo-Html) ;
        # name $attachment for the actual $SmtpAttachment expected by Send-EmailNotif
        #$SmtpAttachment=$transcript ;
        # 1:33 PM 4/28/2017 test for ERROR|CHANGE
        #if($PassStatus ){
            Send-EmailNotif ;
        #} else {
         #   write-host -foregroundcolor green "No Email Report: `$Passstatus is $null ; " ;
        #}  ;


        #11:10 AM 4/2/2015 add an exit comment
        Write-Verbose "END $BARSD4 $scriptBaseName $BARSD4" -Verbose:$verbose
        Write-Verbose "$BARSD40" -Verbose:$verbose
        # finally restore the DebugPref if set
        if ($ShowDebug -OR ($DebugPreference = "Continue")) {
            Write-Verbose -Verbose:$true "Resetting `$DebugPreference from 'Continue' back to default 'SilentlyContinue'" ;
            $showdebug=$false
            # 8:41 AM 10/13/2015 also need to enable write-debug output (and turn this off at end of script, it's a global, normally SilentlyContinue)
            $DebugPreference = "SilentlyContinue" ;
        } # if-E

        $smsg= "#*======^ END PASS:$($ScriptBaseName) ^======" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        break;

    } #*------^ END Function Cleanup ^------


    #*======^ END FUNCTIONS ^======

    #*======v SUB MAIN v======

    # 9:38 AM 8/29/2019 some errors say open a ticket with: Correlation ID, Request ID, and Error code, added to both prop sets
    $failprops = "createdDateTime", "userPrincipalName", "appDisplayName", "resourceDisplayName", "clientAppUsed", "ipAddress", "deviceDetail", "location","riskState","riskLevelAggregated","riskLevelDuringSignIn","riskDetail","riskEventTypes","riskLevel","status","correlationId","originalRequestId","status.errorCode" ;
    $recentevtprops = "createdDateTime", "userPrincipalName", "appDisplayName", "resourceDisplayName", "clientAppUsed", "ipAddress", "deviceDetail", "location", "riskState", "riskLevelAggregated", "riskLevelDuringSignIn", "riskDetail", "riskEventTypes", "riskLevel", "status","correlationId","originalRequestId" ;

    $AADSignOnError = Initialize-AADSignErrorsHash ;

    <#, no mods at this point, it's all simple json data parsi
    #[array]$reqMods=$null ; # force array, otherwise single first makes it a [string]
    # these are the one's that don't have explicit $reqMods+=, above their load blocks (below):
    # Most verb-module PSS's require these two as well
    $reqMods+="Add-PSTitleBar;Remove-PSTitleBar".split(";") ;
    #Disconnect-EMSR (variant name in some ps1's for Disconnect-Ex2010)
    #$reqMods+="Reconnect-CCMS;Connect-CCMS;Disconnect-CCMS".split(";") ;
    #$reqMods+="Reconnect-SOL;Connect-SOL;Disconnect-SOL".split(";") ;
    $reqMods+="Test-TranscriptionSupported;Test-Transcribing;Stop-TranscriptLog;Start-IseTranscript;Start-TranscriptLog;get-ArchivePath;Archive-Log;Start-TranscriptLog".split(";") ;
    # 12:15 PM 9/12/2018 remove dupes
    $reqMods=$reqMods| select -Unique ;
    #>
    $ofile = join-path -path (Split-Path -parent $MyInvocation.MyCommand.Definition) -ChildPath "logs" ;
    if(!(test-path -path $ofile)){ "Creating missing log dir $($ofile)..." ; mkdir $ofile  ; } ;

    $transcript= join-path -path $ofile -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))-Transcript-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-trans-log.txt"  ;
    # 10:21 AM 10/18/2018 add log file variant as target of Write-Log:
    $logfile = join-path -path $ofile -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-LOG.txt"  ;
    $logging = $True ;
    $smsg= "#*======v START PASS:$($ScriptBaseName) v======" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;


    #start-TranscriptLog $Transcript


    # Clear error variable
    $Error.Clear() ;
    <##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    # SCRIPT-CLOSE MATERIAL TO CLEAR THE UNDERLYING $DBGPREF & $EAPREF TO DEFAULTS:
    if ($ShowDebug -OR ($DebugPreference = "Continue")) {
            Write-Verbose -Verbose:$true "Resetting `$DebugPreference from 'Continue' back to default 'SilentlyContinue'" ;
            $showDebug=$false
            # 8:41 AM 10/13/2015 also need to enable write-debug output (and turn this off at end of script, it's a global, normally SilentlyContinue)
            $DebugPreference = "SilentlyContinue" ;
    } # if-E ;
    if($ErrorActionPreference -eq 'Stop') {$ErrorActionPreference = 'Continue' ; write-debug "(Restoring `$ErrorActionPreference:$ErrorActionPreference;"};
    #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    #>


    $rgxSID="^S-\d-\d+-(\d+-){1,14}\d+$" ;

    write-host -foregroundcolor green "Net:$(($Files|measure).count) Json Files" ;
    $ttl=($Files|measure).count ;
    $Procd=0 ;
    foreach ($File in $Files){
        $Procd++ ;
        # 9:20 AM 2/25/2019 Tickets will be an array of nnn's to match the mbxs, so use $Procd-1 as the index for tick# in the array

        # build outfile on the $file fullname
        $ofileobj=gci $File ;
        # $ofileobj=gci "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json" ;
        $logfile = $ofileobj.fullname.replace(".json","-parsed-json-rpt.txt") ;

        $sBnr="#*======v `$File:($($Procd)/$($ttl)):$($File) v======" ;
        $smsg="$($sBnr)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $smsg="Processing output into: $($logfile)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $bConfirmDo=$true ;
        #if($showDebug){Write-Verbose -Verbose:$true "$($File):is present on the `$ConfirmList" };

        if($bConfirmDo){

            #$jFile="c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json" ;
            if ($EVTS = gc $File | Convertfrom-json) {

                # oddity, get-host in ISE returns -1,-1 for fg & bg colors, but the color names in any other host
                $hostsettings = get-host ;
                if ($hostsettings.name -eq 'Windows PowerShell ISE Host') {
                    $bgcolordefault = "Black" ;
                    $fgcolordefault = "gray" ;
                }
                else {
                    $bgcolordefault = $hostsettings.ui.rawui.BackgroundColor ;
                    $fgcolordefault = $hostsettings.ui.rawui.ForegroundColor ;
                } ;
                $evtsProfiled = $evts | ? { $_.status.signinstatus -eq 'Failure' };
                $fltrDesc = "(`$_.status.signinstatus -eq 'Failure')" ;
                #$colors = (get-colorcombo -random) ;

                $smsg = "`n`n==Json Parsing AAD Sign-ins`nin file:$($File)`n`n$((($EVTS|measure).count|out-string).trim()) events found in file`n" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                $smsg = "`n`n==ALL Grouped Status.signinstatus (if populated):`n$(($EVTS.status.signinstatus | group| sort count -des | format-table -auto count,name|out-string).trim())`t" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==ALL Grouped Status.errorCode :`n$(($EVTS.status.errorCode | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==ALL Grouped Appdisplaynames:`n$(($EVTS | group appDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==ALL Grouped Resourcedisplayname :`n$(($EVTS | group resourceDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==ALL Grouped Clientappused:`n$(($EVTS | group clientAppUsed | sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==ALL Grouped devicedetail.operatingsystem:`n$((($evts|?{$_.deviceDetail}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped on devicedetail.operatingsystem:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped on deviceDetail.browser:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).deviceDetail.browser | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped Clientappused:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).Clientappused | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                write-host @colors "$($smsg)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug



                #$smsg= "`n`n==resourcedisplayname:'office 365 exchange online'`nDumped where non-zero status.errorcode:`n`n$(($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'} | ?{$_.status.errorCode -ne 0} | fl createdDateTime, userPrincipalName, appDisplayName, resourceDisplayName, clientAppUsed, ipAddress, deviceDetail, location,risk*,status|out-string).trim())`n`n" ;

                # 8:32 AM 8/21/2019 profile fails
                if ($evtsfail = $evts | ? { $_.status.errorcode -ne '0' } ) {

                    $smsg = "`n`n==FAILED (errorcode -ne 0) EVTS FOUND. PROFILING...`n`n " ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor YELLOW "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    # collect resourceDisplayNames
                    $resDnames = $evtsfail | select -unique resourceDisplayName | select -expand resourceDisplayName ;
                    # collect Appdisplaynames
                    $AppDnames = $evtsfail | select -unique Appdisplaynames | select -expand Appdisplaynames ;
                    # collect clientAppUsed
                    $ClientAppUseds = $evtsfail | select -unique clientAppUsed | select -expand clientAppUsed ;

                    <#
                    #>foreach ($resDname in $resDnames) {
                        $smsg = "`n`n--Profiling resourceDisplayNames:$($resDname)..`n`n " ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    }
                    #>
                    $smsg = "`n`n==FAILED Grouped Appdisplaynames:`n$(($evtsfail | group appDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    $smsg = "`n`n==FAILED Grouped Resourcedisplayname :`n$(($evtsfail | group resourceDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    $smsg = "`n`n==FAILED Grouped Clientappused:`n$(($evtsfail | group clientAppUsed | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    $smsg = "`n`n==FAILED Grouped devicedetail.operatingsystem:`n$((($evtsfail|?{$_.deviceDetail}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    # geo profile
                    $smsg = "`n`n==FAILED Grouped location.city:`n$(($evtsfail.location.city | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                    $smsg = "`n`n==FAILED Grouped location.state:`n$(($evtsfail.location.state | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    #$colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                    $smsg = "`n`n==FAILED Grouped location.countryOrRegion:`n$(($evtsfail.location.countryOrRegion | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    #$colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    # status details
                    $smsg = "`n`n==FAILED Grouped status.failurereason:`n$(($evtsfail.status.failurereason | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    write-host @colors "$($smsg)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug

                    <#
                    #$smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nDumped where non-zero status.errorcode:`n`n" ;
                    $smsg = "`n`n==Dumped Failures (status.errorcode -ne 0):`n`n" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } ; #Error|Warn|Debug

                    #$dumpevts = $evtsfail | ? { $_.resourcedisplayname -eq 'office 365 exchange online' }  ;
                    $dumpevts = $evtsfail | sort Resourcedisplayname, Appdisplaynames, Clientappused  ;
                    foreach ($devt in $dumpevts) {
                        $sBnrS = "`n#*------v $($devt.createdDateTime): v------"
                        $smsg = "$($sBnrS)`n$(($devt| fl $failprops |out-string).trim())`b$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                        # "riskState","riskLevelAggregated","riskLevelDuringSignIn","riskDetail","riskEventTypes","riskLevel"
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } ; #Error|Warn|Debug
                    } ;
                    #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } ; #Error|Warn|Debug
                    #>

                }
                else {
                    $smsg = "`n`n==(no fail/errorcode <> 0 evts found" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;


                # SignOns  profiled
                #$profTag="OWA" ;
                $profTags = "FAIL", "ErrNon0", "Exo-OWA", "Exo-MobileAndDesktopClients", "OlderOfcClients", "ActiveSync", "IMAP", "POP", "MAPI", "SMTP" ;

                foreach ($profTag in $profTags) {
                    switch ($profTag) {
                        "FAIL" {
                            $evtsProfiled = $evts | ? { $_.status.signinstatus -eq 'Failure' };
                            $fltrDesc = "(`$_.status.signinstatus -eq 'Failure')" ;
                            $colors = (get-colorcombo -random) ;
                            <# $_.status.signinstatus -eq 'Failure'
                            #>
                        } ;
                        "ErrNon0" {
                            $evtsProfiled = $evts | ? { $_.status.errorcode -ne '0' };
                            $fltrDesc = "(`$_.status.errorcode -ne '0')" ;
                            $colors = (get-colorcombo -random) ;

                        } ;
                        "Exo-OWA" {
                            $evtsProfiled = $evts | ? { ($_.resourceDisplayName -eq 'office 365 exchange online') -AND ($_.clientAppUsed -eq 'Browser') };
                            $fltrDesc = "(`$_.resourceDisplayName -eq 'office 365 exchange online') -AND (`$_.clientAppUsed -eq 'Browser')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "Exo-MobileAndDesktopClients" {
                            $evtsProfiled = $evts | ? { ($_.resourceDisplayName -eq 'office 365 exchange online') -AND ($_.clientAppUsed -eq 'Mobile Apps and Desktop clients') };
                            $fltrDesc = "(`$_.resourceDisplayName -eq 'office 365 exchange online') -AND (`$_.clientAppUsed -eq 'Mobile Apps and Desktop clients')" ;
                            $colors = (get-colorcombo -random) ;

                        } ;
                        "OlderOfcClients" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; Older Office clients') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; Older Office clients')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "ActiveSync" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Exchange ActiveSync') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Exchange ActiveSync')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "IMAP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; IMAP') };
                            $fltrDesc = "`$_.clientAppUsed -eq 'Other clients; IMAP') " ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "POP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; POP') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; POP')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "MAPI" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; MAPI') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; MAPI')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "SMTP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; SMTP') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; SMTP')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;

                    } ;
                    $sBnrS = "`n#*------v $($profTag) SignOns Profiled  - $(($evtsProfiled|measure).count) events: : v------`n" ;
                    write-host -foregroundcolor yellow "$($sBnrS)`n$($fltrDesc)" ;
                    if ($evtsProfiled ) {

                        if ($profTag -match '(FAIL|ErrNon0)') {
                            #status
                            #deviceDetail
                            #location
                            $iDumpd = 0 ;
                            $ittl = ($evtsProfiled | measure).count ;
                            if ($evtsProfiled) {
                                foreach ($evt in $evtsProfiled) {
                                    $iDumpd++ ;
                                    write-host -foregroundcolor gray " - v Failure #$($iDumpd)/$($ittl) v -" ;
                                    write-host -foregroundcolor white "$(($evt| fl $failprops|out-string).trim())" ;
                                    write-host -foregroundcolor cyan "`nSTATUS:`n$(($evt| select -exp status|out-string).trim())" ;
                                    write-host -foregroundcolor cyan "`nDEVICEDETAIL:`n$(($evt| select -exp devicedetail|out-string).trim())" ;
                                    write-host -foregroundcolor darkgray "`nLOCATION:`n$(($evt | select -exp location|out-string).trim())" ;
                                    write-host -foregroundcolor gray " - ^ Failure #$($iDumpd)/$($ittl)) ^ -" ;
                                } ;
                            }
                            else {
                                "(no matching events to profile)"
                            }
                        }
                        else {
                            $colors = (get-colorcombo -random) ;
                            $smsg = "$($profTag) SignOns grouped status.signInStatus" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = $evtsProfiled.status.signInStatus | group | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $colors = (get-colorcombo -random) ;
                            $smsg = "$($profTag) SignOns grouped status.errorCode"
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret=$evtsProfiled.status.errorCode | group | sort count -des
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } ;
                            if ($errorcodes = $evtsProfiled.status.errorCode | group | select name) {
                                foreach ($ec in $errorcodes) {
                                    $errstring = $aadsignonerror["$($ec.name)"] ;
                                    $smsg = "ErrorCode:$($ec.name):$($errstring)" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                } ;
                                "`n" ;
                            }
                            else {
                                "(no errorcodes to group)"
                            }

                            $colors = (get-colorcombo -random) ;
                            $smsg = "$($profTag) SignOns grouped status.failureReason" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = $evtsProfiled.status.failureReason | group | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };
                            #write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):CMDLET w`n$((|out-string).trim())" ;

                            $colors = (get-colorcombo -random) ;
                            $smsg = "`n$($profTag) SignOns grouped location.countryOrRegion" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = $evtsProfiled | select -exp location | group countryOrRegion | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                write-host $smsg ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            }
                            else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $smsg = "$($profTag) SignOns grouped location.state" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = $evtsProfiled | select -exp location | group state | sort count -desc | format-table -auto count, name ;
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $colors = (get-colorcombo -random) ;
                            $smsg = "`n$($profTag) SignOns grouped ipAddress" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = $evtsProfiled | group ipAddress | sort Name | format-table -auto count, name ;
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $colors = (get-colorcombo -random) ;
                            $smsg = "`n$($profTag) SignOns grouped deviceDetail.browser" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            $ret = ($evtsProfiled.deviceDetail.browser | group $_ | sort count -des | format-table -auto count, name |out-string).trim();
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = ($ret | format-table -auto count, name |out-string).trim();
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $colors = (get-colorcombo -random) ;
                            $smsg = "`n$($profTag) SignOns grouped devicedetail.operatingsystem" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            write-host @colors
                            $ret = ($evtsProfiled.devicedetail.operatingsystem | group $_ | sort count -des | format-table -auto count, name | out-string).trim();
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = $ret | format-table -auto count, name ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $colors = (get-colorcombo -random) ;
                            $smsg = "$($profTag) SignOns grouped deviceDetail.displayname" ;
                            write-host @colors "$($smsg)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -Level Info -NoEcho } ; #Error|Warn|Debug
                            write-host @colors
                            $ret = ($evtsProfiled.deviceDetail.displayname | group $_ | sort count -des |out-string).trim();
                            if (!$ret) {
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            }
                            else {
                                $smsg = $ret | format-table -auto count, name ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            };

                            $sBnrSx = "`n#*------v Most Recent $($profTag) Event: v------" ;
                            write-host -foregroundcolor yellow "$($sBnrSx)" ;
                            $evtlast = ($evtsProfiled | sort createddatetime)[-1] ;
                            write-host -foregroundcolor white "$(($evtlast| format-list $recentevtprops |out-string).trim())" ;
                            write-host -foregroundcolor white "`nStatus details:`n$(($evtlast| select -expand Status|out-string).trim())" ;
                            write-host -foregroundcolor white "`nLocation details:`n$(($evtlast| select -expand location|out-string).trim())" ;
                            write-host -foregroundcolor yellow "$($sBnrSx.replace('-v','-^').replace('v-','^-'))" ;

                        } ;

                    }
                    else {
                        write-host @colors "(No signons matched traditional $($profTag) profile)" ;
                    } ;
                    $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;

                $sBnrS="`n#*------v Most Recent Event in series: v------" ;
                write-host -foregroundcolor yellow "$($sBnrS)" ;
                $evtlast=($evts| sort createddatetime)[-1] ;
                $dynprops = $evtlast.psobject.Properties | select -exp name |?{($_ -ne 'Status') -AND ($_ -ne 'Location') -ANd ($_ -ne 'deviceDetail')} ;

                write-host -foregroundcolor white "$(($evtlast| select $dynprops | format-list|out-string).trim())" ;
                write-host -foregroundcolor white "`nStatus details:`n$(($evtlast| select -expand Status|out-string).trim())" ;
                write-host -foregroundcolor white "`ndeviceDetail details:`n$(($evtlast| select -expand deviceDetail|out-string).trim())" ;
                write-host -foregroundcolor white "`nLocation details:`n$(($evtlast| select -expand location|out-string).trim())" ;
                write-host -foregroundcolor yellow "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;


                $smsg = "`n$($sBnr.replace('=v','=^').replace('v=','^='))`n" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            } ;
        } else {
            $smsg="$($UPN):Not on Confirm List" ;  ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
        # ========================================

        $smsg= "$($sBnr.replace('=v','=^').replace('v=','^='))`n`n" ;;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        start-sleep -Milliseconds 500 ; # 2:51 PM 10/11/2018 add a throttle pause
    } ;  # loop-E

    #stop-transcript ;
    #Cleanup
    #*======^ END SUB MAIN ^======
}

#*------^ profile-AAD-Signons.ps1 ^------

#*------v Remove-MsolUserDirectLicenses.ps1 v------
Function Remove-MsolUserDirectLicenses{
    <#
    .SYNOPSIS
    Remove-MsolUserDirectLicenses - The purpose of this script is to remove unnecessary direct licenses from users who already inherit the same license from a group; for example, as part of a transition to group-based licensing.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Remove-MsolUserDirectLicenses.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed Remove-MsolUserDirectLicenses; roughed in functionalize, put into OTB format, ren'd helperfuncs (added to verb-aad as well); COMPLETELY UNTESTED, REM'ING OUT THE GUTS, AGAINST FUTURE NEED
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Remove-MsolUserDirectLicenses - The purpose of this script is to remove unnecessary direct licenses from users who already inherit the same license from a group; for example, as part of a transition to group-based licensing.
    [!NOTE] It is important to first validate that the direct licenses to be removed do not enable more service functionality than the inherited licenses. Otherwise, removing the direct license may disable access to services and data for users. Currently it is not possible to check via PowerShell which services are enabled via inherited licenses vs direct. In the script, we specify the minimum level of services we know are being inherited from groups and check against that to make sure users do not unexpectedly lose access to services.
    .PARAMETER skuId
    License to be removed - Office 365 E3[-skuId 'contoso:ENTERPRISEPACK']
    .PARAMETER servicePlansFromGroups
    Minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled which could mean that they may lose access after we remove direct licenses[-servicePlansFromGroups ('EXCHANGE_S_ENTERPRISE', 'SHAREPOINTENTERPRISE', 'OFFICESUBSCRIPTION')]
    .PARAMETER groupId
    The group to be processed[-groupId '48ca647b-7e4d-41e5-aa66-40cab1e19101']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Object
    .EXAMPLE
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Parameter(Mandatory=$True,HelpMessage="license to be removed - Office 365 E3[-skuId 'contoso:ENTERPRISEPACK']")]
        [string]$skuId, 
        [Parameter(Mandatory=$True,HelpMessage="minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled which could mean that they may lose access after we remove direct licenses[-servicePlansFromGroups ('EXCHANGE_S_ENTERPRISE', 'SHAREPOINTENTERPRISE', 'OFFICESUBSCRIPTION')]")]
        [string[]]$servicePlansFromGroups,
        [Parameter(Mandatory=$True,HelpMessage="the group to be processed[-groupId '48ca647b-7e4d-41e5-aa66-40cab1e19101']")]
        [string]$groupId
    ) ; 
    
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        #the group to be processed
        #$groupId = "48ca647b-7e4d-41e5-aa66-40cab1e19101"

        #license to be removed - Office 365 E3
        #$skuId = "contoso:ENTERPRISEPACK"

        #minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled
        #which could mean that they may lose access after we remove direct licenses
        #$servicePlansFromGroups = ("EXCHANGE_S_ENTERPRISE", "SHAREPOINTENTERPRISE", "OFFICESUBSCRIPTION")

        <#
        $expectedDisabledPlans = Get-MsolUnexpectedEnabledPlansForUser $skuId $servicePlansFromGroups

        #process all members in the group and get full info about each user in the group looping through group members. 
        Get-MsolGroupMember -All -GroupObjectId $groupId | Get-MsolUser -ObjectId {$_.ObjectId} | Foreach {
                $user = $_;
                $operationResult = "";

                #check if Direct license exists on the user
                if (test-MsolUserLicenseDirectAssigned $user $skuId){
                    #check if the license is assigned from this group, as expected
                    if (test-MsolUserLicenseGroupAssigned $user $skuId $groupId){
                        #check if there are any extra plans we didn't expect - we are being extra careful not to remove unexpected services
                        $extraPlans = Get-MsolUnexpectedEnabledPlansForUser $user $skuId $expectedDisabledPlans ; 
                        if ($extraPlans.Count -gt 0){
                            $operationResult = "User has extra plans that may be lost - license removal was skipped. Extra plans: $extraPlans" ; 
                        }else{
                            #remove the direct license from user
                            Set-MsolUserLicense -ObjectId $user.ObjectId -RemoveLicenses $skuId ; 
                            $operationResult = "Removed direct license from user."    ; 
                        } ; 

                    }else{
                        $operationResult = "User does not inherit this license from this group. License removal was skipped." ; 
                    } ; 
                } else {
                    $operationResult = "User has no direct license to remove. Skipping." ; 
                } ; 

                #format output
                New-Object Object |
                    Add-Member -NotePropertyName UserId -NotePropertyValue $user.ObjectId -PassThru |
                    Add-Member -NotePropertyName OperationResult -NotePropertyValue $operationResult -PassThru ; 
        } | Format-Table ; 
        
        #>
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ Remove-MsolUserDirectLicenses.ps1 ^------

#*------v resolve-GuestExternalAddr2UPN.ps1 v------
Function resolve-GuestExternalAddr2UPN {
    <#
    .SYNOPSIS
    resolve-GuestExternalAddr2UPN - Convert a given External Address into the equivelent Guest UPN, in the local Tenant.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 20200827-0342PM
    FileName    : resolve-GuestExternalAddr2UPN.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    REVISIONS   :
    * 3:26 PM 8/27/2020 init
    .DESCRIPTION
    resolve-GuestExternalAddr2UPN - Convert a given External Address into the equivelent Guest-format UPN, for local Tenant (or Tenant specified by the use of -Credential) .
    .PARAMETER ExternalEmailAddress
    External SMTP Email Address to be resolved to Guest UPN [-ExternalEmailAddress email@gmail.com]
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a string containing the resolved Guest-format UPN
    .EXAMPLE
    resolve-GuestExternalAddr2UPN -Exte email@gmail.com ;
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = resolve-GuestExternalAddr2UPN -UPNs $exombx.userprincipalname -showdebug:$($showdebug) ; 
    Convert email@gmail.com into an equivelent local-Tenant Guest UPN
    .LINK
     https://github.com/tostka/verb-AAD/
    #>
    #Requires -Version 3
    #Requires -Modules AzureAD
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("(lyn|bcc|spb|adl)ms6(4|5)(0|1).(china|global)\.ad\.toro\.com")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    # SMTP rgx: "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$"
    Param(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="External SMTP Email Address to be resolved to Guest UPN [-ExternalEmailAddress email@gmail.com]")]
        [ValidatePattern("^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")]
        [string]$ExternalEmailAddress,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
    ) ;
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        # Get parameters this function was invoked with
        $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        $Verbose = ($VerbosePreference -eq 'Continue') ;
        #$script:PassStatus = $null ;
    } ;
    PROCESS {
        $Error.Clear() ;
        #$ObjReturn=@() ;
        <#$hshRet=[ordered]@{
            Cred=$null ;
            credType=$null ;
        } ;
        #>

        Connect-AAD -Credential:$Credential -verbose:$($verbose) ;
        <#
        if($script:useEXOv2){
            reconnect-eXO2 -Credential:$Credential -verbose:$($verbose) ;
        } else {
            reconnect-EXO -Credential:$Credential -verbose:$($verbose) ;
        } ;
        #>
        $extDom = [regex]::match($ExternalEmailAddress,'@(\w+\.\w+)').captures[0].groups[1].value ;
        $extDom = ($extdom.substring(0,1).toupper())+($extdom.substring(1).tolower()) ;
        $error.clear() ;
        TRY {
            $TenDtl=Get-AzureADTenantDetail ;
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 
        $TenDom = $TenDtl.VerifiedDomains.name -match '^\w*\.onmicrosoft\.com' ;
        $tUPN = "$($ExternalEmailAddress.replace('@','_'))#EXT#@$($TenDom)" ;
        write-verbose "Converted $($ExternalEmailAddress) to equiv Guest UPN:`n$($tUPN)" ; 
    } ; # E-PROC
    END { $tUPN | write-output} ; 
}

#*------^ resolve-GuestExternalAddr2UPN.ps1 ^------

#*------v search-AADSignInReports.ps1 v------
Function search-AADSignInReports {
    <#
    .SYNOPSIS
    search-AADSignInReports.ps1 - Runs GraphAPI RestAPI queries, leveraging certificate-authenticated Tockens
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : search-AADSignInReports.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs
    AddedCredit : Alex Asplund;Tim Spring MSFT
    AddedWebsite: https://automativity.com;https://github.com/TspringMSFT/
    AddedTwitter: @AlexAsplund
    GraphAPI -filter parameter reference on 875: ==== v GRAPH API FILTER PARAM USE:
    REVISIONS   :
    * 10:47 AM 6/16/2021 added record count echo (easier to verifiy return worked) ; purged more rem'd cd ; revised start-log code (accomd cmdlet in allusers module), swapped in all $ofile => sl $logfile w variant exts, moved logging down into the UPN loop ; trimmed rem'd code shifted to search-graphapiAAD() (confirmed functional) ; removed local buffered copies of  get-AADTokenHeaders, get-AADCertToken, search-GraphApiAAD (they're in same module now, no need to buffer)
    * 12:50 PM 6/15/2021 ren Pull-AADSignInReports.ps1 -> search-AADSignInReports.ps1 (compliant verb); porting into verb-aad; added start-log logging ; rearranged trailing graphapi filter param ref, into body, above code where qry is built; removed obsolete/broken *BearerToken() funcs. Made all funcs condityional, and deferential to modules. 
    * 3:16 PM 6/14/2021 made local aad funcs, conditional - defer to verb-aad versions ; fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out redund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
    * 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
    * 7:33 AM 2/28/2020 fixed BadIf
    * 6:40 PM 1/30/2020 rounded out, functional, cleaned up
    * 8:28 AM 1/30/2020 MS fundementally BROKE ADAL token auth (in Azure module). Finally got back to function using to simple Json Invoke-WebRequest auth'd via AAD Registered App + Cert auth, query results now also appears to have *flipped* from returning a json (requiring convers for use) to returning a straight object. Used AAspend's cert auth code (conv to get-AADCertToken() & get-AADTokenHeaders()) & simple append aggreg code, tossed out all of Tim Spring's fancier material (now broken), except the try/catch error sorting, which *still* covers retrying, throttling, and simple perm etc fails. 
    * 3:09 PM 1/27/2020 ren:  get-AADBearToken -> get-AADBearerToken
    * 1:52 PM 8/28/2019 shifted some code into recyclable functions
    * 2:50 PM 8/27/2019 flipped all the renamed xml fieldnames back to the low-level names. also exported the json from the raw $MyReport obj, convertto-json'd.
        Trying to profile-AAD-Signons.ps1 against the exported $xmlreportvalues object (vs orig json obj) resulted in errors.
        Using the exported json from the orig object worked fine.
    * 7:48 AM 8/27/2019 v0.1.0 adding pshelp,passed debugging, base code functional
    * 3/1/19 - posted version
    .DESCRIPTION
    search-AADSignInReports.ps1 - Runs GraphAPI RestAPI queries, leveraging certificate-authenticated Tockens
    This script uses RestAPI calls to authenticate and query GraphAPI. 
    As written, it Authenticates with a certificate 
    **Script configuration:**
    - Update the following parameter default values to your target Tenants values:
    |param|info source|
    |---|---|
    |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
    |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
    |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
    |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|
    #-=-=-=-=-=-=-=-=
    The script queries the Azure AD Audit Graph endpoint for Sign In report entries.
    More information about the filtering options and the data returned can
    be found online at this link:
    https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta
    .PARAMETER TenOrg
    TenantTag value, indicating Tenants to connect to[-TenOrg 'TOL']
    .PARAMETER UPNs
    User UPNs to be processed (array)[-UPNS 'user1@domain.com','user2@domain.com
    .PARAMETER QueryApp
    Application to be filtered target of query (EXO|SFO)[-QueryApp EXO]
    .PARAMETER StartDate
    StartDate (defaults 7d) [-StartDate (Get-Date)]
    .PARAMETER EndDate
    EndDate (defaults now)
    .PARAMETER TopUnits
    Number of records to return per bundle (defaults 1000)[-TopUnits 1000]
    .PARAMETER tenantName
    AAD tenantName [-tenantName (guid)]
    .PARAMETER tenantId
     TenantID (defaulted TOR) [-TenantID (guid)]
    .PARAMETER AppID
    AAD RegisteredApp to execute the query [-AppID (guid)]
    .PARAMETER Certificate
    Authenticating certificate [-Certificate (thumbprint)]
    .PARAMETER Tickets
    Tickets associated with ea UPN #[-Tickets '999999','999998']
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Json & CSV files
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs fname.lname@domain.com -ticket 456277 -showdebug ;
    Retrieve default, last7 days of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs fname.lname@domain.com -ticket 456277 -StartDate (Get-Date).AddDays(-30) -showdebug ;
    Retrieve custom interval (last 30d) of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs "fname.lname@domain.com","Sarah.Bell@toro.com" -ticket "456277","452916" -StartDate (Get-Date).AddDays(-30) -showdebug ;
    Retrieve custom interval (last 30d) of signon records for array of UPNs & tickets
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    #Requires -Modules verb-Auth, verb-IO, verb-logging, verb-Text
    #Requires -RunasAdministrator
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$FALSE,HelpMessage="TenantTag value, indicating Tenants to connect to[-TenOrg 'TOL']")]
        [ValidateNotNullOrEmpty()]
        $TenOrg = 'TOR',    
        [Parameter(Position = 0, HelpMessage = "User UPNs to be processed (array)[-UPNS 'user1@domain.com','user2@domain.com]")]
        $UPNs,
        [Parameter(HelpMessage = "Application to be filtered target of query (EXO|SFO)[-QueryApp EXO]")]
        [ValidateSet("EXO", "SFO")]
        [string]$QueryApp,
        [parameter(HelpMessage = "StartDate (defaults 7d) [-StartDate (Get-Date)]")]
        [datetime]$StartDate = (Get-Date).AddDays(-7),
        [parameter(HelpMessage = "EndDate (defaults now)")]
        [datetime]$EndDate = (Get-Date),
        [parameter(HelpMessage = "Number of records to return per bundle (defaults 1000)[-TopUnits 1000]")]
        [int]$TopUnits = 1000,
        [Parameter(HelpMessage = "AAD tenantName [-tenantName (guid)]]")]
        [string]$tenantName = $global:TorMeta.o365_TenantDomain,
        [Parameter(HelpMessage = "AAD TenantID (defaulted TOR) [-TenantID (guid)]")]
        [string]$tenantId = $global:TorMeta.o365_Tenantid,
        [Parameter(HelpMessage = "AAD RegisteredApp to execute the query [-AppID (guid)]]")]
        [string]$AppID = $global:TORMeta.AAD_App_Audit_ID,
        [Parameter(HelpMessage = "Authenticating certificate [-Certificate (thumbprint)]]")]
        $Certificate = $global:tormeta.AAD_App_Audit_CertThumb,
        [parameter(HelpMessage = "Tickets associated with ea UPN #[-Tickets '999999','999998']")]
        [array]$Tickets,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    # AppSecret token requires -TenantID
    # Cert token requires -tenantName

    #region INIT; # ------
    #*======v SCRIPT/DOMAIN/MACHINE/INITIALIZATION-DECLARE-BOILERPLATE v======
    $verbose = ($VerbosePreference -eq "Continue") ; 
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    # Get parameters this function was invoked with
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
    if ($PSScriptRoot -eq "") {
        if ($psISE) { $ScriptName = $psISE.CurrentFile.FullPath }
        elseif ($context = $psEditor.GetEditorContext()) {$ScriptName = $context.CurrentFile.Path }
        elseif ($host.version.major -lt 3) {
            $ScriptName = $MyInvocation.MyCommand.Path ;
            $PSScriptRoot = Split-Path $ScriptName -Parent ;
            $PSCommandPath = $ScriptName ;
        } else {
            if ($MyInvocation.MyCommand.Path) {
                $ScriptName = $MyInvocation.MyCommand.Path ;
                $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent ;
            } else {throw "UNABLE TO POPULATE SCRIPT PATH, EVEN `$MyInvocation IS BLANK!" } ;
        };
        $ScriptDir = Split-Path -Parent $ScriptName ;
        $ScriptBaseName = split-path -leaf $ScriptName ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($ScriptName) ;
    } else {
        $ScriptDir = $PSScriptRoot ;
        if ($PSCommandPath) {$ScriptName = $PSCommandPath }
        else {
            $ScriptName = $myInvocation.ScriptName
            $PSCommandPath = $ScriptName ;
        } ;
        $ScriptBaseName = (Split-Path -Leaf ((& { $myInvocation }).ScriptName))  ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;
    } ;
    if ($showDebug) { write-debug -verbose:$true "`$ScriptDir:$($ScriptDir)`n`$ScriptBaseName:$($ScriptBaseName)`n`$ScriptNameNoExt:$($ScriptNameNoExt)`n`$PSScriptRoot:$($PSScriptRoot)`n`$PSCommandPath:$($PSCommandPath)" ; } ;
    $ComputerName = $env:COMPUTERNAME ;
    $NoProf = [bool]([Environment]::GetCommandLineArgs() -like '-noprofile'); # if($NoProf){# do this};
    # silently stop any running transcripts
    $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;

    
    # Clear error variable
    $Error.Clear() ;
    
    $sBnr="#*======v $(${CmdletName}): v======" ;
    $smsg = $sBnr ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    # 1:11 PM 6/14/2021 provide dyn param lookup on $TenOrg, via meta infra file

    if(!($tenantName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain)){throw "missing $($TenOrg)meta.value.o365_TenantDomain!" ; break ; } ;
    if(!($tenantId = (gv -name "$($TenOrg)meta").value.o365_Tenantid)){throw "missing $($TenOrg)meta.value.o365_Tenantid!" ; break ; } ;
    if(!($AppID = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_ID)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_ID!" ; break ; } ;
    if(!($Certificate = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_CertThumb)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_CertThumb!" ; break ; } ;

    if(!$MSGraphScope){
        $MSGraphScope = 'https://graph.microsoft.com' ;
        ##$resourceAppIdURI = "https://graph.microsoft.com"
        #$MSGraphURI = "https://graph.microsoft.com"
    } ;
    $MSGraphURI = $MSGraphScope ;

    #$redirectUri      = "https://RedirectURI.com"                #Your Application's Redirect URI
    #$redirectUri = "https://placemarker.com"                #Your Application's Redirect URI
    # redir uri for PS bearer token script(?)
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"


    $ttl = ($UPNs | Measure-Object).count ;
    $tickNum = ($tickets | Measure-Object).count
    if ($ttl -ne $tickNum ) {
        write-host -foregroundcolor RED "$((get-date).ToString('HH:mm:ss')):ERROR!:You have specified $($ttl) UPNs but only $($tickNum) tickets.`nPlease specified a matching number of both objects." ;
        Break ;
    } ;

    # below is hard-coded dates, 2/1/196am to 2/28/19 7am.
    #$fullUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime%20ge%202019-02-01T06:00:00Z%20and%20createdDateTime%20le%202019-02-28T00:07:01.607Z&`$top=1000"

    # UPN query 1 return: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1

    $formattedStart = " {0:s}" -f $StartDate + 'Z' ;
    $formattedEnd = " {0:s}" -f $EndDate + 'Z' ; 
    $baseUri = "$($MSGraphURI)/" ;

    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    # cmdline alt
    #$Request =get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
    # splatted:
    $smsg = "get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $token =get-AADCertToken @pltAADCertToken ; 
    # build tokenheader from token
    $pltAADCertTokenHdr=[ordered]@{token=$token ;Verbose=$($VerbosePreference -eq 'Continue');};
    $smsg = "get-AADTokenHeaders w`n$(($pltAADCertTokenHdr|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $AADTokenHeaders = get-AADTokenHeaders @pltAADCertTokenHdr ;

    <# --==== v GRAPH API FILTER PARAM USE: v ===--
    Use query parameters to customize responses - Microsoft Graph | Microsoft Docs - https://docs.microsoft.com/en-us/graph/query-parameters

    Support for $filter operators varies across Microsoft Graph APIs. The following logical operators are generally supported:

        equals (eq)
        not equals (ne)
        greater than (gt)
        greater than or equals (ge)
        less than (lt), less than or equals (le)
        and (and)
        or (or)
        not (not)


    Note: The following $filter operators are not supported for Azure AD resources: ne, gt, ge, lt, le, and not.
        The contains string operator is currently not supported on any Microsoft Graph resources.

    Note: The startswith string operator is often supported. The any lambda operator is supported for some APIs. For some usage examples, see the following table. For more details about $filter syntax, see the OData protocol

    $filter operator supported logical operators:

    The following table shows some examples that use the $filter query parameter.

        Note: Click the examples to try them in Graph Explorer.

    > On the beta endpoint, the $ prefix is optional. For example, instead of $filter, you can use filter. On the v1 endpoint, the $ prefix is optional for only a subset of APIs. For simplicity, always include $ if using the v1 endpoint.


    Search for users with the name Mary across multiple properties.
    https://graph.microsoft.com/v1.0/users?$filter=startswith(displayName,'mary') or startswith(givenName,'mary') or startswith(surname,'mary') or startswith(mail,'mary') or startswith(userPrincipalName,'mary')

    Get all the signed-in user's events that start after 7/1/2017.
    https://graph.microsoft.com/v1.0/me/events?$filter=start/dateTime ge '2017-07-01T08:00'
    Get all RiskyEvents createdDateTime ge yyyy-MM-dd
    $url = "https://graph.microsoft.com/beta/identityRiskEvents?`$filter=createdDateTime ge XXXX-XX-XX"


    Get all emails from a specific address received by the signed-in user.
    https://graph.microsoft.com/v1.0/me/messages?$filter=from/emailAddress/address eq 'someuser@example.com'

    Get all emails received by the signed-in user in April 2017.
    https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=ReceivedDateTime ge 2017-04-01 and receivedDateTime lt 2017-05-01

    Select by user and createdDateTime
    https://graph.microsoft.com/beta/identityRiskEvents?`$filter=userPrincipalName eq 'username@domainsuffix' and createdDateTime ge xxxx-xx-xx

    Get all unread mail in the signed-in user's Inbox.
    https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=isRead eq false

    List all Office 365 groups in an organization.
    https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c+eq+'Unified')

    OData system query options    

    Name	Description	
        Example
    $count	Retrieves the total count of matching resources.(includes a count of the total number of items in a collection alongside the page of data values returned)	
        /me/messages?$top=2&$count=true
    $expand	Retrieves related resources.	
        /groups?$expand=members
      # gets root drive information along with the top-level child items in a drive
      GET https://graph.microsoft.com/v1.0/me/drive/root?$expand=children
      # ret specific props fr exp
        GET https://graph.microsoft.com/v1.0/me/drive/root?$expand=children($select=id,name)
      
    $filter	Filters results (rows).	
        /users?$filter=startswith(givenName,'J')
    $format	Returns the results in the specified media format.	
        /users?$format=json
      
    $orderby	Orders results.	
        /users?$orderby=displayName desc
    $search	Returns results based on search criteria. Currently supported on messages and person collections.	
        /me/messages?$search=pizza
    $select	Filters properties (columns). Wo you get the default dataset, select winnows it to specified	
        /users?$select=givenName,surname
    $skip	Indexes into a result set. Also used by some APIs to implement paging and can be used together with $top to manually page results.	
        /me/messages?$skip=11
    $top	Sets the page size of results.	
        /users?$top=2

    $skipToken	Retrieves the next page of results from result sets that span multiple pages. (Some APIs use $skip instead.)	
        /users?$skiptoken=X%274453707402000100000017...

    ---	
    Encoding query parameters:
    Values of query parameters should be percent-encoded. 
    An unencoded URL looks like this:
    GET https://graph.microsoft.com/v1.0/users?$filter=startswith(givenName, 'J')
    A properly encoded URL looks like this:
    GET https://graph.microsoft.com/v1.0/users?$filter=startswith(givenName%2C+'J')

    Escaping single quotes
    For requests that use single quotes, if any parameter values also contain single quotes, those must be double escaped
    In string value below  let''s meet for lunch? has the single quote escaped.
    GET https://graph.microsoft.com/v1.0/me/messages?$filter=subject eq 'let''s meet for lunch?'

    #Place all events related to EXO into an array
    # filtering appDisplayName *exchange*
    IMAP hack attempts have been coming in as:
    appDisplayName                   : Office 365
    resourceId                       :
    resourceDisplayName              :
    clientAppUsed                    : Other clients; IMAP
    deviceDetail                     : @{deviceId=; displayName=; operatingSystem=; browser=; isCompliant=; isManaged=;
                                        trustType=}

    ($event.appDisplayName -eq "Office 365" -ANd $event.clientAppUsed -eq 'Other clients; IMAP')

    Outlook logon:
    appDisplayName      : Microsoft Office
    resourceDisplayName : office 365 exchange online
    clientAppUsed       : Mobile Apps and Desktop clients
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=Windows 7; browser=IE 7.0; isCompliant=; isManaged=;
                            trustType=}

    ($event.appDisplayName -eq "Microsoft Office" -AND $event.resourceDisplayName -eq 'office 365 exchange online')

    OWA:
    appDisplayName      : Office 365 Exchange Online
    resourceDisplayName : office 365 exchange online
    clientAppUsed       : Browser
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=Windows 7; browser=IE 11.0; isCompliant=; isManaged=;
                            trustType=}


    Outlook 2010 (vpn):
    appDisplayName                   : Office 365 Exchange Online
    resourceId                       :
    resourceDisplayName              :
    clientAppUsed                    : Other clients; Older Office clients
    deviceDetail                     : @{deviceId=; displayName=; operatingSystem=; browser=Microsoft Office 15.0;
                                        isCompliant=; isManaged=; trustType=}


    ActiveSync:
    appDisplayName      : Office 365 Exchange Online
    resourceDisplayName :
    clientAppUsed       : Exchange ActiveSync
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=; browser=Mobile Safari; isCompliant=; isManaged=;
                            trustType=}
    --==== ^ GRAPH API FILTER PARAM USE: ^ ===--
    #>

    $iProcd=0 ;
    $UPNOrdinal=0 ;
    [array]$jsonFiles = @() ; # aggreg the files for output report BP


    foreach($UPN in $UPNs){
        $iProcd++ ;

        if(!(get-variable LogPathDrives -ea 0)){$LogPathDrives = 'd','c' };
        foreach($budrv in $LogPathDrives){if(test-path -path "$($budrv):\scripts" -ea 0 ){break} } ;
        if(!(get-variable rgxPSAllUsersScope -ea 0)){
            $rgxPSAllUsersScope="^$([regex]::escape([environment]::getfolderpath('ProgramFiles')))\\((Windows)*)PowerShell\\(Scripts|Modules)\\.*\.(ps(((d|m))*)1|dll)$" ;
        } ;
        $pltSL=[ordered]@{Path=$null ;NoTimeStamp=$false ;Tag=$null ;showdebug=$($showdebug) ; Verbose=$($VerbosePreference -eq 'Continue') ; whatif=$($whatif) ;} ;
        #$pltSL.Tag = $tickets -join ',' ;
        if($tickets[$iProcd-1]){$pltSL.Tag = "$($tickets[$iProcd-1])-$($UPN)"} ;
        if($script:PSCommandPath){
            if($script:PSCommandPath -match $rgxPSAllUsersScope){
                write-verbose "AllUsers context script/module, divert logging into [$budrv]:\scripts" ;
                if((split-path $script:PSCommandPath -leaf) -ne $cmdletname){
                    # function in a module/script installed to allusers 
                    $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath "$($cmdletname).ps1") ;
                } else { 
                    # installed allusers script
                    $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $script:PSCommandPath -leaf)) ;
                }
            }else {
                $pltSL.Path = $script:PSCommandPath ;
            } ;
        } else {
            if($MyInvocation.MyCommand.Definition -match $rgxPSAllUsersScope){
                 $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $script:PSCommandPath -leaf)) ;
            } else {
                $pltSL.Path = $MyInvocation.MyCommand.Definition ;
            } ;
        } ;
        write-verbose "start-Log w`n$(($pltSL|out-string).trim())" ; 
        $logspec = start-Log @pltSL ;
        $error.clear() ;
        TRY {
            if($logspec){
                $logging=$logspec.logging ;
                $logfile=$logspec.logfile ;
                $transcript=$logspec.transcript ;
                $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
                start-Transcript -path $transcript ;
            } else {throw "Unable to configure logging!" } ;
        } CATCH {
            $ErrTrapd=$Error[0] ;
            $smsg = "Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;

        #$sBnrS="`n#*------v ($($iProcd) / $($ttl)):Processing:$($UPN) v------" ;
        $sBnrS="`n#*------v ($($iProcd) / $($ttl)):Processing:$($pltSL.Tag) v------" ;
        $smsg = "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $path = 'beta/auditLogs/signIns'
        $queryParameter = "&`$top=$($TopUnits)"
        $formatJsonParam = "?`$format=json" ; # 2:52 PM 1/29/2 020 param to force json return
        if ($UPN) {
            $filter = "?`$filter=(userPrincipalName eq `'$($UPN)`')"
        } ;
        if ($QueryApp -eq "EXO") {
            if($filter){
                $filter += " and (appDisplayName eq `'Office 365`' and clientAppUsed eq `'Other clients; IMAP`') or (resourceDisplayName eq `'office 365 exchange online`') or (appDisplayName eq `'Office 365 Exchange Online`')"
            } else {
                $filter += "&`$filter=(appDisplayName eq `'Office 365`' and clientAppUsed eq `'Other clients; IMAP`') or (resourceDisplayName eq `'office 365 exchange online`') or (appDisplayName eq `'Office 365 Exchange Online`')"
            }
        } ;

        if($formattedStart -OR $formattedEnd){
            if($filter){
                $filter +=" and ("
            } ;
            if($formattedStart){$dateFilter = "(createdDateTime ge $($formattedStart)" }
            # 9:47 AM 1/28/2020 trim leading spurious and: " and createdDateTime...
            if($formattedEnd){$dateFilter = " createdDateTime le $($formattedEnd)" }
            $dateFilter+=")"
            #$dateFilter = "(createdDateTime ge $($formattedStart) and createdDateTime le $($formattedEnd))" ;
            # try rplcing \s with %20 - not necessary, it'll work spaces intact
            #$dateFilter = $dateFilter.replace(" ","%20")
        } ;

        # this works in Gxplr:
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and (createdDateTime ge 2019-08-20T10:46:31Z and createdDateTime le 2019-08-27T10:46:31Z)&$top=10
        # 9:45 AM 1/28/2020failing with
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and ( and createdDateTime le  2020-01-28T08:26:19Z)&$top=1000
        # visible issue: spurious ( and create... in the middle of the param clause
        # but this works in GX
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and (createdDateTime le 2020-01-28)&$top=1000
        
        $fullUri = $baseUri + $path + $filter
        if($datefilter){$fullUri += $dateFilter} ;
        $fullUri += $queryParameter ;
        
        # should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1
        write-verbose "$((get-date).ToString('HH:mm:ss')):`nfullUri:`n$(($fullUri|out-string).trim())"  ;
        if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;
        
        # generated $logfile: d:\scripts\logs\search-AADSignInReports-999999-fname.lname@domain.com-LOG-BATCH-EXEC-20210616-0900AM-log.txt
        write-verbose  "$((get-date).ToString('HH:mm:ss')):`$logfile:$($logfile)" ;

        # (shifted graph call loop code into search-GraphApiAAD)

        #search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
        $pltSrchGraphAPI=[ordered]@{
            fullURI=$fulluri ;
            token=$token ;
            tenantName=$tenantName ;
            tenantId=$tenantId ;
            AppID=$AppID ;
            Certificate=$Certificate ;
            showDebug=$($showDebug) ;
            Verbose=($VerbosePreference -eq 'Continue') ;
        } ;
        $smsg = "search-GraphApiAAD w`n$(($pltSrchGraphAPI|out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $SignInReportArray = search-GraphApiAAD @pltSrchGraphAPI ; 

        if($returns = ($SignInReportArray|measure).count){
            $smsg = "(Report Records returned:$($returns))" ;
        } else { 
            $smsg = "(*NO* Report Records returned)" ;
        } ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $ReportOutputCSV = $logfile.replace('-log.txt','.csv') ;
        #"$($ofile).csv" ;
        $ReportOutputJson =  $logfile.replace('-log.txt','.json') ;
        #"$($ofile).json" ;
        $jsonFiles += $ReportOutputJson ; # aggreg the json outputs for echo'ing profile cmd
        $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
        $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
        if(!$UPN){
            $smsg = "Sign in activity JSON report can be found at`n$($ReportOutputJson)."
            $smsg += "`nSign in activity CSV report can be found at`n$($ReportOutputCSV)."
        } else {
            $smsg = "$($UPN):Sign in activity JSON report can be found at`n$($ReportOutputJson)."
            $smsg += "`n$($UPN):Sign in activity CSV report can be found at`n$($ReportOutputCSV)."
        } ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $smsg = $sBnrS.replace('-v','-^').replace('v-','^-') ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    }  # loop-E


    #  .\profile-AAD-Signons.ps1 -Files $jsonFiles
    $msgHere=@"
  To profile output jsons above, run:
      profile-AAD-Signons -Files '$($jsonFiles -join "','")'

"@ ;
    if ($logging) { Write-Log -LogContent $msgHere -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green $msgHere } ;

    $smsg = $sBnr.replace('=v','=^').replace('v=','^=') ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
}

#*------^ search-AADSignInReports.ps1 ^------

#*------v search-GraphApiAAD.ps1 v------
function search-GraphApiAAD {
    <#
    .SYNOPSIS
    search-GraphApiAAD - Execute a GraphAPI search and return report object, for pre-constructed -fullURI
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-06-15
    FileName    : search-GraphApiAAD.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell
    AddedCredit : Alex Asplund
    AddedWebsite:	https://automativity.com
    AddedTwitter:	@AlexAsplund
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    REVISIONS
    * 9:38 AM 6/16/2021 added non-splatted example
    * 3:11 PM 6/15/2021 functionalized graphapi query code by Alex Asplund from his AADsignInReports script
    * 3:16 PM 6/14/2021 fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out rednund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
    * 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
    * 8:51 AM 1/30/2020
    * 2019-08-12 posted version 
    .DESCRIPTION
     search-GraphApiAAD - Execute a GraphAPI search and return report object, for pre-constructed -fullURI
     As written, it Authenticates with a certificate (thumbprint matchese $global:TOR_AAD_App_Audit_CertThumb), 
     stored in Cert:\CurrentUser\My\ (see 4a) for process to export and import into new machines and account profiles)
     Uses code Alex Asplund demo'd at link below, wrapped into a func
     Configure parameter defaults as follows
        |param|info source|
        |---|---|
        |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
        |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
        |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
        |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|

        This script uses RestAPI calls to authenticate and query GraphAPI. 
        
        The script queries the Azure AD Audit Graph endpoint. 
        More information about the filtering options and the data returned can
        be found online at this link:
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

    .PARAMETER  tenantName
    AAD TenantID [-TenantID (guid)]]
    .PARAMETER  AppID
    AAD AppID [-AppID (guid)]]
    .PARAMETER  Certificate
    Certificate Thumbprint [-Certificate (thumbprint)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
    Simple Example (fulluri is constructed by calling cmdlet/script)
    .EXAMPLE
    $pltSrchGraphAPI=[ordered]@{
        fullURI=$fulluri ;
        token=$token ;
        tenantName=$tenantName ;
        tenantId=$tenantId ;
        AppID=$AppID ;
        Certificate=$Certificate ;
        showDebug=$($showDebug) ;
        Verbose=($VerbosePreference -eq 'Continue') ;
    } ;
    $smsg = "search-GraphApiAAD w`n$(($pltSrchGraphAPI|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $SignInReportArray = search-GraphApiAAD @pltSrchGraphAPI ; 
    $ofile = 'd:\scripts\logs\report' ; 
    $ReportOutputCSV = "$($ofile).csv" ;
    $ReportOutputJson = "$($ofile).json" ;
    $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
    $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
    Splatted example - FullURI query specs are generated externally, and passed in as a complete ODATa syntax uri
    .EXAMPLE
    search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
    $ofile = 'd:\scripts\logs\report' ; 
    $ReportOutputCSV = "$($ofile).csv" ;
    $ReportOutputJson = "$($ofile).json" ;
    $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
    $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
    Non-splatted example - FullURI query specs are generated externally, and passed in as a complete ODATa syntax uri
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage = "GraphAPI complete uri query string in OData format [-fullURI xxxx]")]
        [string]$fullURI,
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Token[-Token (token obj)]")]
        [ValidateNotNullOrEmpty()]$token,
        [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
        [string]$tenantName = $global:TorMeta.o365_TenantDomain,
        [Parameter(HelpMessage = "AAD TenantID (defaulted TOR) [-TenantID (guid)]")]
        [string]$tenantId = $global:TorMeta.o365_Tenantid,
        [Parameter(HelpMessage = "AAD AppID [-AppID (guid)]]")]
        [string]$AppID = $global:TORMeta.AAD_App_Audit_ID,
        [Parameter(HelpMessage = "Certificate Thumbprint [-Certificate (thumbprint)]]")]
        $Certificate = $global:tormeta.AAD_App_Audit_CertThumb,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) # PARAM BLOCK END ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;

        # fulluri should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1
        $smsg = "`nfullUri:`n$(($fullUri|out-string).trim())"  ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;
    } 
    PROCESS {
        $smsg = "--------------------------------------------------------------" ;
        $smsg += "`nDownloading report from `n$($fullUri)"  ;
        $smsg += "`n--------------------------------------------------------------" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    
        # we'll be flipping the $url to the next link after the first pass, so we need to use '$url' going into the loop
        $url = $fullUri ;
        $count = 0
        $retryCount = 0
        $oneSuccessfulFetch = $False
        $ReportArray = @() # aggregator

        Do {
            $smsg = "Fetching data using Url:`n$($url )" 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            Try {
                $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
                 # AAsplund's simplified odata approach - assumes the return is an obj, not json

                #$AuditLogRequest = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                #$myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")
                <# # Splat the parameters for Invoke-Restmethod for cleaner code
                $PostSplat = @{
                    ContentType = 'application/x-www-form-urlencoded' ;
                    Method = 'POST' ;
                    Body = $Body ;
                    Uri = $Url ;
                    Headers = $Header ;
                } ;
                write-verbose "$((get-date).ToString('HH:mm:ss')):Invoke-RestMethod w`n$(($PostSplat|out-string).trim())" ; 
                $token = Invoke-RestMethod @PostSplat ; 
                #>
                #$myReport = Invoke-RestMethod @$PostSplat ; 
                # can't use splats, throws: The remote name could not be resolved: 'system.collections.specialized.ordereddictionary'
                $myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")

                $ReportArray += $myReport.value ; 
                        
                $url = $myReport.'@odata.nextLink'
                $count = $count + $myReport.value.Count
                #"Total Fetched: $count" | write-verbose ; 
                $retryCount = 0 ; 

            } Catch [System.Net.WebException] {
                $statusCode = [int]$_.Exception.Response.StatusCode
                Write-Output $statusCode
                $smsg = "`$statusCode:$($statusCode)`n`$_.Exception.Message:$($_.Exception.Message)`n" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            
                if ($statusCode -eq 401 -and $oneSuccessfulFetch) {
                    # Token might have expired! Renew token and try again
                    <# ADAL Azure mod vers:
                    #$authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
                    #$token = $authResult.AccessToken
                    #$AADTokenHeaders = get-AADBearerTokenHeaders($token)
                    #>
                    $token=get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
                    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue') ;
                    $oneSuccessfulFetch = $False
                    $smsg = "Access token expiry. Requested a new one and now retrying data query..."
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } elseif ($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503) {
                    # throttled request or a temporary issue, wait for a few seconds and retry
                    Start-Sleep -5
                    $smsg = "A throttled request or a temporary issue. Waiting for 5 seconds and then retrying..." ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                } elseif ($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401) {
                    $smsg = "Please check the permissions of the user"
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    break;
                } else {
                    if ($retryCount -lt 5) {
                        $smsg = "Retrying..."
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        $retryCount++
                    } else {
                        $smsg = "Download request failed. Please try again in the future." ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        break ; 
                    } ; 
                } ; 
            } Catch {
                $exType = $_.Exception.GetType().FullName
                $exMsg = $_.Exception.Message

                $smsg = "Exception: $_.Exception"
                $smsg += "`nError Message: $exType"
                $smsg += "`nError Message: $exMsg"
          
                if ($retryCount -lt 5) {
                    $smsg += "`nRetrying..." ;
                    $retryCount++ ;
                }else {
                    $smsg += "`nDownload request failed. Please try again in the future."
                    $smsg += "`n--------------------------------------------------------------" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    break ; 
                }
            }
        
            $smsg += "`n--------------------------------------------------------------" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

       } while($myReport.'@odata.nextLink' -ne $null) ; # loop-E 
   }  # if-E-PROCESS 
   END {$ReportArray| write-output ; } 
}

#*------^ search-GraphApiAAD.ps1 ^------

#*------v test-MsolUserLicenseDirectAssigned.ps1 v------
Function test-MsolUserLicenseDirectAssigned {
    <#
    .SYNOPSIS
    test-MsolUserLicenseDirectAssigned - AzureAD check if a particular product license is assigned directly.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : test-MsolUserLicenseDirectAssigned.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 8:09 AM 8/18/2021 clean strings for public
    * 10:52 AM 4/27/2021 expanded CBH, added simpler example ; renamed 'UserHasLicenseAssignedDirectly()' -> test-MsolUserLicenseDirectAssigned(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    test-MsolUserLicenseDirectAssigned - AzureAD check if a particular product license is assigned directly.
    .PARAMETER  user
    MSOL User object for target user [-user `$MsolUser]
    .PARAMETER  skuId
    License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ "==$($_):" ; test-MsolUserLicenseDirectAssigned -user $msolu -skuId $_ } ;
    Evaluate all licenses on a target MSOLUser for Direct Assignement
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ if(test-MsolUserLicenseDirectAssigned -user $msolu -skuId $_ ){$_}} ;
    Output just the Direct-Assigned licenses
    .EXAMPLE
    #the license SKU we are interested in. 
    $skuId = "contoso:EMS"
    #find all users that have the SKU license assigned
    Get-MsolUser -All | where {$_.isLicensed -eq $true -and $_.Licenses.AccountSKUID -eq $skuId} | select  ObjectId,  @{Name="SkuId";Expression={$skuId}},  @{Name="AssignedDirectly";Expression={(test-MsolUserLicenseDirectAssigned -skuId $_ $skuId)}},  @{Name="AssignedFromGroup";Expression={(test-MsolUserLicenseGroupAssigned -skuId $_ $skuId)}} ; 
    Process all users in Org with specified license, and output whether AssignedFromGroup or AssignedDirectly status.
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-Msol
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Parameter(HelpMessage="MSOL User object for target user [-user `$MsolUser]")]
        [Microsoft.Online.Administration.User]$user, 
        [Parameter(HelpMessage="License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]")]
        [string]$skuId
    ) ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        foreach($license in $user.Licenses){
            #we look for the specific license SKU in all licenses assigned to the user
            if ($license.AccountSkuId -ieq $skuId){
                #GroupsAssigningLicense contains a collection of IDs of objects assigning the license
                #This could be a group object or a user object (contrary to what the name suggests)
                #If the collection is empty, this means the license is assigned directly - this is the case for users who have never been licensed via groups in the past
                if ($license.GroupsAssigningLicense.Count -eq 0){return $true} ; 
                #If the collection contains the ID of the user object, this means the license is assigned directly
                #Note: the license may also be assigned through one or more groups in addition to being assigned directly
                foreach ($assignmentSource in $license.GroupsAssigningLicense){
                    if ($assignmentSource -ieq $user.ObjectId){return $true} ; 
                }
                return $false ; 
            } ; 
        }
        return $false
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ test-MsolUserLicenseDirectAssigned.ps1 ^------

#*------v test-MsolUserLicenseGroupAssigned.ps1 v------
Function test-MsolUserLicenseGroupAssigned {
    <#
    .SYNOPSIS
    test-MsolUserLicenseGroupAssigned - AzureAD check if a particular product license is inheriting the license from a group.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : test-MsolUserLicenseGroupAssigned.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 8:08 AM 8/18/2021 cleaned strings for public
    * 10:52 AM 4/27/2021 expanded CBH, added simpler example ; renamed 'UserHasLicenseAssignedDirectly()' -> test-MsolUserLicenseGroupAssigned(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    test-MsolUserLicenseGroupAssigned - AzureAD check if a particular product license is inheriting the license from a group.
    .PARAMETER  user
    MSOL User object for target user [-user `$MsolUser]
    .PARAMETER  skuId
    License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ "==$($_):" ; test-MsolUserLicenseGroupAssigned -user $msolu -skuId $_ } ;
    Evaluate all licenses on a target MSOLUser for Group Assignement
        .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ if(test-MsolUserLicensegroupAssigned -user $msolu -skuId $_ ){$_}} ;
    Output just the Group-Assigned licenses
    .EXAMPLE
    #the license SKU we are interested in. 
    $skuId = "contoso:EMS"
    #find all users that have the SKU license assigned
    Get-MsolUser -All | where {$_.isLicensed -eq $true -and $_.Licenses.AccountSKUID -eq $skuId} | select  ObjectId,  @{Name="SkuId";Expression={$skuId}},  @{Name="AssignedDirectly";Expression={(test-MsolUserLicenseDirectAssigned -skuId $_ $skuId)}},  @{Name="AssignedFromGroup";Expression={(test-MsolUserLicenseGroupAssigned -skuId $_ $skuId)}} ; 
    Process all users in Org with specified license, and output whether AssignedFromGroup or AssignedDirectly status.
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-Msol
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Parameter(HelpMessage="MSOL User object for target user [-user `$MsolUser]")]
        [Microsoft.Online.Administration.User]$user, 
        [Parameter(HelpMessage="License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]")]
        [string]$skuId
    ) ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        foreach($license in $user.Licenses){
            #we look for the specific license SKU in all licenses assigned to the user
            if ($license.AccountSkuId -ieq $skuId){
                #GroupsAssigningLicense contains a collection of IDs of objects assigning the license
                #This could be a group object or a user object (contrary to what the name suggests)
                foreach ($assignmentSource in $license.GroupsAssigningLicense){
                    #If the collection contains at least one ID not matching the user ID this means that the license is inherited from a group.
                    #Note: the license may also be assigned directly in addition to being inherited
                    if ($assignmentSource -ine $user.ObjectId){return $true} ; 
                }
                return $false ; 
            } ; 
        }; 
        return $false
    } ;  # PROC-E
    END {} ; # END-E
}

#*------^ test-MsolUserLicenseGroupAssigned.ps1 ^------

#*------v Wait-AADSync.ps1 v------
Function Wait-AADSync {
    <#
    .SYNOPSIS
    Wait-AADSync - Dawdle loop for notifying on next AzureAD sync (AzureAD/MSOL)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-01-12
    FileName    : Wait-AADSync.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    Updated By: : Todd Kadrie
    REVISIONS   :
    * 4:22 PM 7/24/2020 added verbose
    * 12:14 PM 5/27/2020 moved alias:wait-msolsync win the func
    * 10:27 AM 2/25/2020 bumped polling interval to 30s
    * 8:50 PM 1/12/2020 expanded aliases
    * 11:38 AM 5/6/2019 moved from tsksid-incl-ServerApp.ps1
    * 9:53 AM 3/1/2019 init vers, repl'd native cmsolsvc with Connect-AAD
    .DESCRIPTION
    Wait-AADSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    Wait-AADSync
    .LINK
    #>
    [CmdletBinding()]
    [Alias('Wait-MSolSync')]
    Param([Parameter()]$Credential = $global:credo365TORSID) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        "Not connected to MSOnline. Now connecting." ;
        Connect-AAD ;
    } ;
    $DirSyncLast = (Get-MsolCompanyInformation).LastDirSyncTime ;
    write-host -foregroundcolor yellow "$((get-date).ToString('HH:mm:ss')):Waiting for next AAD Dirsync:`n(prior:$($DirSyncLast.ToLocalTime()))`n[" ;
    Do { Connect-AAD  ; write-host "." -NoNewLine ; Start-Sleep -m (1000 * 30) ; Connect-MSOL } Until ((Get-MsolCompanyInformation).LastDirSyncTime -ne $DirSyncLast) ;
    write-host -foregroundcolor yellow "]`n$((get-date).ToString('HH:mm:ss')):AD->AAD REPLICATED!" ;
    write-host "`a" ; write-host "`a" ; write-host "`a" ;
}

#*------^ Wait-AADSync.ps1 ^------

#*======^ END FUNCTIONS ^======

Export-ModuleMember -Function Add-ADALType,caadCMW,caadtol,caadTOR,caadVEN,cmsolcmw,cmsolTOL,cmsolTOR,cmsolVEN,Connect-AAD,connect-AzureRM,Connect-MSOL,convert-AADUImmuntableIDToADUObjectGUID,convert-ADUObjectGUIDToAADUImmuntableID,Disconnect-AAD,get-AADBearerToken,get-AADBearerTokenHeaders,get-AADCertToken,get-AADLastSync,get-AADlicensePlanList,get-AADToken,get-AADTokenHeaders,get-aaduser,Get-DsRegStatus,Get-MsolDisabledPlansForSKU,Get-MsolUnexpectedEnabledPlansForUser,get-MsolUserLastSync,Get-MsolUserLicense,get-MsolUserLicenseDetails,Get-ServiceToken,Get-TokenCache,Initialize-AADSignErrorsHash,profile-AAD-Signons,Write-Log,get-colorcombo,Initialize-AADSignErrorsHash,Cleanup,Remove-MsolUserDirectLicenses,resolve-GuestExternalAddr2UPN,search-AADSignInReports,search-GraphApiAAD,test-MsolUserLicenseDirectAssigned,test-MsolUserLicenseGroupAssigned,Wait-AADSync -Alias *


# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPL/Ge/9EkKPAE2CeFuZv+/8l
# hLKgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNDEyMjkxNzA3MzNaFw0zOTEyMzEyMzU5NTlaMBUxEzARBgNVBAMTClRvZGRT
# ZWxmSUkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqRVt7uNweTkZZ+16QG
# a+NnFYNRPPa8Bnm071ohGe27jNWKPVUbDfd0OY2sqCBQCEFVb5pqcIECRRnlhN5H
# +EEJmm2x9AU0uS7IHxHeUo8fkW4vm49adkat5gAoOZOwbuNntBOAJy9LCyNs4F1I
# KKphP3TyDwe8XqsEVwB2m9FPAgMBAAGjdjB0MBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MF0GA1UdAQRWMFSAEL95r+Rh65kgqZl+tgchMuKhLjAsMSowKAYDVQQDEyFQb3dl
# clNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEGwiXbeZNci7Rxiz/r43gVsw
# CQYFKw4DAh0FAAOBgQB6ECSnXHUs7/bCr6Z556K6IDJNWsccjcV89fHA/zKMX0w0
# 6NefCtxas/QHUA9mS87HRHLzKjFqweA3BnQ5lr5mPDlho8U90Nvtpj58G9I5SPUg
# CspNr5jEHOL5EdJFBIv3zI2jQ8TPbFGC0Cz72+4oYzSxWpftNX41MmEsZkMaADGC
# AWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBMb2NhbCBDZXJ0aWZp
# Y2F0ZSBSb290AhBaydK0VS5IhU1Hy6E1KUTpMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS5Rzuu
# qYea2G6lbq8HIYc+5fW/RzANBgkqhkiG9w0BAQEFAASBgBvYgPJPLMJAwJOAikQY
# uxazsL4XxgQDKpLF2YS9gtH36ZTEnOtv+fjB83eFbFGfbA5FYz3fCDVpoEqZYf7l
# /426rqF1lNxgYl1oi7wQcf2iBI0qhkS5KaPxkwZbO3H3vkcqZoYr7f6KfrG5SmfU
# Mw9jvtWZXwzfOsu9ZX2ClUqt
# SIG # End signature block
