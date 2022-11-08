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
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            if(($token.AccessToken).userid -eq $Credential.username){
                $TokenTag = convert-TenantIdToTag -TenantId $TenantId ;                    
                $smsg = "(Authenticated to AAD:$($TokenTag) as $(($token.AccessToken).userid)" ; 
                if($silent){} else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
                $TenOrg=get-TenantTag -Credential $Credential ; 
                $sTitleBarTag = @("AAD") ;
                $sTitleBarTag +=  $TokenTag ;# $TenOrg ;
                Add-PSTitleBar $sTitleBarTag -verbose:$($VerbosePreference -eq "Continue");
            } else { 
                $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).TenantID  -verbose:$($verbose) ; 
                $smsg = "(Disconnecting from $($($TokenTag)) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                Disconnect-AzureAD ; 
                throw "AUTHENTICATED TO WRONG TENANT FOR SPECIFIED CREDENTIAL" 
            } ; 
        } ; 
    } ; # END-E
}

#*------^ Connect-AAD.ps1 ^------
