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
                    Get-AdminCred ;
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
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
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