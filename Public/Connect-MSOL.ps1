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
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
    ) ;
    BEGIN { $verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $MFA = get-TenantMFARequirement -Credential $Credential ;
        # msol doesn't support the -TenantID, it's imputed from the credential

        # 12:10 PM 3/15/2017 disable prefix spec, unless actually blanked (e.g. centrally spec'd in profile).
        #if(!$CommandPrefix){ $CommandPrefix='aad' ; } ;

        $sTitleBarTag = "MSOL" ;
        $TentantTag=$TenOrg = get-TenantTag -Credential $Credential ; 
        if($TentantTag -ne 'TOR'){
            # explicitly leave this tenant (default) untagged
            $sTitleBarTag += $TentantTag ;
        } ; 

        try { Get-MsolAccountSku -ErrorAction Stop | out-null }
        catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
            Write-Verbose "Not connected to MSOnline. Now connecting." ;
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
                write-verbose "EXEC:Connect-MsolService -Credential $($Credential.username) (no MFA, full credential)" ; 
                if($Credential.username){
                    $pltCMSOL.add('Credential',$Credential) ; 
                    write-verbose "(using cred:$($credential.username))" ; 
                } ;
                #Connect-MsolService -Credential $Credential -ErrorAction Stop ;
            }
            else {
                write-verbose "EXEC:Connect-MsolService -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                #if($Credential.username){$pltCMSOL.add('AccountId',$Credential.username)} ;
                #Connect-MsolService -ErrorAction Stop ;
            } ;

            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Connect-MsolService w`n$(($pltCMSOL|out-string).trim())" ; 
            TRY {
                Connect-MsolService @pltCMSOL ; 
            } CATCH {
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                throw $_ #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 

            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { 
                write-host -foregroundcolor darkgray  "(Connected to MSOL)" ; Add-PSTitleBar $sTitleBarTag ; 
            } ;
        } ;
        
    } ;
    END {
        write-verbose "EXEC:Get-MsolDomain" ; 
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
        if( $msoldoms.name.contains($credO365TORSID.username.split('@')[1].tostring()) ){
            <# borked by psreadline v1/v2 breaking changes
            if(($PSFgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSFgColor) -AND ($PSBgColor = (Get-Variable  -name "$($TenOrg)Meta").value.PSBgColor)){
                $Host.UI.RawUI.BackgroundColor = $PSBgColor
                $Host.UI.RawUI.ForegroundColor = $PSFgColor ; 
            } ;
            #>
            write-verbose "(Authenticated to MSOL:$($MsolCoInf.DisplayName))" ;
        } else { 
            #write-verbose "(Disconnecting from $(AADTenDtl.displayname) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
            #Disconnect-AzureAD ; 
            throw "MSOLSERVICE IS CONNECTED TO WRONG TENANT!:$($MsolCoInf.DisplayName)" ;
        } ;             
    } ;
}

#*------^ Connect-MSOL.ps1 ^------