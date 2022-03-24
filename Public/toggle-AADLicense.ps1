#*------v Function toggle-AADLicense v------
function toggle-AADLicense{
    <#
    .SYNOPSIS
    toggle-AADLicense.ps1 - SharedMailboxes: Temp Add & then Remove a Lic to fix 'License Reconcilliation Needed' status
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2019-02-06
    License     : MIT License
    Copyright   : (c) 2019 Todd Kadrie
    Github      : https://github.com/tostka
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 1:22 PM 3/23/2022 sub'd in AzureAD cmdlets for MSOL cmdlets, ren'd toggle-o365License -> toggle-AADLicense (retained as Alias)
    * 1:57 PM 8/25/2021 returning Msol lic-related props (vs no return); added LicenseSku parm, defaulted to EXCHANGESTANDARD ;ren'd O365LicenseToggle -> toggle-o365License
    .DESCRIPTION
    .PARAMETER  User
    User [-User `$UserObjectVariable ]
    .PARAMETER LicenseSku
    MS LicenseSku value for license to be applied (defaults to EXCHANGESTANDARD) [-LicenseSku tenantname:LICENSESKU]
    .PARAMETER Credential
    Credentials [-Credentials [credential object]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .PARAMETER Silent
    Suppress all but error, warn or verbose outputs
    .EXAMPLE
    toggle-AADLicense -User $AADUser -whatif:$($whatif) -showDebug:$($showdebug) ;
    Toggle the license on the specified User object
    .LINK
    https://github.com/tostka/verb-AAD
    #>
    #Requires -Version 3
    #Requires -Modules AzureAD, verb-Text
    [CmdletBinding()]
    [Alias('toggle-o365License')]
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Either AzureADuser object or UserPrincipalName for user[-User upn@domain.com|`$msoluserobj ]")]
        $User,
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "MS LicenseSku value for license to be applied (defaults to EXCHANGESTANDARD) [-LicenseSku tenantname:LICENSESKU]")]
        $LicenseSku = $tormeta.o365LicSkuExStd,
        [Parameter(Mandatory=$False,HelpMessage="Credentials [-Credentials [credential object]]")]
        [System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [switch] $showDebug,
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
        [switch] $whatIf,
        [switch]$silent
    ) # PARAM BLOCK END

    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    $Verbose = ($VerbosePreference -eq 'Continue') ;

    $exprops="SamAccountName","RecipientType","RecipientTypeDetails","UserPrincipalName" ;
    $LicenseSku="toroco:EXCHANGESTANDARD" # 11:05 AM 11/11/2019 switch to 'Exchange Online (Plan 1)', rather than E3
    # "toroco:ENTERPRISEPACK" ;
    $rgxEmailAddress = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$"

    #connect-msol @pltRXO;
    Connect-AAD @pltRXO;

    switch($user.GetType().FullName){
        'Microsoft.Online.Administration.User' {
            $smsg = "MSOLUSER OBJECT IS NO LONGER SUPPORTED BY THIS FUNCTION!" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN }
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            $smsg = "(-user:MsolU detected)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            # use it intact
        } ;
        'Microsoft.Open.AzureAD.Model.User' {
            $smsg = "(-user:AzureADU detected)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            # use it intact
        } ;
        'System.String'{
            $smsg = "(-user:string detected)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            if($user -match $rgxEmailAddress){
                $smsg = "(-user:EmailAddress/UPN detected`nconverting to AzureADUser)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                $pltgMsol=[ordered]@{UserPrincipalName = $tUPN ;ErrorAction = 'STOP';} ;
                $smsg = "get-AzureADUser w`n$(($pltgMsol|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                $pltGAADU=[ordered]@{ ObjectID = $tUPN ; ErrorAction = 'STOP' ; verbose = ($VerbosePreference -eq "Continue") ; } ;
                $smsg = "Get-AzureADUser w`n$(($pltGAADU|out-string).trim())" ;
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;

                $error.clear() ;
                TRY {

                    #$User = get-msoluser -UserPrincipalName $tUPN -EA STOP
                    #$User = get-msoluser @pltgMsol ;
                    $User  = Get-AzureADUser @pltGAADU ;

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

            } ;
        }
        default{
            $smsg = "Unrecognized format for -User:$($User)!. Please specify either a user UPN, or pass a full AzureADUser object." ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            Break ;
        }
    } ;

    $pltGLPList=[ordered]@{ TenOrg= $TenOrg; verbose=$($VerbosePreference -eq "Continue") ; credential= $pltRXO.credential ; } ;

    $skus  = get-AADlicensePlanList @pltGLPList ;

    #if($User.IsLicensed){
    # moving to aad: lacks the islicensed prop. have to interpolate from the AssignedLicenses.count
    # $isLicensed = [boolean]((get-AzureAdUser -obj todd.kadrie@toro.com).AssignedLicenses.count -gt 0)
    if([boolean]($User.AssignedLicenses.count -gt 0)){
        $smsg= "$($User.UserPrincipalName) is already licenced`nREMOVING ONLY" ; ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } else {
            <# -ORIG CODE---------
            if(!$User.UsageLocation){

                write-host -foregroundcolor green "MISSING USAGELOCATION, FORCING" ;
                $spltMUsr=[ordered]@{
                    UserPrincipalName=$User.UserPrincipalName ;
                    UsageLocation="US" ;
                    ErrorAction = 'Stop' ;
                } ;
                $smsg="Set-MsolUser with:`n$(($spltMUsr|out-string).trim())`n" ; ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                if(!$whatif){

                    $Exit = 0 ;
                    Do {
                        Try {
                            Set-MsolUser @spltMUsr ;
                            # 1:59 PM 10/11/2018 pull back and confirm hit
                            $smsg= "POST:Confirming UsageLocation -eq US..." ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                          $Exit = $Retries ;
                        } Catch {
                            Start-Sleep -Seconds $RetrySleep ;
                            $Exit ++ ;
                            $smsg = "Failed to exec cmd because: $($Error[0])" ;
                            $smsg += "`nTry #: $Exit" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            If ($Exit -eq $Retries) {
                                $smsg =  "Unable to exec cmd!" ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } ;
                        }  ;
                    } Until ($Exit -eq $Retries) ;

                } ;
            } ;
            #> # ---ORIG CODE--------

            # 12:36 PM 3/23/2022 splice in verb-aad:set-AADUserUsageLocation support
            if (-not $User.UsageLocation) {
                $smsg = "AADUser: MISSING USAGELOCATION, FORCING" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                $spltSAADUUL = [ordered]@{
                    ObjectID = $User.UserPrincipalName ;
                    UsageLocation = "US" ;
                    whatif = $($whatif) ;
                    verbose = ($VerbosePreference -eq "Continue") ;
                } ;
                $smsg = "set-AADUserUsageLocationw`n$(($spltSAADUUL|out-string).trim())" ;
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                $bRet = set-AADUserUsageLocation @spltSAADUUL ;
                if($bRet.Success){
                    $smsg = "set-AADUserUsageLocation updated UsageLocation:$($bRet.AzureADuser.UsageLocation)" ;
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                    # update the local AADUser to reflect the updated AADU returned
                    $User  = $bRet.AzureADuser ;
                    $Report.FixedUsageLocation = $true ;
                } else {
                    $smsg = "set-AADUserUsageLocation: FAILED TO UPDATE USAGELOCATION!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $Report.FixedUsageLocation = $false ;
                    if(-not $whatif){
                        BREAK;
                    }
                } ;
            } ;

            <# ----ORIG MSOL CODE-------
            $spltLicAdd=[ordered]@{
                UserPrincipalName=$User.UserPrincipalName ;
                AddLicenses=$LicenseSku ;
            } ;

            $smsg= "`nADD-E3:Set-MsolUserLicense with:`n$(($spltLicAdd|out-string).trim())`n" ;;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            if(!$whatif){

                $Exit = 0 ;
                Do {
                    Try {
                      Set-MsolUserLicense @spltLicAdd ;
                      $Exit = $Retries ;
                    } Catch {
                        Start-Sleep -Seconds $RetrySleep ;
                        connect-msol @pltRXO;
                        $Exit ++ ;
                        $smsg = "Failed to exec cmd because: $($Error[0])" ;
                        $smsg += "`nTry #: $Exit" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        If ($Exit -eq $Retries) {
                            $smsg =  "Unable to exec cmd!" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        } ;
                    }  ;
                } Until ($Exit -eq $Retries) ;


                Do {
                    # 7:38 PM 10/11/2018 nail up
                    connect-msol @pltRXO;
                    write-host "." -NoNewLine;Start-Sleep -m (1000 * 5)
                } Until ((Get-MsolUser -userprincipalname $User.UserPrincipalName |?{$_.IsLicensed})) ;
                # 1:53 PM 8/25/2021 cap the result for return
                $Result = Get-MsolUser -userprincipalname $User.UserPrincipalName | select UserPrincipalName,isLicensed,LicenseReconciliationNeeded ;
                $smsg = "Get-MsolUser post-add:`n$(($result | ft -auto UserPrincipalName,isLicensed,LicenseReconciliationNeeded|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } else { "(whatif)" };
            #> # ----ORIG MSOL CODE-------

            # azuerad code:
            if( $LicenseSku.contains(':') ){
                $LicenseSkuName = $LicenseSku.split(':')[1] ;
                # need the skuid, not the name, could pull another licplan list indiexedonName, but can also post-filter the hashtable, and get it.
                $LicenseSku = ($skus.values | ?{$_.SkuPartNumber -eq $LicenseSkuName}).skuid ;
            } ;
            $smsg = "(attempting license:$($LicenseSku)...)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            #$bRes = add-AADUserLicense -Users $User.UserPrincipalName -skuid $LicenseSku -verbose -whatif
            $pltAAADUL=[ordered]@{
                Users=$User.UserPrincipalName ;
                skuid=$LicenseSku ;
                verbose = $($VerbosePreference -eq "Continue") ;
                erroraction = 'STOP' ;
                whatif = $($whatif) ;
            } ;
            $smsg = "add-AADUserLicense w`n$(($pltAAADUL|out-string).trim())" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            $Result = add-AADUserLicense @pltAAADUL ;
            if($Result.Success){
                $smsg = "add-AADUserLicense added  Licenses:$($Result.AddedLicense)" ;
                # $User.AssignedLicenses.skuid
                $smsg += "`n$(($User.AssignedLicenses.skuid|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                $smsg = "Detailed Return:`n$(($Result|out-string).trim())" ;
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                # update the local AADUser to reflect the updated AADU returned
                #$User = $Result.AzureADuser ;
                #$Report.FixedUsageLocation = $true ;
                BREAK ; # abort further loops if one successfully applied
            } elseif($whatif){
                $smsg = "(whatif pass, exec skipped), " ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } else {
                $smsg = "add-AADUserLicense : FAILED TO ADD SPECIFIED LICENSE!" ;
                $smsg += "`n$(($Result|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #$Report.FixedUsageLocation = $false ;
                if(-not $whatif){
                    BREAK;
                }
            } ;

    } ;


    Try {

        #$tMsol=Get-MsolUser -userprincipalname $User.UserPrincipalName ;
        $tAADU = Get-AzureADUser @pltGAADU ;
        $Exit = $Retries ;
    <#
    } Catch {
        Start-Sleep -Seconds $RetrySleep ;
        connect-msol @pltRXO;
        $Exit ++ ;
        $smsg = "Failed to exec cmd because: $($Error[0])" ;
        $smsg += "`nTry #: $Exit" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        If ($Exit -eq $Retries) {
            $smsg =  "Unable to exec cmd!" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
    }  ;
    #>
    } CATCH {
        #$ErrTrapd=$Error[0] ;
        $ErrTrapd=$_ ;
        $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
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



    #if($tMsol | select -expand licenses | ?{$_.AccountSkuId  -eq $LicenseSku}){
    if($tAADU | select -expand AssignedLicenses | ?{$_.SkuId  -eq $LicenseSku}){
        # remove matched license

        <# ---ORIG MSOL CODE--------
        $spltLicRmv=[ordered]@{
            UserPrincipalName=$User.UserPrincipalName ;
            RemoveLicenses=$LicenseSku ;
        } ;

        $smsg= "PULL-$($LicenseSku):Set-MsolUserLicense with:`n$(($spltLicRmv|out-string).trim())`n" ;;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        if(!$whatif){
            Set-MsolUserLicense @spltLicRmv ;
            Do {
                connect-msol @pltRXO;
                write-host "." -NoNewLine;Start-Sleep -m (1000 * 5)
            } Until ((Get-MsolUser -userprincipalname $User.UserPrincipalName |?{!$_.IsLicensed})) ;
            $Result=Get-MsolUser -userprincipalname $User.UserPrincipalName| ft -auto UserPrincipalName,isLicensed,LicenseReconciliationNeeded ;
            if($Result.LicenseReconciliationNeeded){
                $smsg="$($User.UserPrincipalName) LicenseReconciliationNeeded STILL AN ISSUE" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } else {
                $smsg="$($User.UserPrincipalName) LicenseReconciliationNeeded CLEARED" ;                      ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;
            $smsg= "`n$(($result|out-string).trim())`n" ;;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else { "(whatif)" };
        #> # ---ORIG MSOL CODE--------

        # $Result = remove-AADUserLicense -users 'upn@domain.com','upn2@domain.com' -skuid $skuid -verbose -whatif ;
        $pltRAADUL=[ordered]@{
            Users=$User.UserPrincipalName ;
            skuid=$LicenseSku ;
            verbose = $($VerbosePreference -eq "Continue") ;
            erroraction = 'STOP' ;
            whatif = $($whatif) ;
        } ;
        $smsg = "remove-AADUserLicense w`n$(($pltRAADUL|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $Result = remove-AADUserLicense @pltRAADUL ;
        if($Result.Success){
            $smsg = "remove-AADUserLicense removed Licenses:$($Result.RemovedLicenses)" ;
            # $User.AssignedLicenses.skuid
            $smsg += "`n$(($User.AssignedLicenses.skuid|out-string).trim())" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            $smsg = "Detailed Return:`n$(($Result|out-string).trim())" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
            # update the local AADUser to reflect the updated AADU returned
            #$User = $Result.AzureADuser ;
            #$Report.FixedUsageLocation = $true ;
            BREAK ; # abort further loops if one successfully applied
        } elseif($whatif){
            $smsg = "(whatif pass, exec skipped), " ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            $smsg = "remove-AADUserLicense : FAILED TO REMOVE SPECIFIED LICENSE!" ;
            $smsg += "`n$(($Result|out-string).trim())" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #$Report.FixedUsageLocation = $false ;
            if(-not $whatif){
                BREAK;
            }
        } ;


    } else {
            $smsg="$($User.UserPrincipalName) does not have an existing $($LicenseSku) license to remove" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    };

    #$true | write-output ;
    $result | write-output ; # 1:56 PM 8/25/2021 return the msol with lic-related props
    #$Result.Success

}
; #*------^ END Function toggle-AADLicense ^------