# d:\scripts\set-AADUserUsageLocation.ps1

#*------v set-AADUserUsageLocation.ps1 v------
function set-AADUserUsageLocation {
    <#
    .SYNOPSIS
    set-AADUserUsageLocation.ps1 - Set AzureADUser.UsageLocation on an array of AzureADUsers
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-03-22
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	URL
    REVISIONS
    * 1:20 PM 6/18/2024 fixed credential code, spliced over code to resolve creds, and assign to $Credential; Alias Users as ObjectID & Userprincipalname; spliced in latest $Cred handling
    * 3:26 PM 5/30/2023 rouneded out pswlt
    * 3:52 PM 5/23/2023 implemented @rxo @rxoc split, (silence all connectivity, non-silent feedback of functions); flipped all r|cxo to @pltrxoC, and left all function calls as @pltrxo; 
    * 12:01 PM 5/22/2023 add: missing w-o for sucess on report; also test $aad.usageloc actually updated; updated cbh ; 
    * 9:55 AM 5/19/2023 CBH, added full call example context
    * 1:44 PM 5/17/2023 rounded out params for $pltRXO passthru
    * 10:30 AM 3/24/2022 add pipeline support
    2:31 PM 3/22/2022 init, simple subset port of set-aaduserLicense() ; 
    .DESCRIPTION
    set-AADUserUsageLocation.ps1 - Set AzureADUser.UsageLocation on an array of AzureADUsers[-users 'upn@domain.com','upn2@domain.com']
    .PARAMETER  Users
    Array of User Userprincipal/Guids to have the specified license applied
    .PARAMETER  UsageLocation
    Azure UsageLocation to be applied to the users (defaults to 'US)[-UsageLocation 'US'].
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .PARAMETER Silent
    Suppress all but error, warn or verbose outputs
    .EXAMPLE
    PS> $bRet = set-AADUserUsageLocation -users 'upn@domain.com','upn2@domain.com' -usageLocation 'US' -verbose ;
    PS> $bRet | %{if($_.Success){write-host "$($_.AzureADUser.userprincipalname):Success"} else { write-warning "$($_.AzureADUser.userprincipalname):FAILURE" } ; 
    Add US UsageLocation to the array of user UPNs specified in -users, with verbose output
    .EXAMPLE
    PS>  if (-not $AADUser.UsageLocation) {
    PS>      $smsg = "AADUser: MISSING USAGELOCATION, FORCING" ;
    PS>      if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
    PS>      else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS>      $spltSAADUUL = [ordered]@{
    PS>          Users = $AADUser.UserPrincipalName ;
    PS>          UsageLocation = "US" ;
    PS>          whatif = $($whatif) ;
    PS>          Credential = $pltRXO.Credential ;
    PS>          verbose = $pltRXO.verbose  ;
    PS>          silent = $false ;
    PS>      } ;
    PS>      $smsg = "set-AADUserUsageLocationw`n$(($spltSAADUUL|out-string).trim())" ;
    PS>      if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
    PS>      else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
    PS>      $bRet = set-AADUserUsageLocation @spltSAADUUL ;
    PS>      if($bRet.Success){
    PS>          $smsg = "set-AADUserUsageLocation updated UsageLocation:$($bRet.AzureADuser.UsageLocation)" ;
    PS>          if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
    PS>          else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
    PS>          $AADUser = $bRet.AzureADuser ;
    PS>      } else {
    PS>          $smsg = "set-AADUserUsageLocation: FAILED TO UPDATE USAGELOCATION!" ;
    PS>          if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
    PS>          else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS>          if(-not $whatif){
    PS>              BREAK;
    PS>          }
    PS>      } ;
    PS>  } ;
    Fully rounded out call example, with post testing. 
    .LINK
    https://github.com/tostka/verb-AAD
    #>
    #Requires -Version 3
    #Requires -Modules AzureAD, verb-Text
    #Requires -RunasAdministrator
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    [CmdletBinding()]
    PARAM (
        # ValueFromPipeline: will cause params to match on matching type, [array] input -> [array]$param
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,HelpMessage="User Identifiers[-Users 'UPN']")]
            [Alias('ObjectID','UserPrincipalName')]
            [ValidateNotNullOrEmpty()]
                [string[]]$Users,  
        [Parameter(Mandatory=$false,HelpMessage="Microsoft UsageLocation code[-UsageLocation 'US']")]
            [string]$UsageLocation = 'US',
        [Parameter(Mandatory=$false,HelpMessage="Tenant Tag to be processed[-PARAM 'TEN1']")]
            [ValidateNotNullOrEmpty()]
            [string]$TenOrg = $global:o365_TenOrgDefault,
        [Parameter(Mandatory = $false, HelpMessage = "Use specific Credentials (defaults to Tenant-defined SvcAccount)[-Credentials [credential object]]")]
            [System.Management.Automation.PSCredential]$Credential,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
            [switch] $silent,
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
            [switch] $whatIf
    ) ;
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ;
       
        <#
        # recycling the inbound above into next call in the chain
        # downstream commands
        $pltRXO = [ordered]@{
            Credential = $Credential ;
            verbose = $($VerbosePreference -eq "Continue")  ;
        } ;
        #>
        # 9:26 AM 6/17/2024 this needs cred resolution splice over latest get-exomailboxlicenses
        $o365Cred = $null ;
        if($Credential){
            $smsg = "`Credential:Explicit credentials specified, deferring to use..." ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                # get-TenantCredentials() return format: (emulating)
                $o365Cred = [ordered]@{
                Cred=$Credential ;
                credType=$null ;
            } ;
            $uRoleReturn = resolve-UserNameToUserRole -UserName $Credential.username -verbose:$($VerbosePreference -eq "Continue") ; # Username
            #$uRoleReturn = resolve-UserNameToUserRole -Credential $Credential -verbose = $($VerbosePreference -eq "Continue") ;   # full Credential support
            if($uRoleReturn.UserRole){
                $o365Cred.credType = $uRoleReturn.UserRole ;
            } else {
                $smsg = "Unable to resolve `$credential.username ($($credential.username))"
                $smsg += "`nto a usable 'UserRole' spec!" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                throw $smsg ;
                Break ;
            } ;
        } else {
            $pltGTCred=@{TenOrg=$TenOrg ; UserRole=$null; verbose=$($verbose)} ;
            if($UserRole){
                $smsg = "(`$UserRole specified:$($UserRole -join ','))" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $pltGTCred.UserRole = $UserRole;
            } else {
                $smsg = "(No `$UserRole found, defaulting to:'CSVC','SID' " ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $pltGTCred.UserRole = 'CSVC','SID' ;
            } ;
            $smsg = "get-TenantCredentials w`n$(($pltGTCred|out-string).trim())" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level verbose }
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
            $o365Cred = get-TenantCredentials @pltGTCred
        } ;
        if($o365Cred.credType -AND $o365Cred.Cred -AND $o365Cred.Cred.gettype().fullname -eq 'System.Management.Automation.PSCredential'){
            $smsg = "(validated `$o365Cred contains .credType:$($o365Cred.credType) & `$o365Cred.Cred.username:$($o365Cred.Cred.username)" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
            # 9:58 AM 6/13/2024 populate $credential with return, if not populated (may be required for follow-on calls that pass common $Credentials through)
            if((gv Credential) -AND $Credential -eq $null){
                $credential = $o365Cred.Cred ;
            }elseif($credential.gettype().fullname -eq 'System.Management.Automation.PSCredential'){
                $smsg = "(`$Credential is properly populated; explicit -Credential was in initial call)" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            } else {
                $smsg = "`$Credential is `$NULL, AND $o365Cred.Cred is unusable to populate!" ;
                $smsg = "downstream commands will *not* properly pass through usable credentials!" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                throw $smsg ;
                break ;
            } ;
        } else {
            $smsg = "UNABLE TO RESOLVE FUNCTIONAL CredType/UserRole from specified explicit -Credential:$($Credential.username)!" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            break ;
        } ; 

        # downstream commands
        $pltRXO = [ordered]@{
            Credential = $Credential ;
            verbose = $($VerbosePreference -eq "Continue")  ;
        } ;
        if((get-command Connect-AAD).Parameters.keys -contains 'silent'){
            $pltRxo.add('Silent',$silent) ;
        } ;
        # default connectivity cmds - force silent false
        $pltRXOC = [ordered]@{} ; $pltRXO.GetEnumerator() | ?{ $_.Key -notmatch 'silent' }  | ForEach-Object { $pltRXOC.Add($_.Key, $_.Value) } ; $pltRXOC.Add('silent',$true) ; 
        if((get-command ReConnect-AAD).Parameters.keys -notcontains 'silent'){
            $pltRxo.remove('Silent') ;
        } ; 
        #Connect-AAD -Credential:$Credential -verbose:$($verbose) ;
        Connect-AAD @pltRXOC ;         
        
        # check if using Pipeline input or explicit params:
        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ;
        } else {
            # doesn't actually return an obj in the echo
            #write-verbose "Data received from parameter input: " # '$($InputObject)'" ;
        } ;
        
    } 
    PROCESS {
        $Error.Clear() ;
        $ttl = ($users|  measure ).count ;  
        $procd = 0 ; 
        foreach ($user in $users) {
            $procd ++ ; 
            $sBnrS="`n#*------v $(${CmdletName}): PROCESSING ($($procd)/$($ttl)): $($user):$($skuid) v------" ; 
            $smsg = $sBnrS ; 
            if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            $Report = @{
                AzureADUser = $null ; 
                FixedUsageLocation = $false ; 
                Success = $false ; 
            } ; 
            $error.clear() ;
            TRY {

                $pltGAADU=[ordered]@{ ObjectID = $user ; ErrorAction = 'STOP' ; verbose = ($VerbosePreference -eq "Continue") ; } ; 
                $smsg = "Get-AzureADUser w`n$(($pltGAADU|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;                      
                $AADUser = Get-AzureADUser @pltGAADU ;   
            
                if ($AADUser) {
                    $report.AzureADUser = $AADUser ; 
                    if (-not $AADUser.UsageLocation) {
                        $smsg = "AADUser: $($AADUser.userprincipalname): MISSING USAGELOCATION, FORCING TO:$($usagelocation)" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                        $spltSAADU = [ordered]@{ ObjectID = $AADUser.UserPrincipalName ;
                            UsageLocation = "US" ;
                            ErrorAction = 'Stop' ;
                        } ;

                        $smsg = "Set-AzureADUser with:`n$(($spltSAADU|out-string).trim())`n" ; ;
                        if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        if (-not $whatif) {
                            $Exit = 0 ;

                                TRY {
                                    Set-AzureADUser @spltSAADU ;
                                    $Report.FixedUsageLocation = $true ; 
                                    $AADUser = Get-AzureADUser @pltGAADU ; 
                                    $smsg = "POST:Confirming UsageLocation -eq US:$($AADUser.UsageLocation)" ; 
                                    if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    if($AADUser.UsageLocation -eq $spltSAADU.UsageLocation){
                                        $Report = @{
                                            AzureADUser = $AADUser ; 
                                            FixedUsageLocation = $true ; 
                                            Success = $true ; 
                                        } ; 
                                    } else { 
                                         $Report = @{
                                            AzureADUser = $AADUser ; 
                                            FixedUsageLocation = $false ; 
                                            Success = $false ; 
                                        } ; 
                                    } ;
                                    $Report | write-output ; 
                                } CATCH {
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
                                  $Report = @{
                                        AzureADUser = $AADUser ; 
                                        FixedUsageLocation = $false ; 
                                        Success = $false ; 
                                  } ; 
                                  $Report | write-output ; 
                                  BREAK #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                              } ; 
                        } else {
                            $smsg = "(-whatif: skipping exec (set-AureADUser lacks proper -whatif support))" ; ;
                            if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        }  ;
                    } else {
                        $smsg = "AADUser: $($AADUser.userprincipalname): has functional usagelocation pre-set:$($AADUser.usagelocation)" ;
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                         $Report = @{
                            AzureADUser = $AADUser; 
                            FixedUsageLocation = $false ; 
                            Success = $true ; 
                        } ; 
                        $Report | write-output ; 
                    } ;         

                } else {
                    $smsg = "Unable to locate AzureADUser" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    Break ; 
                } ;
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                $smsg += "`n$($ErrTrapd.Exception.Message)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                BREAK ;
            } ; 

            $smsg = $sBnrS.replace('-v','-^').replace('v-','^-')
            if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; # loop-E
    }  # PROC-E
    END{
        $smsg = "(processed $($procd) users)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;         
    } ;
}

#*------^ set-AADUserUsageLocation.ps1 ^------