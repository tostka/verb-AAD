# set-AADUserUsageLocation

#*----------v Function set-AADUserUsageLocation() v----------
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
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Users, 
        [string]$UsageLocation = 'US',
        [Parameter(Mandatory=$false,HelpMessage="Tenant Tag to be processed[-PARAM 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$TenOrg = $global:o365_TenOrgDefault,
        [Parameter(Mandatory=$False,HelpMessage="Credentials [-Credentials [credential object]]")]
        [System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [switch]$whatif,
        [switch]$silent
    ) ;
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ;
       
       $pltRXO = [ordered]@{
            Credential = $Credential 
            verbose = $($VerbosePreference -eq 'Continue') ;
            silent = $true ; # always silent, echo only warn/errors
        } ; 
        #Connect-AAD -Credential:$Credential -verbose:$($verbose) ;
        Connect-AAD @pltRXO ;         
        
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

                <# rem out search string option - if we're mandating UPN/guids, it's always going to fail the initial attempt, skip it, odds of feeding it a dname etc is low
                $pltGAADU=[ordered]@{ SearchString = $user ; ErrorAction = 'STOP' ; verbose = ($VerbosePreference -eq "Continue") ; } ; 
                $smsg = "Get-AzureADUser w`n$(($pltGAADU|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;                      
                $AADUser = Get-AzureADUser @pltGAADU ; 
                if (-not $AADUser) {
                
                    $smsg = "Failed: Get-AzureADUser -SearchString $($pltGAADU.searchstring)" ; 
                    $smsg += "`nretrying as -objectid..." ; 
                    if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
                    $pltGAADU.remove('SearchString') ; 
                    $pltGAADU.Add("ObjectID",$user) ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;                      
                    $AADUser = Get-AzureADUser @pltGAADU ;         
                } ; 
                #>
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
                                    
                                    $Report = @{
                                        AzureADUser = $AADUser ; 
                                        FixedUsageLocation = $true ; 
                                        Success = $true ; 
                                    } ; 

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
                $ErrTrapd = $_ ; 
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                Break ;
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
} ; 
