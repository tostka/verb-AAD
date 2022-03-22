#*----------v Function remove-AADUserLicense() v----------
function remove-AADUserLicense {
    <#
    .SYNOPSIS
    remove-AADUserLicense.ps1 - remove a single license to an array of AzureADUsers
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
    AddedCredit : Jaap de Koning (jaap.adm)
    AddedWebsite:	https://alwaysautomate.it/2018/08/05/hello-world/
    AddedTwitter:	URL
    REVISIONS
    4:08 PM 3/22/2022 init; simple conversion of add-AADUserLicense; verified functional
    .DESCRIPTION
    remove-AADUserLicense.ps1 - remove a single license to an array of AzureADUsers
    .PARAMETER  Users
    Array of User Userprincipal/Guids to have the specified license applied
    .PARAMETER  skuid
    Azure LicensePlan SkuID for the license to be applied to the users.
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .PARAMETER Silent
    Suppress all but error, warn or verbose outputs
    .EXAMPLE
    PS> $lplistn = get-AADlicensePlanList -IndexOnName ; 
    PS> $skuid = $lplistn['EXCHANGESTANDARD'].skuid ; 
    PS> $bRet = remove-AADUserLicense -users 'upn@domain.com','upn2@domain.com' -skuid $skuid -verbose -whatif ; 
    PS> $bRet | %{if($_.Success){write-host "$($_.AzureADUser.userprincipalname):Success"} else { write-warning "$($_.AzureADUser.userprincipalname):FAILURE" } ; 
    Leverage verb-AAD:get-AADlicensplanList() to return an SkuPartNumber-indexed hash of current Tenant LicensePlans; 
    Lookup the SKUId value for the ExchangeStandardLicense in the returned indexed hash; 
    Then remove the specified license from the array of user UPNs specified in -users. 
    .LINK
    https://github.com/tostka/verb-AAD
    #>
    #Requires -Version 3
    #Requires -Modules AzureAD, verb-Text
    #Requires -RunasAdministrator
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$false,HelpMessage="Tenant Tag to be processed[-PARAM 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string[]]$Users, 
        [string]$skuid,
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
        Connect-AAD -Credential:$Credential -verbose:$($verbose) ;
        
        # check if using Pipeline input or explicit params:
        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ;
        } else {
            # doesn't actually return an obj in the echo
            #write-verbose "Data received from parameter input: '$($InputObject)'" ;
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
                AddedLicenses = @(); 
                RemovedLicenses = @(); 
                FixedUsageLocation = $false ; 
                Success = $false ; 
            } ; 
            $error.clear() ;
            TRY {
                #$pltGAADU=[ordered]@{ ObjectId = $tUPN ; ErrorAction = 'STOP' ; verbose = ($VerbosePreference -eq "Continue") ; } ; 
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
                    $smsg = "Get-AzureADUser w`n$(($pltGAADU|out-string).trim())" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;                      
                
                    $AADUser = Get-AzureADUser @pltGAADU ;                 
                } ; 
            
                if ($AADUser) {
                    $report.AzureADUser = $AADUser ; 
                    if (-not $AADUser.UsageLocation) {
                        $smsg = "AADUser: MISSING USAGELOCATION, FORCING" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                        $spltSAADUUL = [ordered]@{ 
                            ObjectID = $AADUser.UserPrincipalName ;
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
                            $AADUser = $bRet.AzureADuser ; 
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
                    
                    # check lic avail
                    $pltGLPList=[ordered]@{ 
                        TenOrg= $TenOrg; 
                        verbose=$($VerbosePreference -eq "Continue") ; 
                        credential= $Credential ;
                        #$pltRXO.credential ; 
                        erroraction = 'STOP' ;
                    } ;
                    $smsg = "get-AADlicensePlanList w`n$(($pltGLPList|out-string).trim())" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $skus = get-AADlicensePlanList @pltGLPList ;
                    
                    if($tsku = $skus[$skuid]){
                        $smsg = "($($skuid):$($tsku.SkuPartNumber) is present in Tenant SKUs)" ;
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    } else { 
                        $smsg = "($($skuid):$($tsku.SkuPartNumber) is NOT PRESENT in Tenant SKUs)" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        
                    } ; 
                    <#
                    $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
                    $AssignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
                    $license.SkuId = $skuid ;
                    $AssignedLicenses.AddLicenses = $license ;
                    #>
                    # confirm that the user doesn't have the lic in question:
                    <# ( get-AzureAdUser -obj todd.kadrie@toro.com | select -expand Assignedlicenses | select -expand skuid ) -contains '6fd2c87f-b296-42f0-b197-1e91e994b900'
                    True
                    #>
                    #if($AADUser.Assignedlicenses.skuid -notcontains $license.SkuId){
                    #if($AADUser.Assignedlicenses.skuid -contains $license.SkuId){
                    if($AADUser.Assignedlicenses.skuid -contains $tsku.SkuId){
                        
                        $licenses = $AADUser.Assignedlicenses.skuid |?{$_ -eq $skuid} ; 

                        $smsg = "Removing license SKUID ($($skuid)) from user:$($user)" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                        $AssignedLicenses = @{
                            addLicenses = @()
                            removeLicenses= @($licenses)
                        } ; 
                        $pltSAADUL=[ordered]@{
                            ObjectId = $AADUser.ObjectID ;
                            AssignedLicenses = $AssignedLicenses ;
                            erroraction = 'STOP' ;
                            verbose = $($VerbosePreference -eq "Continue") ;
                        } ;
                        $smsg = "Set-AzureADUserLicense w`n$(($pltSAADUL|out-string).trim())" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                        if (-not $whatif) {
                            Set-AzureADUserLicense @pltSAADUL ;
                                
                            #$Report.AddedLicenses += "$($tsku.SkuPartNumber):$($tsku.SkuId)" ; 
                            $Report.RemovedLicenses += "$($tsku.SkuPartNumber):$($tsku.SkuId)" ; 
                            $Report.Success = $true ; 
                        } else {
                            #$Report.AddedLicenses += "$($tsku.SkuPartNumber):$($tsku.SkuId)" ; 
                            #$Report.RemovedLicenses += "$($tsku.SkuPartNumber):$($tsku.SkuId)" ; 
                            $Report.Success = $false ; 
                            $smsg = "(-whatif: skipping exec (set-AureADUser lacks proper -whatif support))" ; ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        }  ;

                        $AADUser = Get-AzureADUser @pltGAADU ; 
                        $report.AzureADUser = $AADUser ; 
                        $usrPlans = $usrLics=@() ; 
                        foreach($pLic in $AADUser.AssignedLicenses.skuid){
                            $usrLics += $skus[$plic].SkuPartNumber ; 
                        } ; 
                        foreach($pPlan in $AADUser.assignedplans){
                            $usrPlans += $_.service ; 
                        } ; 
                        $smsg = "POST:`n$(($AADUser|ft -a UserPrincipalName,DisplayName| out-string).trim())" ;
                        $smsg += "`nLicenses: $(($usrLics -join ','|out-string).trim())" ;  
                        $smsg += "`nPlans: $(( ($usrPlan | select -unique) -join ','|out-string).trim())" ; 
                        if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                
                        #[PSCustomObject]$Report | write-output ;
                        New-Object PSObject -Property $Report | write-output ;

                    } else {
                        $smsg = "$($AADUser.userprincipalname) does not have AssignedLicense:$($tsku.SkuPartNumber)" ; 
                        if($silent){} elseif ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        $report.Success = $true ; 
                        #[PSCustomObject]$Report | write-output ;
                        New-Object PSObject -Property $Report | write-output ;
                    } ;
                        
                } else {
                    $smsg = "Unable to locate AzureADUser" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    $report.Success = $false ; 
                    #[PSCustomObject]$Report | write-output ;
                    New-Object PSObject -Property $Report | write-output ;
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
#*------^ END Function remove-AADUserLicense() ^------