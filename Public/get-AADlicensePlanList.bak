#*------v get-AADlicensePlanList v------
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
} ; 
#*------^ get-AADlicensePlanList ^------