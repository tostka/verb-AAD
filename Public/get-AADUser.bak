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