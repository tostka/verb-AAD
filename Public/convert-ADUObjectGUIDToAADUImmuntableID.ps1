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
    * 8:26 AM 2/4/2022 hardtyped guid (string doesn't support the getbytearray method)
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
        #[String]
        [guid]$Guid,
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
