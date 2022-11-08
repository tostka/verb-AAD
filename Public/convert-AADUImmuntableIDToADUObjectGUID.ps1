#*------v convert-AADUImmuntableIDToADUObjectGUID.ps1 v------
Function convert-AADUImmuntableIDToADUObjectGUID {
    <#
    .SYNOPSIS
    convert-AADUImmuntableIDToADUObjectGUID - Convert an AzureADUser.ImmuntableID to the equivelent ADUser.objectGuid (via Base64 conversion).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-12-06
    FileName    : convert-AADUImmuntableIDToADUObjectGUID.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,AzureAD,ActiveDirectory,Conversion
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 10:29 AM 12/6/2021 init
    .DESCRIPTION
    convert-AADUImmuntableIDToADUObjectGUID - Convert an AzureADUser.ImmuntableID to the equivelent ADUser.objectGuid (via Base64 conversion).
    .PARAMETER immutableID
immutableID string to be converted[-immutableID 'SAMPLEINPUT']
    .PARAMETER silent
    Switch to suppress all non-error echos
    .INPUTS
    System.string
    Microsoft.Open.AzureAD.Model.User
    Accepts pipeline input.
    .OUTPUTS
    System.Guid
    .EXAMPLE
    $ObjectGuid = (convert-AADUImmuntableIDToADUObjectGUID -immutableID 'fxTjHP+7AkiDxhZ+afyOEA==' -verbose).guid ; 
    
    Directly convert specified -immutableID string to guid object, and assign to a variable, with verbose output.
    .EXAMPLE
    get-AzureAdUser -objectname fname.lname@domain.tld | convert-AADUImmuntableIDToADUObjectGUID | foreach-object {get-aduser -identity $_.guid} ;
    Pipeline example demoing retrieval of an AzureADUser, conversion to guid mid-pipeline, and retrieval of matching ADUser for the converted immutableID/guid.
    .LINK
    https://github.com/tostka/verb-aad
    #>
    #Requires -Modules AzureAD,ActiveDirectory
    [CmdletBinding()] 
    [Alias('convert-ImmuntableIDToGUID')]
    Param(
         [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="immutableID string to be converted[-immutableID 'SAMPLEINPUT']")]
        [String]$immutableID,
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
        [switch] $silent
    ) ;
    BEGIN {} ;
    PROCESS {
        $error.clear() ;
        TRY {
            $smsg = "convert (AADU.)immutableID:$($immutableID)" ; 
            $smsg += " to (ExchOP.)objectGuid..." ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ; 
            [guid]$guid=New-Object -TypeName guid (,[System.Convert]::FromBase64String($immutableid)) ;
            $smsg = "(returning to pipeline, converted [guid]:$($guid)" ; 
            if($silent){} else { 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ; 
            $guid | write-output ; 
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
    END {} ; 
}

#*------^ convert-AADUImmuntableIDToADUObjectGUID.ps1 ^------
