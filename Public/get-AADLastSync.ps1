#*------v Function get-AADLastSync v------
Function get-AADLastSync {
    <# 
    .SYNOPSIS
    get-AADLastSync - Get specific user's last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 9:17 AM 10/9/2018 get-AADLastSync:simplified the collection, and built a Cobj returned in GMT & local timezone
    * 12:30 PM 11/3/2017 initial version
    .DESCRIPTION
    get-AADLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-AADLastSync
    .LINK
    #>
    
    Param([Parameter()]$Credential = $global:credo365TORSID) ; 
    try{Get-MsolAccountSku -ErrorAction Stop |out-null} 
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        "Not connected to MSOnline. Now connecting." ;
        Connect-MsolService ; 
    } ;
    $DirSyncTimeBefore = (Get-MsolCompanyInformation).LastDirSyncTime ;
    $oReturn= New-Object PSObject -Property @{
      TimeGMT = $DirSyncTimeBefore  ; 
      TimeLocal = $DirSyncTimeBefore.ToLocalTime() ; 
    }; 
    $oReturn | write-output ; 
} ; #*------^ END Function get-AADLastSync ^------
# 11:19 AM 10/18/2018 add msol alias
if(!(get-alias get-MsolLastSync -ea 0) ) {Set-Alias 'get-MsolLastSync' -Value 'get-AADLastSync' ; } ;