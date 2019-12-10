#*------v Function Wait-AADSync v------
Function Wait-AADSync {
    <# 
    .SYNOPSIS
    Wait-AADSync - Dawdle loop for notifying on next AzureAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 11:38 AM 5/6/2019 moved from tsksid-incl-ServerApp.ps1
    * 9:53 AM 3/1/2019 init vers, repl'd native cmsolsvc with Connect-AAD 
    .DESCRIPTION
    Wait-AADSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    Wait-AADSync
    .LINK
    #>
    Param([Parameter()]$Credential = $global:credo365TORSID) ; 
    try{Get-MsolAccountSku -ErrorAction Stop |out-null} 
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        "Not connected to MSOnline. Now connecting." ;
        Connect-AAD ;
    } ;
    $DirSyncLast = (Get-MsolCompanyInformation).LastDirSyncTime ;
    write-host -foregroundcolor yellow "$((get-date).ToString('HH:mm:ss')):Waiting for next AAD Dirsync:`n(prior:$($DirSyncLast.ToLocalTime()))`n[" ; 
    Do {Connect-AAD  ; write-host "." -NoNewLine ; Start-Sleep -m (1000 * 5) ; cmsol} Until ((Get-MsolCompanyInformation).LastDirSyncTime -ne $DirSyncLast) ;
    write-host -foregroundcolor yellow "]`n$((get-date).ToString('HH:mm:ss')):AD->AAD REPLICATED!" ; 
    write-host "`a" ; write-host "`a" ; write-host "`a" ;
} ; #*------^ END Function Wait-AADSync ^------
# 11:19 AM 10/18/2018 add msol alias
if(!(get-alias Wait-MSolSync -ea 0 )) {Set-Alias -Name 'wait-MSolSync' -Value 'Wait-AADSync' ; } ;