#*------v Function Wait-AADSync.ps1 v------
Function Wait-AADSync {
    <#
    .SYNOPSIS
    Wait-AADSync - Dawdle loop for notifying on next AzureAD sync (AzureAD/MSOL)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-01-12
    FileName    : Wait-AADSync.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    Updated By: : Todd Kadrie
    REVISIONS   :
    * 12:14 PM 5/27/2020 moved alias:wait-msolsync win the func
    * 10:27 AM 2/25/2020 bumped polling interval to 30s
    * 8:50 PM 1/12/2020 expanded aliases
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
    [CmdletBinding()]
    [Alias('Wait-MSolSync')]
    Param([Parameter()]$Credential = $global:credo365TORSID) ;
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        "Not connected to MSOnline. Now connecting." ;
        Connect-AAD ;
    } ;
    $DirSyncLast = (Get-MsolCompanyInformation).LastDirSyncTime ;
    write-host -foregroundcolor yellow "$((get-date).ToString('HH:mm:ss')):Waiting for next AAD Dirsync:`n(prior:$($DirSyncLast.ToLocalTime()))`n[" ;
    Do { Connect-AAD  ; write-host "." -NoNewLine ; Start-Sleep -m (1000 * 30) ; Connect-MSOL } Until ((Get-MsolCompanyInformation).LastDirSyncTime -ne $DirSyncLast) ;
    write-host -foregroundcolor yellow "]`n$((get-date).ToString('HH:mm:ss')):AD->AAD REPLICATED!" ;
    write-host "`a" ; write-host "`a" ; write-host "`a" ;
} ; #*------^ END Function Wait-AADSync ^------

