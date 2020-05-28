#*------v Function get-AADLastSync v------
Function get-AADLastSync {
  <#
    .SYNOPSIS
    get-AADLastSync - Get specific user's last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Author      : Todd Kadrie
    Website     :	https://www.toddomation.com
    Twitter     :	@tostka
    REVISIONS   :
    * 1:03 PM 5/27/2020 moved alias: get-MsolLastSync win func
    * 9:51 AM 2/25/2020 condenced output
    * 8:50 PM 1/12/2020 expanded aliases
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
    [CmdletBinding()]
    [Alias('get-MsolLastSync')]
    Param([Parameter()]$Credential = $global:credo365TORSID) ;
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
      "Not connected to MSOnline. Now connecting." ;
      Connect-MsolService ;
    } ;
    $LastDirSyncTime = (Get-MsolCompanyInformation).LastDirSyncTime ;
    New-Object PSObject -Property @{
      TimeGMT   = $LastDirSyncTime  ;
      TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
} ; #*------^ END Function get-AADLastSync ^------
# 11:19 AM 10/18/2018 add msol alias
if(!(get-alias get-MsolLastSync -ea 0) ) {Set-Alias 'get-MsolLastSync' -Value 'get-AADLastSync' ; }