#*------v Function get-MsolUserLastSync v------
Function get-MsolUserLastSync {
    <#
    .SYNOPSIS
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 9:51 AM 2/25/2020 condenced output
    * 8:50 PM 1/12/2020 expanded aliases
    * 11:23 AM 10/18/2018 ported from get-MsolUserLastSync()
    .DESCRIPTION
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLastSync
    .LINK
    #>
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "MSolUser UPN")][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        write-verbose -verbose:$true "$((get-date).ToString('HH:mm:ss')):Not connected to MSOnline. Now connecting." ;
        Connect-MsolService -credential $Credential ;
    } ;
    $LastDirSyncTime = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
    New-Object PSObject -Property @{
        TimeGMT   = $LastDirSyncTime  ;
        TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
} ; #*------^ get-MsolUserLastSync.ps1 ^------