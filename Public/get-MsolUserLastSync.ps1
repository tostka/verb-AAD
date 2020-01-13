# values from central cfg
if(!$DoRetries){$DoRetries = 4 ; } ;          # attempt retries
if(!$RetrySleep){$RetrySleep = 5 ; }          # mid-retry sleep in secs
if(!$retryLimit){[int]$retryLimit=1; }        # just one retry to patch lineuri duped users and retry 1x
if(!$retryDelay){[int]$retryDelay=20; }       # secs wait time after failure
if(!$abortPassLimit){$abortPassLimit = 4;}    # maximum failed users to abort entire pass

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
    "Not connected to MSOnline. Now connecting." ;
    Connect-MsolService ;
  } ;
  #$DirSyncTimeBefore = (Get-MsolCompanyInformation).LastDirSyncTime ;
  $DirSyncTimeBefore = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
  $oReturn = New-Object PSObject -Property @{
    TimeGMT   = $DirSyncTimeBefore  ;
    TimeLocal = $DirSyncTimeBefore.ToLocalTime() ;
  };
  $oReturn | write-output ;
} ; #*------^ END Function get-MsolUserLastSync ^------