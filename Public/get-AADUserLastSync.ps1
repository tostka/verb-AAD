#*------v get-AADUserLastSync.ps1 v------
Function get-AADUserLastSync {
    <#
    .SYNOPSIS
    get-AADUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 3:50 PM 6/21/2022 as MicrosoftOnline MSOL module is wrecked/deprecated with MFA mandates, retool this to use AAD:(get-azureaduser -obj upn@domain.com).LastDirSyncTime ; add aad requires, cmdletbinding, and alias the prior 'msol' name, for overlapping coverage
    * 5:17 PM 8/5/2020 strong-typed Credential
    * 4:21 PM 7/24/2020 added verbose
    * 9:51 AM 2/25/2020 condenced output
    * 8:50 PM 1/12/2020 expanded aliases
    * 11:23 AM 10/18/2018 ported from get-MsolUserLastSync()
    .DESCRIPTION
    get-AADUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-AADUserLastSync
    .LINK
    #>
    #Requires -Modules AzureAD
    [CmdletBinding()]
    [Alias('get-MsolUserLastSync')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "MSolUser UPN")][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    <#try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        write-verbose -verbose:$true "$((get-date).ToString('HH:mm:ss')):Not connected to MSOnline. Now connecting." ;
        Connect-MsolService -credential $Credential ;
    } ;
    #>
    Connect-AAD -Credential $Credential ;
    #$LastDirSyncTime = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
    # (get-azureaduser -obj UPN).LastDirSyncTime 
    $LastDirSyncTime = (get-azureaduser -ObjectId $UserPrincipalName).LastDirSyncTime ;
    New-Object PSObject -Property @{
        TimeGMT   = $LastDirSyncTime  ;
        TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
} ;
#*------^ get-AADUserLastSync.ps1 ^------
