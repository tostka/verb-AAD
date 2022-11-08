#*------v Function get-AADBearerTokenHeaders v------
Function get-AADBearerTokenHeaders {
    <#
    .SYNOPSIS
    get-AADBearerTokenHeaders.ps1 - generates a header from a Bearer token.
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : get-AADBearerTokenHeaders.ps1
    License     : 
    Copyright   : 
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs,Azure,AzureAD,Token,RestAPI
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS   :
    5:41 PM 1/30/2020 BROKEN - whole concept of Bearer token pul: ADAL Azure mod dll no longer has an 'AcquireToken' method
    .PARAMETER tenantId
    AAD TenantID (defaulted TOR) [-TenantID (guid)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADBearerTokenHeaders ;
    Obtain a token
    .EXAMPLE
    $token=get-AADBearerTokenHeaders -tenantId:$($tenantId) ;
    Specing a non-default Tenant
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    [CmdletBinding()]
    param( $token )
    Return @{
        "Authorization" = ("Bearer {0}" -f $token);
        "Content-Type"  = "application/json";
    }
}; #*------^ END Function get-AADBearerTokenHeaders ^------
#*------^ END Function get-AADBearerTokenHeaders ^------
