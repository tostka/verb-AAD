#*------v get-AADBearerToken.ps1 v------
function get-AADBearerToken {
    <#
    .SYNOPSIS
    get-AADBearerToken.ps1 - generates a header from a Bearer token.
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : get-AADBearerToken.ps1
    License     : 
    Copyright   : 
    Github      : https://github.com/tostka/verb-aad
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs,Azure,AzureAD,Token,RestAPI
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    # [does not contain a method named 'AcquireToken' · Issue #29108 · MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs/issues/29108)
    reports a fix:(untested, moved to native auth via certs)
    TomBertie commented Apr 13, 2019 •
    I think I've got it working with AcquireTokenAsync by changing RESTAPI-Auth to:
    #-=-=-=-=-=-=-=-=
    Function RESTAPI-Auth {
        $global:SubscriptionID = $Subscription.Subscription.Id
        # Set Resource URI to Azure Service Management API
        $resourceAppIdURIARM=$ARMResource
        # Authenticate and Acquire Token
        # Create Authentication Context tied to Azure AD Tenant
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
        # Acquire token
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $global:authResultARM = $authContext.AcquireTokenAsync($resourceAppIdURIARM, $clientId, $redirectUri, $platformParameters)
        $global:authResultARM.Wait()
        $authHeader = $global:authResultARM.result.CreateAuthorizationHeader()
        $authHeader
    }
    #-=-=-=-=-=-=-=-=
    REVISIONS   :
    * 1:45 PM 6/16/2021 added logging (although borked, maybe they'll restore function later)
    5:41 PM 1/30/2020 BROKEN - whole concept of Bearer token pull: ADAL Azure mod dll no longer has an 'AcquireToken' method (revised away)
    .PARAMETER tenantId
    AAD TenantID (defaulted TOR) [-TenantID (guid)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADBearerToken ;
    Obtain a token
    .EXAMPLE
    $token=get-AADBearerToken -tenantId:$($tenantId) ;
    Specing a non-default Tenant
    .EXAMPLE
    $authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
    $token = $authResult.AccessToken
    $AADTokenHeaders = get-AADBearerTokenHeaders($token)
    Token rnewal example
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    [CmdletBinding()]
    Param(
        [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
        [string]$tenantId = "549366ae-e80a-44b9-8adc-52d0c29ba08b",
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug,
        [Parameter(HelpMessage = "Whatif Flag  [-whatIf]")]
        [switch] $whatIf
    ) # PARAM BLOCK END ;

    $authority = "https://login.microsoftonline.com/$tenantId"
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    write-verbose "`$authContext:`n$(($authContext|out-string).trim())" ;
    $authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Always")
    write-verbose "`$authResult:`n$(($authResult|out-string).trim())" ;
    # but as of 9:48 AM 1/28/2020 it's working again in ISE (facepalm)
    <# 3:13 PM 1/27/2020 new error:
    get-AADBearerToken : Method invocation failed because [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext] does not contain a method named 'AcquireToken'.
At C:\usr\work\o365\scripts\Pull-AADSignInReports.ps1:434 char:8
+ $token=get-AADBearerToken ;
+        ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [get-AADBearerToken], RuntimeException
    + FullyQualifiedErrorId : MethodNotFound,get-AADBearerToken
    #>
    $token = $authResult.AccessToken
    write-verbose "`$token:`n$(($token|out-string).trim())" ;
    if ($token -eq $null) {
        $smsg = "ERROR: Failed to get an Access Token" ; ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        break ;
    }
    else { $token | write-output }
}

#*------^ get-AADBearerToken.ps1 ^------