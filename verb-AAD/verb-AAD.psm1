﻿# verb-aad.psm1


<#
.SYNOPSIS
verb-AAD - Azure AD-related generic functions
.NOTES
Version     : 1.0.20
Author      : Todd Kadrie
Website     :	https://www.toddomation.com
Twitter     :	@tostka
CreatedDate : 12/17/2019
FileName    : verb-AAD.psm1
License     : MIT
Copyright   : (c) 12/17/2019 Todd Kadrie
Github      : https://github.com/tostka
AddedCredit : REFERENCE
AddedWebsite:	REFERENCEURL
AddedTwitter:	@HANDLE / http://twitter.com/HANDLE
REVISIONS
* 11:06 AM 2/25/2020 1.0.3 connect-azrm updated to reflect my credential prefs, broad updates and tightening across, also abstracted literals & constants out. Validated functions work post chgs
* 12/17/2019 - 1.0.0
* 10:55 AM 12/6/2019 Connect-MSOL & Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
* 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
* 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA, splits specified credential and picks up on global o365_TAG_MFA/o365_TAG_OPDomain varis matching the credential domain. also added Add-PSTitleBar 'XXX' for msol & aad ;
* 2:18 PM 5/14/2019 added Build-AADSignErrorsHash 
* 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD ; ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for AzureAD module
* 11:56 AM 12/7/2018 init version, added Alias connect-msol -> connect-aad
.DESCRIPTION
verb-AAD - Azure AD-related generic functions
.LINK
https://github.com/tostka/verb-AAD
#>


$script:ModuleRoot = $PSScriptRoot ;
$script:ModuleVersion = (Import-PowerShellDataFile -Path (get-childitem $script:moduleroot\*.psd1).fullname).moduleversion ;

#*======v FUNCTIONS v======



#*------v Build-AADSignErrorsHash.ps1 v------
function Build-AADSignErrorsHash {
    <#
    .SYNOPSIS
    Build-AADSignErrorsHash - Builds a hash object containing AzureAD Sign-on Error codes & matching description
    .NOTES
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Additional Credits: Sign-in activity report error codes in the Azure Active Directory portal
    Website:	https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
    REVISIONS   :
    * 8:50 PM 1/12/2020 expanded aliases
    * 10:41 AM 5/13/2019 init vers
    .DESCRIPTION
    Build-AADSignErrorsHas.ps1 - Builds a hash object containing AzureAD Sign-on Error codes & matching description: [Sign-in activity report error codes in the Azure Active Directory portal | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a populated hashtable of AAD signon error codes & descriptions
    .EXAMPLE
    $AADSignOnErrors = Build-AADSignErrorsHash ; 
    $ErrDetail = $AADSignOnErrors[$errorCode] ; 
    Populate hash and lookup errorcode
    .LINK
    https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
    #>
    #Error 	Description
    $AADSignOnError = [ordered]@{ } ;
    $AADSignOnError.add("0", "(undocumented)") ;
    $AADSignOnError.add("16000", "This is an internal implementation detail and not an error condition. You can safely ignore this reference.") ;
    $AADSignOnError.add("20001", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("20012", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("20033", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40008", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40009", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("40014", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
    $AADSignOnError.add("50000", "There is an issue with our sign-in service. Open a support ticket to resolve this issue.") ;
    $AADSignOnError.add("50001", "The service principal name was not found in this tenant. This can happen if the application has not been installed by the administrator of the tenant, or if the resource principal was not found in the directory or is invalid.") ;
    $AADSignOnError.add("50002", "Sign-in failed due to restricted proxy access on tenant. If its your own tenant policy, you can change your restricted tenant settings to fix this issue.") ;
    $AADSignOnError.add("50003", "Sign-in failed due to missing signing key or certificate. This might be because there was no signing key configured in the application. Check out the resolutions outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#certificate-or-key-not-configured. If the issue persists, contact the application owner or the application administrator.") ;
    $AADSignOnError.add("50005", "User tried to login to a device from a platform thats currently not supported through conditional access policy.") ;
    $AADSignOnError.add("50006", "Signature verification failed due to invalid signature. Check out the resolution outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery. If the issue persists, contact the application owner or application administrator.") ;
    $AADSignOnError.add("50007", "Partner encryption certificate was not found for this application. Open a support ticket with Microsoft to get this fixed.") ;
    $AADSignOnError.add("50008", "SAML assertion is missing or misconfigured in the token. Contact your federation provider.") ;
    $AADSignOnError.add("50010", "Audience URI validation for the application failed since no token audiences were configured. Contact the application owner for resolution.") ;
    $AADSignOnError.add("50011", "The reply address is missing, misconfigured, or does not match reply addresses configured for the application. Try the resolution listed at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#the-reply-address-does-not-match-the-reply-addresses-configured-for-the-application. If the issue persists, contact the application owner or application administrator.") ;
    $AADSignOnError.add("50012", "This is a generic error message that indicates that authentication failed. This can happen for reasons such as missing or invalid credentials or claims in the request. Ensure that the request is sent with the correct credentials and claims.") ;
    $AADSignOnError.add("50013", "Assertion is invalid because of various reasons. For instance, the token issuer doesnt match the api version within its valid time range, the token is expired or malformed, or the refresh token in the assertion is not a primary refresh token.") ;
    $AADSignOnError.add("50017", "Certification validation failed, reasons for the following reasons:, Cannot find issuing certificate in trusted certificates list , Unable to find expected CrlSegment , Cannot find issuing certificate in trusted certificates list , Delta CRL distribution point is configured without a corresponding CRL distribution point , Unable to retrieve valid CRL segments due to timeout issue , Unable to download CRL , Contact the tenant administrator.") ;
    $AADSignOnError.add("50020", "The user is unauthorized for one of the following reasons. The user is attempting to login with an MSA account with the v1 endpoint , The user doesnt exist in the tenant. , Contact the application owner.") ;
    $AADSignOnError.add("50027", "Invalid JWT token due to the following reasons:, doesnt contain nonce claim, sub claim , subject identifier mismatch , duplicate claim in idToken claims , unexpected issuer , unexpected audience , not within its valid time range , token format is not proper , External ID token from issuer failed signature verification. , Contact the application owner , ") ;
    $AADSignOnError.add("50029", "Invalid URI - domain name contains invalid characters. Contact the tenant administrator.") ;
    $AADSignOnError.add("50034", "User does not exist in directory. Contact your tenant administrator.") ;
    $AADSignOnError.add("50042", "The salt required to generate a pairwise identifier is missing in principle. Contact the tenant administrator.") ;
    $AADSignOnError.add("50048", "Subject mismatches Issuer claim in the client assertion. Contact the tenant administrator.") ;
    $AADSignOnError.add("50050", "Request is malformed. Contact the application owner.") ;
    $AADSignOnError.add("50053", "Account is locked because the user tried to sign in too many times with an incorrect user ID or password.") ;
    $AADSignOnError.add("50055", "Invalid password, entered expired password.") ;
    $AADSignOnError.add("50056", "Invalid or null password - Password does not exist in store for this user.") ;
    $AADSignOnError.add("50057", "User account is disabled. The account has been disabled by an administrator.") ;
    $AADSignOnError.add("50058", "The application tried to perform a silent sign in and the user could not be silently signed in. The application needs to start an interactive flow giving users an option to sign-in. Contact application owner.") ;
    $AADSignOnError.add("50059", "User does not exist in directory. Contact your tenant administrator.") ;
    $AADSignOnError.add("50061", "Sign-out request is invalid. Contact the application owner.") ;
    $AADSignOnError.add("50072", "User needs to enroll for two-factor authentication (interactive).") ;
    $AADSignOnError.add("50074", "User did not pass the MFA challenge.") ;
    $AADSignOnError.add("50076", "User did not pass the MFA challenge (non interactive).") ;
    $AADSignOnError.add("50079", "User needs to enroll for two factor authentication (non-interactive logins).") ;
    $AADSignOnError.add("50085", "Refresh token needs social IDP login. Have user try signing-in again with their username and password.") ;
    $AADSignOnError.add("50089", "Flow token expired - Authentication failed. Have user try signing-in again with their username and password") ;
    $AADSignOnError.add("50097", "Device Authentication Required. This could occur because the DeviceId or DeviceAltSecId claims are null, or if no device corresponding to the device identifier exists.") ;
    $AADSignOnError.add("50099", "JWT signature is invalid. Contact the application owner.") ;
    $AADSignOnError.add("50105", "The signed in user is not assigned to a role for the signed in application. Assign the user to the application. For more information: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#user-not-assigned-a-role") ;
    $AADSignOnError.add("50107", "Requested federation realm object does not exist. Contact the tenant administrator.") ;
    $AADSignOnError.add("50120", "Issue with JWT header. Contact the tenant administrator.") ;
    $AADSignOnError.add("50124", "Claims Transformation contains invalid input parameter. Contact the tenant administrator to update the policy.") ;
    $AADSignOnError.add("50125", "Sign-in was interrupted due to a password reset or password registration entry.") ;
    $AADSignOnError.add("50126", "Invalid username or password, or invalid on-premises username or password.") ;
    $AADSignOnError.add("50127", "User needs to install a broker application to gain access to this content.") ;
    $AADSignOnError.add("50128", "Invalid domain name - No tenant-identifying information found in either the request or implied by any provided credentials.") ;
    $AADSignOnError.add("50129", "Device is not workplace joined - Workplace join is required to register the device.") ;
    $AADSignOnError.add("50130", "Claim value cannot be interpreted as known auth method.") ;
    $AADSignOnError.add("50131", "Used in various conditional access errors. E.g. Bad Windows device state, request blocked due to suspicious activity, access policy, and security policy decisions.") ;
    $AADSignOnError.add("50132", "Credentials have been revoked due to the following reasons: , SSO Artifact is invalid or expired , Session not fresh enough for application , A silent sign-in request was sent but the users session with Azure AD is invalid or has expired. , ") ;
    $AADSignOnError.add("50133", "Session is invalid due to expiration or recent password change.") ;
    $AADSignOnError.add("50135", "Password change is required due to account risk.") ;
    $AADSignOnError.add("50136", "Redirect MSA session to application - Single MSA session detected.") ;
    $AADSignOnError.add("50140", "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.") ;
    $AADSignOnError.add("50143", "Session mismatch - Session is invalid because user tenant does not match the domain hint due to different resource. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.") ;
    $AADSignOnError.add("50144", "Users Active Directory password has expired. Generate a new password for the user or have the end user using self-service reset tool.") ;
    $AADSignOnError.add("50146", "This application is required to be configured with an application-specific signing key. It is either not configured with one, or the key has expired or is not yet valid. Contact the application owner.") ;
    $AADSignOnError.add("50148", "The code_verifier does not match the code_challenge supplied in the authorization request for PKCE. Contact the application developer.") ;
    $AADSignOnError.add("50155", "Device authentication failed for this user.") ;
    $AADSignOnError.add("50158", "External security challenge was not satisfied.") ;
    $AADSignOnError.add("50161", "Claims sent by external provider is not sufficient, or missing claim requested to external provider.") ;
    $AADSignOnError.add("50166", "Failed to send request to claims provider.") ;
    $AADSignOnError.add("50169", "The realm is not a configured realm of the current service namespace.") ;
    $AADSignOnError.add("50172", "External claims provider is not approved. Contact the tenant administrator") ;
    $AADSignOnError.add("50173", "Fresh auth token is needed. Have the user sign-in again using fresh credentials.") ;
    $AADSignOnError.add("50177", "External challenge is not supported for passthrough users.") ;
    $AADSignOnError.add("50178", "Session Control is not supported for passthrough users.") ;
    $AADSignOnError.add("50180", "Windows Integrated authentication is needed. Enable the tenant for Seamless SSO.") ;
    $AADSignOnError.add("51001", "Domain Hint is not present with On-Premises Security Identifier - On-Premises UPN.") ;
    $AADSignOnError.add("51004", "User account doesnt exist in the directory.") ;
    $AADSignOnError.add("51006", "Windows Integrated authentication is needed. User logged in using session token that is missing via claim. Request the user to re-login.") ;
    $AADSignOnError.add("52004", "User has not provided consent for access to LinkedIn resources.") ;
    $AADSignOnError.add("53000", "Conditional Access policy requires a compliant device, and the device is not compliant. Have the user enroll their device with an approved MDM provider like Intune.") ;
    $AADSignOnError.add("53001", "Conditional Access policy requires a domain joined device, and the device is not domain joined. Have the user use a domain joined device.") ;
    $AADSignOnError.add("53002", "Application used is not an approved application for conditional access. User needs to use one of the apps from the list of approved applications to use in order to get access.") ;
    $AADSignOnError.add("53003", "Access has been blocked due to conditional access policies.") ;
    $AADSignOnError.add("53004", "User needs to complete Multi-factor authentication registration process before accessing this content. User should register for multi-factor authentication.") ;
    $AADSignOnError.add("65001", "Application X doesnt have permission to access application Y or the permission has been revoked. Or The user or administrator has not consented to use the application with ID X. Send an interactive authorization request for this user and resource. Or The user or administrator has not consented to use the application with ID X. Send an authorization request to your tenant admin to act on behalf of the App : Y for Resource : Z.") ;
    $AADSignOnError.add("65004", "User declined to consent to access the app. Have the user retry the sign-in and consent to the app") ;
    $AADSignOnError.add("65005", "The application required resource access list does not contain applications discoverable by the resource or The client application has requested access to resource, which was not specified in its required resource access list or Graph service returned bad request or resource not found. If the application supports SAML, you may have configured the application with the wrong Identifier (Entity). Try out the resolution listed for SAML using the link below: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery?/?WT.mc_id=DMC_AAD_Manage_Apps_Troubleshooting_Nav#no-resource-in-requiredresourceaccess-list") ;
    $AADSignOnError.add("70000", "Invalid grant due to the following reasons:, Requested SAML 2.0 assertion has invalid Subject Confirmation Method , App OnBehalfOf flow is not supported on V2 , Primary refresh token is not signed with session key , Invalid external refresh token , The access grant was obtained for a different tenant. , ") ;
    $AADSignOnError.add("70001", "The application named X was not found in the tenant named Y. This can happen if the application with identifier X has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have misconfigured the Identifier value for the application or sent your authentication request to the wrong tenant.") ;
    $AADSignOnError.add("70002", "The application returned invalid client credentials. Contact the application owner.") ;
    $AADSignOnError.add("70003", "The application returned an unsupported grant type. Contact the application owner.") ;
    $AADSignOnError.add("70004", "The application returned an invalid redirect URI. The redirect address specified by the client does not match any configured addresses or any addresses on the OIDC approve list. Contact the application owner.") ;
    $AADSignOnError.add("70005", "The application returned an unsupported response type due to the following reasons: , response type token is not enabled for the application , response type id_token requires the OpenID scope -contains an unsupported OAuth parameter value in the encoded wctx , Contact the application owner.") ;
    $AADSignOnError.add("70007", "The application returned an unsupported value of response_mode when requesting a token. Contact the application owner.") ;
    $AADSignOnError.add("70008", "The provided authorization code or refresh token is expired or has been revoked. Have the user retry signing in.") ;
    $AADSignOnError.add("70011", "The scope requested by the application is invalid. Contact the application owner.") ;
    $AADSignOnError.add("70012", "A server error occurred while authenticating an MSA (consumer) user. Retry the sign-in, and if the issue persists, open a support ticket") ;
    $AADSignOnError.add("70018", "Invalid verification code due to User typing in wrong user code for device code flow. Authorization is not approved.") ;
    $AADSignOnError.add("70019", "Verification code expired. Have the user retry the sign-in.") ;
    $AADSignOnError.add("70037", "Incorrect challenge response provided. Remote auth session denied.") ;
    $AADSignOnError.add("75001", "An error occurred during SAML message binding.") ;
    $AADSignOnError.add("75003", "The application returned an error related to unsupported Binding (SAML protocol response cannot be sent via bindings other than HTTP POST). Contact the application owner.") ;
    $AADSignOnError.add("75005", "Azure AD doesnt support the SAML Request sent by the application for Single Sign-on. Contact the application owner.") ;
    $AADSignOnError.add("75008", "The request from the application was denied since the SAML request had an unexpected destination. Contact the application owner.") ;
    $AADSignOnError.add("75011", "Authentication method by which the user authenticated with the service doesnt match requested authentication method. Contact the application owner.") ;
    $AADSignOnError.add("75016", "SAML2 Authentication Request has invalid NameIdPolicy. Contact the application owner.") ;
    $AADSignOnError.add("80001", "Authentication Agent unable to connect to Active Directory. Make sure the authentication agent is installed on a domain-joined machine that has line of sight to a DC that can serve the users login request.") ;
    $AADSignOnError.add("80002", "Internal error. Password validation request timed out. We were unable to either send the authentication request to the internal Hybrid Identity Service. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80003", "Invalid response received by Authentication Agent. An unknown error occurred while attempting to authentication against Active Directory on-premises. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80005", "Authentication Agent: An unknown error occurred while processing the response from the Authentication Agent. Open a support ticket to get more details on the error.") ;
    $AADSignOnError.add("80007", "Authentication Agent unable to validate users password.") ;
    $AADSignOnError.add("80010", "Authentication Agent unable to decrypt password.") ;
    $AADSignOnError.add("80011", "Authentication Agent unable to retrieve encryption key.") ;
    $AADSignOnError.add("80012", "The users attempted to log on outside of the allowed hours (this is specified in AD).") ;
    $AADSignOnError.add("80013", "The authentication attempt could not be completed due to time skew between the machine running the authentication agent and AD. Fix time sync issues") ;
    $AADSignOnError.add("80014", "Authentication agent timed out. Open a support ticket with the error code, correlation ID, and Datetime to get more details on this error.") ;
    $AADSignOnError.add("81001", "Users Kerberos ticket is too large. This can happen if the user is in too many groups and thus the Kerberos ticket contains too many group memberships. Reduce the users group memberships and try again.") ;
    $AADSignOnError.add("81005", "Authentication Package Not Supported.") ;
    $AADSignOnError.add("81007", "Tenant is not enabled for Seamless SSO.") ;
    $AADSignOnError.add("81012", "This is not an error condition. It indicates that user trying to sign in to Azure AD is different from the user signed into the device. You can safely ignore this code in the logs.") ;
    $AADSignOnError.add("90010", "The request is not supported for various reasons. For example, the request is made using an unsupported request method (only POST method is supported) or the token signing algorithm that was requested is not supported. Contact the application developer.") ;
    $AADSignOnError.add("90014", "A required field for a protocol message was missing, contact the application owner. If you are the application owner, ensure that you have all the necessary parameters for the login request.") ;
    $AADSignOnError.add("90051", "Invalid Delegation Token. Invalid national Cloud ID ({cloudId}) is specified.") ;
    $AADSignOnError.add("90072", "The account needs to be added as an external user in the tenant first. Sign-out and sign-in again with a different Azure AD account.") ;
    $AADSignOnError.add("90094", "The grant requires administrator permissions. Ask your tenant administrator to provide consent for this application.") ;
    $AADSignOnError.add("500021", "Tenant is restricted by company proxy. Denying the resource access.") ;
    $AADSignOnError.add("500121", "Authentication failed during strong authentication request.") ;
    $AADSignOnError.add("500133", "The assertion is not within its valid time range. Ensure that the access token is not expired before using it for user assertion, or request a new token.") ;
    $AADSignOnError.add("530021", "Application does not meet the conditional access approved app requirements.") ;
    $AADSignOnError | write-output ;
}

#*------^ Build-AADSignErrorsHash.ps1 ^------

#*------v caadCMW.ps1 v------
function caadCMW {Connect-AAD -cred $credO365CMWCSID}

#*------^ caadCMW.ps1 ^------

#*------v caadTOL.ps1 v------
function caadtol {Connect-AAD -cred $credO365TOLSID}

#*------^ caadTOL.ps1 ^------

#*------v caadTOR.ps1 v------
function caadTOR {Connect-AAD -cred $credO365TORSID}

#*------^ caadTOR.ps1 ^------

#*------v caadVEN.ps1 v------
function caadVEN {Connect-AAD -cred $credO365VENCSID}

#*------^ caadVEN.ps1 ^------

#*------v cmsolCMW.ps1 v------
function cmsolcmw {Connect-MSOL -cred $credO365CMWCSID}

#*------^ cmsolCMW.ps1 ^------

#*------v cmsolTOL.ps1 v------
function cmsolTOL {Connect-MSOL -cred $credO365TOLSID}

#*------^ cmsolTOL.ps1 ^------

#*------v cmsolTOR.ps1 v------
function cmsolTOR {Connect-MSOL -cred $credO365CMWCSID}

#*------^ cmsolTOR.ps1 ^------

#*------v cmsolVEN.ps1 v------
function cmsolVEN {Connect-MSOL -cred $credO365VENCSID}

#*------^ cmsolVEN.ps1 ^------

#*------v Connect-AAD.ps1 v------
Function Connect-AAD {
    <#
    .SYNOPSIS
    Connect-AAD - Establish authenticated session to AzureAD Graph Module (AzureAD), also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-05-27
    FileName    : Connect-AAD.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 11:38 AM 7/28/2020 added verbose credential echo and other detail for tenant-match confirmations
    * 12:47 PM 7/24/2020 added code to test for match between get-azureadTenantDetail.VerifiedDomains list and the domain in use for the specified Credential, if no match, it triggers a full credentialed logon (working around the complete lack of an explicit disconnect-AzureAD cmdlet, for permitting changing Tenants)
    * 7:13 AM 7/22/2020 replaced codeblock w get-TenantTag()
    * 4:36 PM 7/21/2020 updated various psms for VEN tenant
    * 12:11 PM 5/27/2020 updated CBH, moved aliases:'caad','raad','reconnect-AAD' win the func
    * 10:55 AM 12/6/2019 Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
    * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    * 1:39 PM 5/8/2019 Connect-AAD:tightened up the installed/imported/authenticated checks
    * 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD
    * 1:54 PM 10/8/2018 Connect-AAD:port from Connect-AAD
    .DESCRIPTION
    Connect-AAD - Establish authenticated session to AzureAD/MSOL, also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
    No need for separate reConnect-AAD - this self tests for connection, and reconnects if it's missing.
    No support for disConnect-AAD, because MSOL has no command to do it, but closing powershell.
    .PARAMETER  ProxyEnabled
    Proxyied connection support
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Connect-AAD
    .EXAMPLE
    Connect-AAD -Credential $cred
    .LINK
    #>
    [CmdletBinding()] 
    [Alias('caad','raad','reconnect-AAD')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        write-verbose "(Credential specified: $($Credential.username))" ; 
        $MFA = get-TenantMFARequirement -Credential $Credential ;

        $sTitleBarTag="AAD" ;
        $TentantTag=get-TenantTag -Credential $Credential ; 
        if($TentantTag -ne 'TOR'){
            # explicitly leave this tenant (default) untagged
            $sTitleBarTag += $TentantTag ;
        } ; 

        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        # with multitenants and changes between, instead we need ot test 'what tenant' we're connected to
        TRY { 
            $AADTenDtl = Get-AzureADTenantDetail ; # err indicates no authenticated connection
            #if connected,verify cred-specified Tenant
            if($AADTenDtl.VerifiedDomains.name.contains($Credential.username.split('@')[1].tostring())){
                write-verbose "(Authenticated to AAD:$($AADTenDtl.displayname))"
            } else { 
                write-verbose "(Disconnecting from $(AADTenDtl.displayname) to reconn to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ; 
                Disconnect-AzureAD ; 
                throw "" 
            }
        } 
        #CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        # for changing Tenant logons, we need to trigger a full credential reconnect, even if connected and not thowing AadNeedAuthenticationException
        CATCH{
            TRY {
                if(!$Credential){
                    if(get-command -Name get-admincred) {
                        Get-AdminCred ;
                    } else {
                        $credDom = ($Credential.username.split("@"))[1] ;
                        $Metas=(get-variable *meta|?{$_.name -match '^\w{3}Meta$'}) ; 
                        foreach ($Meta in $Metas){
                                if( ($credDom -eq $Meta.value.legacyDomain) -OR ($credDom -eq $Meta.value.o365_TenantDomain) -OR ($credDom -eq $Meta.value.o365_OPDomain)){
                                    if($Meta.value.o365_SIDUpn ){$Credential = Get-Credential -Credential $Meta.value.o365_SIDUpn } else { $Credential = Get-Credential } ;
                                    break ; 
                                } ; 
                        } ;
                        if(!$Credential){
                            write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                            $Credential = Get-Credential ; 
                        } ;
                    }  ;
                } ;
                Write-Host "Authenticating to AAD:$($Credential.username.split('@')[1].tostring()), w $($Credential.username)..."  ;
                if(!$MFA){
                    write-verbose "EXEC:Connect-AzureAD -Credential $($Credential.username) (no MFA, full credential)" ; 
                    Connect-AzureAD -Credential $Credential -ErrorAction Stop ;
                } else {
                    write-verbose "EXEC:Connect-AzureAD -Credential $($Credential.username) (w MFA, username & prompted pw)" ; 
                    Connect-AzureAD -AccountID $Credential.userName ;
                } ;

                # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
                if ($?) { write-verbose -verbose:$true  "(connected to AzureAD ver2)" ; Add-PSTitleBar $sTitleBarTag ; } ;
            } CATCH {
                Write-Verbose "There was an error Connecting to Azure Ad - Ensure the module is installed" ;
                Write-Verbose "Download PowerShell 5 or PowerShellGet" ;
                Write-Verbose "https://msdn.microsoft.com/en-us/powershell/wmf/5.1/install-configure" ;
            } ;
        } ;
    } ; 
    END {} ;
}

#*------^ Connect-AAD.ps1 ^------

#*------v connect-AzureRM.ps1 v------
function connect-AzureRM {
    <#
    .SYNOPSIS
    connect-AzureRM.ps1 - Connect to AzureRM module
    .NOTES
    Version     : 1.6.2
    Author      : Kevin Blumenfeld
    Website     :	https://github.com/kevinblumenfeld/Posh365
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2019-02-06
    FileName    :
    License     : MIT License
    Copyright   : (c) 2020 Kevin Blumenfeld. All rights reserved. 
    Github      : https://github.com/kevinblumenfeld/Posh365
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 7:13 AM 7/22/2020 replaced codeblock w get-TenantTag()
    # 5:04 PM 7/21/2020 VEN support added
    # 9:19 AM 2/25/2020 updated to reflect my credential prefs
    # 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    .DESCRIPTION
    .PARAMETER  ProxyEnabled
    Switch for Access Proxy in chain
    .PARAMETER  Credential
    Credential object
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .EXAMPLE
    .\connect-AzureRM.ps1
    .EXAMPLE
    .\connect-AzureRM.ps1
    .LINK
    #>
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    $MFA = get-TenantMFARequirement -Credential $Credential ;

    $sTitleBarTag="AzRM" ;
    $TentantTag=get-TenantTag -Credential $Credential ; 
    if($TentantTag -ne 'TOR'){
        # explicitly leave this tenant (default) untagged
        $sTitleBarTag += $TentantTag ;
    } ; 

    Try {Get-AzureRmTenant -erroraction stop }
    Catch {Install-Module -Name AzureRM -Scope CurrentUser} ;
    Try {Get-AzureRmTenant -erroraction stop}
    Catch {Import-Module -Name AzureRM -MinimumVersion '4.2.1'} ;
    if (! $MFA) {
        $json = Get-ChildItem -Recurse -Include '*@*.json' -Path $CredFolder
        if ($json) {
            Write-Host " Select the Azure username and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
            Write-Host " Otherwise, if this is the first time using this Azure username click `"Cancel`"" -foregroundcolor "magenta" -backgroundcolor "white"
            $json = $json | select name | Out-GridView -PassThru -Title "Select Azure username or click Cancel to use another"
        }
        if (!($json)) {
            Try {
                #$azLogin = Login-AzureRmAccount -ErrorAction Stop
                # looks revised, even gethelp on the above returns these examples:Connect-AzureRmAccount
                $azLogin = Connect-AzureRmAccount -Credential $Credential -ErrorAction Stop
            }
            Catch [System.Management.Automation.CommandNotFoundException] {
                write-verbose -verbose:$true "Download and install PowerShell 5.1 or PowerShellGet so the AzureRM module can be automatically installed"
                write-verbose -verbose:$true "https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-4.2.0#how-to-get-powershellget"
                write-verbose -verbose:$true "or download the MSI installer and install from here: https://github.com/Azure/azure-powershell/releases"
                Break
            }
            Save-AzureRmContext -Path ($CredFolder + "\" + ($azLogin.Context.Account.Id) + ".json")
            Import-AzureRmContext -Path ($CredFolder + "\" +  + ($azLogin.Context.Account.Id) + ".json")
        }
        else {Import-AzureRmContext -Path ($CredFolder + "\" +  + $json.name)}
        Write-Host "Select Subscription and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription"| Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to AzureRm)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        }
        Catch {
            Write-Warning "Azure credentials are invalid or expired. Authenticate again please."
            if ($json.name) {Remove-Item ($CredFolder + "\" +  + $json.name) } ; 
            connect-AzureRM
        }
    } else {
        Try {
            #Login-AzureRmAccount -ErrorAction Stop
            # looks revised, even gethelp on the above returns these examples:Connect-AzureRmAccount
            Connect-AzureRmAccount -AccountID $Credential.userName ;
        }
        Catch [System.Management.Automation.CommandNotFoundException] {
            write-verbose -verbose:$true "Download and install PowerShell 5.1 or PowerShellGet so the AzureRM module can be automatically installed"
            write-verbose -verbose:$true "https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-4.2.0#how-to-get-powershellget"
            write-verbose -verbose:$true "or download the MSI installer and install from here: https://github.com/Azure/azure-powershell/releases"
            Break
        }
        Write-Host "Select Subscription and Click `"OK`" in lower right-hand corner" -foregroundcolor "magenta" -backgroundcolor "white"
        $subscription = Get-AzureRmSubscription | Out-GridView -PassThru -Title "Choose Azure Subscription" | Select-Object id
        Try {
            Select-AzureRmSubscription -SubscriptionId $subscription.id -ErrorAction Stop
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to AzureRm)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        }
        Catch {
            write-verbose -verbose:$true "There was an error selecting your subscription ID"
        }
    }
}

#*------^ connect-AzureRM.ps1 ^------

#*------v Connect-MSOL.ps1 v------
Function Connect-MSOL {
    <#    
    .SYNOPSIS
    Connect-MSOL - Establish authenticated session to AzureAD MSOL Module, also works as reConnect-MSOL, there is no disConnect-MSOL (have to close Powershell to clear it).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 1:28 PM 7/27/2020 restored deleted file (was fat-thumbed 7/22)
    * 5:06 PM 7/21/2020 added VEN supp
    * 6:11 PM 2/26/2020 moved aliases below
    * 2:08 PM 2/26/2020 converted to adv func
    * 8:50 PM 1/12/2020 expanded aliases
    * 10:55 AM 12/6/2019 Connect-MSOL:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
    * 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
    * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
    * 1:32 PM 5/8/2019 switched text into pipe with explicit Write-Verbose's
    * 2:51 PM 5/2/2019 ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for aad2 module
    * 12:06 PM 12/7/2018 added Alias 'connect-msol' -> 'Connect-AAD'
    * 7:38 AM 10/5/2018 out-null the pretesting Get-MsolAccountSku into a vari (was dumping into console)
    * 9:38 AM 9/10/2018 Connect-AAD: now it's working (?.?)7 weird. Also aliased reconnect-aad -> connect-AAD()- it's the same, but easier to just cover the gap.
    * 12:27 PM 11/3/2017 nope, not working, can't authenticate yet.
    * 12:19 PM 11/3/2017 this wasn't really written, sketched it in to see how it works
    .DESCRIPTION
    Connect-MSOL - Establish authenticated session to AzureAD/MSOL, also works as reconnect-AAD, there is no disConnect-MSOL (have to close Powershell to clear it).
    No need for separate reConnect-MSOL - this self tests for connection, and reconnects if it's missing.
    No support for disConnect-MSOL, because MSOL has no command to do it, but closing powershell.
    .PARAMETER  ProxyEnabled
    Proxyied connection support
    .PARAMETER CommandPrefix
    Prefix to be appended to commands (not implemented with MSOL/AAD)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Connect-MSOL
    .LINK
    #>
    [CmdletBinding()]
    [Alias('cmsol','rmsol','Reconnect-MSOL')]
    Param(
        [Parameter()][boolean]$ProxyEnabled = $False,
        [Parameter()][string]$CommandPrefix,
        [Parameter()]$Credential = $global:credo365TORSID
    ) ;
    BEGIN { $verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $MFA = get-TenantMFARequirement -Credential $Credential ;

        # 12:10 PM 3/15/2017 disable prefix spec, unless actually blanked (e.g. centrally spec'd in profile).
        #if(!$CommandPrefix){ $CommandPrefix='aad' ; } ;

        $sTitleBarTag = "MSOL" ;
        $credDom = ($Credential.username.split("@"))[1] ;
        if($Credential.username.contains('.onmicrosoft.com')){
            # cloud-first acct
            switch ($credDom){
                "$($TORMeta['o365_TenantDomain'])" { } 
                "$($TOLMeta['o365_TenantDomain'])" {$sTitleBarTag += $TOLMeta['o365_Prefix']}
                "$($CMWMeta['o365_TenantDomain'])" {$sTitleBarTag += $CMWMeta['o365_Prefix']}
                "$($VENMeta['o365_TenantDomain'])" {$sTitleBarTag += $VENMeta['o365_Prefix']}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_TenantDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } else { 
            # OP federated domain
            switch ($credDom){
                "$($TORMeta['o365_OPDomain'])" { }
                "$($TOLMeta['o365_OPDomain'])" {$sTitleBarTag += $TOLMeta['o365_Prefix']}
                "$($CMWMeta['o365_OPDomain'])" {$sTitleBarTag += $CMWMeta['o365_Prefix']}
                "$($VENMeta['o365_OPDomain'])" {$sTitleBarTag += $VENMeta['o365_Prefix']}
                default {throw "Failed to resolve a `$credVariTag` from populated global 'o365_OPDomain' props, for credential domain:$($CredDom)" } ;
            } ; 
        } ; 

        try { Get-MsolAccountSku -ErrorAction Stop | out-null }
        catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
            Write-Verbose "Not connected to MSOnline. Now connecting." ;
            if (!$Credential) {
                if (test-path function:\get-admincred) {
                    Get-AdminCred ;
                }
                else {
                    switch ($env:USERDOMAIN) {
                        "$($TORMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($TORMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($TORMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $TORMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($TORMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $TORMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($TOLMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($TOLMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($TOLMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $TOLMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($TOLMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $TOLMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($CMWMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($CMWMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($CMWMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $CMWMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($CMWMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $CMWMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        "$($VENMeta['legacyDomain'])" {
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($VENMeta['o365_SIDUpn']))" ;
                            if (!$bUseo365COAdminUID) {
                                if ($VENMeta['o365_SIDUpn'] ) { 
                                    $Credential = Get-Credential -Credential $VENMeta['o365_SIDUpn'] 
                                } else { $Credential = Get-Credential } ;
                            }
                            else {
                                if ($VENMeta['o365_CSIDUpn']) { 
                                    $Credential = Get-Credential -Credential $VENMeta['o365_CSIDUpn'] 
                                    global:o365cred = $Credential ; 
                                } else { $Credential = Get-Credential } ;
                            } ;
                        }
                        default {
                            write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ;
                            $Credential = Get-Credential
                        } ;
                    } ;
                }  ;
            } ;
            Write-Host "Connecting to AzureAD/MSOL"  ;
            $error.clear() ;
            if (!$MFA) {
                Connect-MsolService -Credential $Credential -ErrorAction Stop ;
            }
            else {
                Connect-MsolService -ErrorAction Stop ;
            } ;
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to MSOL)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        } ;
        
    } ;
    END {} ;
}

#*------^ Connect-MSOL.ps1 ^------

#*------v Disconnect-AAD.ps1 v------
Function Disconnect-AAD {
    <#
    .SYNOPSIS
    Disconnect-AAD - Disconnect authenticated session to AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-07-27
    FileName    : Disconnect-AAD.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 3:15 PM 7/27/2020 init vers
    .DESCRIPTION
    Disconnect-AAD - Disconnect authenticated session to AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Disconnect-AAD
    .EXAMPLE
    Disconnect-AAD -Credential $cred
    .LINK
    https://docs.microsoft.com/en-us/powershell/module/azuread/disconnect-azuread?view=azureadps-2.0
    #>
    [CmdletBinding()] 
    [Alias('daad')]
    Param() ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        if(get-command disconnect-AzureAD){
            $sTitleBarTag="AAD" ;
            $AADTenDtl = Get-AzureADTenantDetail ; 
            if($AADTenDtl){
                write-verbose "(Disconnecting from  AAD:$($AADTenDtl.displayname))" ;
                Remove-PSTitleBar -Tag $sTitleBarTag ; 
            } else { write-verbose "(No existing AAD tenant connection)" } ;
        } else {write-verbose "(The AzureAD module isn't currently loaded)" } ; 
    } ; 
    END {} ;
}

#*------^ Disconnect-AAD.ps1 ^------

#*------v get-AADCertToken.ps1 v------
function get-AADCertToken {
    <#
    .SYNOPSIS
     get-AADCertToken - Obtain a certificate-authenticated Azure access token
    .NOTES
    Version     : 1.0.0
    Author      : Alex Asplund
    Website     : https://automativity.com
    Twitter     : @AlexAsplund
    CreatedDate : 2019-08-12
    FileName    : 
    License     :
    Copyright   : 
    Github      : 
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	
    REVISIONS
    * 8:51 AM 1/30/2020
    * 2019-08-12 posted version 
    .DESCRIPTION
     get-AADCertToken - Obtain a certificate-authenticated AADApp Azure access token
     Uses code Alex Asplund demo'd at link below, wrapped into a func
     Configure parameter defaults as follows
        |param|info source|
        |---|---|
        |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
        |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
        |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
        |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|

        This script uses RestAPI calls to authenticate and query GraphAPI. 

        ##Prereqs:
        1) **Verify AAD Premium P1 tenant license:**
          - [https://admin.microsoft.com/Adminportal/](https://admin.microsoft.com/Adminportal/) : *Billing >* appears at top: *Azure Active Directory Premium P1*
          - or [https://portal.azure.com](https://portal.azure.com) ; *AAD *> main overview page, it appear right below* 'The Toro Company'* on the graph: *Azure AD Premium P1*

        2) **Create an Application Identity**
        [https://portal.azure.com](https://portal.azure.com) > *Azure Active Directory* > *Manage pane:* *App Registrations* > **[+]New Registration**
        **Register an application screen**: 
        - **Displayname**: `AuditGraphAccessMessaging`
        - **Supported account types**:
        (x) **Accounts in this organizational directory only (COMPANY - Single tenant)**</br>
        ( ) *Accounts in any organizational directory (Any Azure AD directory - Multitenant)*</br>
        ( ) *Accounts in any organizational directory (Any Azure AD directory - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)*</br>
        - Click **Register**
        - Above refreshes to the details of the new App: upper right: click **Add a Redirect URI**
            - **Type**: ***Web***, **Redirect URI**: `https://localhost` </br>
            *(can set anything here, doesn't need to be functional)*
            - click **Save** *(top left, note the redirect url created)*
        - Record the **Application (client ID)** *(guid)* for future reference.

        3) **Grant necessary App Permissions**
            - If necessary, return to: *AADPortal > App Registrations* > [find and click your new App]
            - Left pane: Click **Api permisions**
                - ***For Audit Log Sign-in Activity, it needs:***
            
                |Permission type |Permissions (from least to most privileged)|
                |---|---|
                |Delegated (work or school account) |AuditLog.Read.All, Directory.Read.All|
                |Delegated (personal Microsoft account) |Not supported|
                |Application |AuditLog.Read.All, Directory.Read.All|
            
            - click **Add a permission** btn
                - **Request API Permissions** blade: **Microsoft Graph**
                - click **Application permissions** *(don't require a logged on user to be present to run)*
                - *Type to search*: [*type out one of the permisison names above*]
                - when the matching entry appears **[x]** (e.g. AuditLog.Read.All)
                - click **Add permission** to commit the change. (refreshes back to the *Configured permissions* screen)
                - Repeat the process above for each additional permission to be added
            - When all permisisons are added & displayed, click the **Grant admin consent for TENANT** button, **Yes**

        4) **Create a self-signed certificate to handle authentication:**
          - Configure values to suite Tenant and App Name. 
        ```powershell
        # gens a self-signed cert for AAD auth of the AAD AuditGraphAccessMessaging API Access secprinc
        # below is displayed by: (Get-AzureADTenantDetail).VerifiedDomain
        $TenantName = $o365_Torolab_TenantDomain ;
        $CerOutputPath = "C:\usr\work\o365\certs\AuditGraphAccessMessagingTOL.cer" ;
        $StoreLocation = "Cert:\CurrentUser\My" ;
        $ExpirationDate = (Get-Date).AddYears(2) ;
        $CreateCertificateSplat = @{
          FriendlyName = "AuditGraphAccessMessagingTOL" ;
            DnsName = $TenantName ;
            CertStoreLocation = $StoreLocation ;
            NotAfter = $ExpirationDate ;
            KeyExportPolicy = "Exportable" ;
            KeySpec = "Signature" ;
            Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider" ;
            HashAlgorithm = "SHA256" ;
        } ;
        $Certificate = New-SelfSignedCertificate @CreateCertificateSplat ;
        $CertificatePath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint ;
        Export-Certificate -Cert $CertificatePath -FilePath $CerOutputPath | Out-Null ;
        gci $CertificatePath ; gci $CerOutputPath | fl fullname,length; 
        ```

        5) **Configure App with Certificate Authentication:**
        - From the registered apps's summary page, click left menu: **Certificates & secrets**  > **Upload certificate**, click folder icon, (*browse .cer*) , **Add**
        - **while we're here lets add a Secret (password) as well:**  
          - **Certificates & secrets**  > **New client secret** 
          - *Description*: 'For SigninActivity review scripts'
          - *Expires*: **(x) in 2 years**
          - click **Add**
          - The newly generated secret (password) string will *only* be displayed *once* on this page. Record it & the expiration date for permanent reference:
    .PARAMETER  tenantName
    AAD TenantID [-TenantID (guid)]]
    .PARAMETER  AppID
    AAD AppID [-AppID (guid)]]
    .PARAMETER  Certificate
    Certificate Thumbprint [-Certificate (thumbprint)]]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a token object
    .EXAMPLE
    $token=get-AADCertToken ;
    Obtain a token, using default params
    .EXAMPLE
    $token=get-AADCertToken -tenantName "[tenant].onmicrosoft.com" -AppID "[appid guid]" -Certificate "7C7D6...[thumbprint]";
    Specing a Token with non-defaults explicits
    .EXAMPLE
    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose -Verbose:$verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token =get-AADCertToken @pltAADCertToken ; 
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue') ; 
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns" ; 
    $myReportRequest = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json") ; 
    $myReport = @()
    $myReport += $myReportRequest.value
    Do {
        $myReportRequest = Invoke-RestMethod -Uri $AuditLogRequest.'@odata.nextLink' -Headers $Header -Method Get -ContentType "application/json"
        $myReport += $myReportRequest.value
    } while($myReportRequest.'@odata.nextLink' -ne $null) ; 
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    #>
    [CmdletBinding()]
    Param(
        [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
        [string]$tenantName = $global:o365_Toroco_TenantDomain,
        [Parameter(HelpMessage = "AAD AppID [-AppID (guid)]]")]
        [string]$AppID = $global:TOR_AAD_App_Audit_ID,
        [Parameter(HelpMessage = "Certificate Thumbprint [-Certificate (thumbprint)]]")]
        $Certificate = $global:TOR_AAD_App_Audit_CertThumb,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) # PARAM BLOCK END ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if($Certificate = Get-Item Cert:\CurrentUser\My\$Certificate){ 
        ( $certificate| fl Subject,DnsNameList,FriendlyName,Not*,Thumbprint | out-string).trim() | write-verbose -Verbose:$verbose ;
        $Scope = "https://graph.microsoft.com/.default" ;
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) ;
        # Create JWT timestamp for expiration
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime() ;
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0) ;
        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0) ;
        # Create JWT header
        $JWTHeader = @{
            alg = "RS256" ;
            typ = "JWT" ;
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '=' ;
        } ;
        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantName/oauth2/token" ;
            # Expiration timestamp
            exp = $JWTExpiration ;
            # Issuer = your application
            iss = $AppId ;
            # JWT ID: random guid
            jti = [guid]::NewGuid() ;
            # Not to be used before
            nbf = $NotBefore ;
            # JWT Subject
            sub = $AppId ;
        } ;
        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json)) ;
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte) ;
        $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json)) ;
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte) ;
        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + "." + $EncodedPayload ;
        # Get the private key object of your certificate
        $PrivateKey = $Certificate.PrivateKey
        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1 ;
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256 ; 
        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding) 
        ) -replace '\+','-' -replace '/','_' -replace '=' ;
        # Join the signature to the JWT with "."
        $JWT = $JWT + "." + $Signature ;
        # Create a hash with body parameters
        $Body = @{
            client_id = $AppId ;
            client_assertion = $JWT ;
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ;
            scope = $Scope ;
            grant_type = "client_credentials" ;
        } ;
        $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" ;
        # Use the self-generated JWT as Authorization
        $Header = @{
            Authorization = "Bearer $JWT" ;
        } ;
        # Splat the parameters for Invoke-Restmethod for cleaner code
        $PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded' ;
            Method = 'POST' ;
            Body = $Body ;
            Uri = $Url ;
            Headers = $Header ;
        } ;
        write-verbose -Verbose:$verbose "$((get-date).ToString('HH:mm:ss')):Invoke-RestMethod w`n$(($PostSplat|out-string).trim())" ; 
        $token = Invoke-RestMethod @PostSplat ; 

    } else { 
        write-warning "Unable to:Get-Item Cert:\CurrentUser\My\$($Certificate)"
        Stop
    } ; 

    write-verbose "`$token:`n$(($token|out-string).trim())" ;
    if ($token -eq $null) {
        Write-Output "ERROR: Failed to get an Access Token" ;
        exit
    }
    else { $token | write-output }
    
}

#*------^ get-AADCertToken.ps1 ^------

#*------v get-AADLastSync.ps1 v------
Function get-AADLastSync {
  <#
    .SYNOPSIS
    get-AADLastSync - Get specific user's last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Author      : Todd Kadrie
    Website     :	https://www.toddomation.com
    Twitter     :	@tostka
    REVISIONS   :
    * 4:08 PM 7/24/2020 added full multi-ten cred support
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
    $verbose = ($VerbosePreference -eq "Continue") ; 
    try { Get-MsolAccountSku -ErrorAction Stop | out-null }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
      "Not connected to MSOnline. Now connecting to $($credo365.username.split('@')[1])." ;
      $MFA = get-TenantMFARequirement -Credential $Credential ;
      if($MFA){ Connect-MsolService }
      else {Connect-MsolService -Credential $Credential ;}
    } ;
    $LastDirSyncTime = (Get-MsolCompanyInformation).LastDirSyncTime ;
    New-Object PSObject -Property @{
      TimeGMT   = $LastDirSyncTime  ;
      TimeLocal = $LastDirSyncTime.ToLocalTime() ;
    } | write-output ;
}

#*------^ get-AADLastSync.ps1 ^------

#*------v get-AADTokenHeaders.ps1 v------
Function get-AADTokenHeaders {
    <#
    .SYNOPSIS
    get-AADTokenHeaders - Construct headers for an Azure access token
    .NOTES
    Version     : 1.0.0
    Author      : Alex Asplund
    Website     :	https://automativity.com
    Twitter     :	@AlexAsplund
    CreatedDate : 2019-08-12
    FileName    : 
    License     :
    Copyright   : 
    Github      : 
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	
    REVISIONS
    * 2019-08-12 posted version 
    .DESCRIPTION
    get-AADTokenHeaders - Construct Azure access token headers
    Uses code Alex Asplund demo'd at link below, wrapped into a func
    .PARAMETER  token
    Token[-Token (token obj)]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a header hashtable
    .EXAMPLE
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Token[-Token (token obj)]")]
        [ValidateNotNullOrEmpty()]$token,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    write-verbose "$((get-date).ToString('HH:mm:ss')):Provided token:`n$(($token|out-string).trim())" ; 
    $Header = @{
        Authorization = "$($token.token_type) $($token.access_token)"
    }
    write-verbose "$((get-date).ToString('HH:mm:ss')):Generated `$Header:`n$(($Header|out-string).trim())" ; 
    $Header | write-output ; 
}

#*------^ get-AADTokenHeaders.ps1 ^------

#*------v get-MsolUserLastSync.ps1 v------
Function get-MsolUserLastSync {
    <#
    .SYNOPSIS
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 4:21 PM 7/24/2020 added verbose
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
    $verbose = ($VerbosePreference -eq "Continue") ; 
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
}

#*------^ get-MsolUserLastSync.ps1 ^------

#*------v get-MsolUserLicenseDetails.ps1 v------
Function get-MsolUserLicenseDetails {
    <#
    .SYNOPSIS
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Based on work by :Brad Wyatt
    Website: https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    REVISIONS   :
    * 4:22 PM 7/24/2020 added verbose
    * 8:50 PM 1/12/2020 expanded aliases
    * 12:00 PM 1/9/2019 replaced broken aggreg with simpler cobj -prop $hash set, now returns proper mult lics
    * 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    * 11:33 AM 1/9/2019 add SPE_F1 lic spec, and export the aggreg, NewObject02 was never more than a single lic (eg. support mult lics)
    * 3:47 PM 12/7/2018 works in prod for single-licenses users, haven't tested on multis yet.
    * 3:17 PM 12/7/2018 added showdebug, updated pshelp
    * 2:58 PM 12/7/2018 initial version
    .DESCRIPTION
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    Based on the core lic hash & lookup code in Brad's "Get Friendly License Name for all Users in Office 365 Using PowerShell" script
    .PARAMETER UPNs
    Array of Userprincipalnames to be looked up
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLicenseDetails -UPNs todd.kadrie@toro.com ;
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = get-MsolUserLicenseDetails -UPNs $exombx.userprincipalname -showdebug:$($showdebug)
    Retrieve MSOL License details on specified UPN, with showdebug specified
    .LINK
    https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    #>
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "An array of MSolUser objects")][ValidateNotNullOrEmpty()]
        [string]$UPNs,
        [Parameter()]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")][switch] $showDebug
    ) ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    $Retries = 4 ;
    $RetrySleep = 5 ;
    #Connect-AAD ;
    # 2:45 PM 11/15/2019
    Connect-Msol ;

    # 11:13 AM 1/9/2019: SPE_F1 isn't in thlist, 'SPE'=="Secure Productive Enterprise (SPE) Licensing Bundle"
    # 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    # [Product names and service plan identifiers for licensing in Azure Active Directory | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference)

    <# whatis an F1 lic: Office 365 F1 is designed to enable Firstline Workers to do their best work.
    Office 365 F1 provides easy-to-use tools and services to help these workers
    easily create, update, and manage schedules and tasks, communicate and work
    together, train and onboard, and quickly receive company news and announcements.
    #>

    # updating sort via text: gc c:\tmp\list.txt | sort ;
    $Sku = @{
        "O365_BUSINESS_ESSENTIALS"           = "Office 365 Business Essentials"
        "O365_BUSINESS_PREMIUM"              = "Office 365 Business Premium"
        "DESKLESSPACK"                       = "Office 365 (Plan K1)"
        "DESKLESSWOFFPACK"                   = "Office 365 (Plan K2)"
        "LITEPACK"                           = "Office 365 (Plan P1)"
        "EXCHANGESTANDARD"                   = "Office 365 Exchange Online Only"
        "STANDARDPACK"                       = "Enterprise Plan E1"
        "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
        "ENTERPRISEPACK"                     = "Enterprise Plan E3"
        "ENTERPRISEPACKLRG"                  = "Enterprise Plan E3"
        "ENTERPRISEWITHSCAL"                 = "Enterprise Plan E4"
        "STANDARDPACK_STUDENT"               = "Office 365 (Plan A1) for Students"
        "STANDARDWOFFPACKPACK_STUDENT"       = "Office 365 (Plan A2) for Students"
        "ENTERPRISEPACK_STUDENT"             = "Office 365 (Plan A3) for Students"
        "ENTERPRISEWITHSCAL_STUDENT"         = "Office 365 (Plan A4) for Students"
        "STANDARDPACK_FACULTY"               = "Office 365 (Plan A1) for Faculty"
        "STANDARDWOFFPACKPACK_FACULTY"       = "Office 365 (Plan A2) for Faculty"
        "ENTERPRISEPACK_FACULTY"             = "Office 365 (Plan A3) for Faculty"
        "ENTERPRISEWITHSCAL_FACULTY"         = "Office 365 (Plan A4) for Faculty"
        "ENTERPRISEPACK_B_PILOT"             = "Office 365 (Enterprise Preview)"
        "STANDARD_B_PILOT"                   = "Office 365 (Small Business Preview)"
        "VISIOCLIENT"                        = "Visio Pro Online"
        "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
        "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
        "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
        "POWER_BI_STANDARD"                  = "Power-BI Standard"
        "PROJECTESSENTIALS"                  = "Project Lite"
        "PROJECTCLIENT"                      = "Project Professional"
        "PROJECTONLINE_PLAN_1"               = "Project Online"
        "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
        "ProjectPremium"                     = "Project Online Premium"
        "ECAL_SERVICES"                      = "ECAL"
        "EMS"                                = "Enterprise Mobility Suite"
        "RIGHTSMANAGEMENT_ADHOC"             = "Windows Azure Rights Management"
        "MCOMEETADV"                         = "PSTN conferencing"
        "SHAREPOINTSTORAGE"                  = "SharePoint storage"
        "PLANNERSTANDALONE"                  = "Planner Standalone"
        "CRMIUR"                             = "CMRIUR"
        "BI_AZURE_P1"                        = "Power BI Reporting and Analytics"
        "INTUNE_A"                           = "Windows Intune Plan A"
        "PROJECTWORKMANAGEMENT"              = "Office 365 Planner Preview"
        "ATP_ENTERPRISE"                     = "Exchange Online Advanced Threat Protection"
        "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
        "AAD_BASIC"                          = "Azure Active Directory Basic"
        "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
        "AAD_PREMIUM"                        = "Azure Active Directory Premium"
        "MFA_PREMIUM"                        = "Azure Multi-Factor Authentication"
        "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
        "STANDARDWOFFPACK_GOV"               = "Microsoft Office 365 (Plan G2) for Government"
        "ENTERPRISEPACK_GOV"                 = "Microsoft Office 365 (Plan G3) for Government"
        "ENTERPRISEWITHSCAL_GOV"             = "Microsoft Office 365 (Plan G4) for Government"
        "DESKLESSPACK_GOV"                   = "Microsoft Office 365 (Plan K1) for Government"
        "ESKLESSWOFFPACK_GOV"                = "Microsoft Office 365 (Plan K2) for Government"
        "EXCHANGESTANDARD_GOV"               = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
        "EXCHANGEENTERPRISE_GOV"             = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
        "SHAREPOINTDESKLESS_GOV"             = "SharePoint Online Kiosk"
        "EXCHANGE_S_DESKLESS_GOV"            = "Exchange Kiosk"
        "RMS_S_ENTERPRISE_GOV"               = "Windows Azure Active Directory Rights Management"
        "OFFICESUBSCRIPTION_GOV"             = "Office ProPlus"
        "MCOSTANDARD_GOV"                    = "Lync Plan 2G"
        "SHAREPOINTWAC_GOV"                  = "Office Online for Government"
        "SHAREPOINTENTERPRISE_GOV"           = "SharePoint Plan 2G"
        "EXCHANGE_S_ENTERPRISE_GOV"          = "Exchange Plan 2G"
        "EXCHANGE_S_ARCHIVE_ADDON_GOV"       = "Exchange Online Archiving"
        "EXCHANGE_S_DESKLESS"                = "Exchange Online Kiosk"
        "SHAREPOINTDESKLESS"                 = "SharePoint Online Kiosk"
        "SHAREPOINTWAC"                      = "Office Online"
        "YAMMER_ENTERPRISE"                  = "Yammer for the Starship Enterprise"
        "EXCHANGE_L_STANDARD"                = "Exchange Online (Plan 1)"
        "MCOLITE"                            = "Lync Online (Plan 1)"
        "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
        "OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ" = "Office ProPlus"
        "EXCHANGE_S_STANDARD_MIDMARKET"      = "Exchange Online (Plan 1)"
        "MCOSTANDARD_MIDMARKET"              = "Lync Online (Plan 1)"
        "SHAREPOINTENTERPRISE_MIDMARKET"     = "SharePoint Online (Plan 1)"
        "OFFICESUBSCRIPTION"                 = "Office ProPlus"
        "YAMMER_MIDSIZE"                     = "Yammer"
        "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
        "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
        "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
        "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
        "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
        "STANDARDWOFFPACK_IW_STUDENT"        = "Office 365 Education for Students"
        "STANDARDWOFFPACK_IW_FACULTY"        = "Office 365 Education for Faculty"
        "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
        "EXCHANGESTANDARD_STUDENT"           = "Exchange Online (Plan 1) for Students"
        "OFFICESUBSCRIPTION_STUDENT"         = "Office ProPlus Student Benefit"
        "STANDARDWOFFPACK_FACULTY"           = "Office 365 Education E1 for Faculty"
        "STANDARDWOFFPACK_STUDENT"           = "Microsoft Office 365 (Plan A2) for Students"
        "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
        "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
        "FLOW_FREE"                          = "Microsoft Flow Free"
        "POWER_BI_PRO"                       = "Power BI Pro"
        "O365_BUSINESS"                      = "Office 365 Business"
        "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
        "RIGHTSMANAGEMENT"                   = "Rights Management"
        "PROJECTPROFESSIONAL"                = "Project Professional"
        "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
        "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
        "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
        "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
        "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
        "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
        "EXCHANGEDESKLESS"                   = "Exchange Online Kiosk"
        "SPZA_IW"                            = "App Connect"
        "WINDOWS_STORE"                      = "Windows Store for Business"
        "MCOEV"                              = "Microsoft Phone System"
        "VIDEO_INTEROP"                      = "Polycom Skype Meeting Video Interop for Skype for Business"
        "SPE_E5"                             = "Microsoft 365 E5"
        "SPE_E3"                             = "Microsoft 365 E3"
        "SPE_F1"                             = "Office 365 F1"
        "ATA"                                = "Advanced Threat Analytics"
        "MCOPSTN2"                           = "Domestic and International Calling Plan"
        "FLOW_P1"                            = "Microsoft Flow Plan 1"
        "FLOW_P2"                            = "Microsoft Flow Plan 2"
        "MS_TEAMS_IW"                        = "Microsoft Teams Trial"
    }

    Foreach ($User in $UPNs) {
        if ($showdebug) { write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Getting all licenses for $($User)..."  ; } ;

        $Exit = 0 ;
        Do {
            Try {
                $MsolU = Get-MsolUser -UserPrincipalName $User ;
                $Licenses = $MsolU.Licenses.AccountSkuID
                $Exit = $Retries ;
            }
            Catch {
                Start-Sleep -Seconds $RetrySleep ;
                $Exit ++ ;
                Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                Write-Verbose "Try #: $Exit" ;
                If ($Exit -eq $Retries) { Write-Warning "Unable to exec cmd!" } ;
            }  ;
        } Until ($Exit -eq $Retries) ;

        $AggregLics = $null
        $AggregLics = @() ;
        If (($Licenses).Count -gt 1) {
            Foreach ($License in $Licenses) {
                if ($showdebug) { Write-Host "Finding $License in the Hash Table..." -ForegroundColor White }
                $LicenseItem = $License -split ":" | Select-Object -Last 1
                $TextLic = $Sku.Item("$LicenseItem")
                If (!($TextLic)) {
                    $smsg = "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!"
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } 
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    $LicenseFallBackName = $License.AccountSkuId

                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName         = $MsolU.DisplayName ;
                        UserPrincipalName   = $MsolU.Userprincipalname
                        LicAccountSkuID     = $License
                        LicenseFriendlyName = $LicenseFallBackName
                    };
                    $AggregLics += $LicSummary ;

                }
                Else {
                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName         = $MsolU.DisplayName
                        UserPrincipalName   = $MsolU.Userprincipalname
                        LicAccountSkuID     = $License
                        LicenseFriendlyName = $TextLic
                    };
                    $AggregLics += $LicSummary ;
                } # if-E
            } # loop-E
        }
        Else {
            if ($showdebug) { Write-Host "Finding $Licenses in the Hash Table..." -ForegroundColor White } ;
            $Exit = 0 ;
            Do {
                Try {
                    #$LicenseItem = ((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID -split ":" | Select-Object -Last 1
                    $LicenseID = ((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID
                    $LicenseItem = $LicenseID -split ":" | Select-Object -Last 1
                    $Exit = $Retries ;
                }
                Catch {
                    Start-Sleep -Seconds $RetrySleep ;
                    $Exit ++ ;
                    Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                    Write-Verbose "Try #: $Exit" ;
                    If ($Exit -eq $Retries) { Write-Warning "Unable to exec cmd!" } ;
                }  ;
            } Until ($Exit -eq $Retries) ;
            $TextLic = $Sku.Item("$LicenseItem")
            If (!($TextLic)) {
                $smsg = "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!"
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error }  
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $LicenseFallBackName = $License.AccountSkuId
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName         = $MsolU.DisplayName
                    UserPrincipalName   = $MsolU.Userprincipalname
                    LicAccountSkuID     = $LicenseID
                    LicenseFriendlyName = $LicenseFallBackName
                };
                $AggregLics += $LicSummary ;
            }
            Else {
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName         = $MsolU.DisplayName
                    UserPrincipalName   = $MsolU.Userprincipalname
                    LicAccountSkuID     = $LicenseID
                    LicenseFriendlyName = "$TextLic"
                };
                $AggregLics += $LicSummary ;
            }
        } # if-E
    } # loop-E

    $AggregLics | write-output ; # 11:33 AM 1/9/2019 export the aggreg, NewObject02 was never more than a single lic
}

#*------^ get-MsolUserLicenseDetails.ps1 ^------

#*------v Wait-AADSync.ps1 v------
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
    * 4:22 PM 7/24/2020 added verbose
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
    $verbose = ($VerbosePreference -eq "Continue") ; 
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
}

#*------^ Wait-AADSync.ps1 ^------

#*======^ END FUNCTIONS ^======

Export-ModuleMember -Function Build-AADSignErrorsHash,caadCMW,caadtol,caadTOR,caadVEN,cmsolcmw,cmsolTOL,cmsolTOR,cmsolVEN,Connect-AAD,connect-AzureRM,Connect-MSOL,Disconnect-AAD,get-AADCertToken,get-AADLastSync,get-AADTokenHeaders,get-MsolUserLastSync,get-MsolUserLicenseDetails,Wait-AADSync -Alias *


# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+vCBFLgfd6gbKC1CKlMtTuZK
# g7KgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNDEyMjkxNzA3MzNaFw0zOTEyMzEyMzU5NTlaMBUxEzARBgNVBAMTClRvZGRT
# ZWxmSUkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqRVt7uNweTkZZ+16QG
# a+NnFYNRPPa8Bnm071ohGe27jNWKPVUbDfd0OY2sqCBQCEFVb5pqcIECRRnlhN5H
# +EEJmm2x9AU0uS7IHxHeUo8fkW4vm49adkat5gAoOZOwbuNntBOAJy9LCyNs4F1I
# KKphP3TyDwe8XqsEVwB2m9FPAgMBAAGjdjB0MBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MF0GA1UdAQRWMFSAEL95r+Rh65kgqZl+tgchMuKhLjAsMSowKAYDVQQDEyFQb3dl
# clNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEGwiXbeZNci7Rxiz/r43gVsw
# CQYFKw4DAh0FAAOBgQB6ECSnXHUs7/bCr6Z556K6IDJNWsccjcV89fHA/zKMX0w0
# 6NefCtxas/QHUA9mS87HRHLzKjFqweA3BnQ5lr5mPDlho8U90Nvtpj58G9I5SPUg
# CspNr5jEHOL5EdJFBIv3zI2jQ8TPbFGC0Cz72+4oYzSxWpftNX41MmEsZkMaADGC
# AWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBMb2NhbCBDZXJ0aWZp
# Y2F0ZSBSb290AhBaydK0VS5IhU1Hy6E1KUTpMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQAC7g6
# LL+rkY81IRRB18071EfNyDANBgkqhkiG9w0BAQEFAASBgHT36to/0JFvWF2yvj5e
# QegSV8qu5olqmBuVZYcyVjQ0YieqyjCaG8ELpp9shCEwMjRhez/xMlykYNUqqe0U
# L5iFDrdcR5H1Gk2qGdlX15VZEZ77h2ok6A8O97XaUk8vXE/X7q3fyDW83acAUVGM
# WoD95INabVpkaSdBweMihoep
# SIG # End signature block
