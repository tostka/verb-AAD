
#*------v Function get-AADCertToken v------
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
    
} ; #*------^ END Function get-AADCertToken ^------

