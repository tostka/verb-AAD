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
    * 3:16 PM 6/14/2021 fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out rednund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
* 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
    * 8:51 AM 1/30/2020
    * 2019-08-12 posted version 
    .DESCRIPTION
     get-AADCertToken - Obtain a certificate-authenticated AADApp Azure access token
     As written, it Authenticates with a certificate (thumbprint matchese $global:TOR_AAD_App_Audit_CertThumb), 
     stored in Cert:\CurrentUser\My\ (see 4a) for process to export and import into new machines and account profiles)
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
         2a) Expired Cert or Secret:
                    This also *expires* (visible by browsing below and checking status)
                    [https://portal.azure.com](https://portal.azure.com) > *Azure Active Directory* > *Manage pane:* *App Registrations*
                    Search 'AuditGraphAccessMessaging'
                    Returns 'A certificate or secret has expired. Create a new one ->', click _->_
                    Sections:
                        Certificates:
                        |Thumb|from|to|id|
                        |7C7D6CA274D687693340918E8CB07D22F2FE4AC4| 1/28/2020| 1/28/2022 |416f6bc7-2e19-4ca8-8f22-2995ed0fbc99|
                        - is still valid
                        Client secrets
                        |Description|Expires|Value|ID|
                        |AudGrphAccMsgKey|4/23/2020|Hidden|195bc9ce-adb7-4b38-8873-ef7d694406fe|
                        - above expired, click _+New Client Secret_
                        Desc: AudGrphAccMsgKey rollover 3:51 PM 20210114-0351PM 2yrs
                        _Add_,
                        "Copy the new client secret value. You won't be able to retrieve it after you perform another operation or leave this blade"
                        click the [copy] btn at right of the secret. The copied material is the 'Value' column (which on the prior, or after leaving this page, displays as 'Hidden')
                        "[looks like a guid]"
                        Also record the Secret's expiration date : 1/14/2023
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
        # revised out:
        #$TenantName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain ;
        #$StoreLocation = "Cert:\CurrentUser\My" ;
        #$ExpirationDate = (Get-Date).AddYears(2) ;
        #
        $TenOrg = 'CMW' ;
        $CertName = "AuditGraphAccessMessaging$($TenOrg)" ;
        $CerOutputPath = "C:\usr\work\o365\certs\$($CertName)-$($TenOrg).cer" ;
        $PfxOutputPath = $CerOutputPath.replace('.cer','.pfx') ;
        $pltNewSSCert = @{
            FriendlyName = $CertName ;
            DnsName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain ; ;
            CertStoreLocation = "Cert:\CurrentUser\My" ;
            NotAfter = (Get-Date).AddYears(2) ;
            KeyExportPolicy = "Exportable" ;
            KeySpec = "Signature" ;
            Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider" ;
            HashAlgorithm = "SHA256" ;
        } ;
        TRY {$cert = New-SelfSignedCertificate @pltNewSSCert ;} CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
        $certPath = Join-Path -Path $pltNewSSCert.CertStoreLocation -ChildPath $cert.Thumbprint ;
        $pltExCER = [ordered]@{
          Cert = $certPath ;
          FilePath = $CerOutputPath ;
          Type = 'CERT' ;
        } ;
        TRY {$exportedCER = Export-Certificate @pltExCER } CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
        $exportedCER.fullname ;
        $cerDtls = gci $certPath ; $cerDtls ;$cerDtls | fl fullname,length;
        ```
        4a) Export the cert to another machine (jumpbox)
            # find it via the thumbprint (stored under Meta and reg global):$tormeta.AAD_App_Audit_CertThumb/$global:TOR_AAD_App_Audit_CertThumb
            # prior CER export lacks the private key (cer's always do) - sufficient for uploading to AAD, to register for auth, but not for moving cert bewteen hosts & accts.
            # export cert with privkey, into pfx file
            #$cert = Get-Item "Cert:\CurrentUser\My\$($global:TORMeta.AAD_App_Audit_CertThumb)" ;
            # dyn path
            #$cert = Get-Item "Cert:\CurrentUser\My\$((gv -name "$($TenOrg)meta").value.AAD_App_Audit_CertThumb)" ;
            # using $pltExCER.Cert
            $pfxcred=(Get-Credential -credential dummy) ;
            if($cert -AND $pfxcred.password){
                $pltExPfx=[ordered]@{
                    Cert=$certPath ;
                    FilePath = $CerOutputPath.replace('.cer','.pfx') ;
                    Password = $pfxcred.password
                };
                TRY {$exportedPFX = Export-PfxCertificate @pltExPfx  } CATCH { Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ; Break ;} ;
                $exportedPfx.fullname ;
                gci $exportedPfx.fullname| fl fullname,length;
                #Copy the pfx to the target machine, and use Certs.msc to import it into hkcu\My. repeat it for each acct that needs to use the cert
                if($exportedPfx.fullname){
                    $smsg = "# cp to target machine (over rdp, from desktop):`ngci $($exportedPfx.fullname -REPLACE "^([A-Za-z]):\\",'\\tsclient\$1\') | cp -Destination d:\scripts\cert\ -whatif ;" ; 
                    $smsg += "`n# import ON targmach:`n"  ; 
                    $smsg += "`$pfxcred = (Get-Credential -credential dummy)`n" ;
                    $smsg += "Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My -FilePath d:\scripts\cert\$(split-path $exportedPfx.fullname -leaf) -Password `$pfxcred.password" ; 
                    write-host $smsg ;
                } ; 
            } else { throw "Missing either `$cert or `$$pfxcred.password!" } ;   
            
        5) **Configure App with Certificate Authentication:**
        - From the registered apps's summary page, click left menu: **Certificates & secrets**  > **Upload certificate**, click folder icon, (*browse .cer*, in PS above, it's stored in $exportedcer.fullname) , **Add**
        - **while we're here lets add a Secret (password) as well:**
          - **Certificates & secrets**  > **New client secret**
          - *Description*: 'For SigninActivity review scripts'
          - *Expires*: **(x) in 24 mos**
          - click **Add**
          - The newly generated secret (password) string will *only* be displayed *once* on this page. Record it & the expiration date for permanent reference: (put the secret value into the password field on the KP entry)
        -
        6) **Script configuration:**
        - Update the following parameter default values to your target Tenants values:
        |param|info source|
        |---|---|
        |`$tenantName`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).VerifiedDomain`)|
        |`$tenantId`| (can be obtained from `caad ;  (Get-AzureADTenantDetail).ObjectId`)|
        |`$AppID`| (the 'Application (client ID)' guid value recorded above)|
        |`$Certificate`|(the Thumbnail value from the self-signed certificate created above)|
        #-=-=-=-=-=-=-=-=


        The script queries the Azure AD Audit Graph endpoint for Sign In report entries.
        More information about the filtering options and the data returned can
        be found online at this link:
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

        Refs: 
        #-=-=-=-=-=-=-=-=
        List signIns - Microsoft Graph beta | Microsoft Docs - https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta
        [List signIns - Microsoft Graph beta | Microsoft Docs](https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta&tabs=http)
        Permissions
        One of the following permissions is required to call this API. To learn more, including how to choose permissions, see Permissions.
        |Permission type |Permissions (from least to most privileged)|
        |---|---|
        |Delegated (work or school account) |AuditLog.Read.All, Directory.Read.All|
        |Delegated (personal Microsoft account) |Not supported|
        |Application |AuditLog.Read.All, Directory.Read.All|
        (TSK: as of 11/5/19 rev: application now needs Directory.Read.All, in addition to AuditLog.Read.All)
        Set/Review: AzPortal (https://portal.azure.com): App registrations > search for the app name & click match > click _API permissions_, _Yes_
        Had:
            AAD Graph:
                User.Read  Delegated
            Microsoft Graph:
                AuditLog.Read.All  Application
        Need to add: Directory.Read.All: click _Add a Permission_ > Microsoft Graph > Application permissions > Search: Directory.Read.All: [x]Directory.Read.All, click _Add permissions_.
        back on API perms page: review that the perms list is now complete, then click _Grant admin consent for the Toro Company (only globals can do)
        #-=-=-=-=-=-=-=-=
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
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
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
    .EXAMPLE
    $pltAADCertToken=[ordered]@{
        tenantName= $TOLMeta.o365_TenantDomain ; AppID= $TOLMeta.AAD_App_Audit_ID ; Certificate= $TOLMeta.AAD_App_Audit_CertThumb ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token = get-AADCertToken @pltAADCertToken ;
    ...
    TOL example
    .EXAMPLE
    # CertToken version
    #$Request = get-AADCertToken -Verbose:($VerbosePreference -eq 'Continue') ; 
    $tenantName = $global:$XXXMeta.o365_TenantDomain ;
    $AppID = $global:XXXMeta.AAD_App_Audit_ID ;
    $Certificate = $global:XXXmeta.AAD_App_Audit_CertThumb ;
    # leverage the params:
    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose -Verbose:$verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    $token =get-AADCertToken @pltAADCertToken ; 
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')

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
        ( $certificate| fl Subject,DnsNameList,FriendlyName,Not*,Thumbprint | out-string).trim() | write-verbose ;
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
        if(! $Certificate.PrivateKey){
            $smsg = "Specified Certificate... $($Certificate.thumbprint)`nis *MISSING* its PRIVATE KEY!`nYou must export the key when moving the cert between hosts & accounts!`n(key is used for signing the token request)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            break ; 
        } ; 
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
        write-verbose "$((get-date).ToString('HH:mm:ss')):Invoke-RestMethod w`n$(($PostSplat|out-string).trim())" ; 
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
    
} ; 
#*------^ END Function get-AADCertToken ^------