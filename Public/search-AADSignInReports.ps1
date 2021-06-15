#*------v Function search-AADSignInReports v------
Function search-AADSignInReports {
    <#
    .SYNOPSIS
    search-AADSignInReports.ps1 - Runs GraphAPI RestAPI queries, leveraging certificate-authenticated Tockens
    .NOTES
    Version     : 1.1.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-1-30
    FileName    : search-AADSignInReports.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,GraphAPI,Authentication,SignInLogs
    AddedCredit : Alex Asplund;Tim Spring MSFT
    AddedWebsite: https://automativity.com;https://github.com/TspringMSFT/
    AddedTwitter: @AlexAsplund
    GraphAPI -filter parameter reference on 875: ==== v GRAPH API FILTER PARAM USE:
    REVISIONS   :
    * 12:50 PM 6/15/2021 ren Pull-AADSignInReports.ps1 -> search-AADSignInReports.ps1 (compliant verb); porting into verb-aad; added start-log logging ; rearranged trailing graphapi filter param ref, into body, above code where qry is built; removed obsolete/broken *BearerToken() funcs. Made all funcs condityional, and deferential to modules. 
    * 3:16 PM 6/14/2021 made local aad funcs, conditional - defer to verb-aad versions ; fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out redund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
    * 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
    * 7:33 AM 2/28/2020 fixed BadIf
    * 6:40 PM 1/30/2020 rounded out, functional, cleaned up
    * 8:28 AM 1/30/2020 MS fundementally BROKE ADAL token auth (in Azure module). Finally got back to function using to simple Json Invoke-WebRequest auth'd via AAD Registered App + Cert auth, query results now also appears to have *flipped* from returning a json (requiring convers for use) to returning a straight object. Used AAspend's cert auth code (conv to get-AADCertToken() & get-AADTokenHeaders()) & simple append aggreg code, tossed out all of Tim Spring's fancier material (now broken), except the try/catch error sorting, which *still* covers retrying, throttling, and simple perm etc fails. 
    * 3:09 PM 1/27/2020 ren:  get-AADBearToken -> get-AADBearerToken
    * 1:52 PM 8/28/2019 shifted some code into recyclable functions
    * 2:50 PM 8/27/2019 flipped all the renamed xml fieldnames back to the low-level names. also exported the json from the raw $MyReport obj, convertto-json'd.
        Trying to profile-AAD-Signons.ps1 against the exported $xmlreportvalues object (vs orig json obj) resulted in errors.
        Using the exported json from the orig object worked fine.
    * 7:48 AM 8/27/2019 v0.1.0 adding pshelp,passed debugging, base code functional
    * 3/1/19 - posted version
    .DESCRIPTION
    search-AADSignInReports.ps1 - Runs GraphAPI RestAPI queries, leveraging certificate-authenticated Tockens
    This script uses RestAPI calls to authenticate and query GraphAPI. 
    As written, it Authenticates with a certificate 
    **Script configuration:**
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
    .PARAMETER TenOrg
    TenantTag value, indicating Tenants to connect to[-TenOrg 'TOL']
    .PARAMETER UPNs
    User UPNs to be processed (array)[-UPNS 'user1@domain.com','user2@domain.com
    .PARAMETER QueryApp
    Application to be filtered target of query (EXO|SFO)[-QueryApp EXO]
    .PARAMETER StartDate
    StartDate (defaults 7d) [-StartDate (Get-Date)]
    .PARAMETER EndDate
    EndDate (defaults now)
    .PARAMETER TopUnits
    Number of records to return per bundle (defaults 1000)[-TopUnits 1000]
    .PARAMETER tenantName
    AAD tenantName [-tenantName (guid)]
    .PARAMETER tenantId
     TenantID (defaulted TOR) [-TenantID (guid)]
    .PARAMETER AppID
    AAD RegisteredApp to execute the query [-AppID (guid)]
    .PARAMETER Certificate
    Authenticating certificate [-Certificate (thumbprint)]
    .PARAMETER Tickets
    Tickets associated with ea UPN #[-Tickets '999999','999998']
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Json & CSV files
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs Addy.Donkhong@toro.com -ticket 456277 -showdebug ;
    Retrieve default, last7 days of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs Addy.Donkhong@toro.com -ticket 456277 -StartDate (Get-Date).AddDays(-30) -showdebug ;
    Retrieve custom interval (last 30d) of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs "Addy.Donkhong@toro.com","Sarah.Bell@toro.com" -ticket "456277","452916" -StartDate (Get-Date).AddDays(-30) -showdebug ;
    Retrieve custom interval (last 30d) of signon records for array of UPNs & tickets
    .LINK
    https://github.com/TspringMSFT/PullAzureADSignInReports-
    #>
    #Requires -Modules verb-Auth, verb-IO, verb-logging, verb-Text
    #Requires -RunasAdministrator
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$FALSE,HelpMessage="TenantTag value, indicating Tenants to connect to[-TenOrg 'TOL']")]
        [ValidateNotNullOrEmpty()]
        $TenOrg = 'TOR',    
        [Parameter(Position = 0, HelpMessage = "User UPNs to be processed (array)[-UPNS 'user1@domain.com','user2@domain.com]")]
        $UPNs,
        [Parameter(HelpMessage = "Application to be filtered target of query (EXO|SFO)[-QueryApp EXO]")]
        [ValidateSet("EXO", "SFO")]
        [string]$QueryApp,
        [parameter(HelpMessage = "StartDate (defaults 7d) [-StartDate (Get-Date)]")]
        [datetime]$StartDate = (Get-Date).AddDays(-7),
        [parameter(HelpMessage = "EndDate (defaults now)")]
        [datetime]$EndDate = (Get-Date),
        [parameter(HelpMessage = "Number of records to return per bundle (defaults 1000)[-TopUnits 1000]")]
        [int]$TopUnits = 1000,
        [Parameter(HelpMessage = "AAD tenantName [-tenantName (guid)]]")]
        [string]$tenantName = $global:TorMeta.o365_TenantDomain,
        [Parameter(HelpMessage = "AAD TenantID (defaulted TOR) [-TenantID (guid)]")]
        [string]$tenantId = $global:TorMeta.o365_Tenantid,
        [Parameter(HelpMessage = "AAD RegisteredApp to execute the query [-AppID (guid)]]")]
        [string]$AppID = $global:TORMeta.AAD_App_Audit_ID,
        [Parameter(HelpMessage = "Authenticating certificate [-Certificate (thumbprint)]]")]
        $Certificate = $global:tormeta.AAD_App_Audit_CertThumb,
        [parameter(HelpMessage = "Tickets associated with ea UPN #[-Tickets '999999','999998']")]
        [array]$Tickets,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    # AppSecret token requires -TenantID
    # Cert token requires -tenantName


    #region INIT; # ------
    #*======v SCRIPT/DOMAIN/MACHINE/INITIALIZATION-DECLARE-BOILERPLATE v======
    $verbose = $VerbosePreference ;

    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    # Get parameters this function was invoked with
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
    $Verbose = ($VerbosePreference -eq 'Continue') ;
    if ($PSScriptRoot -eq "") {
        if ($psISE) { $ScriptName = $psISE.CurrentFile.FullPath }
        elseif ($context = $psEditor.GetEditorContext()) {$ScriptName = $context.CurrentFile.Path }
        elseif ($host.version.major -lt 3) {
            $ScriptName = $MyInvocation.MyCommand.Path ;
            $PSScriptRoot = Split-Path $ScriptName -Parent ;
            $PSCommandPath = $ScriptName ;
        } else {
            if ($MyInvocation.MyCommand.Path) {
                $ScriptName = $MyInvocation.MyCommand.Path ;
                $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent ;
            } else {throw "UNABLE TO POPULATE SCRIPT PATH, EVEN `$MyInvocation IS BLANK!" } ;
        };
        $ScriptDir = Split-Path -Parent $ScriptName ;
        $ScriptBaseName = split-path -leaf $ScriptName ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($ScriptName) ;
    } else {
        $ScriptDir = $PSScriptRoot ;
        if ($PSCommandPath) {$ScriptName = $PSCommandPath }
        else {
            $ScriptName = $myInvocation.ScriptName
            $PSCommandPath = $ScriptName ;
        } ;
        $ScriptBaseName = (Split-Path -Leaf ((& { $myInvocation }).ScriptName))  ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;
    } ;
    if ($showDebug) { write-debug -verbose:$true "`$ScriptDir:$($ScriptDir)`n`$ScriptBaseName:$($ScriptBaseName)`n`$ScriptNameNoExt:$($ScriptNameNoExt)`n`$PSScriptRoot:$($PSScriptRoot)`n`$PSCommandPath:$($PSCommandPath)" ; } ;
    $ComputerName = $env:COMPUTERNAME ;
    $NoProf = [bool]([Environment]::GetCommandLineArgs() -like '-noprofile'); # if($NoProf){# do this};
    # silently stop any running transcripts
    $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;

    #*======v FUNCTIONS v======

    # suppress VerbosePreference:Continue, if set, during mod loads (VERY NOISEY)
    if($VerbosePreference -eq "Continue"){
        $VerbosePrefPrior = $VerbosePreference ;
        $VerbosePreference = "SilentlyContinue" ;
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ; 


    if(!(gcm search-GraphApiAAD)){
        #*------v Function search-GraphApiAAD v------
        function search-GraphApiAAD {
            #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        #VERB-NOUN.ps1, or #*----------v Function VERB-NOUN() v----------
        <#
        .SYNOPSIS
        search-GraphApiAAD - Execute a GraphAPI search and return report object, for pre-constructed -fullURI
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     :	http://www.toddomation.com
        Twitter     :	@tostka / http://twitter.com/tostka
        CreatedDate : 2021-06-15
        FileName    : search-GraphApiAAD.ps1
        License     : MIT License
        Copyright   : (c) 2021 Todd Kadrie
        Github      : https://github.com/tostka/verb-aad
        Tags        : Powershell
        AddedCredit : Alex Asplund
        AddedWebsite:	https://automativity.com
        AddedTwitter:	@AlexAsplund
            Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
            REVISIONS
            * 3:11 PM 6/15/2021 functionalized graphapi query code by Alex Asplund from his AADsignInReports script
            * 3:16 PM 6/14/2021 fixed missing cert(s) on jbox, works now ; strongly typed $tickets array (was pulling 1st char instead of elem) ; subd out rednund -verbose params ;provide dyn param lookup on $TenOrg, via meta infra file, cleaned up the CBH auth & tenant config code (pki certs creation, CER & PFX export/import)
        * 10:56 AM 6/11/2021 added CBH example for TOL; expanded docs to reinforce cert needed, how to lookup name, and where needs to be stored per acct per machine.
            * 8:51 AM 1/30/2020
            * 2019-08-12 posted version 
            .DESCRIPTION
             search-GraphApiAAD - Execute a GraphAPI search and return report object, for pre-constructed -fullURI
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
                
                The script queries the Azure AD Audit Graph endpoint. 
                More information about the filtering options and the data returned can
                be found online at this link:
                https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

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
            search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
            Simple Example (fulluri is constructed by calling cmdlet/script)
            .EXAMPLE
            $pltSrchGraphAPI=[ordered]@{
                fullURI=$fulluri ;
                token=$token ;
                tenantName=$tenantName ;
                tenantId=$tenantId ;
                AppID=$AppID ;
                Certificate=$Certificate ;
                showDebug=$($showDebug) ;
                Verbose=($VerbosePreference -eq 'Continue') ;
            } ;
            $smsg = "search-GraphApiAAD w`n$(($pltSrchGraphAPI|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            $SignInReportArray = search-GraphApiAAD @pltSrchGraphAPI ; 
            $ofile = 'd:\scripts\logs\report' ; 
            $ReportOutputCSV = "$($ofile).csv" ;
            $ReportOutputJson = "$($ofile).json" ;
            $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
            $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
            .LINK
            https://adamtheautomator.com/microsoft-graph-api-powershell/
            .LINK
            https://github.com/tostka/verb-aad
            #>
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,HelpMessage = "GraphAPI complete uri query string in OData format [-fullURI xxxx]")]
                [string]$fullURI,
                [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Token[-Token (token obj)]")]
                [ValidateNotNullOrEmpty()]$token,
                [Parameter(HelpMessage = "AAD TenantID [-TenantID (guid)]]")]
                [string]$tenantName = $global:TorMeta.o365_TenantDomain,
                [Parameter(HelpMessage = "AAD TenantID (defaulted TOR) [-TenantID (guid)]")]
                [string]$tenantId = $global:TorMeta.o365_Tenantid,
                [Parameter(HelpMessage = "AAD AppID [-AppID (guid)]]")]
                [string]$AppID = $global:TORMeta.AAD_App_Audit_ID,
                [Parameter(HelpMessage = "Certificate Thumbprint [-Certificate (thumbprint)]]")]
                $Certificate = $global:tormeta.AAD_App_Audit_CertThumb,
                [Parameter(HelpMessage = "Debugging Flag [-showDebug]")]
                [switch] $showDebug
            ) # PARAM BLOCK END ;
            BEGIN {
                $verbose = ($VerbosePreference -eq "Continue") ;
        
                # fulluri should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'Addy.Donkhong@toro.com'&$top=1
                $smsg = "`nfullUri:`n$(($fullUri|out-string).trim())"  ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;
            } 
            PROCESS {
                $smsg = "--------------------------------------------------------------" ;
                $smsg += "`nDownloading report from `n$($fullUri)"  ;
                $smsg += "`n--------------------------------------------------------------" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            
                # we'll be flipping the $url to the next link after the first pass, so we need to use '$url' going into the loop
                $url = $fullUri ;
                $count = 0
                $retryCount = 0
                $oneSuccessfulFetch = $False
                $ReportArray = @() # aggregator

                Do {
                    $smsg = "Fetching data using Url:`n$($url )" 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    Try {
                        $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
                         # AAsplund's simplified odata approach - assumes the return is an obj, not json

                        #$AuditLogRequest = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                        #$myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")
                        <# # Splat the parameters for Invoke-Restmethod for cleaner code
                        $PostSplat = @{
                            ContentType = 'application/x-www-form-urlencoded' ;
                            Method = 'POST' ;
                            Body = $Body ;
                            Uri = $Url ;
                            Headers = $Header ;
                        } ;
                        write-verbose "$((get-date).ToString('HH:mm:ss')):Invoke-RestMethod w`n$(($PostSplat|out-string).trim())" ; 
                        $token = Invoke-RestMethod @PostSplat ; 
                        #>
                        #$myReport = Invoke-RestMethod @$PostSplat ; 
                        # can't use splats, throws: The remote name could not be resolved: 'system.collections.specialized.ordereddictionary'
                        $myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")

                        $ReportArray += $myReport.value ; 
                                
                        $url = $myReport.'@odata.nextLink'
                        $count = $count + $myReport.value.Count
                        "Total Fetched: $count" | write-verbose ; 
                        $retryCount = 0 ; 

                    } Catch [System.Net.WebException] {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        Write-Output $statusCode
                        $smsg = "`$statusCode:$($statusCode)`n`$_.Exception.Message:$($_.Exception.Message)`n" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    
                        if ($statusCode -eq 401 -and $oneSuccessfulFetch) {
                            # Token might have expired! Renew token and try again
                            <# ADAL Azure mod vers:
                            #$authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
                            #$token = $authResult.AccessToken
                            #$AADTokenHeaders = get-AADBearerTokenHeaders($token)
                            #>
                            $token=get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
                            $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue') ;
                            $oneSuccessfulFetch = $False
                            $smsg = "Access token expiry. Requested a new one and now retrying data query..."
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        } elseif ($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503) {
                            # throttled request or a temporary issue, wait for a few seconds and retry
                            Start-Sleep -5
                            $smsg = "A throttled request or a temporary issue. Waiting for 5 seconds and then retrying..." ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                        } elseif ($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401) {
                            $smsg = "Please check the permissions of the user"
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            break;
                        } else {
                            if ($retryCount -lt 5) {
                                $smsg = "Retrying..."
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                $retryCount++
                            } else {
                                $smsg = "Download request failed. Please try again in the future." ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                break ; 
                            } ; 
                        } ; 
                    } Catch {
                        $exType = $_.Exception.GetType().FullName
                        $exMsg = $_.Exception.Message

                        $smsg = "Exception: $_.Exception"
                        $smsg += "`nError Message: $exType"
                        $smsg += "`nError Message: $exMsg"
                  
                        if ($retryCount -lt 5) {
                            $smsg += "`nRetrying..." ;
                            $retryCount++ ;
                        }else {
                            $smsg += "`nDownload request failed. Please try again in the future."
                            $smsg += "`n--------------------------------------------------------------" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            break ; 
                        }
                    }
                
                    $smsg += "`n--------------------------------------------------------------" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

               } while($myReport.'@odata.nextLink' -ne $null) ; # loop-E 
           }  # if-E-PROCESS 
           END {$ReportArray| write-output ; } 
        } ; 
        #*------^ END Function search-GraphApiAAD ^------
    } ; 

    if(!(gcm get-AADCertToken)){
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
            FileName    : get-AADCertToken.ps1
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-aad
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
            Streamlined example
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
                $pltPost = @{
                    ContentType = 'application/x-www-form-urlencoded' ;
                    Method = 'POST' ;
                    Body = $Body ;
                    Uri = $Url ;
                    Headers = $Header ;
                } ;
                write-verbose "$((get-date).ToString('HH:mm:ss')):Obtain Token:Invoke-RestMethod w`n$(($pltPost|out-string).trim())" ; 
                $token = Invoke-RestMethod @pltPost ; 
            } else { 
                write-warning "Unable to:Get-Item Cert:\CurrentUser\My\$($Certificate)"
                Stop
            } ; 

            write-verbose "`$token:`n$(($token|out-string).trim())" ;
            if ($token -eq $null) {
                Write-Output "ERROR: Failed to get an Access Token" ;
                exit
            } else { $token | write-output }
        } ; 
        #*------^ END Function get-AADCertToken ^------
    } ; 

    if(!(gcm get-AADTokenHeaders)){
        #*------v Function get-AADTokenHeaders v------
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
            write-verbose "$((get-date).ToString('HH:mm:ss')):Provided token:`n$(($token|out-string).trim())" ; 
            $Header = @{
                Authorization = "$($token.token_type) $($token.access_token)"
            }
            write-verbose "$((get-date).ToString('HH:mm:ss')):Generated `$Header:`n$(($Header|out-string).trim())" ; 
            $Header | write-output ; 
        }; 
        #*------^ END Function get-AADTokenHeaders ^------
    } ; 

    # reenable VerbosePreference:Continue, if set, during mod loads (VERY NOISEY)
    if($VerbosePrefPrior -eq "Continue"){
        $VerbosePreference = $VerbosePrefPrior ; 
        $verbose = ($VerbosePreference -eq "Continue") ; 
    } ; 

    #*======^ END FUNCTIONS ^======

    #*======v SUB MAIN v======

    if($VerbosePreference -eq "Continue"){
        $VerbosePrefPrior = $VerbosePreference ;
        $VerbosePreference = "SilentlyContinue" ;
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ; 


    # passes current VerbosePreference in
    # 8:53 AM 1/30/2020 Azure ADAL token auth now broken, don't need the module
    #load-Module Azure -Verbose:($VerbosePreference -eq 'Continue')
    # this uses the initial script launch status
    #load-Module Azure -Verbose:($PSBoundParameters['Verbose'] -eq $true)

    # reenable VerbosePreference:Continue, if set, during mod loads 
    if($VerbosePrefPrior -eq "Continue"){
        $VerbosePreference = $VerbosePrefPrior ;
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ; 

    # Clear error variable
    $Error.Clear() ;

    $error.clear() ;
    TRY {
        
        $pltSL=@{ NoTimeStamp=$false ; Tag = $null ; showdebug=$($showdebug) ; whatif=$($whatif) ; Verbose=$($VerbosePreference -eq 'Continue') ; } ;

        #$pltSL.Tag = "$(split-path -path $CSVPath -leaf)";
        $pltSL.Tag = $tickets -join ',' ;
        if($PSCommandPath){   $logspec = start-Log -Path $PSCommandPath @pltSL }
        else {    $logspec = start-Log -Path ($MyInvocation.MyCommand.Definition) @pltSL ;  } ;

        if($logspec){
            $logging=$logspec.logging ;
            $logfile=$logspec.logfile ;
            $transcript=$logspec.transcript ;
            $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
            start-Transcript -path $transcript ;
        } else {throw "Unable to configure logging!" } ;
    } CATCH {
        $ErrTrapd=$Error[0] ;
        $smsg = "Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } ;

    $sBnr="#*======v $(${CmdletName}): v======" ;
    $smsg = $sBnr ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    # 1:11 PM 6/14/2021 provide dyn param lookup on $TenOrg, via meta infra file

    if(!($tenantName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain)){throw "missing $($TenOrg)meta.value.o365_TenantDomain!" ; break ; } ;
    if(!($tenantId = (gv -name "$($TenOrg)meta").value.o365_Tenantid)){throw "missing $($TenOrg)meta.value.o365_Tenantid!" ; break ; } ;
    if(!($AppID = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_ID)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_ID!" ; break ; } ;
    if(!($Certificate = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_CertThumb)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_CertThumb!" ; break ; } ;


    ##$resourceAppIdURI = "https://graph.microsoft.com"
    $MSGraphURI = "https://graph.microsoft.com"

    #$redirectUri      = "https://RedirectURI.com"                #Your Application's Redirect URI
    #$redirectUri = "https://placemarker.com"                #Your Application's Redirect URI
    # redir uri for PS bearer token script(?)
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"


    $ttl = ($UPNs | Measure-Object).count ;
    $tickNum = ($tickets | Measure-Object).count
    if ($ttl -ne $tickNum ) {
        write-host -foregroundcolor RED "$((get-date).ToString('HH:mm:ss')):ERROR!:You have specified $($ttl) UPNs but only $($tickNum) tickets.`nPlease specified a matching number of both objects." ;
        Exit
    } ;


    # below is hard-coded dates, 2/1/196am to 2/28/19 7am.
    #$fullUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime%20ge%202019-02-01T06:00:00Z%20and%20createdDateTime%20le%202019-02-28T00:07:01.607Z&`$top=1000"

    # UPN query 1 return: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'Addy.Donkhong@toro.com'&$top=1

    $formattedStart = " {0:s}" -f $StartDate + 'Z' ;
    $formattedEnd = " {0:s}" -f $EndDate + 'Z' ; 
    $baseUri = "$($MSGraphURI)/" ;

    # broken get-aadbearertoken vers
    #$token = get-AADBearerToken -tenantId:$($tenantId) -Verbose:($VerbosePreference -eq 'Continue') ;
    # CertToken version
    #$Request = get-AADCertToken -Verbose:($VerbosePreference -eq 'Continue') ; 
    # leverage the params:
    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    #$Request =get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
    $smsg = "get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $token =get-AADCertToken @pltAADCertToken ; 
    $pltAADCertTokenHdr=[ordered]@{
        token=$token ;Verbose=$($VerbosePreference -eq 'Continue');
    };
    $smsg = "get-AADTokenHeaders w`n$(($pltAADCertTokenHdr|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $AADTokenHeaders = get-AADTokenHeaders @pltAADCertTokenHdr ;

    <# --==== v GRAPH API FILTER PARAM USE: v ===--
    Use query parameters to customize responses - Microsoft Graph | Microsoft Docs - https://docs.microsoft.com/en-us/graph/query-parameters

    Support for $filter operators varies across Microsoft Graph APIs. The following logical operators are generally supported:

        equals (eq)
        not equals (ne)
        greater than (gt)
        greater than or equals (ge)
        less than (lt), less than or equals (le)
        and (and)
        or (or)
        not (not)


    Note: The following $filter operators are not supported for Azure AD resources: ne, gt, ge, lt, le, and not.
        The contains string operator is currently not supported on any Microsoft Graph resources.

    Note: The startswith string operator is often supported. The any lambda operator is supported for some APIs. For some usage examples, see the following table. For more details about $filter syntax, see the OData protocol

    $filter operator supported logical operators:

    The following table shows some examples that use the $filter query parameter.

        Note: Click the examples to try them in Graph Explorer.

    > On the beta endpoint, the $ prefix is optional. For example, instead of $filter, you can use filter. On the v1 endpoint, the $ prefix is optional for only a subset of APIs. For simplicity, always include $ if using the v1 endpoint.


    Search for users with the name Mary across multiple properties.
    https://graph.microsoft.com/v1.0/users?$filter=startswith(displayName,'mary') or startswith(givenName,'mary') or startswith(surname,'mary') or startswith(mail,'mary') or startswith(userPrincipalName,'mary')

    Get all the signed-in user's events that start after 7/1/2017.
    https://graph.microsoft.com/v1.0/me/events?$filter=start/dateTime ge '2017-07-01T08:00'
    Get all RiskyEvents createdDateTime ge yyyy-MM-dd
    $url = "https://graph.microsoft.com/beta/identityRiskEvents?`$filter=createdDateTime ge XXXX-XX-XX"


    Get all emails from a specific address received by the signed-in user.
    https://graph.microsoft.com/v1.0/me/messages?$filter=from/emailAddress/address eq 'someuser@example.com'

    Get all emails received by the signed-in user in April 2017.
    https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=ReceivedDateTime ge 2017-04-01 and receivedDateTime lt 2017-05-01

    Select by user and createdDateTime
    https://graph.microsoft.com/beta/identityRiskEvents?`$filter=userPrincipalName eq 'username@domainsuffix' and createdDateTime ge xxxx-xx-xx

    Get all unread mail in the signed-in user's Inbox.
    https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=isRead eq false

    List all Office 365 groups in an organization.
    https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c+eq+'Unified')

    OData system query options    

    Name	Description	
        Example
    $count	Retrieves the total count of matching resources.(includes a count of the total number of items in a collection alongside the page of data values returned)	
        /me/messages?$top=2&$count=true
    $expand	Retrieves related resources.	
        /groups?$expand=members
      # gets root drive information along with the top-level child items in a drive
      GET https://graph.microsoft.com/v1.0/me/drive/root?$expand=children
      # ret specific props fr exp
        GET https://graph.microsoft.com/v1.0/me/drive/root?$expand=children($select=id,name)
      
    $filter	Filters results (rows).	
        /users?$filter=startswith(givenName,'J')
    $format	Returns the results in the specified media format.	
        /users?$format=json
      
    $orderby	Orders results.	
        /users?$orderby=displayName desc
    $search	Returns results based on search criteria. Currently supported on messages and person collections.	
        /me/messages?$search=pizza
    $select	Filters properties (columns). Wo you get the default dataset, select winnows it to specified	
        /users?$select=givenName,surname
    $skip	Indexes into a result set. Also used by some APIs to implement paging and can be used together with $top to manually page results.	
        /me/messages?$skip=11
    $top	Sets the page size of results.	
        /users?$top=2

    $skipToken	Retrieves the next page of results from result sets that span multiple pages. (Some APIs use $skip instead.)	
        /users?$skiptoken=X%274453707402000100000017...

    ---	
    Encoding query parameters:
    Values of query parameters should be percent-encoded. 
    An unencoded URL looks like this:
    GET https://graph.microsoft.com/v1.0/users?$filter=startswith(givenName, 'J')
    A properly encoded URL looks like this:
    GET https://graph.microsoft.com/v1.0/users?$filter=startswith(givenName%2C+'J')

    Escaping single quotes
    For requests that use single quotes, if any parameter values also contain single quotes, those must be double escaped
    In string value below  let''s meet for lunch? has the single quote escaped.
    GET https://graph.microsoft.com/v1.0/me/messages?$filter=subject eq 'let''s meet for lunch?'

    #Place all events related to EXO into an array
    # filtering appDisplayName *exchange*
    IMAP hack attempts have been coming in as:
    appDisplayName                   : Office 365
    resourceId                       :
    resourceDisplayName              :
    clientAppUsed                    : Other clients; IMAP
    deviceDetail                     : @{deviceId=; displayName=; operatingSystem=; browser=; isCompliant=; isManaged=;
                                        trustType=}

    ($event.appDisplayName -eq "Office 365" -ANd $event.clientAppUsed -eq 'Other clients; IMAP')

    Outlook logon:
    appDisplayName      : Microsoft Office
    resourceDisplayName : office 365 exchange online
    clientAppUsed       : Mobile Apps and Desktop clients
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=Windows 7; browser=IE 7.0; isCompliant=; isManaged=;
                            trustType=}

    ($event.appDisplayName -eq "Microsoft Office" -AND $event.resourceDisplayName -eq 'office 365 exchange online')

    OWA:
    appDisplayName      : Office 365 Exchange Online
    resourceDisplayName : office 365 exchange online
    clientAppUsed       : Browser
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=Windows 7; browser=IE 11.0; isCompliant=; isManaged=;
                            trustType=}


    Outlook 2010 (vpn):
    appDisplayName                   : Office 365 Exchange Online
    resourceId                       :
    resourceDisplayName              :
    clientAppUsed                    : Other clients; Older Office clients
    deviceDetail                     : @{deviceId=; displayName=; operatingSystem=; browser=Microsoft Office 15.0;
                                        isCompliant=; isManaged=; trustType=}


    ActiveSync:
    appDisplayName      : Office 365 Exchange Online
    resourceDisplayName :
    clientAppUsed       : Exchange ActiveSync
    deviceDetail        : @{deviceId=; displayName=; operatingSystem=; browser=Mobile Safari; isCompliant=; isManaged=;
                            trustType=}
    --==== ^ GRAPH API FILTER PARAM USE: ^ ===--
    #>

    $iProcd=0 ;
    $UPNOrdinal=0 ;
    [array]$jsonFiles = @() ; # aggreg the files for output report BP


    foreach($UPN in $UPNs){
        $iProcd++ ;

        $sBnrS="`n#*------v ($($iProcd) / $($ttl)):Processing:$($UPN) v------" ;
        $smsg = "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $path = 'beta/auditLogs/signIns'
        $queryParameter = "&`$top=$($TopUnits)"
        $formatJsonParam = "?`$format=json" ; # 2:52 PM 1/29/2 020 param to force json return
        if ($UPN) {
            $filter = "?`$filter=(userPrincipalName eq `'$($UPN)`')"
        } ;
        if ($QueryApp -eq "EXO") {
            if($filter){
                $filter += " and (appDisplayName eq `'Office 365`' and clientAppUsed eq `'Other clients; IMAP`') or (resourceDisplayName eq `'office 365 exchange online`') or (appDisplayName eq `'Office 365 Exchange Online`')"
            } else {
                $filter += "&`$filter=(appDisplayName eq `'Office 365`' and clientAppUsed eq `'Other clients; IMAP`') or (resourceDisplayName eq `'office 365 exchange online`') or (appDisplayName eq `'Office 365 Exchange Online`')"
            }
        } ;

        if($formattedStart -OR $formattedEnd){
            if($filter){
                $filter +=" and ("
            } ;
            if($formattedStart){$dateFilter = "(createdDateTime ge $($formattedStart)" }
            # 9:47 AM 1/28/2020 trim leading spurious and: " and createdDateTime...
            if($formattedEnd){$dateFilter = " createdDateTime le $($formattedEnd)" }
            $dateFilter+=")"
            #$dateFilter = "(createdDateTime ge $($formattedStart) and createdDateTime le $($formattedEnd))" ;
            # try rplcing \s with %20 - not necessary, it'll work spaces intact
            #$dateFilter = $dateFilter.replace(" ","%20")
        } ;
        # this works in Gxplr:
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'Addy.Donkhong@toro.com') and (createdDateTime ge 2019-08-20T10:46:31Z and createdDateTime le 2019-08-27T10:46:31Z)&$top=10
        # 9:45 AM 1/28/2020failing with
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'Austin.Boyce@toro.com') and ( and createdDateTime le  2020-01-28T08:26:19Z)&$top=1000
        # visible issue: spurious ( and create... in the middle of the param clause
        # but this works in GX
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'Austin.Boyce@toro.com') and (createdDateTime le 2020-01-28)&$top=1000
        # lets try an explicit format: ?$format=json
        $fullUri = $baseUri + $path + $filter
        if($datefilter){$fullUri += $dateFilter} ;
        $fullUri += $queryParameter ;
        # force json return by appending ?$format=json Nope: (400) Bad Request.
        #$fullUri += $formatJsonParam  ; 
        # should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'Addy.Donkhong@toro.com'&$top=1
        write-verbose "$((get-date).ToString('HH:mm:ss')):`nfullUri:`n$(($fullUri|out-string).trim())"  ;
        if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;

        $ofile = join-path -path (Split-Path -parent $MyInvocation.MyCommand.Definition) -ChildPath "logs" ;
        if (!(test-path -path $ofile)) { "Creating missing log dir $($ofile)..." ; mkdir $ofile  ; } ;
        $ofile += "\"
        if($tickets[$iProcd-1]){$ofile += "$($tickets[$iProcd-1])-"}
        if ($UPN) { $ofile += "$($UPN)" }
        else {$ofile += "ALL"} ;
        $ofile+="-$([system.io.path]::GetFilenameWithoutExtension(${CmdletName}))"
        $ofile += "-$(get-date $StartDate -format 'yyyyMMdd-HHmmtt')"
        $ofile += "-$(get-date $EndDate -format 'yyyyMMdd-HHmmtt')"
        $ofile += "-runon-$(get-date -format 'yyyyMMdd-HHmmtt')"
        write-verbose  "$((get-date).ToString('HH:mm:ss')):`$ofile:$($ofile)" ;

        <#
        Write-Output "--------------------------------------------------------------"
        Write-Output "Downloading report from `n$($fullUri)"
        Write-Output "Output file: $ofile"
        Write-Output "--------------------------------------------------------------"

        # Call Microsoft Graph
        #$AADTokenHeaders = get-AADBearerTokenHeaders($token)  -Verbose:($VerbosePreference -eq 'Continue')
        # move up next to get-AADCertToken, no reason I can see to split them    
        #$AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
        
        # we'll be flipping the $url to the next link after the first pass, so we need to use '$url' going into the loop
        $url = $fullUri ;
        $count = 0
        $retryCount = 0
        $oneSuccessfulFetch = $False
        $SignInReportArray = @()

        Do {
            "Fetching data using Url:`n$($url )" | write-verbose ;

            Try {

                 # AAsplund's simplified odata approach - assumes the return is an obj, not json

                #$AuditLogRequest = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                #$myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")
                # Splat the parameters for Invoke-Restmethod for cleaner code
                # $PostSplat = @{
    #                 ContentType = 'application/x-www-form-urlencoded' ;
    #                 Method = 'POST' ;
    #                 Body = $Body ;
    #                 Uri = $Url ;
    #                 Headers = $Header ;
    #             } ;
    #             write-verbose "$((get-date).ToString('HH:mm:ss')):Invoke-RestMethod w`n$(($PostSplat|out-string).trim())" ; 
    #             $token = Invoke-RestMethod @PostSplat ; 
                
                #$myReport = Invoke-RestMethod @$PostSplat ; 
                # can't use splats, throws: The remote name could not be resolved: 'system.collections.specialized.ordereddictionary'
                $myReport = (Invoke-RestMethod -Uri $url -Headers $AADTokenHeaders -Method Get -ContentType "application/json")

                $SignInReportArray += $myReport.value ; 
                            
                $url = $myReport.'@odata.nextLink'
                $count = $count + $myReport.value.Count
                write-verbose "Total Fetched: $count" ; 
                $retryCount = 0 ; 

            }
            Catch [System.Net.WebException] {
                $statusCode = [int]$_.Exception.Response.StatusCode
                Write-Output $statusCode
                Write-Output $_.Exception.Message
                if ($statusCode -eq 401 -and $oneSuccessfulFetch) {
                    # Token might have expired! Renew token and try again
                    # ADAL Azure mod vers:
                    #$authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
                    #$token = $authResult.AccessToken
                    #$AADTokenHeaders = get-AADBearerTokenHeaders($token)
                    #
                    $token=get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
                    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
                    $oneSuccessfulFetch = $False
                    Write-Output "Access token expiry. Requested a new one and now retrying data query..."
                }
                elseif ($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503) {
                    # throttled request or a temporary issue, wait for a few seconds and retry
                    Start-Sleep -5
                    Write-Output "A throttled request or a temporary issue. Waiting for 5 seconds and then retrying..."

                }
                elseif ($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401) {
                    Write-Output "Please check the permissions of the user"
                    break;
                }
                else {
                    if ($retryCount -lt 5) {
                        Write-Output "Retrying..."
                        $retryCount++
                    }
                    else {
                        Write-Output "Download request failed. Please try again in the future."
                        break
                    }
                }
            }
            Catch {
                $exType = $_.Exception.GetType().FullName
                $exMsg = $_.Exception.Message

                Write-Output "Exception: $_.Exception"
                Write-Output "Error Message: $exType"
                Write-Output "Error Message: $exMsg"

                if ($retryCount -lt 5) {
                    Write-Output "Retrying..."
                    $retryCount++
                }
                else {
                    Write-Output "Download request failed. Please try again in the future."
                    break
                }
            }

            Write-Output "--------------------------------------------------------------"

       # } while ($url -ne $null)  # loop-E
       } while($myReport.'@odata.nextLink' -ne $null) ; # loop-E (AAsplund)
       #>

        #search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
        $pltSrchGraphAPI=[ordered]@{
            fullURI=$fulluri ;
            token=$token ;
            tenantName=$tenantName ;
            tenantId=$tenantId ;
            AppID=$AppID ;
            Certificate=$Certificate ;
            showDebug=$($showDebug) ;
            Verbose=($VerbosePreference -eq 'Continue') ;
        } ;
        $smsg = "search-GraphApiAAD w`n$(($pltSrchGraphAPI|out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $SignInReportArray = search-GraphApiAAD @pltSrchGraphAPI ; 

        $ReportOutputCSV = "$($ofile).csv" ;
        $ReportOutputJson = "$($ofile).json" ;
        $jsonFiles += $ReportOutputJson ; # aggreg the json outputs for echo'ing profile cmd
        $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
        $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
        if(!$UPN){
            $smsg = "Sign in activity JSON report can be found at`n$($ReportOutputJson)."
            $smsg += "`nSign in activity CSV report can be found at`n$($ReportOutputCSV)."
        } else {
            $smsg = "$($UPN):Sign in activity JSON report can be found at`n$($ReportOutputJson)."
            $smsg += "`n$($UPN):Sign in activity CSV report can be found at`n$($ReportOutputCSV)."
        } ;

        $smsg = -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    }  # loop-E


    #  .\profile-AAD-Signons.ps1 -Files $jsonFiles
    $msgHere=@"
  To profile output jsons above, run:
      profile-AAD-Signons -Files '$($jsonFiles -join "','")'

"@ ;
    if ($logging) { Write-Log -LogContent $msgHere -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green $msgHere } ;

    $smsg = -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
} ; 
#*------^ END Function search-AADSignInReports ^------
