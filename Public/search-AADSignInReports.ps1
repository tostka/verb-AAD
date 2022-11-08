#*------v search-AADSignInReports.ps1 v------
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
    * 10:47 AM 6/16/2021 added record count echo (easier to verifiy return worked) ; purged more rem'd cd ; revised start-log code (accomd cmdlet in allusers module), swapped in all $ofile => sl $logfile w variant exts, moved logging down into the UPN loop ; trimmed rem'd code shifted to search-graphapiAAD() (confirmed functional) ; removed local buffered copies of  get-AADTokenHeaders, get-AADCertToken, search-GraphApiAAD (they're in same module now, no need to buffer)
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
    Ps> search-AADSignInReports.ps1 -UPNs fname.lname@domain.com -ticket 456277 -showdebug ;
    Retrieve default, last7 days of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs fname.lname@domain.com -ticket 456277 -StartDate (Get-Date).AddDays(-30) -showdebug ;
    Retrieve custom interval (last 30d) of signon records for specified UPN
    .EXAMPLE
    Ps> search-AADSignInReports.ps1 -UPNs "fname.lname@domain.com","Sarah.Bell@toro.com" -ticket "456277","452916" -StartDate (Get-Date).AddDays(-30) -showdebug ;
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
    $verbose = ($VerbosePreference -eq "Continue") ; 
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    # Get parameters this function was invoked with
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
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

    
    # Clear error variable
    $Error.Clear() ;
    
    $sBnr="#*======v $(${CmdletName}): v======" ;
    $smsg = $sBnr ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    # 1:11 PM 6/14/2021 provide dyn param lookup on $TenOrg, via meta infra file

    if(!($tenantName = (gv -name "$($TenOrg)meta").value.o365_TenantDomain)){throw "missing $($TenOrg)meta.value.o365_TenantDomain!" ; break ; } ;
    if(!($tenantId = (gv -name "$($TenOrg)meta").value.o365_Tenantid)){throw "missing $($TenOrg)meta.value.o365_Tenantid!" ; break ; } ;
    if(!($AppID = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_ID)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_ID!" ; break ; } ;
    if(!($Certificate = (gv -name "$($TenOrg)meta").value.AAD_App_Audit_CertThumb)){throw "missing $($TenOrg)meta.value.AAD_App_Audit_CertThumb!" ; break ; } ;

    if(!$MSGraphScope){
        $MSGraphScope = 'https://graph.microsoft.com' ;
        ##$resourceAppIdURI = "https://graph.microsoft.com"
        #$MSGraphURI = "https://graph.microsoft.com"
    } ;
    $MSGraphURI = $MSGraphScope ;

    #$redirectUri      = "https://RedirectURI.com"                #Your Application's Redirect URI
    #$redirectUri = "https://placemarker.com"                #Your Application's Redirect URI
    # redir uri for PS bearer token script(?)
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"


    $ttl = ($UPNs | Measure-Object).count ;
    $tickNum = ($tickets | Measure-Object).count
    if ($ttl -ne $tickNum ) {
        write-host -foregroundcolor RED "$((get-date).ToString('HH:mm:ss')):ERROR!:You have specified $($ttl) UPNs but only $($tickNum) tickets.`nPlease specified a matching number of both objects." ;
        Break ;
    } ;

    # below is hard-coded dates, 2/1/196am to 2/28/19 7am.
    #$fullUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime%20ge%202019-02-01T06:00:00Z%20and%20createdDateTime%20le%202019-02-28T00:07:01.607Z&`$top=1000"

    # UPN query 1 return: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1

    $formattedStart = " {0:s}" -f $StartDate + 'Z' ;
    $formattedEnd = " {0:s}" -f $EndDate + 'Z' ; 
    $baseUri = "$($MSGraphURI)/" ;

    $pltAADCertToken=[ordered]@{
        tenantName= $tenantName ; AppID= $AppID ; Certificate= $Certificate ; verbose = ($VerbosePreference -eq 'Continue') ;
    } 
    write-verbose "$((get-date).ToString('HH:mm:ss')):get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    # cmdline alt
    #$Request =get-AADCertToken -tenantName $tenantName -AppID $AppID -Certificate $Certificate -verbose:($VerbosePreference -eq 'Continue');
    # splatted:
    $smsg = "get-AADCertToken w`n$(($pltAADCertToken|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $token =get-AADCertToken @pltAADCertToken ; 
    # build tokenheader from token
    $pltAADCertTokenHdr=[ordered]@{token=$token ;Verbose=$($VerbosePreference -eq 'Continue');};
    $smsg = "get-AADTokenHeaders w`n$(($pltAADCertTokenHdr|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
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

        if(!(get-variable LogPathDrives -ea 0)){$LogPathDrives = 'd','c' };
        foreach($budrv in $LogPathDrives){if(test-path -path "$($budrv):\scripts" -ea 0 ){break} } ;
        if(!(get-variable rgxPSAllUsersScope -ea 0)){
            $rgxPSAllUsersScope="^$([regex]::escape([environment]::getfolderpath('ProgramFiles')))\\((Windows)*)PowerShell\\(Scripts|Modules)\\.*\.(ps(((d|m))*)1|dll)$" ;
        } ;
        $pltSL=[ordered]@{Path=$null ;NoTimeStamp=$false ;Tag=$null ;showdebug=$($showdebug) ; Verbose=$($VerbosePreference -eq 'Continue') ; whatif=$($whatif) ;} ;
        #$pltSL.Tag = $tickets -join ',' ;
        if($tickets[$iProcd-1]){$pltSL.Tag = "$($tickets[$iProcd-1])-$($UPN)"} ;
        if($script:PSCommandPath){
            if($script:PSCommandPath -match $rgxPSAllUsersScope){
                write-verbose "AllUsers context script/module, divert logging into [$budrv]:\scripts" ;
                if((split-path $script:PSCommandPath -leaf) -ne $cmdletname){
                    # function in a module/script installed to allusers 
                    $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath "$($cmdletname).ps1") ;
                } else { 
                    # installed allusers script
                    $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $script:PSCommandPath -leaf)) ;
                }
            }else {
                $pltSL.Path = $script:PSCommandPath ;
            } ;
        } else {
            if($MyInvocation.MyCommand.Definition -match $rgxPSAllUsersScope){
                 $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $script:PSCommandPath -leaf)) ;
            } else {
                $pltSL.Path = $MyInvocation.MyCommand.Definition ;
            } ;
        } ;
        write-verbose "start-Log w`n$(($pltSL|out-string).trim())" ; 
        $logspec = start-Log @pltSL ;
        $error.clear() ;
        TRY {
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
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;

        #$sBnrS="`n#*------v ($($iProcd) / $($ttl)):Processing:$($UPN) v------" ;
        $sBnrS="`n#*------v ($($iProcd) / $($ttl)):Processing:$($pltSL.Tag) v------" ;
        $smsg = "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
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
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and (createdDateTime ge 2019-08-20T10:46:31Z and createdDateTime le 2019-08-27T10:46:31Z)&$top=10
        # 9:45 AM 1/28/2020failing with
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and ( and createdDateTime le  2020-01-28T08:26:19Z)&$top=1000
        # visible issue: spurious ( and create... in the middle of the param clause
        # but this works in GX
        # https://graph.microsoft.com/beta/auditLogs/signIns?$filter=(userPrincipalName eq 'fname.lname@domain.com') and (createdDateTime le 2020-01-28)&$top=1000
        
        $fullUri = $baseUri + $path + $filter
        if($datefilter){$fullUri += $dateFilter} ;
        $fullUri += $queryParameter ;
        
        # should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1
        write-verbose "$((get-date).ToString('HH:mm:ss')):`nfullUri:`n$(($fullUri|out-string).trim())"  ;
        if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;
        
        # generated $logfile: d:\scripts\logs\search-AADSignInReports-999999-fname.lname@domain.com-LOG-BATCH-EXEC-20210616-0900AM-log.txt
        write-verbose  "$((get-date).ToString('HH:mm:ss')):`$logfile:$($logfile)" ;

        # (shifted graph call loop code into search-GraphApiAAD)

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

        if($returns = ($SignInReportArray|measure).count){
            $smsg = "(Report Records returned:$($returns))" ;
        } else { 
            $smsg = "(*NO* Report Records returned)" ;
        } ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $ReportOutputCSV = $logfile.replace('-log.txt','.csv') ;
        #"$($ofile).csv" ;
        $ReportOutputJson =  $logfile.replace('-log.txt','.json') ;
        #"$($ofile).json" ;
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
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $smsg = $sBnrS.replace('-v','-^').replace('v-','^-') ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    }  # loop-E


    #  .\profile-AAD-Signons.ps1 -Files $jsonFiles
    $msgHere=@"
  To profile output jsons above, run:
      profile-AAD-Signons -Files '$($jsonFiles -join "','")'

"@ ;
    if ($logging) { Write-Log -LogContent $msgHere -Path $logfile -useHost -Level H2 } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green $msgHere } ;

    $smsg = $sBnr.replace('=v','=^').replace('v=','^=') ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
}
#*------^ search-AADSignInReports.ps1 ^------
