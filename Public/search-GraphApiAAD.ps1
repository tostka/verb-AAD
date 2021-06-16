#*------v search-GraphApiAAD.ps1 v------
function search-GraphApiAAD {
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
    * 9:38 AM 6/16/2021 added non-splatted example
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
    Splatted example - FullURI query specs are generated externally, and passed in as a complete ODATa syntax uri
    .EXAMPLE
    search-GraphApiAAD -fullURI $fulluri -token $token -tenantName $tenantName -tenantId $tenantId -AppID $AppID -Certificate $Certificate -showDebug $showDebug -Verbose:($VerbosePreference -eq 'Continue') ;
    $ofile = 'd:\scripts\logs\report' ; 
    $ReportOutputCSV = "$($ofile).csv" ;
    $ReportOutputJson = "$($ofile).json" ;
    $SignInReportArray | Convertto-Json | Out-File $ReportOutputJson -Force ;
    $SignInReportArray | Select-Object * | Export-csv $ReportOutputCSV -NoTypeInformation -Force ; 
    Non-splatted example - FullURI query specs are generated externally, and passed in as a complete ODATa syntax uri
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

        # fulluri should resemble: https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq 'fname.lname@domain.com'&$top=1
        $smsg = "`nfullUri:`n$(($fullUri|out-string).trim())"  ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        if($showdebug){$fullUri|C:\WINDOWS\System32\clip.exe} ;
    } 
    PROCESS {
        $smsg = "--------------------------------------------------------------" ;
        $smsg += "`nDownloading report from `n$($fullUri)"  ;
        $smsg += "`n--------------------------------------------------------------" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    
        # we'll be flipping the $url to the next link after the first pass, so we need to use '$url' going into the loop
        $url = $fullUri ;
        $count = 0
        $retryCount = 0
        $oneSuccessfulFetch = $False
        $ReportArray = @() # aggregator

        Do {
            $smsg = "Fetching data using Url:`n$($url )" 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
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
                #"Total Fetched: $count" | write-verbose ; 
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
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H3 } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

       } while($myReport.'@odata.nextLink' -ne $null) ; # loop-E 
   }  # if-E-PROCESS 
   END {$ReportArray| write-output ; } 
}
#*------^ search-GraphApiAAD.ps1 ^------