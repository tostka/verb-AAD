# get-AADToken.ps1

#*------v get-AADToken.ps1 v------
function get-AADToken {
    <#
    .SYNOPSIS
    get-AADToken - Retrieve and summarize [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : get-AADToken
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 2:18 PM 5/25/2023 CBH, expanded exmpl; remvd rem's 
    * 4:21 PM 5/22/2023 added -silent, and pswlt support; 
    * 3:29 PM 5/10/2023 tweaked verbose comments re: token status
    * 12:59 PM 5/9/2023 added trailing test for unauth, single tenant auth, and multi-token auth.
    * 8:50 AM 3/16/2021 added extra catchblock on expired token, but found that MS had massive concurrent Auth issues, so didn't finish - isolated event, not a normal fail case
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    get-AADToken - Retrieve and summarize [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens
    Works with MSAL (as it's accessing the underlying class).
    .EXAMPLE
    PS> $token = get-AADToken ; 
    PS> if( ($null -eq $token) -OR ($token.count -eq 0)){
    PS>     # not connected/authenticated
    PS>     Connect-AzureAD ; 
    PS> } else { 
    PS>     write-verbose "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
    PS> } ; 
    Retrieve and evaluate status of AzureSession token
    .EXAMPLE
    PS> write-verbose "if it's a 40char hex string -> cert thumbprint" ; 
    PS> if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; 
    PS> $token = get-AADToken -verbose:$($verbose) ;
    PS> $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ;
    PS> $Tenantdomain = convert-TenantIdToDomainName -TenantId ($token.AccessToken).tenantid ;
    PS> $uRoleReturn = resolve-UserNameToUserRole -UserName $Credential.username -verbose:$($VerbosePreference -eq "Continue") ; 
    PS> #$uRoleReturn = resolve-UserNameToUserRole -Credential $Credential -verbose = $($VerbosePreference -eq "Continue") ; 
    PS> if( ($null -eq $token) -OR ($token.count -eq 0)){
    PS>     $smsg = "NOT authenticated to any o365 Tenant AzureAD!" ; 
    PS>     if($credential.username -match $rgxCertThumbprint){
    PS>         $smsg = "Connecting to -Credential Tenant as $($uRoleReturn.FriendlyName)" ;
    PS>     } else {
    PS>         $smsg = "Connecting to -Credential Tenant:$($Credential.username.split('@')[1].tostring()))" ;
    PS>     } ;
    PS>     if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
    PS>     else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    PS> 
    PS>     Disconnect-AzureAD ;
    PS>     Connect-AAD -Credential $Credential -verbose:$($verbose) -Silent:$false  ; 
    PS> } else {
    PS>     $smsg = "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ;
    PS>     $smsg += "`n$($urolereturn.TenOrg):$($urolereturn.UserRole)" ; 
    PS>     if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
    PS>     else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    PS> } ; 
    Fancier demo leveraging a variety of verb-Auth mod functions for info parsing
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    PARAM(
        [Parameter(HelpMessage="Silent output (suppress status echos)[-silent]")]
            [switch] $silent
    ) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $token = $false ;
        $error.clear() ;
        TRY {
            $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens ; 
        } CATCH [System.Management.Automation.RuntimeException] {
            $smsg = "(No authenticated connection found)" ;
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
            #$token = $false ; 
        } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            # reflects unauthenticated
            $smsg = "(requires AAD authentication)" ;
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ;  
    } ; 
    END{ 
        if( ($null -eq $token) -OR ($token.count -eq 0)){
            $smsg = "no token: unconnected" ; 
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        }elseif($token.count -eq 1){
            $smsg = "(returning $(($token|measure).count) token)" ; 
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        }elseif($token.count -gt 1){
            $smsg = "(returning $(($token|measure).count) tokens)" ; 
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        } ; 
        if($token.count -gt 0){
            $smsg = "(Connected to tenant: $($token.AccessToken.TenantId) with user: $($token.AccessToken.UserId)" ; 
            if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        } ; 
        $token | Write-Output 
    } ;
}

#*------^ get-AADToken.ps1 ^------
