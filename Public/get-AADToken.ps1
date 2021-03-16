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
    * 8:50 AM 3/16/2021 added extra catchblock on expired token, but found that MS had massive concurrent Auth issues, so didn't finish - isolated event, not a normal fail case
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    get-AADToken - Retrieve and summarize [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens
    .EXAMPLE
    $token = get-AADToken ; 
    if( ($null -eq $token) -OR ($token.count -eq 0)){
        # not connected/authenticated
        Connect-AzureAD ; 
    } else { 
        write-verbose "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ; 
    } ; 
    Retrieve and evaluate status of AzureSession token
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param([Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        $token = $false ;
        $error.clear() ;
        TRY {
            $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens ; 
            # 3:50 PM 3/15/2021: I'm getting a token, but it's *expired*, need another test - actually MS was having massive auth issues concurrent w the error. Likely transitory
        } CATCH [System.Management.Automation.RuntimeException] {
            # pre connect it throws this
            <#
                Unable to find type [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession].
                At line:1 char:10
                + $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::Access ...
                +          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    + CategoryInfo          : InvalidOperation: (Microsoft.Open....ry.AzureSession:TypeName) [], RuntimeException
                    + FullyQualifiedErrorId : TypeNotFound
            #>
            write-verbose "(No authenticated connection found)"
            #$token = $false ; 
        } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            # reflects unauthenticated
            <#
                At line:2 char:11
            +  $myVar = Get-AzureADTenantDetail
            +           ~~~~~~~~~~~~~~~~~~~~~~~
                + CategoryInfo          : NotSpecified: (:) [Get-AzureADTenantDetail], AadNeedAuthenticationException
                + FullyQualifiedErrorId : Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException,Microsoft.Open.AzureAD16.PowerShell.GetTenantDetails 
            #>
            write-verbose "(requires AAD authentication)"
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ;  
    } ; 
    END{ 
        if($token.count -gt 1){
            write-verbose "(returning $(($token|measure).count) tokens)" ; 
        } ; 
        write-verbose "(Connected to tenant: $($token.AccessToken.TenantId) with user: $($token.AccessToken.UserId)" ; 
        $token | Write-Output 
    } ;
}

#*------^ get-AADToken.ps1 ^------