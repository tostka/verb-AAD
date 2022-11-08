#*------v Get-ServiceToken.ps1 v------
function Get-ServiceToken {
    <#
    .SYNOPSIS
    Get-ServiceToken - Get a token for a given Microsoft Cloud Service 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Get-ServiceToken
    License     : MIT License
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Get-ServiceToken - Get a token for a given Microsoft Cloud Service 
    Returns an ADAL token for a given Microsoft Cloud Service
    Will attempt to acquire the token silently (refresh) if possible 
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    # References https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/AcquireTokenSilentAsync-using-a-cached-token
     https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/tree/adalv3/dev
    .OUTPUTS
    Returns a token object for the requested cloud service
    .EXAMPLE
    Get-ServiceToken -Service EXO
    Returns a token for the Exchange Online Service.
    .LINK
    https://github.com/Canthv0/CloudAuthModule 
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateSet("EXO","AzureGraph")]
        [string]
        $Service
    ) ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        # Ensure our ADAL types are loaded and availble
        Add-ADALType ; 

        switch ($Service) {
            exo {
                # EXO Powershell Client ID
                $clientId = "a0c73c16-a7e3-4564-9a95-2bdf47383716"  ; 
                # Set redirect URI for PowerShell
                $redirectUri = "urn:ietf:wg:oauth:2.0:oob" ; 
                # Set Resource URI to EXO endpoint
                $resourceAppIdURI = "https://outlook.office365.com" ; 
                # Set Authority to Azure AD Tenant
                $authority = "https://login.windows.net/common" ; 
            } ; 
            AzureGraph {
                # Azure PowerShell Client ID
                $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" ; 
                # Set redirect URI for PowerShell
                $redirectUri = "urn:ietf:wg:oauth:2.0:oob" ; 
                # Set Resource URI to EXO endpoint
                $resourceAppIdURI = "https://graph.windows.net" ; 
                # Set Authority to Azure AD Tenant
                $authority = "https://login.windows.net/common"             ; 
            } ; 
            Default { Write-Error "Service Not Implemented" -ErrorAction Stop } ; 
        } ; 

        # Create AuthenticationContext tied to Azure AD Tenant
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority ; 

        # Create platform Options, we want it to prompt if it needs to.
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always" ; 

        # Acquire token, this will place it in the token cache
        # $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters)

        Write-Debug "Looking in token cache" ; 
        $Result = $authContext.AcquireTokenSilentAsync($resourceAppIdURI, $clientId) ; 

        while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "silent sleep" }

        # Check if we failed to get the token
        if (!($Result.IsFaulted -eq $false)) {
             
            Write-Debug "Acquire token silent failed" ; 
            switch ($Result.Exception.InnerException.ErrorCode) {
                failed_to_acquire_token_silently { 
                    # do nothing since we pretty much expect this to fail
                    Write-Information "Cache miss, asking for credentials" ; 
                    $Result = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters) ; 
                    
                    while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "sleep" }
                } ; 
                multiple_matching_tokens_detected {
                    # we could clear the cache here since we don't have a UPN, but we are just going to move on to prompting
                    Write-Information "Multiple matching entries found, asking for credentials" ; 
                    $Result = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters) ; 
                    
                    while ($result.IsCompleted -ne $true) { Start-Sleep -Milliseconds 500; write-debug "sleep" }
                } ; 
                Default { Write-Error -Message "Unknown Token Error $Result.Exception.InnerException.ErrorCode" -ErrorAction Stop } ; 
            } ; 
        }    ; 

        Return $Result ; 
    } ;  # PROC-E
    END{} ;
} ; 
#*------^ Get-ServiceToken.ps1 ^------
