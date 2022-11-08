#*------v Get-TokenCache.ps1 v------
function Get-TokenCache {
    <#
    .SYNOPSIS
    Get-TokenCache - Returns the current contents of the token cache 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Get-TokenCache
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 1:58 PM 6/16/2021 fixed typo (spurious ;)
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Get-TokenCache - Returns the current contents of the token cache 
    Returns basic properties about the objects currently in the token cache.
    Returns the local time that the token will expire. 
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    .OUTPUTS
    List of the information in the token cache. 
    .EXAMPLE
    Get-TokenCache
    Displays the information currently in the token cache. 
    .LINK
    https://github.com/Canthv0/CloudAuthModule 
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param() ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        # Ensure our ADAL types are loaded and availble
        Add-ADALType ;
        $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared ;
        if ($full){
            Return $Cache.ReadItems() ;
        } else {
            $cache.ReadItems() | Select-Object DisplayableId, Authority, ClientId, Resource, @{Name = "ExpiresOn"; Expression = { $_.ExpiresOn.localdatetime } } ;
        } ;
    } ; 
    END{} ;
}
#*------^ Get-TokenCache.ps1 ^------
