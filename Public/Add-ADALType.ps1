#*------v Add-ADALType.ps1 v------
function Add-ADALType {
    <#
    .SYNOPSIS
    Add-ADALType - Path & Load the AzureAD 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-08-08
    FileName    : Add-ADALType
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Add-ADALType - Path & Load the AzureAD 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    Lifted from [PowerShell Gallery | CloudConnect.psm1 1.0.0](https://www.powershellgallery.com/packages/CloudConnect/1.0.0/Content/CloudConnect.psm1)
    .EXAMPLE
    $token = Add-ADALType ; 
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
        $path = join-path (split-path (Get-Module azuread -ListAvailable | Where-Object { $_.Version -eq '2.0.2.16' }).Path -parent) 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll' ; 
        Add-Type -Path $path ; 
    } ; 
    END{} ;
} ; 
#*------^ Add-ADALType.ps1 ^------