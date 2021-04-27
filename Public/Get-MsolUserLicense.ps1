#*------v Get-MsolUserLicense.ps1 v------
Function Get-MsolUserLicense {
    <#
    .SYNOPSIS
    Get-MsolUserLicense - AzureAD Returns the license object corresponding to the skuId. Returns NULL if not found.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolUserLicense.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed 'GetUserLicense()' -> Get-MsolUserLicense(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolUserLicense - AzureAD Returns the license object corresponding to the skuId. Returns NULL if not found.
    .PARAMETER user, 
    .PARAMETER groupId
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Microsoft.Online.Administration.User]$user,
        [string]$skuId, [Guid]$groupId
    )
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        #we look for the specific license SKU in all licenses assigned to the user
        foreach($license in $user.Licenses) {
            if ($license.AccountSkuId -ieq $skuId){return $license } ; 
        } ; 
        return $null ; 
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ Get-MsolUserLicense.ps1 ^------