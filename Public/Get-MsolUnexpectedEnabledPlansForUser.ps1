#*------v Get-MsolUnexpectedEnabledPlansForUser.ps1 v------
Function Get-MsolUnexpectedEnabledPlansForUser {
    <#
    .SYNOPSIS
    Get-MsolUnexpectedEnabledPlansForUser - AzureAD produces a list of enabled service plan names that are not present in the list specified by the -expectedDisabledPlans param.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolUnexpectedEnabledPlansForUser.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed 'GetDisabledPlansForSKU()' -> Get-MsolUnexpectedEnabledPlansForUser; put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolUnexpectedEnabledPlansForUser - AzureAD produces a list of enabled service plan names that are not present in the list specified by the -expectedDisabledPlans param.
    .PARAMETER  user
    .PARAMETER skuId
    .PARAMETER expectedDisabledPlans
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $extraPlans = Get-MsolUnexpectedEnabledPlansForUser $user $skuId $expectedDisabledPlans ; 
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Microsoft.Online.Administration.User]$user, 
        [string]$skuId, 
        [string[]]$expectedDisabledPlans
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        $license = Get-MsolUserLicense $user $skuId ;
        $extraPlans = @();
        if($license -ne $null){
            $userDisabledPlans = $license.ServiceStatus | where {$_.ProvisioningStatus -ieq "Disabled"} | Select -ExpandProperty ServicePlan | Select -ExpandProperty ServiceName ;
            $extraPlans = $expectedDisabledPlans | where {$userDisabledPlans -notcontains $_} ;
        } ;
        return $extraPlans ;
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ Get-MsolUnexpectedEnabledPlansForUser.ps1 ^------
