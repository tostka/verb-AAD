#*------v Get-MsolDisabledPlansForSKU.ps1 v------
Function Get-MsolDisabledPlansForSKU {
    <#
    .SYNOPSIS
    Get-MsolDisabledPlansForSKU - AzureAD produces a list of disabled service plan names for a set of plans we want to leave enabled.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Get-MsolDisabledPlansForSKU.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed 'GetDisabledPlansForSKU()' -> Get-MsolDisabledPlansForSKU; put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Get-MsolDisabledPlansForSKU - AzureAD produces a list of disabled service plan names for a set of plans we want to leave enabled.
    .PARAMETER  skuId
    .PARAMETER enabledPlans
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
        [string]$skuId, 
        [string[]]$enabledPlans
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        $allPlans = Get-MsolAccountSku | where {$_.AccountSkuId -ieq $skuId} | Select -ExpandProperty ServiceStatus | Where {$_.ProvisioningStatus -ine "PendingActivation" -and $_.ServicePlan.TargetClass -ieq "User"} | Select -ExpandProperty ServicePlan | Select -ExpandProperty ServiceName ; 
        $disabledPlans = $allPlans | Where {$enabledPlans -inotcontains $_} ; 
        return $disabledPlans
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ Get-MsolDisabledPlansForSKU.ps1 ^------