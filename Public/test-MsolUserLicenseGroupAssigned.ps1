#*------v test-MsolUserLicenseGroupAssigned.ps1 v------
Function test-MsolUserLicenseGroupAssigned {
    <#
    .SYNOPSIS
    test-MsolUserLicenseGroupAssigned - AzureAD check if a particular product license is inheriting the license from a group.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : test-MsolUserLicenseGroupAssigned.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 8:08 AM 8/18/2021 cleaned strings for public
    * 10:52 AM 4/27/2021 expanded CBH, added simpler example ; renamed 'UserHasLicenseAssignedDirectly()' -> test-MsolUserLicenseGroupAssigned(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    test-MsolUserLicenseGroupAssigned - AzureAD check if a particular product license is inheriting the license from a group.
    .PARAMETER  user
    MSOL User object for target user [-user `$MsolUser]
    .PARAMETER  skuId
    License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ "==$($_):" ; test-MsolUserLicenseGroupAssigned -user $msolu -skuId $_ } ;
    Evaluate all licenses on a target MSOLUser for Group Assignement
        .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Some.User@toro.com ; 
    $msolu.licenses.accountskuid |%{ if(test-MsolUserLicensegroupAssigned -user $msolu -skuId $_ ){$_}} ;
    Output just the Group-Assigned licenses
    .EXAMPLE
    #the license SKU we are interested in. 
    $skuId = "contoso:EMS"
    #find all users that have the SKU license assigned
    Get-MsolUser -All | where {$_.isLicensed -eq $true -and $_.Licenses.AccountSKUID -eq $skuId} | select  ObjectId,  @{Name="SkuId";Expression={$skuId}},  @{Name="AssignedDirectly";Expression={(test-MsolUserLicenseDirectAssigned -skuId $_ $skuId)}},  @{Name="AssignedFromGroup";Expression={(test-MsolUserLicenseGroupAssigned -skuId $_ $skuId)}} ; 
    Process all users in Org with specified license, and output whether AssignedFromGroup or AssignedDirectly status.
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-Msol
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Parameter(HelpMessage="MSOL User object for target user [-user `$MsolUser]")]
        [Microsoft.Online.Administration.User]$user, 
        [Parameter(HelpMessage="License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]")]
        [string]$skuId
    ) ;
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        foreach($license in $user.Licenses){
            #we look for the specific license SKU in all licenses assigned to the user
            if ($license.AccountSkuId -ieq $skuId){
                #GroupsAssigningLicense contains a collection of IDs of objects assigning the license
                #This could be a group object or a user object (contrary to what the name suggests)
                foreach ($assignmentSource in $license.GroupsAssigningLicense){
                    #If the collection contains at least one ID not matching the user ID this means that the license is inherited from a group.
                    #Note: the license may also be assigned directly in addition to being inherited
                    if ($assignmentSource -ine $user.ObjectId){return $true} ; 
                }
                return $false ; 
            } ; 
        }; 
        return $false
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ test-MsolUserLicenseGroupAssigned.ps1 ^------
