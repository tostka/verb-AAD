#*------v test-MsolUserLicenseDirectAssigned.ps1 v------
Function test-MsolUserLicenseDirectAssigned {
    <#
    .SYNOPSIS
    test-MsolUserLicenseDirectAssigned - AzureAD check if a particular product license is assigned directly.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : test-MsolUserLicenseDirectAssigned.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 10:52 AM 4/27/2021 expanded CBH, added simpler example ; renamed 'UserHasLicenseAssignedDirectly()' -> test-MsolUserLicenseDirectAssigned(); put into OTB format
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    test-MsolUserLicenseDirectAssigned - AzureAD check if a particular product license is assigned directly.
    .PARAMETER  user
    MSOL User object for target user [-user `$MsolUser]
    .PARAMETER  skuId
    License AccountSkuID to be evaluated  [-skuID contoso:ENTERPRISEPACK]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Dennis.Cain@toro.com ; 
    $msolu.licenses.accountskuid |%{ "==$($_):" ; test-MsolUserLicenseDirectAssigned -user $msolu -skuId $_ } ;
    Evaluate all licenses on a target MSOLUser for Direct Assignement
    .EXAMPLE
    $msolu = get-msoluser -UserPrincipalName Dennis.Cain@toro.com ; 
    $msolu.licenses.accountskuid |%{ if(test-MsolUserLicenseDirectAssigned -user $msolu -skuId $_ ){$_}} ;
    Output just the Direct-Assigned licenses
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
                #If the collection is empty, this means the license is assigned directly - this is the case for users who have never been licensed via groups in the past
                if ($license.GroupsAssigningLicense.Count -eq 0){return $true} ; 
                #If the collection contains the ID of the user object, this means the license is assigned directly
                #Note: the license may also be assigned through one or more groups in addition to being assigned directly
                foreach ($assignmentSource in $license.GroupsAssigningLicense){
                    if ($assignmentSource -ieq $user.ObjectId){return $true} ; 
                }
                return $false ; 
            } ; 
        }
        return $false
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ test-MsolUserLicenseDirectAssigned.ps1 ^------