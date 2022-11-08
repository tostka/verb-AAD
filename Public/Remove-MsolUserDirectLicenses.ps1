#*------v Remove-MsolUserDirectLicenses.ps1 v------
Function Remove-MsolUserDirectLicenses{
    <#
    .SYNOPSIS
    Remove-MsolUserDirectLicenses - The purpose of this script is to remove unnecessary direct licenses from users who already inherit the same license from a group; for example, as part of a transition to group-based licensing.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-12-16
    FileName    : Remove-MsolUserDirectLicenses.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD,License
    AddedCredit : Alex Buck (alexbuckgit)
    AddedWebsite:	https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    REVISIONS   :
    * 9:23 AM 4/27/2021 renamed Remove-MsolUserDirectLicenses; roughed in functionalize, put into OTB format, ren'd helperfuncs (added to verb-aad as well); COMPLETELY UNTESTED, REM'ING OUT THE GUTS, AGAINST FUTURE NEED
    * 12/16/2020 AB git-posted rev
    .DESCRIPTION
    Remove-MsolUserDirectLicenses - The purpose of this script is to remove unnecessary direct licenses from users who already inherit the same license from a group; for example, as part of a transition to group-based licensing.
    [!NOTE] It is important to first validate that the direct licenses to be removed do not enable more service functionality than the inherited licenses. Otherwise, removing the direct license may disable access to services and data for users. Currently it is not possible to check via PowerShell which services are enabled via inherited licenses vs direct. In the script, we specify the minimum level of services we know are being inherited from groups and check against that to make sure users do not unexpectedly lose access to services.
    .PARAMETER skuId
    License to be removed - Office 365 E3[-skuId 'contoso:ENTERPRISEPACK']
    .PARAMETER servicePlansFromGroups
    Minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled which could mean that they may lose access after we remove direct licenses[-servicePlansFromGroups ('EXCHANGE_S_ENTERPRISE', 'SHAREPOINTENTERPRISE', 'OFFICESUBSCRIPTION')]
    .PARAMETER groupId
    The group to be processed[-groupId '48ca647b-7e4d-41e5-aa66-40cab1e19101']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Object
    .EXAMPLE
    .LINK
    https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-ps-examples.md
    .LINK
    http://twitter.com/tostka/verb-aad
    #>
    #Requires -Modules MSOnline
    [CmdletBinding()] 
    Param(
        [Parameter(Mandatory=$True,HelpMessage="license to be removed - Office 365 E3[-skuId 'contoso:ENTERPRISEPACK']")]
        [string]$skuId, 
        [Parameter(Mandatory=$True,HelpMessage="minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled which could mean that they may lose access after we remove direct licenses[-servicePlansFromGroups ('EXCHANGE_S_ENTERPRISE', 'SHAREPOINTENTERPRISE', 'OFFICESUBSCRIPTION')]")]
        [string[]]$servicePlansFromGroups,
        [Parameter(Mandatory=$True,HelpMessage="the group to be processed[-groupId '48ca647b-7e4d-41e5-aa66-40cab1e19101']")]
        [string]$groupId
    ) ; 
    
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ;
    } ;
    PROCESS {
        #the group to be processed
        #$groupId = "48ca647b-7e4d-41e5-aa66-40cab1e19101"

        #license to be removed - Office 365 E3
        #$skuId = "contoso:ENTERPRISEPACK"

        #minimum set of service plans we know are inherited from groups - we want to make sure that there aren't any users who have more services enabled
        #which could mean that they may lose access after we remove direct licenses
        #$servicePlansFromGroups = ("EXCHANGE_S_ENTERPRISE", "SHAREPOINTENTERPRISE", "OFFICESUBSCRIPTION")

        <#
        $expectedDisabledPlans = Get-MsolUnexpectedEnabledPlansForUser $skuId $servicePlansFromGroups

        #process all members in the group and get full info about each user in the group looping through group members. 
        Get-MsolGroupMember -All -GroupObjectId $groupId | Get-MsolUser -ObjectId {$_.ObjectId} | Foreach {
                $user = $_;
                $operationResult = "";

                #check if Direct license exists on the user
                if (test-MsolUserLicenseDirectAssigned $user $skuId){
                    #check if the license is assigned from this group, as expected
                    if (test-MsolUserLicenseGroupAssigned $user $skuId $groupId){
                        #check if there are any extra plans we didn't expect - we are being extra careful not to remove unexpected services
                        $extraPlans = Get-MsolUnexpectedEnabledPlansForUser $user $skuId $expectedDisabledPlans ; 
                        if ($extraPlans.Count -gt 0){
                            $operationResult = "User has extra plans that may be lost - license removal was skipped. Extra plans: $extraPlans" ; 
                        }else{
                            #remove the direct license from user
                            Set-MsolUserLicense -ObjectId $user.ObjectId -RemoveLicenses $skuId ; 
                            $operationResult = "Removed direct license from user."    ; 
                        } ; 

                    }else{
                        $operationResult = "User does not inherit this license from this group. License removal was skipped." ; 
                    } ; 
                } else {
                    $operationResult = "User has no direct license to remove. Skipping." ; 
                } ; 

                #format output
                New-Object Object |
                    Add-Member -NotePropertyName UserId -NotePropertyValue $user.ObjectId -PassThru |
                    Add-Member -NotePropertyName OperationResult -NotePropertyValue $operationResult -PassThru ; 
        } | Format-Table ; 
        
        #>
    } ;  # PROC-E
    END {} ; # END-E
} ; 
#*------^ Remove-MsolUserDirectLicenses.ps1 ^------
