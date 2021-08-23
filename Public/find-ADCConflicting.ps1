# find-ADCConflicting
<#
.SYNOPSIS
find-ADCConflicting.ps1 - Run array of email addresses and resolve in ExchangeOnline, onPrem Exchange, ADUser, & AzureADObject, with eye toward spotting issues in ADC fails on the o365 AAD end.
.NOTES
Version     : 1.0.0
Author      : Todd Kadrie
Website     :	http://www.toddomation.com
Twitter     :	@tostka / http://twitter.com/tostka
CreatedDate : 2021-08-20
FileName    : find-ADCConflicting.ps1
License     : MIT License
Copyright   : (c) 2021 Todd Kadrie
Github      : https://github.com/tostka/verb-AAD
Tags        : Powershell,ActiveDirectoryConnect,AzureAD,ActiveDirectory
AddedCredit : REFERENCE
AddedWebsite:	URL
AddedTwitter:	URL
REVISIONS
* 3:17 PM 8/19/2021 init, roughed in, pulls AD/EX/EXO/AAD/MSOL objs for addreses, doesn't do much logic comparisons & outputs on the objects, yet, but runs wo errors (error handling sketchy on not-founds).
.DESCRIPTION
find-ADCConflicting.ps1 - Run array of email addresses and resolve in ExchangeOnline, onPrem Exchange, ADUser, & AzureADObject

Relevent 
.PARAMETER  Recipient
Array of recipient descriptors: displayname, emailaddress, UPN, samaccountname[-recip some.user@domain.com]
.PARAMETER useEXOv2
Use EXOv2 (ExchangeOnlineManagement) over basic auth legacy connection [-useEXOv2]
.EXAMPLE
PS> .\find-ADCConflicting.ps1 -recipients "10011239@toro.com","mccartx@toro.com","25159@toro.com","hernajx6@toro.com" -verbose ;
.EXAMPLE
PS> $RESULTS = .\find-ADCConflicting.ps1 -recipients "10011239@toro.com","mccartx@toro.com","25159@toro.com","hernajx6@toro.com" -verbose ;
Capture results into variable for post-processing
Resolve an array of addresses
.LINK
https://github.com/tostka/verb-AAD
#>
#Requires -Modules ActiveDirectory, AzureAD, MSOnline, ExchangeOnlineManagement, verb-AAD, verb-ADMS, verb-Auth, verb-Ex2010, verb-EXO, verb-IO, verb-logging, verb-Text, verb-logging
[CmdletBinding()]
PARAM(
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Array of recipient descriptors: displayname, emailaddress, UPN, samaccountname[-recip some.user@domain.com]")]
    [ValidateNotNullOrEmpty()]
    #[Alias('ALIAS1', 'ALIAS2')]
    $Recipients,
    [Parameter(HelpMessage="Use EXOv2 (ExchangeOnlineManagement) over basic auth legacy connection [-useEXOv2]")]
    [switch] $useEXOv2
) ;
BEGIN{
    $sBnr="`n#*======v find-ADCConflicting : v======" ; 
    write-host -foregroundcolor green ":$($sBnr)" ;
    $Verbose = ($VerbosePreference -eq 'Continue') ; 

    rx10 -Verbose:$false ; 
    rxo  -Verbose:$false ; cmsol -Verbose:$false ; connect-ad -Verbose:$false | out-null ;;
    
    $ttl = ($Recipients|measure).count ; 

    # $xMProps: add email-drivers: CustomAttribute5, EmailAddressPolicyEnabled
    $xMProps="samaccountname","windowsemailaddress","DistinguishedName","Office","RecipientTypeDetails","CustomAttribute5","EmailAddressPolicyEnabled" ;
    $lProps = @{Name='HasLic'; Expression={$_.IsLicensed }},@{Name='LicIssue'; Expression={$_.LicenseReconciliationNeeded }} ;
    $adprops = "samaccountname","UserPrincipalName","distinguishedname" ; 
    $xrcpprops = 'Alias','City','Notes','Company','CountryOrRegion','PostalCode','ExternalDirectoryObjectId',
        'EmailAddresses','ExternalEmailAddress','DisplayName','FirstName','LastName','ResourceType','ManagedBy',
        'Manager','Name','Office','ObjectCategory','OrganizationalUnit','PrimarySmtpAddress','RecipientType',
        'RecipientTypeDetails','SamAccountName','StateOrProvince','Title','WindowsLiveID','WhenMailboxCreated',
        'UsageLocation','ExchangeGuid','DistinguishedName','ObjectClass','WhenChanged','WhenCreated','ExchangeObjectId',
        'OrganizationId','Id','Guid','IsValid' ;
    $xrcppropsT = 'Alias','ExternalDirectoryObjectId',
        'EmailAddresses','ExternalEmailAddress','DisplayName','FirstName','LastName','ResourceType','Name',
        'Office','PrimarySmtpAddress','RecipientType','RecipientTypeDetails','WindowsLiveID','WhenMailboxCreated',
        'ExchangeGuid','WhenChanged','WhenCreated','ExchangeObjectId','Guid' ;
    $oprcpprops = 'Alias','City','Notes','Company','CountryOrRegion','PostalCode','Department','ExternalDirectoryObjectId',
        'EmailAddresses','ExternalEmailAddress','DisplayName','FirstName','LastName','ResourceType','ManagedBy','Manager','Name',
        'Office','ObjectCategory','OrganizationalUnit','RecipientType','RecipientTypeDetails','SamAccountName','StateOrProvince',
        'Title','WindowsLiveID','WhenMailboxCreated','UsageLocation','ExchangeVersion','DistinguishedName','Identity','Guid',
        'ObjectClass','WhenChanged','WhenCreated','OrganizationId','OriginatingServer','IsValid' ;
    $oprcppropsT = 'Alias','Notes','Company','CountryOrRegion','Department','ExternalDirectoryObjectId',
        'EmailAddresses','ExternalEmailAddress','DisplayName','FirstName','LastName','Name',
        'Office','PrimarySmtpAddress','RecipientType','RecipientTypeDetails','SamAccountName','StateOrProvince',
        'Title','WindowsLiveID','WhenMailboxCreated','DistinguishedName','Guid',
        'WhenChanged','WhenCreated' ;
    $aduprops = 'City','CN','co','Company','Country','countryCode','Created','createTimeStamp','Deleted','Department','Description',
        'DisplayName','DistinguishedName','Division','EmailAddress','EmployeeID','EmployeeNumber','employeeType','Enabled',
        'GivenName','Initials','isDeleted','lastLogoff','lastLogon','LastLogonDate','lastLogonTimestamp','legacyExchangeDN',
        'logonCount','mail','mailNickname','Manager','Modified','Name','ObjectCategory','ObjectClass','ObjectGUID','objectSid',
        'Office','Organization','physicalDeliveryOfficeName','POBox','PostalCode','proxyAddresses','SamAccountName','SID','SIDHistory',
        'st','State','StreetAddress','Surname','Title','UserPrincipalName','whenChanged','whenCreated' ;
    $adupropsT = 'createTimeStamp','Deleted','Description', 'DisplayName','DistinguishedName','Division','EmailAddress','EmployeeID',
        'EmployeeNumber','employeeType','Enabled', 'GivenName','Initials','isDeleted','mail','mailNickname','Name','ObjectGUID',
        'Office','physicalDeliveryOfficeName','proxyAddresses','SamAccountName','Surname','Title','UserPrincipalName','whenChanged',
        'whenCreated' ;
    $aaduprops = 'DeletionTimestamp','ObjectId','ObjectType','AccountEnabled','AssignedLicenses','AssignedPlans','City','CompanyName',
        'Country','Department','DirSyncEnabled','DisplayName','GivenName','ImmutableId','JobTitle','LastDirSyncTime','Mail',
        'MailNickName','OnPremisesSecurityIdentifier','OtherMails','PhysicalDeliveryOfficeName','PostalCode','ProvisionedPlans',
        'ProvisioningErrors','ProxyAddresses','SipProxyAddress','State','StreetAddress','Surname','TelephoneNumber','UsageLocation',
        'UserPrincipalName','UserType' ;
    $aadupropsT = 'DeletionTimestamp','ObjectId','AssignedLicenses','AssignedPlans','DirSyncEnabled','DisplayName','GivenName','
        ImmutableId','LastDirSyncTime','Mail','MailNickName','OnPremisesSecurityIdentifier','PhysicalDeliveryOfficeName',
        'ProvisionedPlans','ProvisioningErrors','ProxyAddresses','Surname','UserPrincipalName','UserType' ;
    $msoluprops = 'AlternateEmailAddresses','City','CloudExchangeRecipientDisplayType','Country','Department','DirSyncProvisioningErrors',
        'DisplayName','Errors','FirstName','ImmutableId','IndirectLicenseErrors','IsLicensed','LastDirSyncTime','LastName',
        'LastPasswordChangeTimestamp','LicenseAssignmentDetails','LicenseReconciliationNeeded','Licenses','LiveId',
        'MSExchRecipientTypeDetails','MSRtcSipDeploymentLocator','MSRtcSipPrimaryUserAddress','ObjectId','Office',
        'OverallProvisioningStatus','PostalCode','ProxyAddresses','SignInName','SoftDeletionTimestamp','State','StreetAddress',
        'Title','UsageLocation','UserPrincipalName','UserType','ValidationStatus','WhenCreated' ;
    $msolupropsT = 'DirSyncProvisioningErrors',
        'DisplayName','Errors','FirstName','ImmutableId','IndirectLicenseErrors','IsLicensed','LastDirSyncTime','LastName',
        'LicenseAssignmentDetails','LicenseReconciliationNeeded','Licenses','ObjectId','Office',
        'OverallProvisioningStatus','ProxyAddresses','SignInName','SoftDeletionTimestamp',
        'Title','UserPrincipalName','UserType','WhenCreated' ;

        $Report = @() ; 

} 
PROCESS{
    $Procd = 0 ; 
    foreach($eml in $Recipients.tolower()){
        $hSum = [ordered]@{
            xrcp = '' ; 
            oprcp = '' ; 
            ADU = '' ; 
            ado = '' ; 
            aadu = '' ; 
            msolu = '' ; 
        } ;
        $Procd++ ; 
        $sBnrS="`n#*------v ($($Procd)/$($ttl)):PROCESSING $($eml): v------" ; 
        write-host -foregroundcolor yellow ":$($sBnrS)" ;
        rxo;rx10 ;
        $xrcp=$oprcp=$adu=$ado = $aadu = $msolu ; 
        $error.clear() ;
        write-host -foregroundcolor yellow "`nget-exorecipient -id $($eml)" ; 
        
        if($hSum.xrcp = get-exorecipient -id $eml ){
            write-host -foregroundcolor green ":EXO Recipients w`n$(($hSum.xrcp | fl $xrcppropsT|out-string).trim())" ; 
        } ;

        write-host -foregroundcolor yellow "`nget-recipient -id $($eml)" ; 
        if($hSum.oprcp = get-recipient -id $eml -ErrorAction STOP){
        } elseif($hSum.xrcp){
            write-host -foregroundcolor yellow "RETRY on xRcp.ALIAS :get-recipient -id $($hSum.xrcp.alias)}" ; 
            $hSum.oprcp = get-recipient -id $hSum.xrcp.alias -ErrorAction STOP
        } ; 
        if($hSum.oprcp){write-host -foregroundcolor green ":OnPrem Recipients w`n$(($hSum.oprcp | fl $oprcppropsT|out-string).trim())" }
        else {write-warning "Neither $($eml), nor found xRcp.Alias $($hSum.xrcp.alias) was matched to an OnPrem Recipient"}  ;

        write-host -foregroundcolor yellow "`nget-aduser -filter {ProxyAddresses -like '*$eml*'}" ; 
        if($hSum.ADU = get-aduser -filter "ProxyAddresses -like '*$eml*'" ){
        } else {
            write-host -foregroundcolor yellow "RETRY:get-aduser -filter {userprincipalname -eq '$($eml)'}" ; 
            if($hSum.ADU = get-aduser -filter "userprincipalname -eq '$($eml)'"  -prop * ){
            } elseif($hSum.xrcp){
                write-host -foregroundcolor yellow "RETRY matched xRCP mail Alias, as SamAccountName equiv:get-aduser -id $($hSum.xrcp.Alias)" ; 
                $hSum.ADU = get-aduser -id $hSum.xrcp.Alias 
                if($hSum.ADU){
                    write-host -foregroundcolor green ":MATCHED ADUSER ON XRCP ALIAS (NOT PROPER UPN, EMAIL ADDR):`nADUsers w`n$(($hSum.ADU| fl $adupropsT|out-string).trim())" ; 
                }
            } 
        } ; 
        if($hSum.OpRcp){
            write-host -foregroundcolor green "OnPrem.Recipient w`n$(($hSum.OpRcp| fl $oprcppropsT|out-string).trim())" 
            if($hsum.xrcp.PrimarySmtpAddress -eq $hsum.oprcp.primarysmtpaddress){
                write-warning "matched EXO.Recipient $($hsum.xrcp.PrimarySmtpAddress)`nAND OnPrem.Recipient $($hsum.oprcp.primarysmtpaddress)`nPrimarySMTPAddress values *DO NO MATCH!*`nTHESE OBJECTS CANNOT BE ALIGNED PROPERLY!"
            } 
        }else {write-warning "$($eml) does not match *any* onprem ADUser (UPN online & onprem out of alighnment: Onboard damage)" } ;
        
        write-host -foregroundcolor yellow "`nget-adObject -filter {ProxyAddresses -like '*$eml*'}" ; 
        if($hSum.ado = get-adObject -filter "ProxyAddresses -like '*$eml*'" -ErrorAction STOP){
            write-host -foregroundcolor green ":ADObjects w`n$(($hSum.ado| fl $adupropsT|out-string).trim())" ; 
        } else {write-warning "$($eml) does not match ProxyAddresses on any ADObject"} ;

        write-host -foregroundcolor yellow "`nGet-AzureADUser -Filter {proxyAddresses/any(c:c eq 'smtp:$($eml)')}" ; 
        if($hsum.aadu = Get-AzureADUser -Filter "proxyAddresses/any(c:c eq 'smtp:$eml')" ){
        } else{ 
            write-host -foregroundcolor yellow "`nRetry:get-azureaduser -ObjectId $($eml)" ; 
            if($hSum.aadu = get-azureaduser -ObjectId $eml -ErrorAction STOP){
            } elseif($hSum.xrcp){
                write-host -foregroundcolor yellow "`nRETRY matched xRCP primaryAddr:get-azureaduser -ObjectId $($hSum.xrcp.PrimarySmtpAddress)" ; 
                $hSum.aadu = Get-AzureADUser -Filter "userPrincipalName eq '$eml'" ;
                if($hSum.aadu){
                } else { 
                    write-host -foregroundcolor yellow "`nRETRY matched xRCP primaryAddr:get-azureaduser -ObjectId $($hSum.xrcp.PrimarySmtpAddress)" ; 
                    if($hSum.aadu = Get-AzureADUser -Filter "userPrincipalName eq '$eml'" -ErrorAction STOP){
                    } ;
                } ;
            }  ; 
        } ;
        if($hSum.aadu){write-host -foregroundcolor green ":AzureADUser w`n$(($hSum.aadu| fl $aadupropsT|out-string).trim())" ; }
        else {write-warning "Unable to match an AzureADUser on:UPN:$($eml); or filter UPN, .PrimSmtp:$($hSum.xrcp.PrimarySmtpAddress)`n(UPN online & onprem out of alighnment: Onboard damage)" ;} ; 
        
        write-host -foregroundcolor yellow "`nget-msoluser -UserPrincipalName $($eml)" ; 
        if($hSum.msolu = get-msoluser -UserPrincipalName $eml -ErrorAction STOP){
        } elseif($hSum.xrcp){
            write-host -foregroundcolor yellow "`nRETRY matched xRCP primaryAddr:get-msoluser -UserPrincipalName $($hSum.xrcp.PrimarySmtpAddress)" ; 
            $hSum.aadu = get-msoluser -UserPrincipalName $hSum.xrcp.PrimarySmtpAddress 
            if($hSum.aadu){
                write-host -foregroundcolor green ":ADUsers w`n$(($hSum.aadu| fl $aadupropsT|out-string).trim())" ; 
            } else {
                write-warning "Unable to match an MSOLUser on:UPN:$($eml); or xRcp.PrimSmtp:$($hSum.xrcp.PrimarySmtpAddress)`n(UPN online & onprem out of alighnment: Onboard damage)" ;
            } ; 
        }  ; 
        if($hSum.msolu){write-host -foregroundcolor green "`nADObjects w`n$(($hSum.msolu| fl $adupropsT|out-string).trim())" }
        else {write-warning "Unable to match an MsolUser on:UPN:$($eml); or filter UPN, .PrimSmtp:$($hSum.xrcp.PrimarySmtpAddress)`n(UPN online & onprem out of alighnment: Onboard damage)" ;} ; 


        $hmsg=@"
-----------
==$($eml): Resolved to:
EXORecipients:
$(($hSum.xrcp|out-string).trim())

ONPremRecipients:
$(($hSum.oprcp|out-string).trim())

ADUsers:
$(($hSum.ADU|out-string).trim())

ADObjects:
$(($hSum.ado|out-string).trim())

AzureADUsers:
$(($hSum.aadu|out-string).trim())

MsolUsers:
$(($hSum.msolu|out-string).trim())
-----------

"@ ; 
        write-host -foregroundcolor Yellow $hmsg ;

        $Report += New-Object PSObject -Property $hsum ; 
        

        write-host -foregroundcolor green ":$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    };
}  # PROC-E ; 
END {
    write-host -foregroundcolor green "returning $(($Report|measure).count) objects to the pipeline..." ; 
    $Report | write-output
    write-host -foregroundcolor green ":$($sBnr.replace('=v','=^').replace('v=','^='))`n" ;
} ; 

