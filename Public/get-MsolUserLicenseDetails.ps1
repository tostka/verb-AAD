#*------v Function get-MsolUserLicenseDetails v------
Function get-MsolUserLicenseDetails {
    <# 
    .SYNOPSIS
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Based on work by :Brad Wyatt
    Website: https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    REVISIONS   :
    * 12:00 PM 1/9/2019 replaced broken aggreg with simpler cobj -prop $hash set, now returns proper mult lics
    * 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    * 11:33 AM 1/9/2019 add SPE_F1 lic spec, and export the aggreg, NewObject02 was never more than a single lic (eg. support mult lics)
    * 3:47 PM 12/7/2018 works in prod for single-licenses users, haven't tested on multis yet. 
    * 3:17 PM 12/7/2018 added showdebug, updated pshelp
    * 2:58 PM 12/7/2018 initial version
    .DESCRIPTION
    get-MsolUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    Based on the core lic hash & lookup code in his "Get Friendly License Name for all Users in Office 365 Using PowerShell" script
    .PARAMETER UPNs
    Array of Userprincipalnames to be looked up
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLicenseDetails -UPNs todd.kadrie@toro.com ; 
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = get-MsolUserLicenseDetails -UPNs $exombx.userprincipalname -showdebug:$($showdebug)
    Retrieve MSOL License details on specified UPN, with showdebug specified
    .LINK
    https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    #>
    Param(
      [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="An array of MSolUser objects")][ValidateNotNullOrEmpty()]
      [string]$UPNs,
      [Parameter()]$Credential = $global:credo365TORSID,
      [Parameter(HelpMessage="Debugging Flag [-showDebug]")][switch] $showDebug
    ) ; 

    $Retries = 4 ;
    $RetrySleep = 5 ;
    #Connect-AAD ; 
    # 2:45 PM 11/15/2019
    Connect-Msol ; 

    # 11:13 AM 1/9/2019: SPE_F1 isn't in thlist, 'SPE'=="Secure Productive Enterprise (SPE) Licensing Bundle"
    # 11:42 AM 1/9/2019 added "MS_TEAMS_IW"      (portal displayname used below)
    # [Product names and service plan identifiers for licensing in Azure Active Directory | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference)

    <# whatis an F1 lic: Office 365 F1 is designed to enable Firstline Workers to do their best work. 
    Office 365 F1 provides easy-to-use tools and services to help these workers 
    easily create, update, and manage schedules and tasks, communicate and work 
    together, train and onboard, and quickly receive company news and announcements.
    #>

    # updating sort via text: gc c:\tmp\list.txt | sort ;
    $Sku = @{
        "O365_BUSINESS_ESSENTIALS"		     = "Office 365 Business Essentials"
        "O365_BUSINESS_PREMIUM"			     = "Office 365 Business Premium"
        "DESKLESSPACK"					     = "Office 365 (Plan K1)"
        "DESKLESSWOFFPACK"				     = "Office 365 (Plan K2)"
        "LITEPACK"						     = "Office 365 (Plan P1)"
        "EXCHANGESTANDARD"				     = "Office 365 Exchange Online Only"
        "STANDARDPACK"					     = "Enterprise Plan E1"
        "STANDARDWOFFPACK"				     = "Office 365 (Plan E2)"
        "ENTERPRISEPACK"					 = "Enterprise Plan E3"
        "ENTERPRISEPACKLRG"				     = "Enterprise Plan E3"
        "ENTERPRISEWITHSCAL"				 = "Enterprise Plan E4"
        "STANDARDPACK_STUDENT"			     = "Office 365 (Plan A1) for Students"
        "STANDARDWOFFPACKPACK_STUDENT"	     = "Office 365 (Plan A2) for Students"
        "ENTERPRISEPACK_STUDENT"			 = "Office 365 (Plan A3) for Students"
        "ENTERPRISEWITHSCAL_STUDENT"		 = "Office 365 (Plan A4) for Students"
        "STANDARDPACK_FACULTY"			     = "Office 365 (Plan A1) for Faculty"
        "STANDARDWOFFPACKPACK_FACULTY"	     = "Office 365 (Plan A2) for Faculty"
        "ENTERPRISEPACK_FACULTY"			 = "Office 365 (Plan A3) for Faculty"
        "ENTERPRISEWITHSCAL_FACULTY"		 = "Office 365 (Plan A4) for Faculty"
        "ENTERPRISEPACK_B_PILOT"			 = "Office 365 (Enterprise Preview)"
        "STANDARD_B_PILOT"				     = "Office 365 (Small Business Preview)"
        "VISIOCLIENT"					     = "Visio Pro Online"
        "POWER_BI_ADDON"					 = "Office 365 Power BI Addon"
        "POWER_BI_INDIVIDUAL_USE"		     = "Power BI Individual User"
        "POWER_BI_STANDALONE"			     = "Power BI Stand Alone"
        "POWER_BI_STANDARD"				     = "Power-BI Standard"
        "PROJECTESSENTIALS"				     = "Project Lite"
        "PROJECTCLIENT"					     = "Project Professional"
        "PROJECTONLINE_PLAN_1"			     = "Project Online"
        "PROJECTONLINE_PLAN_2"			     = "Project Online and PRO"
        "ProjectPremium"					 = "Project Online Premium"
        "ECAL_SERVICES"					     = "ECAL"
        "EMS"							     = "Enterprise Mobility Suite"
        "RIGHTSMANAGEMENT_ADHOC"			 = "Windows Azure Rights Management"
        "MCOMEETADV"						 = "PSTN conferencing"
        "SHAREPOINTSTORAGE"				     = "SharePoint storage"
        "PLANNERSTANDALONE"				     = "Planner Standalone"
        "CRMIUR"							 = "CMRIUR"
        "BI_AZURE_P1"					     = "Power BI Reporting and Analytics"
        "INTUNE_A"						     = "Windows Intune Plan A"
        "PROJECTWORKMANAGEMENT"			     = "Office 365 Planner Preview"
        "ATP_ENTERPRISE"					 = "Exchange Online Advanced Threat Protection"
        "EQUIVIO_ANALYTICS"				     = "Office 365 Advanced eDiscovery"
        "AAD_BASIC"						     = "Azure Active Directory Basic"
        "RMS_S_ENTERPRISE"				     = "Azure Active Directory Rights Management"
        "AAD_PREMIUM"					     = "Azure Active Directory Premium"
        "MFA_PREMIUM"					     = "Azure Multi-Factor Authentication"
        "STANDARDPACK_GOV"				     = "Microsoft Office 365 (Plan G1) for Government"
        "STANDARDWOFFPACK_GOV"			     = "Microsoft Office 365 (Plan G2) for Government"
        "ENTERPRISEPACK_GOV"				 = "Microsoft Office 365 (Plan G3) for Government"
        "ENTERPRISEWITHSCAL_GOV"			 = "Microsoft Office 365 (Plan G4) for Government"
        "DESKLESSPACK_GOV"				     = "Microsoft Office 365 (Plan K1) for Government"
        "ESKLESSWOFFPACK_GOV"			     = "Microsoft Office 365 (Plan K2) for Government"
        "EXCHANGESTANDARD_GOV"			     = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
        "EXCHANGEENTERPRISE_GOV"			 = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
        "SHAREPOINTDESKLESS_GOV"			 = "SharePoint Online Kiosk"
        "EXCHANGE_S_DESKLESS_GOV"		     = "Exchange Kiosk"
        "RMS_S_ENTERPRISE_GOV"			     = "Windows Azure Active Directory Rights Management"
        "OFFICESUBSCRIPTION_GOV"			 = "Office ProPlus"
        "MCOSTANDARD_GOV"				     = "Lync Plan 2G"
        "SHAREPOINTWAC_GOV"				     = "Office Online for Government"
        "SHAREPOINTENTERPRISE_GOV"		     = "SharePoint Plan 2G"
        "EXCHANGE_S_ENTERPRISE_GOV"		     = "Exchange Plan 2G"
        "EXCHANGE_S_ARCHIVE_ADDON_GOV"	     = "Exchange Online Archiving"
        "EXCHANGE_S_DESKLESS"			     = "Exchange Online Kiosk"
        "SHAREPOINTDESKLESS"				 = "SharePoint Online Kiosk"
        "SHAREPOINTWAC"					     = "Office Online"
        "YAMMER_ENTERPRISE"				     = "Yammer for the Starship Enterprise"
        "EXCHANGE_L_STANDARD"			     = "Exchange Online (Plan 1)"
        "MCOLITE"						     = "Lync Online (Plan 1)"
        "SHAREPOINTLITE"					 = "SharePoint Online (Plan 1)"
        "OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ" = "Office ProPlus"
        "EXCHANGE_S_STANDARD_MIDMARKET"	     = "Exchange Online (Plan 1)"
        "MCOSTANDARD_MIDMARKET"			     = "Lync Online (Plan 1)"
        "SHAREPOINTENTERPRISE_MIDMARKET"	 = "SharePoint Online (Plan 1)"
        "OFFICESUBSCRIPTION"				 = "Office ProPlus"
        "YAMMER_MIDSIZE"					 = "Yammer"
        "DYN365_ENTERPRISE_PLAN1"		     = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
        "ENTERPRISEPREMIUM_NOPSTNCONF"	     = "Enterprise E5 (without Audio Conferencing)"
        "ENTERPRISEPREMIUM"				     = "Enterprise E5 (with Audio Conferencing)"
        "MCOSTANDARD"					     = "Skype for Business Online Standalone Plan 2"
        "PROJECT_MADEIRA_PREVIEW_IW_SKU"	 = "Dynamics 365 for Financials for IWs"
        "STANDARDWOFFPACK_IW_STUDENT"	     = "Office 365 Education for Students"
        "STANDARDWOFFPACK_IW_FACULTY"	     = "Office 365 Education for Faculty"
        "EOP_ENTERPRISE_FACULTY"			 = "Exchange Online Protection for Faculty"
        "EXCHANGESTANDARD_STUDENT"		     = "Exchange Online (Plan 1) for Students"
        "OFFICESUBSCRIPTION_STUDENT"		 = "Office ProPlus Student Benefit"
        "STANDARDWOFFPACK_FACULTY"		     = "Office 365 Education E1 for Faculty"
        "STANDARDWOFFPACK_STUDENT"		     = "Microsoft Office 365 (Plan A2) for Students"
        "DYN365_FINANCIALS_BUSINESS_SKU"	 = "Dynamics 365 for Financials Business Edition"
        "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
        "FLOW_FREE"						     = "Microsoft Flow Free"
        "POWER_BI_PRO"					     = "Power BI Pro"
        "O365_BUSINESS"					     = "Office 365 Business"
        "DYN365_ENTERPRISE_SALES"		     = "Dynamics Office 365 Enterprise Sales"
        "RIGHTSMANAGEMENT"				     = "Rights Management"
        "PROJECTPROFESSIONAL"			     = "Project Professional"
        "VISIOONLINE_PLAN1"				     = "Visio Online Plan 1"
        "EXCHANGEENTERPRISE"				 = "Exchange Online Plan 2"
        "DYN365_ENTERPRISE_P1_IW"		     = "Dynamics 365 P1 Trial for Information Workers"
        "DYN365_ENTERPRISE_TEAM_MEMBERS"	 = "Dynamics 365 For Team Members Enterprise Edition"
        "CRMSTANDARD"					     = "Microsoft Dynamics CRM Online Professional"
        "EXCHANGEARCHIVE_ADDON"			     = "Exchange Online Archiving For Exchange Online"
        "EXCHANGEDESKLESS"				     = "Exchange Online Kiosk"
        "SPZA_IW"						     = "App Connect"
        "WINDOWS_STORE"					     = "Windows Store for Business"
        "MCOEV"							     = "Microsoft Phone System"
        "VIDEO_INTEROP"					     = "Polycom Skype Meeting Video Interop for Skype for Business"
        "SPE_E5"							 = "Microsoft 365 E5"
        "SPE_E3"							 = "Microsoft 365 E3"
        "SPE_F1"                             = "Office 365 F1"
        "ATA"							     = "Advanced Threat Analytics"
        "MCOPSTN2"						     = "Domestic and International Calling Plan"
        "FLOW_P1"						     = "Microsoft Flow Plan 1"
        "FLOW_P2"						     = "Microsoft Flow Plan 2"
        "MS_TEAMS_IW"                        = "Microsoft Teams Trial"
    }

    Foreach ($User in $UPNs) {
        if($showdebug){write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Getting all licenses for $($User)..."  ; } ; 

        $Exit = 0 ;
        Do {
            Try {
                #$Licenses = ((Get-MsolUser -UserPrincipalName $User.UserPrincipalName).Licenses).AccountSkuID
                $MsolU=Get-MsolUser -UserPrincipalName $User ; 
                $Licenses = $MsolU.Licenses.AccountSkuID
                #$Licenses = ((Get-MsolUser -UserPrincipalName $User).Licenses).AccountSkuID
                $Exit = $Retries ;
            } Catch {
                Start-Sleep -Seconds $RetrySleep ;
                $Exit ++ ;
                Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                Write-Verbose "Try #: $Exit" ;
                If ($Exit -eq $Retries) {Write-Warning "Unable to exec cmd!"} ;
            }  ;
        } Until ($Exit -eq $Retries) ; 

        
        # 11:31 AM 1/9/2019 if yo u want to aggreg licesnse, you need the aggreg outside of the loop!
        $AggregLics = $null
        $AggregLics=@() ; 
        If (($Licenses).Count -gt 1){
            Foreach ($License in $Licenses){
                if($showdebug){Write-Host "Finding $License in the Hash Table..." -ForegroundColor White}
                $LicenseItem = $License -split ":" | Select-Object -Last 1
                $TextLic = $Sku.Item("$LicenseItem")
                If (!($TextLic)) {
                    $smsg= "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!" 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } ; #Error|Warn 

                    $LicenseFallBackName = $License.AccountSkuId

                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName =$MsolU.DisplayName ; 
                        UserPrincipalName = $MsolU.Userprincipalname
                        LicAccountSkuID = $License
                        LicenseFriendlyName = $LicenseFallBackName
                    };
                    $AggregLics += $LicSummary ;

                } Else {
                    $LicSummary = New-Object PSObject -Property @{
                        DisplayName = $MsolU.DisplayName
                        UserPrincipalName = $MsolU.Userprincipalname
                        LicAccountSkuID = $License
                        LicenseFriendlyName = $TextLic
                    };
                    $AggregLics += $LicSummary ;
                } # if-E
            } # loop-E
        }Else{
            if($showdebug){Write-Host "Finding $Licenses in the Hash Table..." -ForegroundColor White} ; 
            $Exit = 0 ;
            Do {
                Try {
                    #$LicenseItem = ((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID -split ":" | Select-Object -Last 1
                    $LicenseID=((Get-MsolUser -UserPrincipalName $MsolU.Userprincipalname).Licenses).AccountSkuID 
                    $LicenseItem = $LicenseID -split ":" | Select-Object -Last 1
                    $Exit = $Retries ;
                } Catch {
                    Start-Sleep -Seconds $RetrySleep ;
                    $Exit ++ ;
                    Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                    Write-Verbose "Try #: $Exit" ;
                    If ($Exit -eq $Retries) {Write-Warning "Unable to exec cmd!"} ;
                }  ;
            } Until ($Exit -eq $Retries) ; 
            $TextLic = $Sku.Item("$LicenseItem")
            If (!($TextLic)) {
                $smsg= "Error: The Hash Table has no match for $LicenseItem for $($MsolU.DisplayName)!"
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error } ; #Error|Warn 
                $LicenseFallBackName = $License.AccountSkuId
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName = $MsolU.DisplayName
                    UserPrincipalName = $MsolU.Userprincipalname
                    LicAccountSkuID = $LicenseID
                    LicenseFriendlyName = $LicenseFallBackName
                };
                $AggregLics += $LicSummary ;
            } Else {
                $LicSummary = New-Object PSObject -Property @{
                    DisplayName = $MsolU.DisplayName
                    UserPrincipalName = $MsolU.Userprincipalname
                    LicAccountSkuID = $LicenseID
                    LicenseFriendlyName = "$TextLic"
                };
                $AggregLics += $LicSummary ;
            }
        } # if-E
    } # loop-E

    #$NewObject02
    <#
    #$DirSyncTimeBefore = (Get-MsolCompanyInformation).LastDirSyncTime ;
    $DirSyncTimeBefore = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
    
    $oReturn= New-Object PSObject -Property @{
      TimeGMT = $DirSyncTimeBefore  ; 
      TimeLocal = $DirSyncTimeBefore.ToLocalTime() ; 
    }; 
    #>
    #$NewObject02 | write-output ; 
    $AggregLics | write-output ; # 11:33 AM 1/9/2019 export the aggreg, NewObject02 was never more than a single lic
} ; #*------^ END Function get-MsolUserLicenseDetails ^------