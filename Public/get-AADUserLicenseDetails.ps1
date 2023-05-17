# get-AADUserLicenseDetails

#*------v get-AADUserLicenseDetails.ps1 v------ 
Function get-AADUserLicenseDetails {
    <#
    .SYNOPSIS
    get-AADUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Based on work by :Brad Wyatt
    Website: https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    REVISIONS   :
    * 2:02 PM 3/23/2022 convert verb-aad:get-MsolUserLicensedetails -> get-AADUserLicenseDetails (Msonline -> AzureAD module rewrite)
    .DESCRIPTION
    get-AADUserLicenseDetails - Collec the equiv friendly name for a user's assigned o365 license (AzureAD)
    Based on the core lic hash & lookup code in Brad's "Get Friendly License Name for all Users in Office 365 Using PowerShell" script
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
    get-AADUserLicenseDetails -UPNs fname.lname@domain.com ;
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = get-AADUserLicenseDetails -UPNs $exombx.userprincipalname -showdebug:$($showdebug)
    Retrieve MSOL License details on specified UPN, with showdebug specified
    .LINK
    https://thelazyadministrator.com/2018/03/19/get-friendly-license-name-for-all-users-in-office-365-using-powershell/
    #>
    
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "An array of MSolUser objects")][ValidateNotNullOrEmpty()]
        [alias('Userprincipalname')]
        [string]$UPNs,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID,
        [Parameter(HelpMessage = "Debugging Flag [-showDebug]")][switch] $showDebug
    ) ;
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    $Verbose = ($VerbosePreference -eq 'Continue') ;
    
    $Retries = 4 ;
    $RetrySleep = 5 ;
    #Connect-AAD ;
    #Connect-Msol ;
    Connect-AAD -Credential:$Credential -verbose:$($verbose) -silent ;


    # [Product names and service plan identifiers for licensing in Azure Active Directory | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference)

    <# whatis an F1 lic: Office 365 F1 is designed to enable Firstline Workers to do their best work.
    Office 365 F1 provides easy-to-use tools and services to help these workers
    easily create, update, and manage schedules and tasks, communicate and work
    together, train and onboard, and quickly receive company news and announcements.
    #>

    # updating sort via text: gc c:\tmp\list.txt | sort ;
    $Sku = @{
        "AAD_BASIC"                          = "Azure Active Directory Basic"
        "AAD_PREMIUM"                        = "Azure Active Directory Premium"
        "ATA"                                = "Advanced Threat Analytics"
        "ATP_ENTERPRISE"                     = "Exchange Online Advanced Threat Protection"
        "BI_AZURE_P1"                        = "Power BI Reporting and Analytics"
        "CRMIUR"                             = "CMRIUR"
        "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
        "DESKLESSPACK"                       = "Office 365 (Plan K1)"
        "DESKLESSPACK_GOV"                   = "Microsoft Office 365 (Plan K1) for Government"
        "DESKLESSWOFFPACK"                   = "Office 365 (Plan K2)"
        "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
        "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
        "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
        "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
        "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
        "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
        "ECAL_SERVICES"                      = "ECAL"
        "EMS"                                = "Enterprise Mobility Suite"
        "ENTERPRISEPACK"                     = "Enterprise Plan E3"
        "ENTERPRISEPACK_B_PILOT"             = "Office 365 (Enterprise Preview)"
        "ENTERPRISEPACK_FACULTY"             = "Office 365 (Plan A3) for Faculty"
        "ENTERPRISEPACK_GOV"                 = "Microsoft Office 365 (Plan G3) for Government"
        "ENTERPRISEPACK_STUDENT"             = "Office 365 (Plan A3) for Students"
        "ENTERPRISEPACKLRG"                  = "Enterprise Plan E3"
        "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
        "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
        "ENTERPRISEWITHSCAL"                 = "Enterprise Plan E4"
        "ENTERPRISEWITHSCAL_FACULTY"         = "Office 365 (Plan A4) for Faculty"
        "ENTERPRISEWITHSCAL_GOV"             = "Microsoft Office 365 (Plan G4) for Government"
        "ENTERPRISEWITHSCAL_STUDENT"         = "Office 365 (Plan A4) for Students"
        "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
        "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
        "ESKLESSWOFFPACK_GOV"                = "Microsoft Office 365 (Plan K2) for Government"
        "EXCHANGE_L_STANDARD"                = "Exchange Online (Plan 1)"
        "EXCHANGE_S_ARCHIVE_ADDON_GOV"       = "Exchange Online Archiving"
        "EXCHANGE_S_DESKLESS"                = "Exchange Online Kiosk"
        "EXCHANGE_S_DESKLESS_GOV"            = "Exchange Kiosk"
        "EXCHANGE_S_ENTERPRISE_GOV"          = "Exchange Plan 2G"
        "EXCHANGE_S_ESSENTIALS"              = "Exchange Online Essentials   "
        "EXCHANGE_S_STANDARD_MIDMARKET"      = "Exchange Online (Plan 1)"
        "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
        "EXCHANGEDESKLESS"                   = "Exchange Online Kiosk"
        "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
        "EXCHANGEENTERPRISE_GOV"             = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
        "EXCHANGEESSENTIALS"                 = "Exchange Online Essentials"
        "EXCHANGESTANDARD"                   = "Office 365 Exchange Online Only"
        "EXCHANGESTANDARD_GOV"               = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
        "EXCHANGESTANDARD_STUDENT"           = "Exchange Online (Plan 1) for Students"
        "FLOW_FREE"                          = "Microsoft Flow Free"
        "FLOW_P1"                            = "Microsoft Flow Plan 1"
        "FLOW_P2"                            = "Microsoft Flow Plan 2"
        "INTUNE_A"                           = "Windows Intune Plan A"
        "LITEPACK"                           = "Office 365 (Plan P1)"
        "LITEPACK_P2"                        = "Office 365 Small Business Premium"
        "M365_F1"                            = "Microsoft 365 F1"
        "MCOEV"                              = "Microsoft Phone System"
        "MCOLITE"                            = "Lync Online (Plan 1)"
        "MCOMEETACPEA"                       = "Pay Per Minute Audio Conferencing"
        "MCOMEETADD"                         = "Audio Conferencing"
        "MCOMEETADV"                         = "PSTN conferencing"
        "MCOPSTN1"                           = "Domestic Calling Plan (3000 min US / 1200 min EU plans)"
        "MCOPSTN2"                           = "International Calling Plan"
        "MCOPSTN5"                           = "Domestic Calling Plan (120 min calling plan)"
        "MCOPSTN6"                           = "Domestic Calling Plan (240 min calling plan) Note: Limited Availability"
        "MCOPSTNC"                           = "Communications Credits"
        "MCOPSTNPP"                          = "Communications Credits"
        "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
        "MCOSTANDARD_GOV"                    = "Lync Plan 2G"
        "MCOSTANDARD_MIDMARKET"              = "Lync Online (Plan 1)"
        "MFA_PREMIUM"                        = "Azure Multi-Factor Authentication"
        "MIDSIZEPACK"                        = "Office 365 Midsize Business"
        "MS_TEAMS_IW"                        = "Microsoft Teams Trial"
        "O365_BUSINESS"                      = "Office 365 Business"
        "O365_BUSINESS_ESSENTIALS"           = "Office 365 Business Essentials"
        "O365_BUSINESS_PREMIUM"              = "Office 365 Business Premium"
        "OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ" = "Office ProPlus"
        "OFFICESUBSCRIPTION"                 = "Office ProPlus"
        "OFFICESUBSCRIPTION_GOV"             = "Office ProPlus"
        "OFFICESUBSCRIPTION_STUDENT"         = "Office ProPlus Student Benefit"
        "PLANNERSTANDALONE"                  = "Planner Standalone"
        "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
        "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
        "POWER_BI_PRO"                       = "Power BI Pro"
        "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
        "POWER_BI_STANDARD"                  = "Power-BI Standard"
        "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
        "PROJECTCLIENT"                      = "Project Professional"
        "PROJECTESSENTIALS"                  = "Project Lite"
        "PROJECTONLINE_PLAN_1"               = "Project Online"
        "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
        "ProjectPremium"                     = "Project Online Premium"
        "PROJECTPROFESSIONAL"                = "Project Professional"
        "PROJECTWORKMANAGEMENT"              = "Office 365 Planner Preview"
        "RIGHTSMANAGEMENT"                   = "Rights Management"
        "RIGHTSMANAGEMENT_ADHOC"             = "Windows Azure Rights Management"
        "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
        "RMS_S_ENTERPRISE_GOV"               = "Windows Azure Active Directory Rights Management"
        "SHAREPOINTDESKLESS"                 = "SharePoint Online Kiosk"
        "SHAREPOINTDESKLESS_GOV"             = "SharePoint Online Kiosk"
        "SHAREPOINTENTERPRISE"               = "Sharepoint Online (Plan 2)"
        "SHAREPOINTENTERPRISE_GOV"           = "SharePoint Plan 2G"
        "SHAREPOINTENTERPRISE_MIDMARKET"     = "SharePoint Online (Plan 1)"
        "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
        "SHAREPOINTSTANDARD"                 = "Sharepoint Online (Plan 1)"
        "SHAREPOINTSTORAGE"                  = "SharePoint storage"
        "SHAREPOINTWAC"                      = "Office Online"
        "SHAREPOINTWAC_GOV"                  = "Office Online for Government"
        "SMB_BUSINESS"                       = "Microsoft 365 Apps For Business"
        "SMB_BUSINESS_ESSENTIALS"            = "Microsoft 365 Business Basic       "
        "SMB_BUSINESS_PREMIUM"               = "Microsoft 365 Business Standard"
        "SPB"                                = "Microsoft 365 Business Premium"
        "SPE_E3"                             = "Microsoft 365 E3"
        "SPE_E5"                             = "Microsoft 365 E5"
        "SPE_F1"                             = "Office 365 F1"
        "SPZA_IW"                            = "App Connect"
        "STANDARD_B_PILOT"                   = "Office 365 (Small Business Preview)"
        "STANDARDPACK"                       = "Enterprise Plan E1"
        "STANDARDPACK_FACULTY"               = "Office 365 (Plan A1) for Faculty"
        "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
        "STANDARDPACK_STUDENT"               = "Office 365 (Plan A1) for Students"
        "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
        "STANDARDWOFFPACK_FACULTY"           = "Office 365 Education E1 for Faculty"
        "STANDARDWOFFPACK_GOV"               = "Microsoft Office 365 (Plan G2) for Government"
        "STANDARDWOFFPACK_IW_FACULTY"        = "Office 365 Education for Faculty"
        "STANDARDWOFFPACK_IW_STUDENT"        = "Office 365 Education for Students"
        "STANDARDWOFFPACK_STUDENT"           = "Microsoft Office 365 (Plan A2) for Students"
        "STANDARDWOFFPACKPACK_FACULTY"       = "Office 365 (Plan A2) for Faculty"
        "STANDARDWOFFPACKPACK_STUDENT"       = "Office 365 (Plan A2) for Students"
        "TEAMS_COMMERCIAL_TRIAL"             = "Teams Commercial Trial"
        "TEAMS_EXPLORATORY"                  = "Teams Exploratory"
        "VIDEO_INTEROP"                      = "Polycom Skype Meeting Video Interop for Skype for Business"
        "VISIOCLIENT"                        = "Visio Pro Online"
        "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
        "WINDOWS_STORE"                      = "Windows Store for Business"
        "YAMMER_ENTERPRISE"                  = "Yammer for the Starship Enterprise"
        "YAMMER_MIDSIZE"                     = "Yammer"
    }

    Foreach ($User in $UPNs) {
        if ($showdebug) { write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Getting all licenses for $($User)..."  ; } ;

        $Exit = 0 ;
        Do {
            Try {

                $pltGLPList=[ordered]@{ 
                    TenOrg= $TenOrg; 
                    IndexOnName =$true ;
                    verbose=$($VerbosePreference -eq "Continue") ; 
                    credential= $Credential ;
                    #$pltRXO.credential ; 
                    erroraction = 'STOP' ;
                } ;
                $smsg = "get-AADlicensePlanList w`n$(($pltGLPList|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $skus = get-AADlicensePlanList @pltGLPList ;
                
                #$MsolU = Get-MsolUser -UserPrincipalName $User ;

                $pltGAADU=[ordered]@{ ObjectID = $user ; ErrorAction = 'STOP' ; verbose = ($VerbosePreference -eq "Continue") ; } ; 
                $smsg = "Get-AzureADUser w`n$(($pltGAADU|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;                      
                $AADUser = Get-AzureADUser @pltGAADU ; 

                #$Licenses = $MsolU.Licenses.AccountSkuID
                # resolve sku to name (SkuPartNumber)
                $Licenses = $AADUser.AssignedLicenses.skuid ; 
                # come back as lic guids, not TENANT:guid
                # have to be converted to suit
                $Licenses = $Licenses |%{$skus[$_].SkuPartNumber ; } ; 

                $Exit = $Retries ;
            } Catch {
                Start-Sleep -Seconds $RetrySleep ;
                $Exit ++ ;
                Write-Verbose "Failed to exec cmd because: $($Error[0])" ;
                Write-Verbose "Try #: $Exit" ;
                If ($Exit -eq $Retries) { Write-Warning "Unable to exec cmd!" } ;
            }  ;
        } Until ($Exit -eq $Retries) ;

        $AggregLics = @() ;
        
        Foreach ($License in $Licenses) {
            if ($showdebug) { Write-Host "Finding $License in the Hash Table..." -ForegroundColor White }
            #$LicenseItem = $License -split ":" | Select-Object -Last 1
            #$TextLic = $Sku.Item("$LicenseItem")
            $TextLic = $sku[$License] ; 
            If (!($TextLic)) {
                $smsg = "Error: The Hash Table has no match for $($License) for $($AADUser.DisplayName)!"
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error }
                else { write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #$LicenseFallBackName = "$License.AccountSkuId:(($lplist.values | ?{$_.SkuPartNumber -eq 'exchangestandard'}).SkuPartNumber))"
                $LicenseFallBackName = $license ; 

                $LicSummary = New-Object PSObject -Property @{
                    DisplayName         = $AADUser.DisplayName ; 
                    UserPrincipalName   = $AADUser.Userprincipalname ; 
                    LicAccountSkuID     = $License; 
                    LicenseFriendlyName = $LicenseFallBackName
                };
                $AggregLics += $LicSummary ;

            } Else {
                $LicSummary = New-Object PSObject -Property @{
                    #DisplayName         = $MsolU.DisplayName
                    DisplayName         = $AADUser.DisplayName ; 
                    #UserPrincipalName   = $MsolU.Userprincipalname ;
                    UserPrincipalName   = $AADUser.Userprincipalname ; 
                    LicAccountSkuID     = $License ; 
                    LicenseFriendlyName = $TextLic ;
                };
                $AggregLics += $LicSummary ;
            } # if-E
        } # loop-E
        
    } # if-E


    $AggregLics | write-output ; # 11:33 AM 1/9/2019 export the aggreg, NewObject02 was never more than a single lic
}

#*------^ get-AADUserLicenseDetails.ps1 ^------