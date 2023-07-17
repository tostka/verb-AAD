#*------v Get-DsRegStatus.ps1 v------
function Get-DsRegStatus {
    <#
    .SYNOPSIS
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject (returns device domain-join status in re:AzureAD (AAD), Enterprise (onprem DRS), Domain (AD)). 
    .NOTES
    Version     : 0.1.17
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / ttps://github.com/tostka/verb-aad
    CreatedDate : 2021-06-23
    FileName    : Get-DsRegStatus
    License     : (none asserted)
    Copyright   : (c) 2019 Thomas Kurth. All rights reserved.
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Thomas Kurth
    AddedWebsite: https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions/Get-DsRegStatus.ps1
    AddedTwitter: 
    REVISIONS
    * 9:15 AM 6/28/2021 updated CBH
    * 9:54 AM 6/23/2021 added to verb-aad
    * 12:21 PM 8/8/2020 init; added CBH
    .DESCRIPTION
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject (returns device domain-join status in re:AzureAD (AAD), Enterprise (onprem DRS), Domain (AD)). 
    
    Returns the output of dsregcmd /status as a PSObject. All returned values are accessible by their property name.
    Lifted from [PowerShell Gallery | Functions/Get-DsRegStatus.ps1 0.1.3 - www.powershellgallery.com/](https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions%5CGet-DsRegStatus.ps1)
    Alt to manual cmdline parsing:
    ```powershell
    $results = dsregcmd /status;
    $results|sls azureadjoined ; $results | sls domainjoined ; $results | sls workplacejoined ;
    ```
    Or remote exec: 
    ```powershell
     Invoke-Command -ComputerName MyComputerName -ScriptBlock {dsregcmd /status}
    ```
    .OUTPUTS
    List of the information in the token cache. 
    .Example
    PS> $stat = Get-DsRegStatus ;
    PS> $stat.devicestate

        AzureAdJoined              : YES
        EnterpriseJoined           : NO
        DeviceId                   : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        Thumbprint                 : D69DC6003BAF9xxxxxxxxxxxxxxE8D1BEB2796A9
        KeyContainerId             : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        KeyProvider                : Microsoft Software Key Storage Provider
        TpmProtected               : NO
        Idp                        : login.windows.net
        TenantId                   : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        TenantName                 : COMPANY
        AuthCodeUrl                : https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/authorize
        AccessTokenUrl             : https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/token
        MdmUrl                     : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
        MdmTouUrl                  : https://portal.manage.microsoft.com/TermsofUse.aspx
        MdmComplianceUrl           : https://portal.manage.microsoft.com/?portalAction=Compliance
        JoinSrvVersion             : 1.0
        JoinSrvUrl                 : https://enterpriseregistration.windows.net/EnrollmentServer/device/
        JoinSrvId                  : urn:ms-drs:enterpriseregistration.windows.net
        KeySrvVersion              : 1.0
        KeySrvUrl                  : https://enterpriseregistration.windows.net/EnrollmentServer/key/
        KeySrvId                   : urn:ms-drs:enterpriseregistration.windows.net
        WebAuthNSrvVersion         : 1.0
        WebAuthNSrvUrl             : https://enterpriseregistration.windows.net/webauthn/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/
        WebAuthNSrvId              : urn:ms-drs:enterpriseregistration.windows.net
        DeviceManagementSrvVersion : 1.0
        DeviceManagementSrvUrl     : https://enterpriseregistration.windows.net/manage/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/
        DeviceManagementSrvId      : urn:ms-drs:enterpriseregistration.windows.net
        DomainJoined               : YES
        DomainName                 : DOMAINNAME
        
    PS> $stat.userstate

        NgcSet              : NO
        WorkplaceJoined     : NO
        WamDefaultSet       : ERROR
        AzureAdPrt          : YES
        AzureAdPrtAuthority : https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        EnterprisePrt       : NO
    
    PS> $stat.NgcPrerequisiteCheck

        IsUserAzureAD      : YES
        PolicyEnabled      : NO
        PostLogonEnabled   : YES
        DeviceEligible     : YES
        SessionIsNotRemote : YES
        CertEnrollment     : none
        AadRecoveryNeeded  : NO
        PreReqResult       : WillNotProvision
        
    Displays a dsregcmd / status parsed as an object
    .LINK
    https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.17/Content/Functions%5CGet-DsRegStatus.ps1
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param() ;
    PROCESS {
        $dsregcmd = dsregcmd /status
        $o = New-Object -TypeName PSObject
        foreach($line in $dsregcmd){
            if($line -like "| *"){
                 if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
                      Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
                 }
                 $currentSection = $line.Replace("|","").Replace(" ","").Trim()
                 $so = New-Object -TypeName PSObject
            } elseif($line -match " *[A-z]+ : [A-z0-9\{\}]+ *"){
                 Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
            }
        }
        if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
            Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
        }
        return $o
    } ; 
}
#*------^ Get-DsRegStatus.ps1 ^------
