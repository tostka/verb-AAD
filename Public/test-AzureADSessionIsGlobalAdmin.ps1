# test-AzureADSessionIsGlobalAdmin_func.ps1

#*------v Function test-AzureADSessionIsGlobalAdmin v------
Function test-AzureADSessionIsGlobalAdmin{
    <#
    .SYNOPSIS
    test-AzureADSessionIsGlobalAdmin - Test that current AzureAD session account is a Global Admin
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-06-07
    FileName    : test-AzureADSessionIsGlobalAdmin
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-AAD
    Tags        : Powershell,AzureAD,Authentication,Test
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS
    * 9:56 AM 6/12/2024 add: Aliases: 'test-IsGlobalAdmin','test-isAADGlobalAdmin'; pasted in minimalist variant into Descr
    * 12:38 PM 6/7/2024 init
    .DESCRIPTION
    test-AzureADSessionIsGlobalAdmin - Test that current AzureAD session account is a Global Admin

    Minimalist includable version:

    ```powershell
    if(-not (gcm test-AzureADSessionIsGlobalAdmin -ea 0)){
        Function test-AzureADSessionIsGlobalAdmin{
            TRY{
                $UserPrincipalName = (Get-AzureADUser -ObjectId (Get-AzureADCurrentSessionInfo -EA STOP).Account.Id -EA STOP).UserPrincipalName ; 
                $GARole = Get-AzureADDirectoryRole -ea STOP| Where-Object {$_.displayName -eq  'Global Administrator'} ;
                if($CurrUserRole = Get-AzureADDirectoryRoleMember -ObjectId $GARole.ObjectId -EA STOP| Where-Object {$_.UserPrincipalName -eq $UserPrincipalName }){
                    $true | write-output ;
                } else {
                    $false | write-output ;
                }; 
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
        } ;
    } ; 
    if(-not (test-AzureADSessionIsGlobalAdmin)){
        throw "Current AzureADCurrentSessionInfo is *not* a Global Admin!`nAborting!" ; 
        break ; 
    } ; 
    ```

    .PARAMETER  UserPrincipalName
    Optional UserPrincipalName to be validated (defaults to current user context)[-CoUserPrincipalNamemputerName SomeAcct@domain.tld]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> if(test-AzureADSessionIsGlobalAdmin -UserPrincipalName SomeAcct@domain.tld){
    PS>     write-host "Doing GA level things" ; 
    PS> } else { write-warning "User is not currently GA!"};  ; 
    Demo simple test with explicit UPN
    .EXAMPLE
    PS> if(test-AzureADSessionIsGlobalAdmin){
    PS>     write-host "Doing GA level things" ; 
    PS> } else { write-warning "User is not currently GA!"};  ; 
    Demo simple test with implicit discovered UPN
    .LINK
    https://github.com/tostka/verb-AAD
    .LINK
    #>    
    ##Requires -Modules AzureAD, verb-AAD
    [CmdletBinding()]
    ## PSV3+ whatif support:[CmdletBinding(SupportsShouldProcess)]
    [Alias('test-IsGlobalAdmin','test-isAADGlobalAdmin')]
    PARAM(
        [Parameter(Position=0,Mandatory=$false,HelpMessage="Optional UserPrincipalName to be validated (defaults to current user context)[-UserPrincipalNamemputerName SomeAcct@domain.tld]")]
            #[ValidateNotNullOrEmpty()]
            [string]$UserPrincipalName,
        [Parameter(Position=0,Mandatory=$false,HelpMessage="Optional AzureAD RoleName to be validated (defaults to 'Global Administrator')[-RoleName 'Exchange Administrator']")]
            #[ValidateNotNullOrEmpty()]
            #[ValidateSet('Exchange Administrator','Privileged Authentication Administrator','Azure Information Protection Administrator','Attribute Assignment Administrator','Desktop Analytics Administrator','Cloud Application Administrator','Exchange Recipient Administrator','Search Administrator','Edge Administrator','Fabric Administrator','Application Administrator','Dynamics 365 Administrator','User Administrator','Authentication Administrator','Security Administrator','Cloud Device Administrator','Teams Communications Administrator','Global Reader','Directory Synchronization Accounts','Azure DevOps Administrator','License Administrator','Guest Inviter','Groups Administrator','Directory Readers','Teams Communications Support Engineer','Azure AD Joined Device Local Administrator','Intune Administrator','Compliance Administrator','Skype for Business Administrator','Billing Administrator','Conditional Access Administrator','Service Support Administrator','SharePoint Administrator','Helpdesk Administrator','Global Administrator','Security Reader','Teams Communications Support Specialist','Teams Administrator','Teams Devices Administrator','Directory Writers','Reports Reader','Office Apps Administrator','Power Platform Administrator','Message Center Reader')]
            [string]$RoleName= 'Global Administrator'
    );
    $RoleSet = 'Exchange Administrator','Privileged Authentication Administrator','Azure Information Protection Administrator','Attribute Assignment Administrator','Desktop Analytics Administrator','Cloud Application Administrator','Exchange Recipient Administrator','Search Administrator','Edge Administrator','Fabric Administrator','Application Administrator','Dynamics 365 Administrator','User Administrator','Authentication Administrator','Security Administrator','Cloud Device Administrator','Teams Communications Administrator','Global Reader','Directory Synchronization Accounts','Azure DevOps Administrator','License Administrator','Guest Inviter','Groups Administrator','Directory Readers','Teams Communications Support Engineer','Azure AD Joined Device Local Administrator','Intune Administrator','Compliance Administrator','Skype for Business Administrator','Billing Administrator','Conditional Access Administrator','Service Support Administrator','SharePoint Administrator','Helpdesk Administrator','Global Administrator','Security Reader','Teams Communications Support Specialist','Teams Administrator','Teams Devices Administrator','Directory Writers','Reports Reader','Office Apps Administrator','Power Platform Administrator','Message Center Reader' ; 
    TRY{
        if(-not ($RoleSet -contains $RoleName)){
            $smsg = "Specified -RoleName: $($RoleName) is not a permitted AzureADDirectoryRole DisplayName:" ; 
            $smsg += "`n$($RoleSet -join '|')" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            break ; 
        } ; 
        if (!(Get-Module AzureAD -ListAvailable)) { Write-Host -BackgroundColor Red "This script requires a recent version of the AzureAD PowerShell module. Download it here: https://www.powershellgallery.com/packages/AzureAD/"; return } ; 
        if(-not $UserPrincipalName){
            $smsg = "No -UserPrincipalName specified, defaulting to AzureADCurrentSessionInfo UPN" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            if($sessInfo = Get-AzureADCurrentSessionInfo -EA STOP){
                $currentUser = (Get-AzureADUser -ObjectId $sessInfo.Account.Id -EA STOP) ;
                $UserPrincipalName = $currentUser.UserPrincipalName ; 
            }else {
                $smsg = "Unable to Get-AzureADCurrentSessionInfo! " ; 
                $smsg += "`nuse Connect-AzureAD to connect first" ;  
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ; 
        } ; 
        $GARole = Get-AzureADDirectoryRole -ea STOP| Where-Object {$_.displayName -eq $RoleName} ;
        if($CurrUserRole = Get-AzureADDirectoryRoleMember -ObjectId $GARole.ObjectId -EA STOP| Where-Object {$_.UserPrincipalName -eq $UserPrincipalName }){
            $true | write-output ;
        } else {
            $false | write-output ;
        }; 
    } CATCH {
        $ErrTrapd=$Error[0] ;
        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } ; 
} ; 
#*------^ END Function test-AzureADSessionIsGlobalAdmin ^------

