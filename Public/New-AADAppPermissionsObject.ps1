# New-AADAppPermissionsObject_func.ps1

#*----------v Function New-AADAppPermissionsObject() v----------
function New-AADAppPermissionsObject {
    <#
    .SYNOPSIS
    New-AADAppPermissionsObject.ps1 - Create GrantObject for AzureADApplication objects, from 'SecurityPrincipalName;[comma-delimitedpermissions]' input array.
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : New-AADAppPermissionsObject.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,AzureAD,Authentication,Certificate,CertificateAuthentication
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 3:45 PM 6/23/2023 pulled req: verb-AAD 
    * 2:54 PM 6/13/2022 debugged, functional
    .DESCRIPTION
    New-AADAppPermissionsObject.ps1 - Create GrantObject for AzureADApplication objects, from 'SecurityPrincipalName;[comma-delimitedpermissions]' input array.
    -Permisisons parameter is an array of permissions summaries in following format, per target SecurityPrincipal:
    [SecurityPrincipalName1];[permission1],[permission2]
    [SecurityPrincipalName2];[permission1],[permission2]
    for Expl:
    # create an array of permissions
    [array]$procPerms = "Microsoft Graph;AuditLog.Read.All,Directory.ReadWrite.All,Group.Create,Group.ReadWrite.All,GroupMember.ReadWrite.All" ; 
    $procPerms += "Office 365 Exchange Online;Exchange.ManageAsApp,Mailbox.Migration,MailboxSettings.ReadWrite,Organization.Read.All,User.Read.All" ;
    Above has two specs in the array:
    - First grants against 'Microsoft Graph' svcPrincipal, the AuditLog.Read.All, Directory.ReadWrite.All, Group.Create, Group.ReadWrite.All, & GroupMember.ReadWrite.All permissions
    - Second grants against 'Office 365 Exchange Online' svcPrincipal, the Exchange.ManageAsApp, Mailbox.Migration, MailboxSettings.ReadWrite, Organization.Read.All & User.Read.All permissions
    
    A "Microsoft.Open.AzureAD.Model.RequiredResourceAccess" object is built:
    - with the svcPrincipal.AppID set to ResourceAppId
    - and a series of "Microsoft.Open.AzureAD.Model.ResourceAccess" objects added per specified role.
    The resulting array of RequiredResourceAccess objects is returned to the pipeline. ready for use as the RequiredResourceAccess parameter of a New-AzureADApplication pass.
    
    .PARAMETER Permissions
    Array of permission grants defined as 1)SecurityPrincipal identifier, semicolon-delimited with permission tags (which are each comma-delimited between themselves)[-Permissions 'Microsoft Graph;AuditLog.Read.All,Directory.ReadWrite.All,Group.Create,Group.ReadWrite.All,GroupMember.ReadWrite.All']
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    Returns System.Object[] System.Array with constructed permissions grant object
    .EXAMPLE
    PS> [array]$procPerms = "Microsoft Graph;AuditLog.Read.All,Directory.ReadWrite.All,Group.Create,Group.ReadWrite.All,GroupMember.ReadWrite.All" ; 
    PS> $procPerms += "Office 365 Exchange ;  Online;Exchange.ManageAsApp,Mailbox.Migration,MailboxSettings.ReadWrite,Organization.Read.All,User.Read.All" ;
    PS> $bRet = New-AADAppPermissionsObject -Permissions $procPerms -verbose ; 
    if($bRet.GrantArray){
    PS> $pltNAADApp=[ordered]@{
    PS>     DisplayName = $appName ;
    PS>     IdentifierUris = $adalUrlIdentifier ;
    PS>     ReplyUrls = $appReplyUrl ;
    PS>     RequiredResourceAccess = $GrantArray ;
    PS>     ErrorAction = 'STOP' ; 
    PS> } ;
    PS> $smsg = "`n$((get-date).ToString('HH:mm:ss')):New-AzureADApplication w`n$(($pltNAADApp|out-string).trim())"  ;
    PS> if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    PS> else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS> $application = New-AzureADApplication @pltNAADApp ;
    PS> } else { 
    PS>     throw "New-AADAppPermissionsObject failed to return populated GrantArray!" ; 
    PS> } ; 
    PS> Run permissions build on MS Graph & EXO, verbose, then use the permission object with splatted New-AzureADApplication cmdlet.
    .LINK
    https://bitbucket.org/tostka/powershell/
    #>
    #Requires -Modules AzureAD, PKI, verb-IO, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Array of permission grants defined as 1)SecurityPrincipal identifier, semicolon-delimited with permission tags (which are each comma-delimited between themselves)[-Permissions 'Microsoft Graph;AuditLog.Read.All,Directory.ReadWrite.All,Group.Create,Group.ReadWrite.All,GroupMember.ReadWrite.All']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string[]]$Permissions,
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
        [switch] $whatIf=$true
    ) ;
    #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
    # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
    write-verbose -verbose:$verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
    $Verbose = ($VerbosePreference -eq 'Continue') ; 
    
    $objReturn = @{
        GrantArray = $null ; 
        Valid = $false ; 
    } ; 
    
     $smsg = "---Build Permissions Object:" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    # Add AuditLog.Read.All access
    $pltGAADSP=[ordered]@{
        All=$true ;
        erroraction = 'STOP' ;
    } ;
    $smsg = "----4a)Get-AzureADServicePrincipal w`n$(($pltGAADSP|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
 
    $allSvcPrinc = Get-AzureADServicePrincipal @pltGAADSP ; 

    # try to build an array of delimted strings set to loop out and build the objects
    # syntax: "[SecPrin filterable name];[perm1],[perm2]..."
    # Secprin & perms array are semi-colon delimited, perms are comma-delimited
    #[array]$procPerms = "Microsoft Graph;AuditLog.Read.All,Directory.ReadWrite.All,Group.Create,Group.ReadWrite.All,GroupMember.ReadWrite.All" ; 
    #$procPerms += "Office 365 Exchange Online;Exchange.ManageAsApp,Mailbox.Migration,MailboxSettings.ReadWrite,Organization.Read.All,User.Read.All" ;
    $smsg = "----4b):loop-resolving following SecPrins & per-SP perms:`n$(($procPerms|out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $GrantArray = @() ; 
    foreach($procPerm in $procPerms){
        $SecPrinName,$roleArray = $procPerm.split(';') ; # split sp from roles
        $rolearray = $roleArray.split(',') ; # split roles into an array
        $smsg = "`n`n===`n`$SecPrinName:$($SecPrinName)" ;
        $smsg += "`n`$rolearray:$($rolearray)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $resAccessArray = @() ; 
        $smsg = "Resolving SecPrin:$($SecPrinName)..." ;
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        if($svcPrincipal = $allSvcPrinc | ? { $_.DisplayName -eq $SecPrinName } ){
            $smsg = "Resolved $($SecPrinnAME)=>`n$(($svcPrincipal|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            $oRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess" ;
            $oRequiredResourceAccess.ResourceAppId = $svcPrincipal.AppId ; 
            foreach ($role in $roleArray){
                $smsg = "`n`nResolving SP:$($svcPrincipal.displayname):$($role)..." ;
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                if($appRole = $svcPrincipal.AppRoles | ? { $_.Value -eq $role }){
                     $smsg = "Resolved $($svcPrincipal.displayname):$($role)=>`n$(($appRole|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $appPermission = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "$($appRole.Id)", "Role" ;
                    $resAccessArray += $appPermission ;
                } else { 
                    $smsg = "FAILED TO RESOLVE AppRole $($role) FROM SvcPrinicpal available AppRoles!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    break ; 
                } ; 
            } ;  
            # $oRequiredResourceAccess.ResourceAccess = $appPermission, $appPermission2, $appPermission3, $appPermission4, $appPermission5, $appPermission6 ;
            if($resAccessArray){
                $oRequiredResourceAccess.ResourceAccess = $resAccessArray ; 
                $GrantArray += $oRequiredResourceAccess ; 
                $smsg = "`n$($SecPrinName) SecPrin AccessArray:`n$(($oRequiredResourceAccess|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } else { 
                $smsg = "`$resAccessArray IS UNPOPULATED!" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                break ; 
            } ; 
        } else { 
            $smsg = "FAILED TO RESOLVE SECPRIN $($SecPrinName) FROM Get-AzureADServicePrincipal FULL COLLECTION!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            break ; 
        } ; 
    } ;

    $objReturn.GrantArray = $GrantArray ; 
    
    if($objReturn.GrantArray ){ 
        $smsg = "Populated GrantArray: Setting Valid:`$true" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $objReturn.Valid = $true ; 
    } else { 
        $smsg = "POPULATED GRANTARRAY: Setting Valid:`$FALSE" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        $objReturn.Valid = $false 
    } ; 
    
    $smsg = "(Returning object to pipeline: w`n$(($objReturn|out-string).trim()))" ; 
    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    New-Object -TypeName PSObject -Property $objReturn | write-output ; 
} ;  
#*------^ END Function New-AADAppPermissionsObject ^------