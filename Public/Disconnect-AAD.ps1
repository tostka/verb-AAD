#*------v Disconnect-AAD.ps1 v------
Function Disconnect-AAD {
    <#
    .SYNOPSIS
    Disconnect-AAD - Disconnect current authenticated session to Azure Active Directory tenant via AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does (wraps new underlying disconnect-azuread())
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-07-27
    FileName    : Disconnect-AAD.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,AzureAD
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS   :
    * 10:58 AM 3/16/2021 updated cbh & new try-catch to accomodate non-existing 
    * 2:44 PM 3/2/2021 added console TenOrg color support
    * 3:03 PM 8/8/2020 rewrote to leverage AzureSession checks, without need to qry Get-AzureADTenantDetail (trying to avoid sporadic VEN AAD 'Forbidden' errors)
    * 3:24 PM 8/6/2020 added CATCH block for AzureAD perms errors seeing on one tenant, also shifted only the AAD cmdlets into TRY, to isolate errs
    * 5:17 PM 8/5/2020 strong-typed Credential;added verbose outputs, try/catch, and catch targeting unauthenticated status, added missing Disconnect-AzureAD (doh)
    * 3:15 PM 7/27/2020 init vers
    .DESCRIPTION
    Disconnect-AAD - Disconnect authenticated session to AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Disconnect-AAD
    .EXAMPLE
    Disconnect-AAD -Credential $cred
    .LINK
    https://docs.microsoft.com/en-us/powershell/module/azuread/disconnect-azuread?view=azureadps-2.0
    #>
    [CmdletBinding()] 
    [Alias('daad')]
    Param() ;
    BEGIN {$verbose = ($VerbosePreference -eq "Continue") } ;
    PROCESS {
        write-verbose "(Check for/install AzureAD module)" ; 
        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        write-verbose "Import-Module -Name AzureAD -MinimumVersion '2.0.0.131'" ; 
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        #try { Get-AzureADTenantDetail | out-null  } # authenticated to "a" tenant
        write-verbose "get-command disconnect-AzureAD" ; 
        if(get-command disconnect-AzureAD){
            $sTitleBarTag="AAD" ;
            $error.clear() ;
            TRY {
                <# old code
                write-verbose "Checking for existing AzureADTenantDetail (AAD connection)" ; 
                $AADTenDtl = Get-AzureADTenantDetail ; 
                if($AADTenDtl){
                    write-host "(disconnect-AzureAD from:$($AADTenDtl.displayname))" ;
                    disconnect-AzureAD ; 
                    write-verbose "Remove-PSTitleBar -Tag $($sTitleBarTag)" ; 
                    Remove-PSTitleBar -Tag $sTitleBarTag ; 
                } else { write-host "(No existing AAD tenant connection)" } ;
                #>
                try{
                    Disconnect-AzureAD -EA SilentlyContinue -ErrorVariable AADError ;
                    Write-Host -ForegroundColor green ("Azure Active Directory - Disconnected") ;
                }
                catch  {
                    $ErrTrpd = $Error[0] ; 
                    if($AADError.Exception.Message -eq "Object reference not set to an instance of an object."){
                        Write-Host -foregroundcolor yellow "Azure AD - No active Azure Active Directory Connections" ;
                    }else{
                        Write-Host -foregroundcolor "Azure Active Directory - $($ErrTrpd.Exception.Message)" ;
                        $error.clear() ;
                        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($ErrTrpd.Exception.ItemName). `nError Message: $($ErrTrpd.Exception.Message)`nError Details: $($ErrTrpd)" ;
                        $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($Error[0].Exception.GetType().FullName)]{" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ; 
        
                } ;
                # shift to AzureSession token checks
                $token = get-AADToken -verbose:$($verbose) ;
                if( ($null -eq $token) -OR ($token.count -eq 0)){
                    # not connected/authenticated
                    #Connect-AzureAD -TenantId $TenantID -Credential $Credential ;
                    #throw "" # gen an error to dump into generic CATCH block
                } else {
                    write-verbose "Connected to Tenant:`n$((($token.AccessToken) | fl TenantId,UserId,LoginType|out-string).trim())" ;
                    $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).TenantID  -verbose:$($verbose) ; 
                    write-host "(disconnect-AzureAD from:$($TokenTag))" ;
                    disconnect-AzureAD ; 
                    write-verbose "Remove-PSTitleBar -Tag $($sTitleBarTag)" ; 
                    Remove-PSTitleBar -Tag $sTitleBarTag ; 
                    #[console]::ResetColor()  # reset console colorscheme
                } ; 
            
            } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]{
                write-host "(No existing AAD tenant connection)"
            } CATCH [Microsoft.Open.AzureAD16.Client.ApiException] {
                $ErrTrpd = $_ ; 
                Write-Warning "$((get-date).ToString('HH:mm:ss')):AzureAD Tenant Permissions Error" ; 
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                throw $ErrTrpd ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } CATCH {
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                throw $_ ; #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 
        } else {write-host "(The AzureAD module isn't currently loaded)" } ; 
    } ; 
    END {} ;
}

#*------^ Disconnect-AAD.ps1 ^------