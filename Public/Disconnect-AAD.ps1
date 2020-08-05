#*------v Disconnect-AAD.ps1 v------
Function Disconnect-AAD {
    <#
    .SYNOPSIS
    Disconnect-AAD - Disconnect authenticated session to AzureAD Graph Module (AzureAD), as the MSOL & orig AAD2 didn't support, but *now* it does
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
    * 8:13 AM 8/5/2020 added verbose outputs, try/catch, and catch targeting unauthenticated status
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
        write-verbose "get-command disconnect-AzureAD" ; 
        if(get-command disconnect-AzureAD){
            $sTitleBarTag="AAD" ;
            $error.clear() ;
            TRY {
                write-verbose "Checking for existing AzureADTenantDetail (AAD connection)" ; 
                $AADTenDtl = Get-AzureADTenantDetail ; 
                if($AADTenDtl){
                    write-host "(disconnect-AzureAD from:$($AADTenDtl.displayname))" ;
                    disconnect-AzureAD ; 
                    write-verbose "Remove-PSTitleBar -Tag $($sTitleBarTag)" ; 
                    Remove-PSTitleBar -Tag $sTitleBarTag ; 
                } else { write-host "(No existing AAD tenant connection)" } ;
            } CATCH [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]{
                write-host "(No existing AAD tenant connection)"
            } CATCH {
                Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                Exit #STOP(debug)|EXIT(close)|Continue(move on in loop cycle) ; 
            } ; 
        } else {write-host "(The AzureAD module isn't currently loaded)" } ; 
    } ; 
    END {} ;
} ; 
#*------^ Disconnect-AAD.ps1 ^------