# verb-AAD.psm1


  <#
  .SYNOPSIS
  verb-AAD - Azure AD-related generic functions
  .NOTES
  Version     : 1.0.0
  Author      : Todd Kadrie
  Website     :	https://www.toddomation.com
  Twitter     :	@tostka
  CreatedDate : 12/11/2019
  FileName    : verb-AAD.psm1
  License     : MIT
  Copyright   : (c) 12/11/2019 Todd Kadrie
  Github      : https://github.com/tostka
  AddedCredit : REFERENCE
  AddedWebsite:	REFERENCEURL
  AddedTwitter:	@HANDLE / http://twitter.com/HANDLE
  REVISIONS
  * 12/11/2019 - 0.0.0.1
  * 10:55 AM 12/6/2019 Connect-MSOL & Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
* 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
* 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA, splits specified credential and picks up on global o365_TAG_MFA/o365_TAG_OPDomain varis matching the credential domain. also added Add-PSTitleBar 'XXX' for msol & aad ;
* 2:18 PM 5/14/2019 added Build-AADSignErrorsHash 
* 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD ; ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for AzureAD module
* 11:56 AM 12/7/2018 init version, added Alias connect-msol -> connect-aad
  .DESCRIPTION
  verb-AAD - Azure AD-related generic functions
  .INPUTS
  None
  .OUTPUTS
  None
  .EXAMPLE
  .EXAMPLE
  .LINK
  https://github.com/tostka/verb-AAD
  #>



#Get public and private function definition files.
$functionFolders = @('Public', 'Internal', 'Classes') ;
ForEach ($folder in $functionFolders) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder ;
    If (Test-Path -Path $folderPath) {
        Write-Verbose -Message "Importing from $folder" ;
        $functions = Get-ChildItem -Path $folderPath -Filter '*.ps1'  ;
        ForEach ($function in $functions) {
            Write-Verbose -Message "  Importing $($function.BaseName)" ;
            . $($function.FullName) ;
        } ;
    } ;
} ;
$publicFunctions = (Get-ChildItem -Path "$PSScriptRoot\Public" -Filter '*.ps1').BaseName ;
Export-ModuleMember -Function $publicFunctions ;
