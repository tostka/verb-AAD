

  <#
  .SYNOPSIS
  verb-AAD - Azure AD-related generic functions
  .NOTES
  Version     : 0.0.0.1
  Author      : Todd Kadrie
  Website     :	https://www.toddomation.com
  Twitter     :	@tostka
  CreatedDate : 12/10/2019
  FileName    :
  License     :
  Copyright   :
  Github      : https://github.com/tostka
  AddedCredit : REFERENCE
  AddedWebsite:	REFERENCEURL
  AddedTwitter:	@HANDLE / http://twitter.com/HANDLE
  REVISIONS
  * 12/10/2019 - 0.0.0.1
  .DESCRIPTION
  verb-AAD - Azure AD-related generic functions
  .PARAMETER  PARAMNAME
  PARAMDESC
  .PARAMETER  Mbx
  Mailbox identifier [samaccountname,name,emailaddr,alias]
  .PARAMETER  Computer
  Computer Name [-ComputerName server]
  .PARAMETER  ServerFqdn
  Server Fqdn (24-25char) [-serverFqdn lynms650.global.ad.toro.com)] 
  .PARAMETER  Server
  Server NBname (8-9chars) [-server lynms650)]
  .PARAMETER  SiteName
  Specify Site to analyze [-SiteName (USEA|GBMK|AUSYD]
  .PARAMETER  Ticket
  Ticket # [-Ticket nnnnn]
  .PARAMETER  Path
  Path [-path c:\path-to\]
  .PARAMETER  File
  File [-file c:\path-to\file.ext]
  .PARAMETER  String
  2-30 char string [-string 'word']
  .PARAMETER  Credential
  Credential (PSCredential obj) [-credential ]
  .PARAMETER  Logonly
  Run a Test no-change pass, and log results [-Logonly]
  .PARAMETER  FORCEALLPINS
  Reset All PINs (boolean) [-FORCEALLPINS:True]
  .PARAMETER Whatif
  Parameter to run a Test no-change pass, and log results [-Whatif switch]
  .PARAMETER ShowProgress
  Parameter to display progress meter [-ShowProgress switch]
  .PARAMETER ShowDebug
  Parameter to display Debugging messages [-ShowDebug switch]
  .INPUTS
  None
  .OUTPUTS
  None
  .EXAMPLE
  .EXAMPLE
  .LINK
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
