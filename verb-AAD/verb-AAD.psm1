

  <#
  .SYNOPSIS
  verb-AAD - Azure AD-related generic functions
  .NOTES
  Version     : 0.0.2.1
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
  * 12/10/2019 - 0.0.2.1
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
  import-module verb-AAD
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

# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4feJNcsQ6O6QTfuyl0INcdJ6
# koegggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNDEyMjkxNzA3MzNaFw0zOTEyMzEyMzU5NTlaMBUxEzARBgNVBAMTClRvZGRT
# ZWxmSUkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqRVt7uNweTkZZ+16QG
# a+NnFYNRPPa8Bnm071ohGe27jNWKPVUbDfd0OY2sqCBQCEFVb5pqcIECRRnlhN5H
# +EEJmm2x9AU0uS7IHxHeUo8fkW4vm49adkat5gAoOZOwbuNntBOAJy9LCyNs4F1I
# KKphP3TyDwe8XqsEVwB2m9FPAgMBAAGjdjB0MBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MF0GA1UdAQRWMFSAEL95r+Rh65kgqZl+tgchMuKhLjAsMSowKAYDVQQDEyFQb3dl
# clNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEGwiXbeZNci7Rxiz/r43gVsw
# CQYFKw4DAh0FAAOBgQB6ECSnXHUs7/bCr6Z556K6IDJNWsccjcV89fHA/zKMX0w0
# 6NefCtxas/QHUA9mS87HRHLzKjFqweA3BnQ5lr5mPDlho8U90Nvtpj58G9I5SPUg
# CspNr5jEHOL5EdJFBIv3zI2jQ8TPbFGC0Cz72+4oYzSxWpftNX41MmEsZkMaADGC
# AWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBMb2NhbCBDZXJ0aWZp
# Y2F0ZSBSb290AhBaydK0VS5IhU1Hy6E1KUTpMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQjGEwC
# KHcGIqve0D7dpxhnN6PnLTANBgkqhkiG9w0BAQEFAASBgJBAR+jw6xD1uqLg8kMW
# 1L2bRoKpp8/FmhhYJAQQyzLtkPfpYFdssRbRaURkoVmDflLDqyi3u6p/2hgg8Of7
# CDPOBGGQXxRvrxYtW+PrSeiLA+ZROArq9ypTVXpFKf38w75IUzbaEaVrOHXcuuQg
# 712pWEh7i3C6kx9W5wuKvb8R
# SIG # End signature block
