#rebuild-module.ps1

<#
.SYNOPSIS
rebuild-module.ps1 - Rebuild verb-AAD & publish to localrepo
.NOTES
Version     : 1.0.0
Author      : Todd Kadrie
Website     : http://www.toddomation.com
Twitter     : @tostka / http://twitter.com/tostka
CreatedDate : 2020-03-17
FileName    : rebuild-module.ps1
License     : MIT License
Copyright   : (c) 2020 Todd Kadrie
Github      : https://github.com/tostka
Tags        : Powershell
REVISIONS
* 8:49 AM 3/17/2020 init
.DESCRIPTION
rebuild-module.ps1 - Rebuild verb-AAD & publish to localrepo
.PARAMETER Whatif
Parameter to run a Test no-change pass [-Whatif switch]
.INPUTS
None. Does not accepted piped input.
.OUTPUTS
None. Returns no objects or output
.EXAMPLE
.\rebuild-module.ps1 -whatif ; 
Rebuild pass with -whatif
.EXAMPLE
.\rebuild-module.ps1
Non-whatif rebuild
.LINK
https://github.com/tostka
#>
[CmdletBinding()]
PARAM(
    [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
    [switch] $whatIf
) ;
    $Verbose = ($VerbosePreference -eq 'Continue') ; 
    write-verbose -verbose:$verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ; 

.\process-NewModule.ps1 -ModuleName "verb-AAD" -ModDirPath "C:\sc\verb-AAD" -Repository "`$localPSRepo" -Merge -RunTest -showdebug -whatif:$($whatif) ;
# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6KEv9IHiNXgCvObb4rlHBL1S
# zvygggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTkI+hV
# ZTIqJPzX4d6Ufni45rvN9jANBgkqhkiG9w0BAQEFAASBgAButldZ2PtUHRtOmyPS
# out7cWCKoGSL8FiIXFG7NSHufOsofb5ZTWzqCLnLD3kMBptId8kavJIlViE2Wtig
# dhReq2JTwHWvCZGoF+6UPNr1Q3gv8RqtAhiTjXg8k8FUiV1sMiVF3P7O2yd47F2x
# LdjKKmPQTuStZBL/Ia75ch6W
# SIG # End signature block
