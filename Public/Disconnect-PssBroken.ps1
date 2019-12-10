if(!(test-path function:\Disconnect-PssBroken)) { 
    #*------v Function Disconnect-PssBroken v------
    Function Disconnect-PssBroken {
        <# 
        .SYNOPSIS
        Disconnect-PssBroken - Remove all local broken PSSessions
        .NOTES
        Author: Todd Kadrie
        Website:	http://tinstoys.blogspot.com
        Twitter:	http://twitter.com/tostka
        REVISIONS   :
        * 12:56 PM 11/7/2f018 fix typo $s.state.value, switched tests to the strings, over values (not sure worked at all)
        * 1:50 PM 12/8/2016 initial version
        .DESCRIPTION
        Disconnect-PssBroken - Remove all local broken PSSessions
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. Returns no objects or output.
        .EXAMPLE
        Disconnect-PssBroken ; 
        .LINK
        #>
        Get-PsSession |?{$_.State -ne 'Opened' -or $_.Availability -ne 'Available'} | Remove-PSSession -Verbose ;
    } ; #*------^ END Function Disconnect-PssBroken ^------
} ; 
# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+9f1KJbBrGSJwJnHUj/5H2h3
# QOCgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSTZCzM
# L841hdRyId36mYYMqAysvjANBgkqhkiG9w0BAQEFAASBgBWBoH5EFrvjaVqtoXDX
# JGwXu2Cx+SfWRu+DKQLLJinPT+DFR5JxyVqsloboLG4RRboUAL7dkOVhG60r8YSj
# m8Hst2LrjmJdtmQTFtfA6SrcBuX5SfGBztzyqX6wUXo1yk0J8y8NwD2Ian6Cwk5v
# KlW4ZXniuu/QT8BnTrofUJfd
# SIG # End signature block
