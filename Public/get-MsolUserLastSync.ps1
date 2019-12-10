# values from central cfg 
if(!$DoRetries){$DoRetries = 4 ; } ;          # attempt retries
if(!$RetrySleep){$RetrySleep = 5 ; }          # mid-retry sleep in secs
if(!$retryLimit){[int]$retryLimit=1; }        # just one retry to patch lineuri duped users and retry 1x
if(!$retryDelay){[int]$retryDelay=20; }       # secs wait time after failure
if(!$abortPassLimit){$abortPassLimit = 4;}    # maximum failed users to abort entire pass

#*------v Function get-MsolUserLastSync v------
Function get-MsolUserLastSync {
    <# 
    .SYNOPSIS
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .NOTES
    Updated By: : Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    * 11:23 AM 10/18/2018 ported from get-MsolUserLastSync()
    .DESCRIPTION
    get-MsolUserLastSync - Collect last AD-AAD sync (AzureAD/MSOL)
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns an object with LastDirSyncTime, expressed as TimeGMT & TimeLocal
    .EXAMPLE
    get-MsolUserLastSync
    .LINK
    #>
    Param(
      [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="MSolUser UPN")][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
      [Parameter()]$Credential = $global:credo365TORSID
    ) ; 
    try{Get-MsolAccountSku -ErrorAction Stop |out-null} 
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
        "Not connected to MSOnline. Now connecting." ;
        Connect-MsolService ; 
    } ;
    #$DirSyncTimeBefore = (Get-MsolCompanyInformation).LastDirSyncTime ;
    $DirSyncTimeBefore = (Get-MsolUser -UserPrincipalName $UserPrincipalName).LastDirSyncTime ;
    $oReturn= New-Object PSObject -Property @{
      TimeGMT = $DirSyncTimeBefore  ; 
      TimeLocal = $DirSyncTimeBefore.ToLocalTime() ; 
    }; 
    $oReturn | write-output ; 
} ; #*------^ END Function get-MsolUserLastSync ^------
# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU80nQqOkXJGB2cvtc1T9xjL9v
# 5qSgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBREO8IW
# f7tX73YuHNO8cQmxBAtjvjANBgkqhkiG9w0BAQEFAASBgCM4ovNWF7xbtkDKlZ0Y
# XV/WY2yltpf6d1D5ANORmRwpMW3BZAicAz5LC2NKykvaV3I5t+WKL11oTru0PInj
# udauzlzBP4j39ZCdQl+4e7BgwFpSTtHS9p7Rk4QcdAxFu0uvyasXN182PjJBfSXU
# ADzFaS2Av/WsxDHKa3VfBpNp
# SIG # End signature block
