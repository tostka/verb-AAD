# values from central cfg 
if(!$DoRetries){$DoRetries = 4 ; } ;          # attempt retries
if(!$RetrySleep){$RetrySleep = 5 ; }          # mid-retry sleep in secs
if(!$retryLimit){[int]$retryLimit=1; }        # just one retry to patch lineuri duped users and retry 1x
if(!$retryDelay){[int]$retryDelay=20; }       # secs wait time after failure
if(!$abortPassLimit){$abortPassLimit = 4;}    # maximum failed users to abort entire pass

$RootPath = $env:USERPROFILE + "\ps\"
if(!(test-path $RootPath)){ mkdir $RootPath}  ; 
$KeyPath = $Rootpath + "creds\"
if(!(test-path $KeyPath)){ mkdir $KeyPath}  ; 

#*------v Function Connect-AAD v------
if(!(test-path function:Connect-AAD)){
    Function Connect-AAD {
        <# 
        .SYNOPSIS
        Connect-AAD - Establish authenticated session to AzureAD Graph Module (AzureAD), also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
        .NOTES
        Updated By: : Todd Kadrie
        Website:	http://tinstoys.blogspot.com
        Twitter:	http://twitter.com/tostka
        REVISIONS   :
        * 10:55 AM 12/6/2019 Connect-AAD:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
        * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
        * 1:39 PM 5/8/2019 Connect-AAD:tightened up the installed/imported/authenticated checks
        * 2:53 PM 5/2/2019 ren'd Connect-AAD2 -> Connect-AAD
        * 1:54 PM 10/8/2018 Connect-AAD:port from Connect-AAD
        .DESCRIPTION
        Connect-AAD - Establish authenticated session to AzureAD/MSOL, also works as reConnect-AAD, there is no disConnect-AAD (have to close Powershell to clear it).
        No need for separate reConnect-AAD - this self tests for connection, and reconnects if it's missing. 
        No support for disConnect-AAD, because MSOL has no command to do it, but closing powershell.
        .PARAMETER  ProxyEnabled
        Proxyied connection support
        .PARAMETER Credential
        Credential to be used for connection
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. Returns no objects or output.
        .EXAMPLE
        Connect-AAD
        .EXAMPLE
        Connect-AAD -Credential $cred
        .LINK
        #>
        Param(
            [Parameter()][boolean]$ProxyEnabled = $False,  
            [Parameter()]$Credential = $global:credo365TORSID
        ) ; 
        
        $MFA = get-TenantMFARequirement -Credential $Credential ; 

        $sTitleBarTag="AAD" ; 
        if($Credential){
            switch -regex ($Credential.username.split('@')[1]){
                "toro\.com" {
                    # leave untagged
                 } 
                 "torolab\.com" {
                    $sTitleBarTag = $sTitleBarTag + "tlab"
                } 
                "(charlesmachineworks\.onmicrosoft\.com|charlesmachine\.works)" {
                    $sTitleBarTag = $sTitleBarTag + "cmw"
                } 
            } ; 
        } ; 

        Try {Get-Module AzureAD -listavailable -ErrorAction Stop | out-null } Catch {Install-Module AzureAD -scope CurrentUser ; } ;                 # installed
        Try {Get-Module AzureAD -ErrorAction Stop | out-null } Catch {Import-Module -Name AzureAD -MinimumVersion '2.0.0.131' -ErrorAction Stop  } ; # imported
        try { Get-AzureADTenantDetail | out-null  } # authenticated 
        catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] { 
            Write-Host "You're not Authenticated to AAD: Connecting..."  ; 
            Try {
                if(!$Credential){
                    if(test-path function:\get-admincred) { 
                        Get-AdminCred ; 
                    } else {
                        switch($env:USERDOMAIN){
                            "TORO" { 
                            write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($o365AdmUid ))" ; 
                            if(!$bUseo365COAdminUID){
                                if($o365AdmUid ){$Credential = Get-Credential -Credential $o365AdmUid } else { $Credential = Get-Credential } ; 
                            } else {
                                if($o365COAdmUid){global:o365cred = Get-Credential -Credential $o365COAdmUid} else { $Credential = Get-Credential } ; 
                            } ; 
                            }
                            "TORO-LAB" { 
                                write-host -foregroundcolor yellow "PROMPTING FOR O365 CRED ($($o365LabAdmUid ))" ; 
                                if(!$bUseo365COAdminUID){
                                    if($o365LabAdmUid){$Credential = Get-Credential -Credential $o365LabAdmUid} else { $Credential = Get-Credential } ; 
                                } else {
                                    if($o365LabCOAdmUid){$Credential = Get-Credential -Credential $o365LabCOAdmUid} else { $Credential = Get-Credential } ; 
                                } ; 
                            }
                            default {
                                write-host -foregroundcolor yellow "$($env:USERDOMAIN) IS AN UNKNOWN DOMAIN`nPROMPTING FOR O365 CRED:" ; 
                                $Credential = Get-Credential 
                            } ; 
                        } ; 
                    }  ; 
              } ;
              if(!$MFA){
                  Connect-AzureAD -Credential $Credential -ErrorAction Stop ; 
              } else { 
                  Connect-AzureAD -AccountID $Credential.userName ;
              } ; 

              Write-Verbose "(connected to AzureAD ver2)" ; Add-PSTitleBar $sTitleBarTag ; ; 
            } Catch {
                Write-Verbose"There was an error Connecting to Azure Ad - Ensure the module is installed" ; 
                Write-Verbose"Download PowerShell 5 or PowerShellGet" ; 
                Write-Verbose"https://msdn.microsoft.com/en-us/powershell/wmf/5.1/install-configure" ; 
            } ; 
        } ; 
    } ; #*------^ END Function Connect-AAD ^------
} else { write-host -foregroundcolor green "(Deferring to pre-loaded Connect-AAD)" ;} ; 
if(!(get-alias caad -ea 0) ) {Set-Alias 'caad' -Value 'Connect-AAD' ; } ;
if(!(get-alias raad -ea 0) ) {Set-Alias 'raad' -Value 'Connect-AAD' ; } ;
if(!(get-alias reConnect-AAD -ea 0) ) {Set-Alias 'reConnect-AAD' -Value 'Connect-AAD' ; } ;
function caadtol {Connect-AAD -cred $credO365TOLSID};
function caadcmw {Connect-AAD -cred $credO365CMWCSID};
function caadtor {Connect-AAD -cred $credO365TORSID};
# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUb2VAxFDMAhtIHqT5b5PWWbEU
# OsmgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQzOfY6
# r+eo3jVzmgcJHXkz5T8mVjANBgkqhkiG9w0BAQEFAASBgI46aQ+6icdhVJ6eNR3i
# zp/ZnpgYyAtJm97zDanXa3CufFzvkYr+c4NwItwpDtx0804W0kQTO37UeJQuPMeK
# XNO/6BABETtleudMtV4AcyGBBejoPpx63XjeJhLRaRz8/tGqTs4Rct883Tv23ZBU
# 9MTC9I1KWD8GgELj2/GHVp1O
# SIG # End signature block
