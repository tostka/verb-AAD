# New-AADAppAuthCertificate_func.ps1

#*----------v Function New-AADAppAuthCertificate() v----------
function New-AADAppAuthCertificate {
    <#
    .SYNOPSIS
    New-AADAppAuthCertificate.ps1 - Create SelfSigned certificate (PKI) in specified -CertStoreLocation location, export same to pfx (named for DnsName with dateranges), and return a raw object version of the cert, along with the PFXPath and certificate properties to the pipeline. Objects created are suitable for Certificate-Based-Authentication of AzureADApplication objects. 
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : New-AADAppAuthCertificate.ps1
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
    New-AADAppAuthCertificate.ps1 - Create SelfSigned certificate (PKI) in specified -CertStoreLocation location, export same to pfx (named for DnsName with dateranges), and return a raw object version of the cert, along with the PFXPath and certificate properties to the pipeline. Objects created are suitable for Certificate-Based-Authentication of AzureADApplication objects. 
    .PARAMETER DnsName
    Certificate DNSName (AppFQDN)[-DnsName server.domain.com]
    .PARAMETER CertStoreLocation
    Certificate store for storage of new certificate[-CertStoreLocation 'Cert:\CurrentUser\My']
    .PARAMETER Years
    New certificate lifespan in integer years[-years 3]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> $pltNAAC=[ordered]@{
    PS>     DnsName=$AppFqDN ;
    PS>     CertStoreLocation = $certStore ;
    PS>     EndDate=$endDate ;
    PS>     StartDate = $startDate ; 
    PS>     verbose = $($verbose) ; 
    PS>     whatif = $($whatif) ;
    PS> } ;
    PS> $smsg = "New-AADAppAuthCertificate w`n$(($pltNAAC|out-string).trim())" ;
    PS> if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    PS> else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS> $bRet = New-AADAppAuthCertificate @pltNAAC ; 
    PS> if($bREt.Valid){
    PS>     $smsg = "New-AADAppAuthCertificate returned VALID outputs`n$(($bRet|out-string).trim())" ;
    PS>     if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    PS>     else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS>     $newcert = $bRet.Certificate ; 
    PS>     $certRaw = $bRet.CertRaw ; 
    PS>     # need to update: $pltExPfx.FilePath to a variable
    PS>     $PfxPath = $bRet.PFXPath ; 
    PS>     $pltNAADAppKeyCred=[ordered]@{
                ObjectId = $application.ObjectId ;
                CustomKeyIdentifier = "$appName" ;
                Type = 'AsymmetricX509Cert' ;
                Usage = 'Verify' ;
                Value = $certRaw ;
                StartDate = $newcert.NotBefore ;
                EndDate = $newcert.NotAfter ;
            } ;
            $smsg = "New-AzureADApplicationKeyCredential w`n$(($pltNAADAppKeyCred|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            # 2:14 PM 6/9/2022 cap output, keep out of pipeline
            $newKeyCred = New-AzureADApplicationKeyCredential @pltNAADAppKeyCred ; 
    PS> } else { 
    PS>     $smsg ="New-AADAppAuthCertificate returned INVALID outputs`n$(($bRet|out-string).trim())" ;
    PS>     if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
    PS>     else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    PS>     throw $smsg ; 
    PS>     break ; 
    PS> } ;     
    Splatted demo with whatif & verbose, gens cert, exports pfx, provides raw content of cert (for mounting on appreg), and runs cmd to add cert to existing AAD Registered App.
    .LINK
    https://github.com/tostka/verb-XXX
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    [ name related topic(one keyword per topic), or http://|https:// to help, or add the name of 'paired' funcs in the same niche (enable/disable-xxx)]
    #>
    #Requires -Modules AzureAD, PKI, verb-IO, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Certificate DNSName (AppFQDN)[-DnsName server.domain.com]")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$DnsName,
        [Parameter(Mandatory=$True,HelpMessage="Certificate store for storage of new certificate[-CertStoreLocation 'Cert:\CurrentUser\My']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$CertStoreLocation,
        [Parameter(Mandatory=$True,HelpMessage="New certificate StartDate[-StartDate '6/9/2022']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [datetime]$startDate, 
        [Parameter(Mandatory=$True,HelpMessage="New certificate EndDate[-EndDate '6/9/2024']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [datetime]$endDate,
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
        Certificate = $null ; 
        CertRaw = $null ; 
        PFXPath = $null ; 
        Valid = $false ; 
    } ; 
    
    $smsg = "---1)ENTER CERTIFICATE PFX Password: (use 'dummy' for UserName)" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $pfxcred=(Get-Credential -credential dummy) ;

    $pltNSSCert=[ordered]@{
        DnsName=$DnsName ;
        CertStoreLocation = $CertStoreLocation ;
        KeyExportPolicy='Exportable' ;
        Provider="Microsoft Enhanced RSA and AES Cryptographic Provider" ;
        NotAfter=$endDate ;
        KeySpec='KeyExchange' ;
        erroraction='STOP';
        whatif = $($whatif) ;
    } ;
    $smsg = "---2)New-SelfSignedCertificate w`n$(($pltNSSCert|out-string).trim())" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    # precheck for conflicting existing on same dnsname
    if($conflicts = gci $pltNSSCert.CertStoreLocation |?{$_.subject -eq "CN=$($pltNSSCert.DnsName)"} ){
        $smsg = "PREXISTING CERT IN $($CertStoreLocation) W MATCHING DNSNAME!`n$(($conflicts | ft -a thumbprint,subject,when*|out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $bRet=Read-Host "Enter YYY to continue. Anything else will exit" 
        if ($bRet.ToUpper() -eq "YYY") {
            $smsg = "Moving on" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            $smsg = "Invalid response. Exiting"
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            Break ;# exit <asserted exit error #>
            #exit 1
        } # if-block end
    } ; 
    
    $newcert = (New-SelfSignedCertificate @pltNSSCert); 
    $objReturn.Certificate = $newcert ; 
    
    if(-not $whatif -AND $newcert){
        $smsg = "(new cert:$($newcert.thumbprint) created)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

        #$newcert.thumbprint | set-Content -Path "$(split-path $transcript)\cert-$($DnsName)-thumb-$(get-date -format 'yyyyMMdd-HHmmtt').txt" ; 

        $pltExPfx=[ordered]@{
            Cert= "$($CertStoreLocation)\$($newcert.thumbprint)"
            FilePath="$(split-path $profile)\keys\$($DnsName)-NOTAFTER-$(get-date $pltNSSCert.notafter -format 'yyyyMMdd-HHmmtt').pfx" ;
            Password=$pfxcred.password ;
            erroraction='STOP';
        } ;
        $smsg = "---3)Export-PfxCertificate  w`n$(($pltExPfx|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $newpfx = Export-PfxCertificate @pltExPfx ;
        $objReturn.PFXPath = $pltExPfx.FilePath ; 

        $smsg = "`n$(($newpfx|out-string).trim())" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    
        $smsg = "(create cert object)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($pltExPfx.FilePath, $pfxcred.password) ;
        $smsg = "`ncert obj created:w`n$(($cert | ft -a handle,issuer,subject |out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green $($smsg) } ;

        $certRaw = [System.Convert]::ToBase64String($cert.GetRawCertData()) ;
        $objReturn.CertRaw = $certRaw ; 
        
        if($objReturn.Certificate -AND $objReturn.CertRaw -AND $objReturn.PFXPath){ 
            $smsg = "Valid Certificate, CertRaw, and PFX values: Setting Valid:`$true" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $objReturn.Valid = $true ; 
        } else { 
            $smsg = "INVALID CERTIFICATE, CERTRAW, or PFX: Setting Valid:`$FALSE" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            $objReturn.Valid = $false 
        } ; 
        
        New-Object -TypeName PSObject -Property $objReturn | write-output ; 
        
    } else { 
        $smsg = "`n(-whatif, skipping post-creation cert-handling code)" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } ; 
} ;  
#*------^ END Function New-AADAppAuthCertificate ^------
