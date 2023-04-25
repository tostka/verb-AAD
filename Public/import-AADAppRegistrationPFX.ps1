# import-AADAppRegistrationPFX

#*----------v Function import-AADAppRegistrationPFX() v----------
function import-AADAppRegistrationPFX {
    <#
    .SYNOPSIS
    import-AADAppRegistrationPFX.ps1 - Import CBA-Auth-supporting PFX file(s) into Cert:\CurrentUser\My. Leverages stock PKI module Import-PfxCertificate cmdlet, but parses and populates CBA-auth-releated values, that aren't present in the stock cmdlet.
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : import-AADAppRegistrationPFX.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,AzureAD,Authentication,Certificate,CertificateAuthentication
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 2:53 PM 4/25/2023 init version; removed verb-AAD req (avoid circ)
    .DESCRIPTION
    import-AADAppRegistrationPFX.ps1 - Import CBA-Auth-supporting PFX file(s) into Cert:\CurrentUser\My. Leverages stock PKI module Import-PfxCertificate cmdlet, but parses and populates CBA-auth-releated values, that aren't present in the stock cmdlet.
    These coordinate with connect-exo() and the Auth functions to work with canned CBA authentication objects.
    .PARAMETER Path
    Array of PFX files to be imported[-path 'c:\pathto\file.pfx','c:\pathto\file2.ext']
    .PARAMETER CertStoreLocation
    Certificate store for storage of new certificate (defaults to CU\My)[-CertStoreLocation 'Cert:\LocalMachine\My']
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .INPUTS
    Accepts piped input
    .OUTPUTS
    System.PsObject array of imported or pre-imported certificate objects
    .EXAMPLE
    PS> $pfxs = 'C:\usr\work\o365\certs\o365ESvcCBACert-TOL.Torolab.onmicrosoft.com-NOTAFTER-20240622-0928AM.pfx','C:\usr\work\o365\certs\o365SIDCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1547PM.pfx','C:\usr\work\o365\certs\o365CSvcCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1530PM.pfx','C:\usr\work\o365\certs\o365ESvcCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1314PM.pfx', 'C:\usr\work\o365\certs\o365CSvcCBACert-TOL.Torolab.onmicrosoft.com-NOTAFTER-20240622-0952AM.pfx' ; 
    PS> $results = import-AADAppRegistrationPFX -Path $pfxs -whatif ; 
    Demos import of a series of pfx files, with whatif, with verbose
    .EXAMPLE
    PS> $pfxs = 'C:\usr\work\o365\certs\o365ESvcCBACert-TOL.Torolab.onmicrosoft.com-NOTAFTER-20240622-0928AM.pfx','C:\usr\work\o365\certs\o365SIDCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1547PM.pfx','C:\usr\work\o365\certs\o365CSvcCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1530PM.pfx','C:\usr\work\o365\certs\o365ESvcCBACert-TOR.toroco.onmicrosoft.com-NOTAFTER-20240622-1314PM.pfx', 'C:\usr\work\o365\certs\o365CSvcCBACert-TOL.Torolab.onmicrosoft.com-NOTAFTER-20240622-0952AM.pfx' ; 
    PS> $results = $pfxs | import-AADAppRegistrationPFX -whatif ; 
    Pipeline demo. 
    .LINK
    https://github.com/tostka/verb-AAD
    #>
    #Requires -Modules AzureAD, PKI, verb-IO, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory = $False,Position = 0,ValueFromPipeline = $True, HelpMessage = 'Array of PFX files to be imported[-path c:\pathto\file.ext]')]
            [Alias('PsPath')]
            #[ValidateScript({Test-Path $_ -PathType 'Container'})]
            [ValidateScript({Test-Path $_})]
            [ValidateScript({$_ -match '\.pfx$'})]
            [system.io.fileinfo[]]$Path,
        [Parameter(HelpMessage="Certificate store for storage of new certificate (defaults to CU\My)[-CertStoreLocation 'Cert:\LocalMachine\My']")]
            [ValidateNotNullOrEmpty()]
            [string]$CertStoreLocation= 'Cert:\CurrentUser\My',
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
            [switch] $whatIf
    ) ;
    BEGIN{
        #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
        # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        write-verbose -verbose:$verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 

        $certprops="thumbprint","not*","subject","FriendlyName","use","HasPrivateKey" ;
        
        #region BANNER ; #*------v BANNER v------
        $sBnr="#*======v  $(${CmdletName}): v======" ;
        $smsg = $sBnr ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #endregion BANNER ; #*------^ END BANNER ^------


        $tMod = 'PKI' ; 
        if(-not (get-module $tMod -ListAvailable)){
            $smsg = "MISSING dependant $($tMod) Module! Install the module to use this script!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            Break ; 
        } ; 

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 
        $oAggr = @()  ; 
    } ;  # BEGIN-E
    PROCESS {
        foreach($certfile in $Path) {
            $sBnrS = $smsg = "`n#*------v PROCESSING $($certfile): v------" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            $certlocal = $pfxcred = $certificateObject = $tthumb = $xcert = $null ; 

            TRY{
                #$certfile=$_ ; 
                $pfxcred = $null ; 
                $certfile | out-clipboard ; 

	            if($certfile = get-childitem $certfile){
		            $pltImport=[ordered]@{
			            FilePath=$certfile.fullname ;
			            Exportable=$True ;
			            CertStoreLocation = $CertStoreLocation ;
			            whatif=$($whatif) ;
			            ErrorAction = 'Stop' ; 
		            } ;
		            if($certfile.extension -eq '.pfx'){
			            #if(!$pfxcred){
				            $smsg = "For PFX:$($certfile):" ; 
                            $smsg += "`nENTER PFX PW: (use 'dummy' for User Name)`n(friendlyname copied to CB)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                            else{ write-host -foregroundcolor yellow "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
				            $pfxcred=(Get-Credential -credential dummy) ;
				            $smsg = "WV$((get-date).ToString('HH:mm:ss')):Importing pfx to $($env:computername)..." ;
                            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

			            #} else { $smsg = "WV$((get-date).ToString('HH:mm:ss')):(using existing `$pfxcred password)" };
			            $pltImport.Add('Password',$pfxcred.Password) ;       
		            } ;

                    # check for pre-existing
                    $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ; 
                    $certificateObject.Import($pltImport.FilePath, $pfxcred.Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet) ; 
                    $tthumb = $certificateObject.Thumbprint ; 
                    #if($certlocal = get-childitem "$($pltImport.CertStoreLocation)\$($tthumb)" -ea 0){
                    if($certlocal = get-childitem -path "$($pltimport.CertStoreLocation)\$($tthumb)" -ea 0){
                        $smsg = "Pre-imported Cert with target Thumbprint - $($tthumb) - found" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                        $smsg = "`n$(($certlocal| fl $certprops |out-string).trim())" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        $oAggr += $certlocal ; 
                    } else { 

		                $smsg = "Import-PfxCertificate  w`n$(($pltImport|out-string).trim())" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
		                $error.clear() ;
		                TRY {
			                $certobj = Import-PfxCertificate @pltImport ;
			                $certobj ; 
			                if(-not $whatif){
				                if($certlocal=get-childitem "$($pltImport.CertStoreLocation)\$($certobj.thumbprint)"){
					                $appname = $certlocal.subject.split('.')[0].replace('CN=o365','o365_') ; 
					                $smsg = "Updating local FriendlyName:cert:PRE w`n$(($certlocal | fl $propsCert |out-string).trim())" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
					                $certlocal.FriendlyName = $appName ;
					                $ncert = get-childitem "$($pltImport.CertStoreLocation)\$($certobj.thumbprint)" -ea STOP ;# | fl $certprops ; 
                                    $smsg = "`n$(($ncert| fl $certprops |out-string).trim())" ; 
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    $oAggr += $ncert ; 

			                    } else { 
                                    $smsg = "Missing installed cert:$($pltImport.CertStoreLocation)\$($certobj.thumbprint)" 
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                                } ;
                            } else {
                                $smsg = "(whatif)" 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            } ;
                        
		                } CATCH {
			                $smsg = "FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
			                CONTINUE ;
		                } ;
                    } ; 
	            } else { 
                    $smsg = "Missing pfx file:$($certfile)" 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } ;
        
       
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #-=-record a STATUSWARN=-=-=-=-=-=-=
                $statusdelta = ";WARN"; # CHANGE|INCOMPLETE|ERROR|WARN|FAIL ;
                if(gv passstatus -scope Script -ea 0){$script:PassStatus += $statusdelta } ;
                if(gv -Name PassStatus_$($tenorg) -scope Script -ea 0){set-Variable -Name PassStatus_$($tenorg) -scope Script -Value ((get-Variable -Name PassStatus_$($tenorg)).value + $statusdelta)} ; 
                #-=-=-=-=-=-=-=-=
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
            } ; 
            
            $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; # loop-E
    } ;  # PROC-E
    END{
        if($oAggr ){ 
            $smsg = "(Returning imported cert summaries to pipeline)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            $oAggr | write-output ;     
        } elseif($whatif){
            $smsg = "(whatif pass, skipping report)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        } else { 
            $smsg = "No Imported Cert Summaries! Nothing To Return To Pipeline!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } ; 
        $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } ;  # END-E
} ;  
#*------^ END Function import-AADAppRegistrationPFX ^------

