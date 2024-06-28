# Update-AADAppRegistrationKeyCertificate.ps1
#*------v Function Update-AADAppRegistrationKeyCertificate v------
function Update-AADAppRegistrationKeyCertificate{
    <#
    .SYNOPSIS
    Update-AADAppRegistrationKeyCertificate.ps1 - Rollver expired/expiring Cert on AAD Registered App with CBA-auth. All necessary values are derived from the local cert and dynamic queries to the connected Tenant
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-06-25
    FileName    : Update-AADAppRegistrationKeyCertificate.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-AAD
    Tags        : Powershell,AzureAD,CertificateBasedAuthentication
    AddedCredit : myatix
    AddedWebsite: https://stackoverflow.com/users/2439507/myatix
    AddedTwitter: 
    REVISIONS
    * 2:44 PM 6/27/2024, fixed error in old cert removal on remote (cited thumb for new cert, not input cert); added PriorCertThumbprint to output;  tested, confirmed functional for TOL ESvc rollover ;  add other machine cert removal; rarranged output  instructions to single block; add returned summary object fix spaces after $'s in demo output code ; 
        functionalize and ren Rollover-AADAppRegistrationCBAAuth -> Update-AADAppRegistrationKeyCertificate
    * 3:30 PM 6/26/2024 used it to roll over the , 6/2022 CBA sets ; added output code demoing code to to purge obsolete .psxml cred files on other machines ; 
        added fall back on attempt to use $cert.friendlyname for ADApplicationlookup fail (prompts for App DNAME for re-search); 
        tweaked, ported in psparamt disco & startlog, per-loop level, added pipeline support
    * 3:39 PM 6/25/2024 convert New-AADAppRegistrationCBAAuth.ps1 -> Update-AADAppRegistrationKeyCertificate.ps1
    .DESCRIPTION
    Update-AADAppRegistrationKeyCertificate.ps1 - Rollver expired/expiring Cert on AAD Registered App with CBA-auth. All necessary values are derived from the local cert and dynamic queries to the connected Tenant

    1. Uses the specified local CurrentUser\My\[thumbrpint] from the passed certificate, to obtain FriendlyName, that is then queried against the displayname of all get-AzureADApplication registrations, 
        to locate the tied application. 
    2. It then uses the Remove-AzureADApplicationKeyCredential cmdlet to remove the existing registered KeyCredential cert from the Application
    3. It then removes the local \CurrentUser\My certificate hive copy of the retiring cert (passed as original input)
    4. It then uses my verb-AAD\New-AADAppAuthCertificate() to create a new self-signed certificate, assign the Application Displayname as cert FriendlyName, and then export the cert to PFX (with prompted password), 
    5. And then uses the New-AzureADApplicationKeyCredential cmdlet to add the new self-signed cert to the existing AzureADApplication
    6. Finally it locates the local credential psxml file (used by get-admincred()) and purges the file so that a fresh pass can be run to restock with the updated values

    Outputs CustomObject summary of related components, changes, and follow-on configuration actions. 

    Notes: 
    - A model certificate must be input, to drive updates. If no suitable current certificate is installed, simply reimport a prior version PFX into the store, and configure it's FriendlyName (see Example). 
        Even a long-expired cert will be sufficient to drive use of this function to generate fresh KeyCredential updates.
    
    - if the associated Application has been purged as well, see New-AADAppRegistrationCBAAuth.ps1 to generate a new applicaiton plus KeyCredential set from scratch.
    

    .PARAMETER Certificate
    Expiring/Expired certificate object (product of gci cert:\currentuser\my\THUMBPRINT) that is an existing AzureADApplication KeyCredential, to be rolled over (removed, regenerated, and re-added to the existing Application)[-certificate `$ocert]
    .PARAMETER years
    Years of lifespan on the authenticating cert [-years 3]
    .PARAMETER certStore
    Path to local certificate store in which authenticating cert will be stored(defaults to CU\My)[-certStore 'Cert:\LocalMachine\My']
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2[] Certificate array object

    Accepts piped input
    .OUTPUTS
    System.Management.Automation.PSCustomObject

    Returns Summary PSCustomObject, bundling following components:
     - Application
     - ServicePrincipal
     - TenantDetail
     - Owner
     - KeyCred
     - Certificate
     - PfxPath
     - PriorCertificateThumbprint
     - Instructions
    .EXAMPLE
    PS> $ocert =  gci cert:\currentuser\my\CnEBDEEnnnnnnnBCDFADnnEnnnnEDnnECnnAnnnF ; 
    PS> $results = Update-AADAppRegistrationKeyCertificate -certificate $ocert ;
    PS> if($results.Certificate){ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Updated Certificate`n$(($results.Certificate| ft -a Subject,NotAfter,Thumbprint|out-string).trim())" ; } ; 
    Demo rollover of specified cert (located as a suitable input object, via get-childitem on the thumbprint)
    .EXAMPLE
    PS> $expiredcerts = gci cert:\currentuser\my | ?{(get-date $_.notafter) -le (get-date ) -AND $_.subject -match 'CBACert'} ;
    PS> $Aggreg = @() ; 
    PS> foreach($ocert in $expiredcerts){
    PS>     write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`n`nRolling over cert: w`n$(($ocert| ft -a thumb*,subject,notafter|out-string).Trim())`n`n" ; 
    PS>     $results = Update-AADAppRegistrationKeyCertificate -certificate $ocert ;
    PS>     if($results.Certificate){
    PS>         write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Updated Certificate`n$(($results.Certificate| ft -a Subject,NotAfter,Thumbprint|out-string).trim())" ; 
    PS>         $Aggreg += $results ; 
    PS>     } ;     
    PS> } ; 
    Demo filter for expired certs on subject substring, looped into the function, test results and append to an aggregator variable. 
    .EXAMPLE
    PS> $expiredcerts = gci cert:\currentuser\my |  ?{(get-date $_.notafter) -le (get-date ) -AND $_.subject -match 'CBACert'} ;
    PS> $expiredcerts | Update-AADAppRegistrationKeyCertificate -verbose;
    Demo pipeline use
    .EXAMPLE
    PS> $results = (gci Cert:\CurrentUser\my\CnEBDEEnnnnnnnBCDFADnnEnnnnEDnnECnnAnnnF | Update-AADAppRegistrationKeyCertificate -verbose ) ; 
    Pipeline example pushing a specific cert by thumbprint, through.
    .EXAMPLE
    PS> $expiredcerts = gci cert:\currentuser\my |  ?{(get-date $_.notafter) -le (get-date ) -AND $_.subject -match 'CBACert'} ;
    Simple demo to gather expired certs with a subject substring match
    .EXAMPLE
    PS> $whatif = $true ;
    PS> 'C:\usr\work\o365\certs\o365XXX-NOTAFTER-20240622-0928AM.pfx','C:\usr\work\o365\certs\o365YYY-NOTAFTER-20240622-1547PM.pfx' |%{
    PS> 	$certfile=$_ ; $pfxcred = $null ;
    PS> 	write-host "==$($certfile):" ;
    PS> 	$certfile  | clip.exe ;
    PS> 	$certprops="thumbprint","not*","subject","FriendlyName","use","HasPrivateKey" ;
    PS> 	if($certfile=gci $certfile){
    PS> 		$pltImport=[ordered]@{
    PS> 			FilePath=$certfile.fullname ;
    PS> 			Exportable=$True ;
    PS> 			CertStoreLocation = 'Cert:\CurrentUser\My' ;
    PS> 			whatif=$($whatif) ;
    PS> 			ErrorAction = 'Stop' ;
    PS> 		} ;
    PS> 		if($certfile.extension -eq '.pfx'){
    PS> 			if(!$pfxcred){
    PS> 				write-host -foregroundcolor yellow "ENTER PFX PW: (use 'dummy' for User Name)`n(friendlyname copied to CB)" ;
    PS> 				$pfxcred=(Get-Credential -credential dummy) ;
    PS> 				write-verbose -verbose:$true  "$((get-date).ToString('HH:mm:ss')):Importing pfx to $($env:computername)..." ;
    PS> 			} else { write-verbose -verbose:$true  "$((get-date).ToString('HH:mm:ss')):(using existing `$pfxcred password)" };
    PS> 			$pltImport.Add('Password',$pfxcred.Password) ;
    PS> 		} ;
    PS> 		write-host "Import-PfxCertificate  w`n$(($pltImport|out-string).trim())" ;
    PS> 		$error.clear() ;
    PS> 		TRY {
    PS> 			$certobj = Import-PfxCertificate @pltImport ;
    PS> 			$certobj ;
    PS> 			if(-not $whatif){
    PS> 				if($certlocal=get-childitem "$($pltImport.CertStoreLocation)\$($certobj.thumbprint)"){
    PS> 					$appname = $certlocal.subject.split('.')[0].replace('CN=o365','o365_') ;
    PS> 					$smsg = "Updating local FriendlyName:cert:PRE w`n$(($certlocal | fl $propsCert |out-string).trim())" ;
    PS> 					write-host $smsg ;
    PS> 					$certlocal.FriendlyName = $appName ;
    PS> 					get-childitem "$($pltImport.CertStoreLocation)\$($certobj.thumbprint)" | fl $certprops ;
    PS>         } else { write-host "missing installed cert:$($pltImport.CertStoreLocation)\$($certobj.thumbprint)" } ;
    PS>       } else { write-host "(whatif)" } ;
    PS> 		} CATCH {
    PS> 			Write-Warning "$(get-date -format 'HH:mm:ss'): FAILED PROCESSING $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
    PS> 			Stop ;
    PS> 		} ;
    PS> 	} else { write-host "missing pfx file:$($certfile)" } ;
    PS> } ;
    Demo import an array of pathed .pfx files into local system's Cu\My store, and update FriendlyName to equiv of AppName (backed out of SubjectName of the cert)
    .EXAMPLE
    PS> $whatif = $true ;
    PS> $certstore = 'Cert:\CurrentUser\My' ; 
    PS> $certprops="thumbprint","notbefore","notafter","subject","FriendlyName","use","HasPrivateKey" ;
    PS> gci $certstore | ?{$_.Subject -match 'CN=o365.*CBACert-\w{3}' -AND $_.FriendlyName.length -eq 0} |%{
    PS>   $certlocal=$_ ; 
    PS>   $sBnrS="`n#*------v PROCESSING FriendlyName update on: $($certlocal.Subject) v------" ; 
    PS>   write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
    PS>   $appname = $certlocal.subject.split('.')[0].replace('CN=o365','o365_') ;
    PS>   $smsg = "Updating local FriendlyName ($($appname)): on cert: PRE:`n$(($certlocal | fl $certprops |out-string).trim())" ;
    PS>   write-host $smsg ;
    PS>   if(-not $whatif){
    PS>       $certlocal.FriendlyName = $appName ;
    PS>   } else{write-host "-whatif, skip update"} ; 
    PS>   get-childitem "$(join-path $certstore $certlocal.thumbprint)" | fl $certprops ;
    PS>   write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    PS> } ;
    Demo (for other machine post-PFX imports found with blank FriendlyNames) that sets all CurrentUser\My\CN=o365.*CBACert-\w{3} certs with blank FriendlyNames, to use the AzureADApplication's Displayname (derived from the subject name on the imported cert)
    .LINK
    https://stackoverflow.com/questions/67565934/powershell-azuread-app-registration-permissions-new-azureadapplication-required
    https://github.com/tostka/verb-AAD
    #>
    #Requires -Version 3
    #requires -PSEdition Desktop
    #Requires -Modules AzureAD, verb-AAD, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    [OutputType('System.Management.Automation.PSCustomObject')] # optional specified output type
    [CmdletBinding()]
    [Alias('Rollover-AADAppRegistrationKeyCertificate')]
    PARAM(
        [Parameter(Mandatory=$True,ValueFromPipeline = $True,HelpMessage="Expiring/Expired certificate object that is an existing AzureADApplication Key Credential, to be rolled over (removed, regenerated, and added to the existing Application)[-certificate `$ocert]")]
            [ValidateNotNullOrEmpty()]
            [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [Parameter(HelpMessage="Path to local certificate store in which authenticating cert will be stored(defaults to CU\My)[-certStore 'Cert:\LocalMachine\My']")]
            [string] $certStore="Cert:\CurrentUser\My",
        [Parameter(HelpMessage="Integer years of authentication certificate lifespan, from the current date (defaults 2)[-Years 3]")]
            [int]$Years=2,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
            [switch] $showDebug
    ) ;
    BEGIN{
        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
        $rPSScriptRoot = $PSScriptRoot ; 
        $rPSCommandPath = $PSCommandPath ; 
        $rMyInvocation = $MyInvocation ; 
        $rPSBoundParameters = $PSBoundParameters ; 
        [array]$score = @() ; 
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName -match '\.ps1$'){
                $score+= 'ExternalScript' 
            }elseif($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                write-warning "dot-sourced invocation detected!:$($rPSCmdlet.MyInvocation.InvocationName)`n(will be unable to leverage script path etc from MyInvocation objects)" ; 
                # dot sourcing is implicit scripot exec
                $score+= 'ExternalScript' ; 
            } else {$score+= 'Function' };
        } ; 
        if($rPSCmdlet.CommandRuntime){
            if($rPSCmdlet.CommandRuntime.tostring() -match '\.ps1$'){$score+= 'ExternalScript' } else {$score+= 'Function' }
        } ; 
        $score+= $rMyInvocation.MyCommand.commandtype.tostring() ; 
        $grpSrc = $score | group-object -NoElement | sort count ;
        if( ($grpSrc |  measure | select -expand count) -gt 1){
            write-warning  "$score mixed results:$(($grpSrc| ft -a count,name | out-string).trim())" ;
            if($grpSrc[-1].count -eq $grpSrc[-2].count){
                write-warning "Deadlocked non-majority results!" ;
            } else {
                $runSource = $grpSrc | select -last 1 | select -expand name ;
            } ;
        } else {
            write-verbose "consistent results" ;
            $runSource = $grpSrc | select -last 1 | select -expand name ;
        };
        write-host "Calculated `$runSource:$($runSource)" ;
        'score','grpSrc' | get-variable | remove-variable ; # cleanup temp varis

        # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        ${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ;
        $PSParameters = New-Object -TypeName PSObject -Property $rPSBoundParameters ;
        write-verbose "`$rPSBoundParameters:`n$(($rPSBoundParameters|out-string).trim())" ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # pre psv2, no $rPSBoundParameters autovari to check, so back them out:
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                $smsg = "detected dot-sourced invocation: Skipping `$PSCmdlet.MyInvocation.InvocationName-tied cmds..." ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } else { 
                write-verbose 'Collect all non-default Params (works back to psv2 w CmdletBinding)'
                $ParamsNonDefault = (Get-Command $rPSCmdlet.MyInvocation.InvocationName).parameters | Select-Object -expand keys | Where-Object{$_ -notmatch '(Verbose|Debug|ErrorAction|WarningAction|ErrorVariable|WarningVariable|OutVariable|OutBuffer)'} ;
            } ; 
        } else { 
            $smsg = "(blank `$rPSCmdlet.MyInvocation.InvocationName, skipping Parameters collection)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        <#
        # Debugger:proxy automatic variables that aren't directly accessible when debugging ; 
        $rPSScriptRoot = $PSScriptRoot ; 
        $rPSCommandPath = $PSCommandPath ; 
        $rMyInvocation = $MyInvocation ; 
        $rPSBoundParameters = $PSBoundParameters ; 
        #>
        $ScriptDir = $scriptName = '' ;     
        if($ScriptDir -eq '' -AND ( (get-variable -name rPSScriptRoot -ea 0) -AND (get-variable -name rPSScriptRoot).value.length)){
            $ScriptDir = $rPSScriptRoot
        } ; # populated rPSScriptRoot
        if( (get-variable -name rPSCommandPath -ea 0) -AND (get-variable -name rPSCommandPath).value.length){
            $ScriptName = $rPSCommandPath
        } ; # populated rPSCommandPath
        if($ScriptDir -eq '' -AND $runSource -eq 'ExternalScript'){$ScriptDir = (Split-Path -Path $rMyInvocation.MyCommand.Source -Parent)} # Running from File
        # when $runSource:'Function', $rMyInvocation.MyCommand.Source is empty,but on functions also tends to pre-hit from the rPSCommandPath entFile.FullPath ;
        if( $scriptname -match '\.psm1$' -AND $runSource -eq 'Function'){
            write-host "MODULE-HOMED FUNCTION:Use `$CmdletName to reference the running function name for transcripts etc (under a .psm1 `$ScriptName will reflect the .psm1 file  fullname)"
            if(-not $CmdletName){write-warning "MODULE-HOMED FUNCTION with BLANK `$CmdletNam:$($CmdletNam)" } ;
        } # Running from .psm1 module
        if($ScriptDir -eq '' -AND (Test-Path variable:psEditor)) {
            write-verbose "Running from VSCode|VS" ; 
            $ScriptDir = (Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path -Parent) ; 
                if($ScriptName -eq ''){$ScriptName = $psEditor.GetEditorContext().CurrentFile.Path }; 
        } ;
        if ($ScriptDir -eq '' -AND $host.version.major -lt 3 -AND $rMyInvocation.MyCommand.Path.length -gt 0){
            $ScriptDir = $rMyInvocation.MyCommand.Path ; 
            write-verbose "(backrev emulating `$rPSScriptRoot, `$rPSCommandPath)"
            $ScriptName = split-path $rMyInvocation.MyCommand.Path -leaf ;
            $rPSScriptRoot = Split-Path $ScriptName -Parent ;
            $rPSCommandPath = $ScriptName ;
        } ;
        if ($ScriptDir -eq '' -AND $rMyInvocation.MyCommand.Path.length){
            if($ScriptName -eq ''){$ScriptName = $rMyInvocation.MyCommand.Path} ;
            $ScriptDir = $rPSScriptRoot = Split-Path $rMyInvocation.MyCommand.Path -Parent ;
        }
        if ($ScriptDir -eq ''){throw "UNABLE TO POPULATE SCRIPT PATH, EVEN `$rMyInvocation IS BLANK!" } ;
        if($ScriptName){
            if(-not $ScriptDir ){$ScriptDir = Split-Path -Parent $ScriptName} ; 
            $ScriptBaseName = split-path -leaf $ScriptName ;
            $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($ScriptName) ;
        } ; 
        # blank $cmdlet name comming through, patch it for Scripts:
        if(-not $CmdletName -AND $ScriptBaseName){
            $CmdletName = $ScriptBaseName
        }
        # last ditch patch the values in if you've got a $ScriptName
        if($rPSScriptRoot.Length -ne 0){}else{ 
            if($ScriptName){$rPSScriptRoot = Split-Path $ScriptName -Parent }
            else{ throw "Unpopulated, `$rPSScriptRoot, and no populated `$ScriptName from which to emulate the value!" } ; 
        } ; 
        if($rPSCommandPath.Length -ne 0){}else{ 
            if($ScriptName){$rPSCommandPath = $ScriptName }
            else{ throw "Unpopulated, `$rPSCommandPath, and no populated `$ScriptName from which to emulate the value!" } ; 
        } ; 
        if(-not ($ScriptDir -AND $ScriptBaseName -AND $ScriptNameNoExt  -AND $rPSScriptRoot  -AND $rPSCommandPath )){ 
            throw "Invalid Invocation. Blank `$ScriptDir/`$ScriptBaseName/`ScriptNameNoExt" ; 
            BREAK ; 
        } ; 
        # echo results dyn aligned:
        $tv = 'runSource','CmdletName','ScriptName','ScriptBaseName','ScriptNameNoExt','ScriptDir','PSScriptRoot','PSCommandPath','rPSScriptRoot','rPSCommandPath' ; 
        $tvmx = ($tv| Measure-Object -Maximum -Property Length).Maximum * -1 ; 
        $tv | get-variable | %{  write-verbose ("`${0,$tvmx} : {1}" -f $_.name,$_.value) } ; 
        'tv','tvmx'|get-variable | remove-variable ; # cleanup temp varis
        
        #endregion ENVIRO_DISCOVER ; #*------^ END ENVIRO_DISCOVER ^------

        if(-not $DoRetries){$DoRetries = 4 } ;    # # times to repeat retry attempts
        if(-not $RetrySleep){$RetrySleep = 10 } ; # wait time between retries
        if(-not $RetrySleep){$DawdleWait = 30 } ; # wait time (secs) between dawdle checks
        if(-not $DirSyncInterval){$DirSyncInterval = 30 } ; # AADConnect dirsync interval
        if(-not $ThrottleMs){$ThrottleMs = 50 ;}
        if(-not $rgxDriveBanChars){$rgxDriveBanChars = '[;~/\\\.:]' ; } ; # ;~/\.:,
        if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; # if it's a 40char hex string -> cert thumbprint  
        if(-not $rgxSmtpAddr){$rgxSmtpAddr = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$" ; } ; # email addr/UPN
        if(-not $rgxDomainLogon){$rgxDomainLogon = '^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$' } ; # DOMAIN\samaccountname 
        if(-not $exoMbxGraceDays){$exoMbxGraceDays = 30} ; 

        #region WHPASSFAIL ; #*------v WHPASSFAIL v------
        $whPASS = @{Object = "$([Char]8730) PASS" ;ForegroundColor = 'Green' ; NoNewLine = $true ; } ; 
        $whFAIL = @{
            # light diagonal cross: ╳ U+2573 DOESN'T RENDER IN PS
            #Object = [Char]2573 ;
            object = ' X FAIL'
            ForegroundColor = 'RED' ;
            NoNewLine = $true ;
        } ;
        <#$smsg = "Testing:Thing" ; 
        $Passed = $true ; 
        Write-Host "$($smsg)... " -NoNewline ; 
        if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
        Write-Host " (Done)" ;
        #>
        #endregion WHPASSFAIL ; #*------^ END  ^------

        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------
    
        # no EXO, but we need AAD creds - no, prompt, we want a global, no svcacct, and the existing cred is hosed on the cbacert; manual prompt


        <#
        $pltRXO = @{
            Credential = (Get-Variable -name cred$($tenorg) ).value ;
            verbose = $($verbose) ; silent = $false ;} ; 

        Connect-AAD @pltRXO ; 
        #>

        #*======v SUB MAIN v======

        # existing =========================
        #$whatif=$true ; 
        $error.clear() ;
        #$transcript = "d:\scripts\logs\ResourceMbxs-ENT-Perm-Grants-$(get-date -format 'yyyyMMdd-HHmmtt')log.txt" ; 
        #$stopResults = try {Stop-transcript -ErrorAction stop} catch {} ; 
        #start-transcript $transcript ; 

        #region BANNER ; #*------v BANNER v------
        $sBnr="#*======v $(${CmdletName}): v======" ;
        $smsg = $sBnr ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #endregion BANNER ; #*------^ END BANNER ^------

        # email trigger vari, it will be semi-delimd list of mail-triggering events
        $script:PassStatus = $null ;
        [array]$SmtpAttachment = $null ; 
        $Alltranscripts = @() ;
        # instant the PassStatus_$($tenorg) 
        #New-Variable -Name PassStatus_$($tenorg) -scope Script -Value $null ;

        $error.clear() ;

        $dCmds = 'Connect-AzureAD','get-AADToken','convert-TenantIdToTag','New-SelfSignedCertificate','New-AzADAppCredential','New-AADAppAuthCertificate','convertFrom-MarkdownTable' ; 
        foreach($dcmd in $dCmds){
            $tMod = (gcm $dcmd).source
            $pltIMod = @{Name = $tMod ; ErrorAction = 'Stop' ; verbose=$false} ;
            if($xmod = Get-Module $tMod -ErrorAction Stop| sort version | select -last 1 ){ } else {
                $smsg = "Import-Module w`n$(($pltIMod|out-string).trim())" ;
                if($silent){}elseif($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                Try {
                    Import-Module @pltIMod | out-null ;
                    $xmod = Get-Module $tMod -ErrorAction Stop | sort version | select -last 1 ;
                } Catch {
                    $ErrTrapd=$Error[0] ;
                    $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $smsg = $ErrTrapd.Exception.Message ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                    else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    Break ;
                } ;
            } ; # IsImported
        } ; 

        # static constants
        $propsAADAppT = 'DisplayName','ObjectId','AppId' ; 
        $propsCert = 'FriendlyName', @{name="DnsNameList";expression={$_.DnsNameList.punycode -join ";"}}, 'Thumbprint', 
            @{name="EnhancedKeyUsageList";expression={$_.EnhancedKeyUsageList.FriendlyName -join ";"}}, 
            @{Name='Extensions';Expression={$_.Extensions.KeyUsages }}, 'NotAfter', 'NotBefore', 
            @{Name='IssuerName';Expression={$_.IssuerName.name }}, 'HasPrivateKey', 'PrivateKey', 'PublicKey' ;
        $propsAADU = 'UserPrincipalName','DisplayName','MailNickName','PhysicalDeliveryOfficeName' ; 
        $propsAADU = 'ObjectId','DisplayName','UserPrincipalName','UserType' ; 
        $propsKeyCred = 'KeyId','Type','StartDate','EndDate','Usage' ;
        $propsAADApp = 'DisplayName','ObjectId','ObjectType','AppId','AvailableToOtherTenants','KeyCredentials',
            'PasswordCredentials','PublisherDomain','RequiredResourceAccess','SignInAudience' ; 

        # dyn values
        $startDate = Get-Date ;
        $endDate = $startDate.AddYears($years) ;

        $token = get-AADToken ;     
        if( ($null -eq $token) -OR ($token.count -eq 0)){
            $smsg = "CONNECTING TO AZUREAD - USE YOUR SID! DO *NOT* USE THE SVC ACCT, OR THE EXPIRED/ING CBA CERT!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            TRY{
                $AADConnection = Connect-AzureAD -ea STOP ; 
                $smsg = "AAD:`n$(($AADConnection|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
            # conn to AAD
            $token = get-AADToken ;
            # $TenOrg = get-TenantTag -Credential $Credential ;
            $TenOrg = $TokenTag = convert-TenantIdToTag -TenantId ($token.AccessToken).tenantid -verbose:$($verbose) ;
            $rgxThisTenOrg = [regex]::Escape("CBACert-$($TenOrg).") ; 
        }elseif($token.count -gt 1){
        } else {write-verbose "AzureAD already Connected"} ; 
        # constants/values
        TRY{
            $tenantDetail = Get-AzureADTenantDetail -ErrorAction STOP ;
            $TenantDomain = ($tenantDetail | select -expand VerifiedDomains |?{$_._Default -eq $true}).Name ; 
        } CATCH {
            $ErrTrapd=$Error[0] ;
            $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ; 
        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;
    } #  # BEG-E

    PROCESS{
        $ttl = $Certificate|  measure | select -expand count ; 
        $Prcd = 0 ; 
        foreach($thisCert in $Certificate) {
            $Prcd++ ; 
            $smsg = $sBnrS="`n#*------v PROCESSING ($($prcd)/$($ttl)): $($thiscert.Subject)::$($thiscert.thumbprint) v------" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            #region START-LOG #*======v START-LOG OPTIONS v======
            #region START-LOG-HOLISTIC #*------v START-LOG-HOLISTIC v------
            # Single log for script/function example that accomodates detect/redirect from AllUsers scope'd installed code, and hunts a series of drive letters to find an alternate logging dir (defers to profile variables)
            #${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ;
            if(!(get-variable LogPathDrives -ea 0)){$LogPathDrives = 'd','c' };
            foreach($budrv in $LogPathDrives){if(test-path -path "$($budrv):\scripts" -ea 0 ){break} } ;
            if(!(get-variable rgxPSAllUsersScope -ea 0)){
                $rgxPSAllUsersScope="^$([regex]::escape([environment]::getfolderpath('ProgramFiles')))\\((Windows)*)PowerShell\\(Scripts|Modules)\\.*\.(ps(((d|m))*)1|dll)$" ;
            } ;
            if(!(get-variable rgxPSCurrUserScope -ea 0)){
                $rgxPSCurrUserScope="^$([regex]::escape([Environment]::GetFolderPath('MyDocuments')))\\((Windows)*)PowerShell\\(Scripts|Modules)\\.*\.(ps((d|m)*)1|dll)$" ;
            } ;
            $pltSL=[ordered]@{Path=$null ;NoTimeStamp=$false ;Tag=$null ;showdebug=$($showdebug) ; Verbose=$($VerbosePreference -eq 'Continue') ; whatif=$($whatif) ;} ;
            if($thisCert.friendlyname){
                $pltSL.Tag = $thisCert.friendlyname
            } else { 
                $smsg = "Target Cert: $($thisCert.Subject) has a *blank* FriendLyName`nUsing cleaned SubjectName CN name (wo domain)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $pltSL.Tag = $thiscert.Subject.replace('CN=','').split('.')[0] ; 
            } ; 
            # if using [CmdletBinding(SupportsShouldProcess)] + -WhatIf:$($WhatIfPreference):
            #$pltSL=[ordered]@{Path=$null ;NoTimeStamp=$false ;Tag=$null ;showdebug=$($showdebug) ; Verbose=$($VerbosePreference -eq 'Continue') ; whatif=$($WhatIfPreference) ;} ;
            #$pltSL=[ordered]@{Path=$null ;NoTimeStamp=$false ;Tag="$($ticket)-$($TenOrg)-LASTPASS-" ;showdebug=$($showdebug) ; Verbose=$($VerbosePreference -eq 'Continue') ; whatif=$($WhatIfPreference) ;} ;
            #$pltSL.Tag = $ModuleName ; 
            if($script:rPSCommandPath){ $prxPath = $script:rPSCommandPath }
            elseif($script:PSCommandPath){$prxPath = $script:PSCommandPath}
            if($rMyInvocation.MyCommand.Definition){$prxPath2 = $rMyInvocation.MyCommand.Definition }
            elseif($MyInvocation.MyCommand.Definition){$prxPath2 = $MyInvocation.MyCommand.Definition } ; 
            if($prxPath){
                if(($prxPath -match $rgxPSAllUsersScope) -OR ($prxPath -match $rgxPSCurrUserScope)){
                    $bDivertLog = $true ; 
                    switch -regex ($prxPath){
                        $rgxPSAllUsersScope{$smsg = "AllUsers"} 
                        $rgxPSCurrUserScope{$smsg = "CurrentUser"}
                    } ;
                    $smsg += " context script/module, divert logging into [$budrv]:\scripts" 
                    write-verbose $smsg  ;
                    if($bDivertLog){
                        if((split-path $prxPath -leaf) -ne $cmdletname){
                            # function in a module/script installed to allusers|cu - defer name to Cmdlet/Function name
                            $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath "$($cmdletname).ps1") ;
                        } else {
                            # installed allusers|CU script, use the hosting script name
                            $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $prxPath -leaf)) ;
                        }
                    } ;
                } else {
                    $pltSL.Path = $prxPath ;
                } ;
           }elseif($prxPath2){
                if(($prxPath2 -match $rgxPSAllUsersScope) -OR ($prxPath2 -match $rgxPSCurrUserScope) ){
                     $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath (split-path $prxPath2 -leaf)) ;
                } elseif(test-path $prxPath2) {
                    $pltSL.Path = $prxPath2 ;
                } elseif($cmdletname){
                    $pltSL.Path = (join-path -Path "$($budrv):\scripts" -ChildPath "$($cmdletname).ps1") ;
                } else {
                    $smsg = "UNABLE TO RESOLVE A FUNCTIONAL `$CMDLETNAME, FROM WHICH TO BUILD A START-LOG.PATH!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Warn } #Error|Warn|Debug 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    BREAK ;
                } ; 
            } else{
                $smsg = "UNABLE TO RESOLVE A FUNCTIONAL `$CMDLETNAME, FROM WHICH TO BUILD A START-LOG.PATH!" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Warn } #Error|Warn|Debug 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                BREAK ;
            }  ;
            write-verbose "start-Log w`n$(($pltSL|out-string).trim())" ; 
            $logspec = start-Log @pltSL ;
            $error.clear() ;
            TRY {
                if($logspec){
                    $logging=$logspec.logging ;
                    $logfile=$logspec.logfile ;
                    $transcript=$logspec.transcript ;
                    $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
                    if($stopResults){
                        $smsg = "Stop-transcript:$($stopResults)" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    } ; 
                    $startResults = start-Transcript -path $transcript ;
                    if($startResults){
                        $smsg = "start-transcript:$($startResults)" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ; 
                } else {throw "Unable to configure logging!" } ;
            } CATCH [System.Management.Automation.PSNotSupportedException]{
                if($host.name -eq 'Windows PowerShell ISE Host'){
                    $smsg = "This version of $($host.name):$($host.version) does *not* support native (start-)transcription" ; 
                } else { 
                    $smsg = "This host does *not* support native (start-)transcription" ; 
                } ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;
            #endregion START-LOG-HOLISTIC #*------^ END START-LOG-HOLISTIC ^------
       
            if($thisCert.friendlyname){
                $appName = $thisCert.friendlyname ; 
            } else { 
                $smsg = "Target Cert: $($thisCert.Subject) has a *blank* FriendLyName`nsetting `$appName to cleaned SubjectName CN name (wo domain)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $appName = $ocert.Subject.replace('CN=','').split('.')[0] ; 
            } ; 
        
            if($thisCert.subject -match $rgxThisTenOrg){
                $smsg = "$($thisCert.subject) confirmed matches `$TenOrg CBA pattern: $($rgxThisTenOrg)" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            } else { 
                $smsg = "`n`n$($thisCert.subject) DOES NOT MATCH $TenOrg CBA pattern: $($rgxThisTenOrg)!" ; 
                $SMSG += "SKIPPING!`n(may want to issue disconnect-AzureAD if on wrong tenant)`n`n" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 

                $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
                if($stopResults){
                    $smsg = "Stop-transcript:$($stopResults)" ; 
                    # Opt:verbose
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    # # Opt:pswlt
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                } ; 

                $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                Continue
            } ; 

            #$Years=2 ; 
            if($appName.length -gt 32){write-warning "`$appName exceeds 32char limit!:`n$($appName)" ; Break ; } ; 
            #$certStore = "Cert:\CurrentUser\My" ;

            $appFqDN = "$(($appName.ToCharArray() |?{$_ -match '[a-zA-Z0-9-]'}) -join '').$($TenantDomain)" ;
            $appReplyUrl = $adalUrlIdentifier = "https://$($AppFqDN)/" ;

            $pltGAADA=[ordered]@{
                Filter = "DisplayName eq '$($appName)'" ;
                erroraction = 'STOP' ;
            } ;
            $smsg = "Get-AzureADApplication w`n$(($pltGAADA|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            if($application = Get-AzureADApplication @pltGAADA){}else{
                $smsg = "Unable to resolve certificate FriendlyName to an existing AzureADApplication Displayname!" ; 
                $smsg += "`nInput target Application Display, and we'll attempt to re-resolve" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $aDName = read-host "Input target existing AzureADApplication DisplayName" ; 
                $appName = $aDName ; 
                $pltGAADA.Filter = "DisplayName eq '$($appName)'" ;
                if($application = Get-AzureADApplication @pltGAADA){}else{
                    $smsg = "Unable to resolve specified Displayname to an existing AzureADApplication Displayname!`nABORTING!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
                    if($stopResults){
                        $smsg = "Stop-transcript:$($stopResults)" ; 
                        # Opt:verbose
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                        # # Opt:pswlt
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    } ; 
                    Continue ; 
                } ; 
            } ; 
            if($application){
                $nOwner = Get-AzureADApplicationOwner -ObjectId $application.ObjectId -ea STOP ; 
                $servicePrincipal = Get-AzureADServicePrincipal -All $true -ea STOP | Where-Object {$_.AppId -eq $application.AppId } ;
                if($KeyCred = $application | get-AzureADApplicationKeyCredential -erroraction Continue){
                    $smsg = "Remove expired/expiring existing KeyCred..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $pltRAADKeyCred=[ordered]@{
                        ObjectId = $application.ObjectId ;
                        KeyId = $KeyCred.KeyId ; 
                        erroraction = 'STOP' ;
                    } ;
                    $smsg = "Remove-AzureADApplicationKeyCredential w`n$(($pltRAADKeyCred|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    TRY{
                        Remove-AzureADApplicationKeyCredential @pltRAADKeyCred
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ; 
                    $KeyCred = $null ; # removed, no longer valid, will reuse on new
                } ; # $Keycred
                if(gci (join-path -path $certStore -childpath $thisCert.thumbprint)){
                    # clear old cert copy in store
                    $smsg = "Removing Existing Old Cert: `$thisCert | remove-item -force" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    TRY{
                        $thisCert | remove-item -force -verbose ; 
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ; 
                } ; 
                if(-not $Keycred_){
                    # copy the appname to cb, for searching key archive for updates & pfx pw etc
                    $smsg = "(copying the application.displayname to clipboard - for key vault lookup" ; 
                    $smsg += "`n$($application.displayname)`n)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $application.DisplayName | out-Clipboard ; 
                    # call new: New-AADAppAuthCertificate() (creates selfsigned cert, exports to pfx, returns summary)
                    $pltNAAC=[ordered]@{
                        DnsName=$AppFqDN ;
                        CertStoreLocation = $certStore ;
                        EndDate=$endDate ;
                        StartDate = $startDate ; 
                        verbose = $($verbose) ; 
                        whatif = $($whatif) ;
                    } ;
                    $smsg = "New-AADAppAuthCertificate w`n$(($pltNAAC|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $objAppAuthCert = New-AADAppAuthCertificate @pltNAAC ; 
                    if($objAppAuthCert.Valid){
                        $smsg = "New-AADAppAuthCertificate returned VALID outputs`n$(($objAppAuthCert|out-string).trim())" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        $certlocal = $objAppAuthCert.Certificate ; 
                        $certRaw = $objAppAuthCert.CertRaw ; 
                        # need to update: $pltExPfx.FilePath to a variable
                        $PfxPath = $objAppAuthCert.PFXPath ; 
                        $smsg = "Updating local FriendlyName:cert:PRE w`n$(($certlocal | fl $propsCert |out-string).trim())" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                        $certlocal.FriendlyName = $appName ; 
                        $smsg = "certlocal:FINAL w`n$(($certlocal | fl $propsCert |out-string).trim())`n`n" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } elseif($whatif){
                        $smsg = "-whatif: no return expected" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } else { 
                        $smsg ="New-AADAppAuthCertificate returned INVALID outputs`n$(($objAppAuthCert|out-string).trim())" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        throw $smsg ; 
                        break ; 
                    } ; 

                    $pltNAADAppKeyCred=[ordered]@{
                        ObjectId = $application.ObjectId ;
                        CustomKeyIdentifier = "$appName" ;
                        Type = 'AsymmetricX509Cert' ;
                        Usage = 'Verify' ;
                        Value = $certRaw ;
                        StartDate = $startDate ;
                        EndDate = $endDate.AddDays(-1) ;
                    } ;
                    $smsg = "New-AzureADApplicationKeyCredential w`n$(($pltNAADAppKeyCred|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    # 2:14 PM 6/9/2022 cap output, keep out of pipeline
                    $KeyCred = New-AzureADApplicationKeyCredential @pltNAADAppKeyCred ; 

    <#
    | SourceValue | Value | StoredAs            |
    | -------------------------------- | ------------------- |
    | Application (client) ID: | $($application.AppId)         | AppClientID         |
    | Directory (tenant) ID: | $($tenantDetail.ObjectId)           | Directory(tenant)ID |
    | DisplayName:  |$($application.DisplayName)                     | Dname               |
    | DnsNameList:  |$($certlocal) | DNSName             |
    | StartDate, EndDate:  |$($KeyCred.StartDate) $($KeyCred.EndDate)               | KeyCredDates        |
    | KeyId:  |$($KeyCred.KeyId)                            | KeyCredID           |
    | ObjectID: |$($application.ObjectID)                        | ObjectID            |
    | (demo EXO conn) |[`$pltCXOCThmb splat block below] | PSUse               |
    | SvcPrincipal.ObjectID: |$($servicePrincipal.ObjectId)           | SvcPrinObjID        |
    | Thumbprint: |$($certlocal.Thumbprint)                       | Thumbprint          |
    #>
                    $hInstructions =@"

#*======v POST CERT ROLLOVER INSTRUCTIONS ($($prcd)/$($ttl)): $($thiscert.Subject)::$($thiscert.thumbprint) v======

## AAD App Registration ApplicationKeyCredential Rollover Completed:
DisplayName:             $($application.DisplayName)
Application (client) ID: $($application.AppId) (AppID)
ObjectID:                $($application.ObjectID)
SvcPrincipal.ObjectID:   $($servicePrincipal.ObjectId)
Directory (tenant) ID:   $($tenantDetail.ObjectId)
Supported account types: $($tenantDetail.SignInAudience)
Client credentials:      $($tenantDetail.KeyCredentials)
Redirect URIs:           $($tenantDetail.ReplyUrls) 
IdentifierUris:          $($tenantDetail.IdentifierUris)
Owner:                   
$(($nOwner| ft -a $propsAADU|out-string).trim()))

... with ApplicationKeyCredential:
$(($KeyCred | fl $propsKeyCred |out-string).trim())

...with Certificate-Based-Authentication (CBA), using the cert:
$(($certlocal | fl $propsCert |out-string).trim())

... which is also exported to PFX at:
$($PfxPath) 

## To copy PFX back for storage:
copy-item -path $($PfxPath) -dest \\tsclient\c\usr\work\o365\certs\ -verbose

## Record the above for permanent reference (in password archive):

$(
$hsTable = @"
| SourceValue | Value | StoredAs |
| -------------------------------- | ------------------- |
| Application (client) ID: | $($application.AppId)| AppClientID |
| Directory (tenant) ID: | $($tenantDetail.ObjectId)| Directory(tenant)ID |
| DisplayName:  |$($application.DisplayName)| Dname |
| DnsNameList:  |$($certlocal.DnsNameList.unicode) | DNSName|
| StartDate, EndDate:  |$($KeyCred.StartDate) $($KeyCred.EndDate) | KeyCredDates |
| KeyId:  |$($KeyCred.KeyId)| KeyCredID |
| ObjectID: |$($application.ObjectID)| ObjectID |
| (demo EXO conn) |[`$pltCXOCThmb splat block below] | PSUse |
| SvcPrincipal.ObjectID: |$($servicePrincipal.ObjectId)| SvcPrinObjID |
| Thumbprint: |$($certlocal.Thumbprint)| Thumbprint |
"@ ; 
$hsTable| convertFrom-MarkdownTable | convertTo-MarkdownTable -border 

)

- also attach the PFX to key archive, 
- and set the key archive entry to EXPIRE one month before $($KeyCred.EndDate))

## The new Certificate+RegisteredApp combo should now be useable for authentication into configured o365 services.

### Verification against CBA logon using the app & local cert, into EXO:

`$pltCXOCThmb=[ordered]@{
CertificateThumbPrint = '$($certlocal.thumbprint)' ;
AppID = '$($application.AppId)' ;
Organization = '$($TenantDomain)' ;
Prefix = 'xo' ;
ShowBanner = `$false ;
};
write-host "Connect-ExchangeOnline w
`$((`$pltCXOCThmb|out-string).trim())" ;
try{Disconnect-ExchangeOnline ; get-pssession | Remove-PSSession ; Connect-ExchangeOnline @pltCXOCThmb } catch {Connect-ExchangeOnline @pltCXOCThmb } ;
get-xomailbox -resultsize 1 ;

"@ ; 
                    # credfile purge code, we know the details now, easiest to do it here, rather than manually post; and the file is worthless, the cert is gone/non-functional
                    if($credfile = get-childitem "$(split-path $profile)\keys" | ? {$_.Extension -eq '.psxml'} |?{$_.name -match [regex]::Escape($certlocal.FriendlyName)}){
                        $smsg = "Existing cred .psxml file:" ; 
                        $smsg += "`n$($credfile.fullname)"
                        $smsg += "`n...will need to be removed, and Get-AdminCred() run to reset the file to updated specs above" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        $pltRCF=[ordered]@{
                            path = $credfile.fullname ; 
                            force = $true ; 
                            erroraction = 'STOP' ;
                            verbose = $true ; 
                        } ;
                        $smsg = "Remove-item w`n$(($pltRCF|out-string).trim())" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        $smsg = "Do you want to remove the file _NOW_?" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                        $bRet=Read-Host "Enter YYY to continue. Anything else will exit"  ; 
                        if ($bRet.ToUpper() -eq "YYY") {
                            $smsg = "(Moving on)" ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            TRY{
                                remove-item @pltRCF ; 
                            } CATCH {
                                $ErrTrapd=$Error[0] ;
                                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } ; 

                            $hsCredFileRemove=@"

===========

## code to remove matching cred file from other machines:

get-childitem "$(split-path $profile)\keys" | ? {$_.Extension -eq '.psxml' -AND $_.name -match `"$([regex]::Escape($certlocal.FriendlyName))"} | remove-item -verbose -whatif ; 

"@ ; 

                            $hInstructions += $hsCredFileRemove ; 

                        } ;

                    } ; 

                    if($certlocal){
                        $hsCertLocalRemove=@"

===========

## code to remove matching in-hive Certificate 
$($thisCert.thumbprint) 
from other machines (before PFX import):

get-childitem $(join-path -path $certStore -childpath $thisCert.thumbprint) | remove-item -force -verbose ; ; 

"@ ; 

                            $hInstructions += $hsCertLocalRemove ; 

                    } ; 

                    if($pfxpath ){
                        $hsPFXImport=@"

===========

## code to import pfx file on other machines and set FriendlyName to application's displayname (required, as the certs are discovered via the FriendlyName value)

`$pltImport=[ordered]@{
    FilePath=`"$(join-path -path C:\usr\work\o365\certs\ -child (split-path $pfxpath -leaf))`" ;
    Exportable=`$True ;
    CertStoreLocation = 'Cert:\CurrentUser\My' ;
} ;
`$propsCert="thumbprint","notbefore","notafter","subject","FriendlyName","use","HasPrivateKey" ;
write-host -foregroundcolor yellow "ENTER PFX PW: (use 'dummy' for User Name)``n (friendlyname copied to CB)" ;
`$pfxcred=(Get-Credential -credential dummy) ;
write-verbose -verbose:`$true  "`$((get-date).ToString('HH:mm:ss')):Importing pfx to `$(`$env:computername)..." ;
`$pltImport.Add('Password',`$pfxcred.Password) ;
write-host "Import-PfxCertificate  w``n `$((`$pltImport|out-string).trim())" ;
`$certobj = Import-PfxCertificate @pltImport ;
`$certobj ;
if(`$certlocal=get-childitem "`$(`$pltImport.CertStoreLocation)\`$(`$certobj.thumbprint)"){
    `$appname = `$certlocal.subject.split('.')[0].replace('CN=o365','o365_') ;
    `$smsg = "Updating local FriendlyName:cert:PRE w`n`$((`$certlocal | fl `$propsCert |out-string).trim())" ;
    write-host `$smsg ;
    `$certlocal.FriendlyName = `$appName ;
    get-childitem "`$(`$pltImport.CertStoreLocation)\`$(`$certobj.thumbprint)" | fl `$propsCert ;
} else { write-host "missing installed cert:`$(`$pltImport.CertStoreLocation)\`$(`$certobj.thumbprint)" } ;



"@ ; 
                        $hInstructions += $hsPFXImport ; 
                    } ; 


                    $hInstructions += @"

#*======^ END POST CERT ROLLOVER INSTRUCTIONS  ^======

"@ ; 
                    
                    $smsg = $hInstructions ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    $smsg = "`n`n==>Be sure to run get-admincred() immediately after exiting this script!`n`n" ; 
                    $smsg += "`nThen close & reopen this PS window, to refresh to latest creds" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                    $outReport = [ordered]@{
                        Application = $application ; 
                        ServicePrincipal = $servicePrincipal ; 
                        TenantDetail = $tenantDetail ;
                        Owner = $nOwner ; 
                        KeyCred = $KeyCred ; 
                        Certificate = $certlocal ; 
                        PfxPath = $PfxPath ; 
                        PriorCertificateThumbprint = $thisCert.thumbprint ; 
                        Instructions = $hInstructions ; 
                    } ; 

                    $smsg = "Returning update summary to pipelinew`n$(($outReport.Certificate.Subject|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #$certlocal
                    New-Object PSObject -Property $outReport | write-output ; 
                    
                } ; # if -not $KeyCred
                                
            } ; # $application

            $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
            if($stopResults){
                $smsg = "Stop-transcript:$($stopResults)" ; 
                # Opt:verbose
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                # # Opt:pswlt
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } ; 

            $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            #if($prcd -le $ttl){
                #$smsg = "REMAINING PENDING CERTIFICATES TO PROCESS" ; 
                #$smsg += "`nwaiting here to permit data-recording on the above, before moving on" ; 
                $smsg = "`n(waiting here to permit data-recording on the above, before moving on)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $bRet=Read-Host "Enter YYY to continue."  ; 
                if ($bRet.ToUpper() -eq "YYY") {
                    $smsg = "(Moving on)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ; 
        
            #} ; 
        } ;  # loop-E

    }  # PROC-E
    END{
        $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    } ;  # END-E
} ;
#*------^ END Function Update-AADAppRegistrationKeyCertificate ^------ 