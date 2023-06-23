# Remove-AADAppRegistrationCBAAuth.ps1

#*----------v Function Remove-AADAppRegistrationCBAAuth() v----------
function Remove-AADAppRegistrationCBAAuth {
    <#
    .SYNOPSIS
    Remove-AADAppRegistrationCBAAuth.ps1 - Remove AAD-Application that uses Certificate-Based-Auth (CBA): 1) remove any AzureADApplicationKeyCredential certs; 2)Remove the App itself; 3) Remove any local SelfSigned certificate (PKI) in specified -CertStoreLocation location
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : Remove-AADAppRegistrationCBAAuth.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,AzureAD,Authentication,Certificate,CertificateAuthentication
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 3:45 PM 6/23/2023 pulled req: verb-AAD 
    * 3:26 PM 6/22/2022 added chk for preexisting cred$TenOrg var, its freestanding, added cred & tenorg handling; debugs functional
    * 4:48 PM 6/20/2022 fixed pfxpath typo; added serviceprincipal check and sketched in removal (if remove-aadapp doesn't get it too) ; added verbose to aad removal cmds; fixed typo #146, $pfxpath spec; typo in the trailing if/then block
    * 2:54 PM 6/13/2022 debugged, functional
    .DESCRIPTION
    Remove-AADAppRegistrationCBAAuth.ps1 - Remove AAD-Application that uses Certificate-Based-Auth (CBA): 1) remove any AzureADApplicationKeyCredential certs; 2)Remove the App itself; 3) Remove any local SelfSigned certificate (PKI) in specified -CertStoreLocation location.
    .PARAMETER TenOrg
    Tenant Tag (3-letter abbrebiation)[-TenOrg 'XYZ']
    .PARAMETER DisplayName
    Certificate DisplayName (AppFQDN)[-DisplayName server.domain.com]
    .PARAMETER CertStoreLocation
    Certificate store for storage of new certificate[-CertStoreLocation 'Cert:\CurrentUser\My']
    .PARAMETER ObjectID
    New certificate lifespan in integer ObjectID[-ObjectID 3]
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Object
    .EXAMPLE
    PS> $results = remove-AADAppRegistrationCBAAuth -DisplayName 'Application Dname' -TenOrg 'XYZ' -verbose -whatif ; 
    Demos removal via displayname, whatif, with verbose
    .EXAMPLE
    PS> $results = remove-AADAppRegistrationCBAAuth -ObjectID '[guid]' -TenOrg 'XYZ' -whatif ; 
    Demos removal via AzureADApplication ObjectID, whatif
    .LINK
    https://github.com/tostka/verb-AAD    
    #>
    #Requires -Modules AzureAD, PKI, verb-IO, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Tenant Tag (3-letter abbrebiation)[-TenOrg 'XYZ']")]
        [ValidateNotNullOrEmpty()]
        [string]$TenOrg = 'TOR',
        [Parameter(HelpMessage="Target AzureADApplication DisplayName[-DisplayName 'application displayname]")]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$DisplayName,
        [Parameter(HelpMessage="Certificate store for storage of new certificate (defaults to CU\My)[-CertStoreLocation 'Cert:\LocalMachine\My']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$CertStoreLocation= 'Cert:\CurrentUser\My',
        [Parameter(HelpMessage="Target AzureADApplication ObjectID[-ObjectID '[guid]']")]
        [ValidateNotNullOrEmpty()]
        #[Alias('ALIAS1', 'ALIAS2')]
        [string]$ObjectID, 
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
        [switch] $whatIf
    ) ;
    #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
    # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
    write-verbose -verbose:$verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
    $Verbose = ($VerbosePreference -eq 'Continue') ; 
    
    $objReturn = @{
        Certificate = @(); 
        Application= $null ; 
        #PFXPath = $null ; 
        Success = $false ; 
    } ; 
    TRY{
        # no EXO, but we need AAD creds
        if($o365Cred=(get-TenantCredentials -TenOrg $TenOrg -UserRole 'SID','CSVC' -verbose:$($verbose))){
            # make it script scope, so we don't have to predetect & purge before using new-variable
            if(Get-Variable -Name cred$($tenorg) -scope Script -ea 0){
                Set-Variable -Name cred$($tenorg) -scope Script -Value $o365Cred.cred ;
            } else { 
                New-Variable -Name cred$($tenorg) -scope Script -Value $o365Cred.cred ;
            } ; 
            $smsg = "Resolved $($Tenorg) `$o365cred:$($o365Cred.cred.username) (assigned to `$cred$($tenorg))" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            #-=-record a STATUSERROR=-=-=-=-=-=-=
            $statusdelta = ";ERROR"; # CHANGE|INCOMPLETE|ERROR|WARN|FAIL ;
            if(gv passstatus -scope Script){$script:PassStatus += $statusdelta } ;
            if(gv -Name PassStatus_$($tenorg) -scope Script){set-Variable -Name PassStatus_$($tenorg) -scope Script -Value ((get-Variable -Name PassStatus_$($tenorg)).value + $statusdelta)} ; 
            #-=-=-=-=-=-=-=-=
            $smsg = "Unable to resolve $($tenorg) `$o365Cred value!"
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            throw "Unable to resolve $($tenorg) `$o365Cred value!`nEXIT!"
            BREAK ;
        } ;


        $pltRXO = @{
            Credential = (Get-Variable -name cred$($tenorg) ).value ;
            verbose = $($verbose) ; silent = $false ;} ; 

        Connect-AAD @pltRXO ; 

        if($DisplayName){
            $smsg = "Get-AzureADApplication -SearchString $($displayname)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $tApp = Get-AzureADApplication -SearchString $displayname -ea STOP -verbose:$($verbose); 
        } elseif ($ObjectID){
            $smsg = "Get-AzureADApplication -ObjectID $($ObjectID)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $tApp = Get-AzureADApplication -ObjectID $ObjectID -ea STOP -verbose:$($verbose); 
        } ; 
        
        if($tApp){
            $smsg = "matched AADApp:`n$(($tApp|out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
            $objReturn.Application = $tApp.ObjectID ; 
            $tKCs = $tApp | get-AzureADApplicationKeyCredential -ea STOP ;
            foreach($tkc in $tkcs){
                $objReturn.Certificate += $tkc.thumbprint ; 
                $smsg = "remove-AzureADApplicationKeyCredential:`n$(($tkc|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                if(!$whatif){
                    remove-AzureADApplicationKeyCredential -objectid $tapp.objectid -keyid $tkc.keyid -ErrorAction 'STOP' -verbose ;
                } else {
                    $smsg = "(-whatif)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
                }; 
            } ;
            if(!$whatif){
                $smsg = "Remove-AzureADApplication :`n$(($tapp|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $tapp | Remove-AzureADApplication -ErrorAction 'STOP' -verbose ; 
                # check for Get-AzureADServicePrincipal -All $true | Where-Object {$_.AppId -eq $appId} ;
                if($tsp = Get-AzureADServicePrincipal -All $true | Where-Object {$_.AppId -eq $tapp.AppID}){
                    $smsg = "SvcPrin: Remove-AzureADServicePrincipal:`n$(($tsp|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $tsp | Remove-AzureADServicePrincipal -ErrorAction 'STOP' -verbose ;   
                } ; 
            } else {
                $smsg = "(-whatif)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
            }; 
            $appfqdnName = ($tapp.displayname.ToCharArray() |?{$_ -match '[a-zA-Z0-9-]'}) -join '' ; 
            
            if($objReturn.Certificate = gci "$CertStoreLocation\*" | ? friendlyname -eq $tapp.displayname ){
                $smsg = "Matched cert by FriendlyName:$($appfqdnName)" ;    
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
            } elseif($objReturn.Certificate =  gci "$CertStoreLocation\*" |? subject -like "CN=$($appfqdnName)*"){
                $smsg = "Matched cert by AppFqDN string:$($appfqdnName)" ;    
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
            } ; 
            if($objReturn.Certificate){
                $smsg = "Remove-Item:`n$(($objReturn.Certificate|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $objReturn.Certificate| remove-item -whatif:$($whatif) -ErrorAction 'STOP' -verbose ;

                # check for pfx built around the found cert:
                #  C:\Users\USER\Documents\WindowsPowerShell\keys\o365SIDCBACert-XYZ.TENDOMAIN.onmicrosoft.com-NOTAFTER-20240616-1118AM.pfx
                # dnsname == $appFqDN = "$(($appName.ToCharArray() |?{$_ -match '[a-zA-Z0-9-]'}) -join '').$($TenantDomain)" ;
                # FilePath="$(split-path $profile)\keys\$($DnsName)-NOTAFTER-$(get-date $pltNSSCert.notafter -format 'yyyyMMdd-HHmmtt').pfx" ;
                $pfxPath = gci -path "$(split-path $profile)\keys\$($objReturn.Certificate.subjectname.name.replace('CN=',''))-NOTAFTER-$(get-date $objReturn.Certificate.notafter -format 'yyyyMMdd-HHmmtt').pfx" -ea SilentlyContinue ;
                if($pfxPath){
                    $smsg = "Remove-Item:`n$(($pfxPath|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $pfxPath.FullName | remove-item -whatif:$($whatif) -ErrorAction 'STOP' -verbose ;
                } ; 
            } ; 
        } else {
            $smsg = "Nomatch GAADApp:$($displayname)" 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
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
    
    if($objReturn.Certificate -And $objReturn.Application ){ 
        $smsg = "Valid Certificate, Application: Setting Success:`$true" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $objReturn.Success = $true ; 
    }elseif($whatif){
        $smsg = "(-whatif:not setting `$objReturn.Success:$true)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $objReturn.Success = $true ; 
    } else { 
        $smsg = "INVALID AADApplication/CERTIFICATE removal attempt: Setting Success:`$FALSE" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        $objReturn.Success = $false 
    } ; 
    New-Object -TypeName PSObject -Property $objReturn | write-output ;     
} ;  
#*------^ END Function Remove-AADAppRegistrationCBAAuth ^------