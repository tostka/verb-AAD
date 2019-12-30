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

#*------v Function Connect-MSOL v------
if(!(test-path function:connect-msol)){
    Function Connect-MSOL {
        <#
        .SYNOPSIS
        Connect-MSOL - Establish authenticated session to AzureAD MSOL Module, also works as reConnect-MSOL, there is no disConnect-MSOL (have to close Powershell to clear it).
        .NOTES
        Updated By: : Todd Kadrie
        Website:	http://tinstoys.blogspot.com
        Twitter:	http://twitter.com/tostka
        REVISIONS   :
        * 10:55 AM 12/6/2019 Connect-MSOL:added suffix to TitleBar tag for non-TOR tenants, also config'd a central tab vari
        * 1:07 PM 11/25/2019 added *tol/*tor/*cmw alias variants for connect & reconnect
        * 9:19 AM 11/19/2019 added MFA tenant detect (fr cred), and code to support MFA
        * 1:32 PM 5/8/2019 switched text into pipe with explicit Write-Verbose's
        * 2:51 PM 5/2/2019 ren'd Connect-AAD -> Connect-MSOL ; repurp'ing connect-aad for aad2 module
        * 12:06 PM 12/7/2018 added Alias 'connect-msol' -> 'Connect-AAD'
        * 7:38 AM 10/5/2018 out-null the pretesting Get-MsolAccountSku into a vari (was dumping into console)
        * 9:38 AM 9/10/2018 Connect-AAD: now it's working (?.?)7 weird. Also aliased reconnect-aad -> connect-AAD()- it's the same, but easier to just cover the gap.
        * 12:27 PM 11/3/2017 nope, not working, can't authenticate yet.
        * 12:19 PM 11/3/2017 this wasn't really written, sketched it in to see how it works
        .DESCRIPTION
        Connect-MSOL - Establish authenticated session to AzureAD/MSOL, also works as reconnect-AAD, there is no disConnect-MSOL (have to close Powershell to clear it).
        No need for separate reConnect-MSOL - this self tests for connection, and reconnects if it's missing.
        No support for disConnect-MSOL, because MSOL has no command to do it, but closing powershell.
        .PARAMETER  ProxyEnabled
        Proxyied connection support
        .PARAMETER CommandPrefix
        Prefix to be appended to commands (not implemented with MSOL/AAD)
        .PARAMETER Credential
        Credential to be used for connection
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. Returns no objects or output.
        .EXAMPLE
        Connect-MSOL
        .LINK
        #>

        Param(
            [Parameter()][boolean]$ProxyEnabled = $False,
            [Parameter()][string]$CommandPrefix,
            [Parameter()]$Credential = $global:credo365TORSID
        ) ;

        $MFA = get-TenantMFARequirement -Credential $Credential ;

        # 12:10 PM 3/15/2017 disable prefix spec, unless actually blanked (e.g. centrally spec'd in profile).
        #if(!$CommandPrefix){ $CommandPrefix='aad' ; } ;

        $sTitleBarTag="MSOL" ;
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

        <# expl of my profile xml credential storage points by account
        $LUAuid="TORO\kadrits" ;
        $SIDDomLogon="TORO\kadriTSS" ;
        if("$($env:USERDOMAIN)\$($env:USERNAME)" -eq $LUAuid ){
            # lua uid profile
            Import-Clixml "c:\usr\home\db\O365lua.xml" ;
        } elseif("$($env:USERDOMAIN)\$($env:USERNAME)" -eq $SIDDomLogon ){
          # sid profile
          Import-Clixml "c:\usr\home\db\O365SID.XML" ;
        #>

        try{Get-MsolAccountSku -ErrorAction Stop |out-null}
        catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
            Write-Verbose "Not connected to MSOnline. Now connecting." ;
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
            Write-Host "Connecting to AzureAD/MSOL"  ;
            $error.clear() ;
            if(!$MFA){
                Connect-MsolService -Credential $Credential -ErrorAction Stop ;
            } else {
                Connect-MsolService -ErrorAction Stop ;
            } ;
            # can still detect status of last command with $? ($true = success, $false = $failed), and use the $error[0] to examine any errors
            if ($?) { write-verbose -verbose:$true  "(Connected to MSOL)" ; Add-PSTitleBar $sTitleBarTag ; } ;
        } ;
    } ; #*------^ END Function Connect-MSOL ^------
} else { write-host -foregroundcolor green "(Deferring to pre-loaded connect-msol)" ;} ;
if(!(get-alias cmsol -ea 0) ) {Set-Alias 'cmsol' -Value 'Connect-MSOL' ; } ;
if(!(get-alias rmsol -ea 0) ) {Set-Alias 'rmsol' -Value 'Connect-MSOL' ; } ;
if(!(get-alias reConnect-MSOL -ea 0) ) {Set-Alias 'reConnect-MSOL' -Value 'Connect-MSOL' ; } ;
function cmsoltol {Connect-MSOL -cred $credO365TOLSID};
function cmsolcmw {Connect-MSOL -cred $credO365CMWCSID};
function cmsoltor {Connect-MSOL -cred $credO365TORSID};