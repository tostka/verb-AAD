# profile-AAD-Signons.ps1

#*------v Function profile-AAD-Signons v------
Function profile-AAD-Signons {
    <#
    .SYNOPSIS
    profile-AAD-Signons - profile AAD Sign-ons Activity JSON dump Splitbrain and outline remediation steps
    .NOTES
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Additional Credits: REFERENCE
    Website:	URL
    Twitter:	URL
    REVISIONS   : 
    * 5:09 PM 2/2/2023 updated to -indent support, latest w-l support, I believe I've now got it logging *everything*, to capture the full report into the logs.
    * 2:41 PM 1/30/2023 fixed fundemental path-discovery breaks since moving it into verb-AAD (wasn't discovering any prior .ps1 paths; needed function discovery code spliced in). : 
    * 11:18 AM 9/16/2021 string cleaning
    * 3:04 PM 6/16/2021, shifted to standard start-log mod support, conditioned helper funcs, added test for events in target file, echo on gap
    * 11:11 AM 6/15/2021 Ren'd Build-AADSignErrorsHash() -> Initialize-AADSignErrorsHash (compliant verb) ; sync'd copy & set it to defer to the verb-AAD mod version
    # 10:46 AM 6/2/2021 sub'd verb-logging for v-trans
    * 9:19 AM 8/29/2019 fixed $filterdesc's, alot didn't match the actual filters, added device.displayname (workstation name, blank on a lot of browsers too), also added correlid, requsestidto fail dumps, as some error recommend a ticket with those values and the errornumber
    * * 2:49 PM 8/27/2019 updated errornumber 0 to be (undocumented - successful), as it is the code on a non-error logon
    * 12:22 PM 8/26/2019 hybrid in a *lot* of code and color-coding (get-colorcombo) from older 5/19 profile-AADSignOnsJson.ps1 (forgotten I had it), which resolves the error codes into useful descriptions
    * 1:48 PM 8/20/2019 v0.1.1 reworked outputs to cleanup and hibrid, delimted the trailing evt dumps too.
    * 1:01 PM 8/20/2019 v0.1.0 init vers (converted check-ExosplitBrain.ps1), subbed in write-log from verb-transcript (debug support)
    .DESCRIPTION
    profile-AAD-Signons.ps1 - profile AAD Sign-ons Activity JSON dump Splitbrain and outline remediation steps

    ## Retrieve logs for a given user via AAD Portal [process in 1/30/2023 UI]

    1. Edge browse: https://portal.azure.com/ 
    2. Azure AD > Users > [search]
    3. UL pane: click Sign-in logs
    4. Date: Last 1 month, _Apply_ 
    5. Columns: [x]ALL!, OK
    6. Add-Filters:
      - (x) Status >  'Status: None Selected' > [x]Success|Failure|Interrupted, Apply 
      > Application: *appears* to be Client, not resource 
      > Office 365 Exchange Online - looks like OWA?
      > Outlook Mobile - OM (?)
    7. Click _Download_ to pull down, export to csv/(x)json. (preserves the sub-objects!)
      -  Ren default filename: `SignIns_2022-12-31_2023-01-30` ->
      `TICKET-AADSignIns-UPNPREFIX-30d_2022-12-31_2023-01-30`
    8. _Download_
    9. Pops dlg: click _Save as_ (v Save).  
    10. Click _Downloads_ toolbar link in Edge (far L) > find the download, click _Show in folder_ > explorer opens host folder. 
    11. Locate file & Move to:  `d:\scripts\logs\`
    12. Profile the resulting .json file in this script:
    
    PS> profile-AAD-Signons -Files [fullpath to json] ; 

    .PARAMETER  UPNs
    User Userprincipalnames (array)[-UPNs]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    PS> profile-AAD-Signons -Files "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json";
    Process a single json AAD signon log
    .EXAMPLE
    PS> profile-AAD-Signons -Files "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json","c:\usr\work\incid\todd.USER-SignIns__2019-07-07__2019-08-06b.csv.json" ;
    Process an array of json AAD signon logs
    .LINK
    #>
    ### Note: vers 2: #Requires -Version 2.0
    ##Requires -Modules ActiveDirectory
    ##Requires -Version 3
    Param(
        [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Files [-file c:\path-to\file.ext]")]
        [array]$Files,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) # PARAM BLOCK END

    $whatif=$true ;
    #region INIT; # ------
    #*======v SCRIPT/DOMAIN/MACHINE/INITIALIZATION-DECLARE-BOILERPLATE v======
    # SCRIPT-CONFIG MATERIAL TO SET THE UNDERLYING $DBGPREF:
    if ($ShowDebug) { $DebugPreference = "Continue" ; write-debug "(`$showDebug:$showDebug ;`$DebugPreference:$DebugPreference)" ; };
    if ($Whatif){Write-Verbose -Verbose:$true "`$Whatif is TRUE (`$whatif:$($whatif))" ; };
    if($showDebug){$ErrorActionPreference = 'Stop' ; write-debug "(Setting `$ErrorActionPreference:$ErrorActionPreference;"};
    # If using WMI calls, push any cred into WMI:
    #if ($Credential -ne $Null) {$WmiParameters.Credential = $Credential }  ;

    # 2:28 PM 1/30/2023 getting fail on all path res, update to current mixed discovery
    # scriptname with extension
    #if ($PSScriptRoot -eq "") {
    if( -not (get-variable -name PSScriptRoot -ea 0) -OR ($PSScriptRoot -eq '')){
        if ($psISE) { $ScriptName = $psISE.CurrentFile.FullPath } 
        elseif($psEditor){
            if ($context = $psEditor.GetEditorContext()) {$ScriptName = $context.CurrentFile.Path } 
        } elseif ($host.version.major -lt 3) {
            $ScriptName = $MyInvocation.MyCommand.Path ;
            $PSScriptRoot = Split-Path $ScriptName -Parent ;
            $PSCommandPath = $ScriptName ;
        } else {
            if ($MyInvocation.MyCommand.Path) {
                $ScriptName = $MyInvocation.MyCommand.Path ;
                $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent ;
            } else {throw "UNABLE TO POPULATE SCRIPT PATH, EVEN `$MyInvocation IS BLANK!" } ;
        };
        if($ScriptName){
            $ScriptDir = Split-Path -Parent $ScriptName ;
            $ScriptBaseName = split-path -leaf $ScriptName ;
            $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($ScriptName) ;
        } ; 
    } else {
        if($PSScriptRoot){$ScriptDir = $PSScriptRoot ;}
        else{
            write-warning "Unpopulated `$PSScriptRoot!" ; 
            $ScriptDir=(Split-Path -parent $MyInvocation.MyCommand.Definition) + "\" ;
        }
        if ($PSCommandPath) {$ScriptName = $PSCommandPath } 
        else {
            $ScriptName = $myInvocation.ScriptName
            $PSCommandPath = $ScriptName ;
        } ;
        $ScriptBaseName = (Split-Path -Leaf ((& { $myInvocation }).ScriptName))  ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;
    } ;
    if(!$ScriptDir){
        write-host "Failed `$ScriptDir resolution on PSv$($host.version.major): Falling back to $MyInvocation parsing..." ; 
        $ScriptDir=(Split-Path -parent $MyInvocation.MyCommand.Definition) + "\" ;
        $ScriptBaseName = (Split-Path -Leaf ((&{$myInvocation}).ScriptName))  ; 
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;     
    } else {
        if(-not $PSCommandPath ){
            $PSCommandPath  = $ScriptName ; 
            if($PSCommandPath){ write-host "(Derived missing `$PSCommandPath from `$ScriptName)" ; } ;
        } ; 
        if(-not $PSScriptRoot  ){
            $PSScriptRoot   = $ScriptDir ; 
            if($PSScriptRoot){ write-host "(Derived missing `$PSScriptRoot from `$ScriptDir)" ; } ;
        } ; 
    } ; 
    if(-not ($ScriptDir -AND $ScriptBaseName -AND $ScriptNameNoExt)){ 
        throw "Invalid Invocation. Blank `$ScriptDir/`$ScriptBaseName/`ScriptNameNoExt" ; 
        BREAK ; 
    } ; 

    $smsg = "`$ScriptDir:$($ScriptDir)" ;
    $smsg += "`n`$ScriptBaseName:$($ScriptBaseName)" ;
    $smsg += "`n`$ScriptNameNoExt:$($ScriptNameNoExt)" ;
    $smsg += "`n`$PSScriptRoot:$($PSScriptRoot)" ;
    $smsg += "`n`$PSCommandPath:$($PSCommandPath)" ;  ;
    write-host $smsg ; 
    $ComputerName = $env:COMPUTERNAME ;
    $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
    #$smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
    $smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;
    $smtpTo=$TORMeta['NotificationAddr1'] ;
    $sQot = [char]34 ; $sQotS = [char]39 ;

    #$ProgInterval= 500 ; # write-progress wait interval in ms
    # 12:23 PM 2/20/2015 add gui vb prompt support
    #[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null ;
    # 11:00 AM 3/19/2015 should use Windows.Forms where possible, more stable



    #*======v FUNCTIONS v======

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        #region WriteLogS ;#*======v Write-Log SIMPLIFIED (psb-psWriteLog.cbp) v======
if(-not(get-command write-log -ea 0)){
    #*------v Function write-log v------
    <# write-log includable version, does FULL RANGE of levels, but has stripped down comments and details
    - Call: 
    write-verbose 'define log before first call:'
    $logfile = "c:\scripts\logs\$($env:COMPUTERNAME)-Exzd-check-$(get-date -format 'yyyyMMdd-HHmmtt')-trans-log.txt" ; 
    $smsg = "Unable to locate IIS logs through WebAdmin module!" ;
    write-Log -message $smsg -Path $logfile -useHost -Level Warn ;
    - syntax matches 7pswlt, aside from _ name prefix7ah
    - can be unwrapped wo issues (no comments within).
    - works well where start/stop-transcript aren't supported but you want to capture results into a file (Remote invoke-command, enter-pssession etc)
    Native indent support relies on setting the $env:HostIndentSpaces to target indent. 
    Also leverages following verb-io funcs: (life cycle: (init indent); (mod indent); write-log -indent; (clear indent e-vari))
    (reset-HostIndent), (push-HostIndent,pop-HostIndent,set-HostIndent), write-log -indent, (clear-HostIndent).
    #>
    function write-log  {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, 
                HelpMessage = "Message is the content that you wish to add to the log file")]
                [ValidateNotNullOrEmpty()][Alias("LogContent")]
                [Alias('Message')] 
                [System.Object]$Object,
            [Parameter(Mandatory = $false, 
                HelpMessage = "The path to the log file to which you would like to write. By default the function will create the path and file if it does not exist.")]
                [Alias('LogPath')]
                [string]$Path = 'C:\Logs\PowerShellLog.log',
            [Parameter(Mandatory = $false, 
                HelpMessage = "Specify the criticality of the log information being written to the log (defaults Info): (Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success)[-level Info]")]
                [ValidateSet('Error','Warn','Info','H1','H2','H3','H4','H5','Debug','Verbose','Prompt','Success')]
                [string]$Level = "Info",
            [Parameter(
                HelpMessage = "Switch to use write-host rather than write-[verbose|warn|error] [-useHost]")]
                [switch] $useHost,
            [Parameter(
                HelpMessage="Specifies the background color. There is no default. The acceptable values for this parameter are:
        (Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | White)")]
                [System.ConsoleColor]$BackgroundColor,
            [Parameter(
                HelpMessage="Specifies the text color. There is no default. The acceptable values for this parameter are:
    (Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | White)")]
                [System.ConsoleColor]$ForegroundColor,
            [Parameter(
                HelpMessage="The string representations of the input objects are concatenated to form the output. No spaces or newlines are inserted between
    the output strings. No newline is added after the last output string.")]
                [System.Management.Automation.SwitchParameter]$NoNewline,
            [Parameter(
                HelpMessage = "Switch to use write-HostIndent-type code for console echos(see get-help write-HostIndent)[-useHost]")]
                [Alias('in')]
                [switch] $Indent,
             [Parameter(
                HelpMessage = "Switch to strip empty lines when using -Indent (which auto-splits multiline Objects)[-Flatten]")]
                #[Alias('flat')]
                [switch] $Flatten,
            [Parameter(
                HelpMessage="Specifies a separator string to insert between objects displayed by the host.")]
            [System.Object]$Separator,
            [Parameter(
                HelpMessage="Character to use for padding (defaults to a space).[-PadChar '-']")]
            [string]$PadChar = ' ',
            [Parameter(
                HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrment 8]")]
            [int]$PadIncrment = 4,
            [Parameter(
                    HelpMessage = "Switch to suppress console echos (e.g log to file only [-NoEcho]")]
                [switch] $NoEcho,
            [Parameter(Mandatory = $false, 
                HelpMessage = "Use NoClobber if you do not wish to overwrite an existing file.")]
                [switch]$NoClobber,
            [Parameter(
                HelpMessage = "Debugging Flag [-showDebug]")]
                [switch] $showDebug,
            [Parameter(
                HelpMessage = "Switch to output a demo display of each Level, and it's configured color scheme (requires specification of a 'dummy' message string to avoid an error).[-Demo]")]
                [switch] $demo
        )  ;
        BEGIN {
            ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
            $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
            write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
            $Verbose = ($VerbosePreference -eq 'Continue') ;     
            $pltWH = @{ Object = $null ; } ; 
            if ($PSBoundParameters.ContainsKey('BackgroundColor')) {$pltWH.add('BackgroundColor',$BackgroundColor) ; } ;
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $pltWH.add('ForegroundColor',$ForegroundColor) ;} ;
            if ($PSBoundParameters.ContainsKey('NoNewline')) {$pltWH.add('NoNewline',$NoNewline) ; } ;
            if($Indent){
                if ($PSBoundParameters.ContainsKey('Separator')) {$pltWH.add('Separator',$Separator) ; } ;
                if (-not ([int]$CurrIndent = (Get-Item -Path Env:HostIndentSpaces -erroraction SilentlyContinue).Value ) ){[int]$CurrIndent = 0 ; } ; 
                write-verbose "$($CmdletName): Discovered `$env:HostIndentSpaces:$($CurrIndent)" ; 
            } ; 
            if($host.Name -eq 'Windows PowerShell ISE Host' -AND $host.version.major -lt 3){
                $pltError=@{foregroundcolor='yellow';backgroundcolor='darkred'};
                $pltWarn=@{foregroundcolor='DarkMagenta';backgroundcolor='yellow'};
                $pltInfo=@{foregroundcolor='gray';backgroundcolor='darkblue'};
                $pltH1=@{foregroundcolor='black';backgroundcolor='darkyellow'};
                $pltH2=@{foregroundcolor='darkblue';backgroundcolor='gray'};
                $pltH3=@{foregroundcolor='black';backgroundcolor='darkgray'};
                $pltH4=@{foregroundcolor='gray';backgroundcolor='DarkCyan'};
                $pltH5=@{foregroundcolor='cyan';backgroundcolor='DarkGreen'};
                $pltDebug=@{foregroundcolor='red';backgroundcolor='black'};
                $pltVerbose=@{foregroundcolor='darkgray';backgroundcolor='black'};
                $pltPrompt=@{foregroundcolor='DarkMagenta';backgroundcolor='darkyellow'};
                $pltSuccess=@{foregroundcolor='Blue';backgroundcolor='green'};
            } else {
                $pltError=@{foregroundcolor='yellow';backgroundcolor='darkred'};
                $pltWarn=@{foregroundcolor='DarkMagenta';backgroundcolor='yellow'};
                $pltInfo=@{foregroundcolor='gray';backgroundcolor='darkblue'};
                $pltH1=@{foregroundcolor='black';backgroundcolor='darkyellow'};
                $pltH2=@{foregroundcolor='darkblue';backgroundcolor='gray'};
                $pltH3=@{foregroundcolor='black';backgroundcolor='darkgray'};
                $pltH4=@{foregroundcolor='gray';backgroundcolor='DarkCyan'};
                $pltH5=@{foregroundcolor='cyan';backgroundcolor='DarkGreen'};
                $pltDebug=@{foregroundcolor='red';backgroundcolor='black'};
                $pltVerbose=@{foregroundcolor='darkgray';backgroundcolor='black'};
                $pltPrompt=@{foregroundcolor='DarkMagenta';backgroundcolor='darkyellow'};
                $pltSuccess=@{foregroundcolor='Blue';backgroundcolor='green'};
            } ; 
            if ($PSCmdlet.MyInvocation.ExpectingInput) {
                write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
            } else {
                write-verbose "(non-pipeline - param - input)" ; 
            } ; 
        }  ;
        PROCESS {
                if($Flatten){
                    if($object.gettype().name -eq 'FormatEntryData'){
                        write-verbose "skip split/flatten on these (should be pre-out-string'd before write-logging)" ; 
                    } else { 
                        [string[]]$Object = [string[]]$Object.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) ;
                    } ; 
                } else { 
                    [string[]]$Object = [string[]]$Object.ToString().Split([Environment]::NewLine) 
                } ; 
                if ((Test-Path $Path) -AND $NoClobber) {
                    Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."  ;
                    Return  ;
                } elseif (!(Test-Path $Path)) {
                    Write-Verbose "Creating $Path."  ;
                    $NewLogFile = New-Item $Path -Force -ItemType File  ;
                } else { }  ;
                $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"  ;
                $EchoTime = "$((get-date).ToString('HH:mm:ss')): " ;
                $pltWH.Object = $EchoTime ; 
                $pltColors = @{} ; 
                switch ($Level) {
                    'Error' {$LevelText = 'ERROR: ' ; $pltColors = $pltErr ; 
                        if ($useHost) {} else {if (!$NoEcho) { Write-Error ($smsg + $Object) } } ;}
                    'Warn' { $LevelText = 'WARNING: ' ; $pltColors = $pltWarn ; 
                        if ($useHost) {} else {if (!$NoEcho) { Write-Warning ($smsg + $Object) } } ;}
                    'Info' {$LevelText = 'INFO: ' ;  $pltColors = $pltInfo ; }
                    'H1' { $LevelText = '# ' ; $pltColors = $pltH1 ; }
                    'H2' {$LevelText = '## ' ; $pltColors = $pltH2 ;  }
                    'H3' {$LevelText = '### ' ; $pltColors = $pltH3 ; }
                    'H4' {$LevelText = '#### ' ; $pltColors = $pltH4 ; }
                    'H5' { $LevelText = '##### ' ;  $pltColors = $pltH5 ; }
                    'Debug' {$LevelText = 'DEBUG: ' ; $pltColors = $pltDebug ; 
                        if ($useHost) {} else {if (!$NoEcho) { Write-Degug $smsg } }  ; }
                    'Verbose' {
                        $LevelText = 'VERBOSE: ' ; $pltColors = $pltVerbose ; 
                        if ($useHost) {}else {if (!$NoEcho) { Write-Verbose ($smsg) } } ;  }
                    'Prompt' {$LevelText = 'PROMPT: ' ; $pltColors = $pltPrompt ; }
                    'Success' {$LevelText = 'SUCCESS: ' ; $pltColors = $pltSuccess ; }
                } ;
                if($pltColors.foregroundcolor){
                if(-not ($pltWH.keys -contains 'foregroundcolor')){
                    $pltWH.add('foregroundcolor',$pltColors.foregroundcolor) ; 
                } elseif($pltWH.foregroundcolor -eq $null){
                    $pltWH.foregroundcolor = $pltColors.foregroundcolor ; 
                } ; 
            } ; 
            if($pltColors.backgroundcolor){
                if(-not ($pltWH.keys -contains 'backgroundcolor')){
                    $pltWH.add('backgroundcolor',$pltColors.backgroundcolor) ; 
                } elseif($pltWH.backgroundcolor -eq $null){
                    $pltWH.backgroundcolor = $pltColors.backgroundcolor ; 
                } ; 
            } ; 
                if ($useHost) {
                    if(-not $Indent){
                        if($Level -match '(Debug|Verbose)' ){$pltWH.Object += "$($LevelText) ($($Object))" ;
                        } else { $pltWH.Object += "$($LevelText) $($Object)" ; } ; 
                        $smsg = "write-host w`n$(($pltWH|out-string).trim())" ; 
                        write-host @pltwh ; 
                    } else { 
                        write-verbose 'indent support' ; 
                        foreach ($obj in $object){
                            $pltWH.Object = $EchoTime ; 
                            if($Level -match '(Debug|Verbose)' ){
                                if($obj.length -gt 0){ $pltWH.Object += "$($LevelText) ($($obj))" ;
                                } else { $pltWH.Object += "$($LevelText)" ;} ; 
                            } else {$pltWH.Object += "$($LevelText) $($obj)" ;} ; 
                            Write-Host -NoNewline $($PadChar * $CurrIndent)  ; 
                            write-host @pltwh ; 
                        } ; 
                    } ; 
                } 
                "$FormattedDate $LevelText : $Object" | Out-File -FilePath $Path -Append  ;
        }  ; 
    } ; 
    #*------^ Write-Log.ps1 ^------
} ; 
<# VERS: * 2:58 PM 2/2/2023 updated fr prim vers
11:47 AM 1/17/2023 rearranged comments
#>
#endregion  ; #*======^ Write-Log SIMPLIFIED (psb-psWriteLog.cbp) ^======

    #region HostIndentS ; #*======v HostIndent SIMPLIFIED (psb-psHostIndent.cbp) v======
    if(-not(get-command HostIndent -ea 0)){
        #*------v Function HostIndent v------
        <# HostIndent includable version of core cmdlets, has stripped down comments and details
        - Call: 
        write-verbose 'define log before first call:'
        $smsg = "Unable to locate IIS logs through WebAdmin module!" ;
        HostIndent -message $smsg ;
        - can be unwrapped wo issues (no comments within).
        - works well where you have complicated console output, but verb-io isn't supported (or verb-logging, for write-log)
        Native indent support relies on setting the $env:HostIndentSpaces to target indent. 
        Also leverages following verb-io funcs: (life cycle: (init indent); (mod indent); Write-HostIndent; (clear indent e-vari))
        (reset-HostIndent), (push-HostIndent,pop-HostIndent,set-HostIndent),Write-HostIndent,  (clear-HostIndent),
        Write-HostIndent -ForegroundColor Gray "($Domain)" -verbose ;
        #>
        #*------v Function reset-HostIndent v------
        function reset-HostIndent {
            <# * 2:01 PM 2/1/2023 add: -PID param
            #>
            [CmdletBinding()]
            [Alias('r-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrement 8]")]
                [int]$PadIncrement = 4,
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ; 
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;     
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $HISName = "Env:HostIndentSpaces$($PID)" ; 
                } else { 
                    $HISName = "Env:HostIndentSpaces" ; 
                } ; 
            
                if(($smsg = Get-Item -Path "Env:HostIndentSpaces$($PID)" -erroraction SilentlyContinue).value){
                  write-verbose $smsg ; 
                } ; 
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ; 
                } ; 
                $pltSV=[ordered]@{
                    Path = $HISName 
                    Value = 0; 
                    Force = $true ; 
                    erroraction = 'STOP' ;
                } ;
                $smsg = "$($CmdletName): Set 1 lvl:Set-Variable w`n$(($pltSV|out-string).trim())" ; 
                write-verbose $smsg  ;
                TRY{
                    Set-Item @pltSV #-verbose ; 
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    BREAK ;
                } ;
            } ;  
        } ; 
        #*------^ END Function reset-HostIndent ^------
    } ; 
    if(-not(get-command push-HostIndent -ea 0)){
        #*------v Function push-HostIndent v------
        function push-HostIndent {
            <#
            * 2:01 PM 2/1/2023 add: -PID param
            #>
            [CmdletBinding()]
            [Alias('push-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrement 8]")]
                [int]$PadIncrement = 4,
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ;
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;
                write-verbose "$($CmdletName): Using `$PadIncrement:`'$($PadIncrement)`'" ;
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ;
                } ;
                write-verbose "$($CmdletName): Discovered `$$($HISName):$($CurrIndent)" ;
                $pltSV=[ordered]@{
                    Path = $HISName ;
                    Value = [int](Get-Item -Path $HISName -erroraction SilentlyContinue).Value + $PadIncrement;
                    Force = $true ;
                    erroraction = 'STOP' ;
                } ;
                $smsg = "$($CmdletName): Set 1 lvl:Set-Variable w`n$(($pltSV|out-string).trim())" ;
                write-verbose $smsg  ;
                TRY{
                    #Set-Variable @pltSV -verbose ;
                    Set-Item @pltSV #-verbose ;
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    BREAK ;
                } ;
            } ; 
        } ;
        #*------^ END Function push-HostIndent ^------
    } ; 
    if(-not(get-command pop-HostIndent -ea 0)){
        #*------v Function pop-HostIndent v------
        function pop-HostIndent {
            <#
            * 2:01 PM 2/1/2023 add: -PID param
            #>
            [CmdletBinding()]
            [Alias('pop-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrement 8]")]
                    [int]$PadIncrement = 4,
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ; 
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;     
                write-verbose "$($CmdletName): Using `$PadIncrement:`'$($PadIncrement)`'" ; 
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                if(($smsg = Get-Item -Path "Env:HostIndentSpaces$($PID)" -erroraction SilentlyContinue).value){
                  write-verbose $smsg ; 
                } ; 
            
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ; 
                } ; 
                write-verbose "$($CmdletName): Discovered `$$($HISName):$($CurrIndent)" ;  
                if(($NewIndent = $CurrIndent - $PadIncrement) -lt 0){
                    write-warning "$($CmdletName): `$HostIndentSpaces has reached 0/left margin (limiting to 0)" ; 
                    $NewIndent = 0 ; 
                } ; 
                $pltSV=[ordered]@{
                    Path = $HISName ; 
                    Value = $NewIndent ; 
                    Force = $true ; 
                    erroraction = 'STOP' ;
                } ;
                $smsg = "$($CmdletName): Set 1 lvl:Set-Variable w`n$(($pltSV|out-string).trim())" ; 
                write-verbose $smsg  ;
                TRY{
                    #Set-Variable @pltSV -verbose ; 
                    Set-Item @pltSV #-verbose ; 
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    BREAK ;
                } ;
            } ; 
        } ; 
        #*------^ END Function pop-HostIndent ^------
    } ; 
    if(-not(get-command set-HostIndent -ea 0)){
        #*------v Function set-HostIndent v------
        function set-HostIndent {
            <#
            * 2:01 PM 2/1/2023 add: -PID param
            #>
            [CmdletBinding()]
            [Alias('pop-hi')]
            PARAM(
                [Parameter(Position=0,
                    HelpMessage="Number of spaces to set write-hostIndent current indent (`$scop:HostIndentpaces) to.[-Spaces 8]")]
                    [int]$Spaces,
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrement 8]")]
                [int]$PadIncrement = 4,
                [Parameter(
                    HelpMessage="Mathematical rounding logic to use for calculating nearest multiple of PadIncrement (RoundUp|RoundDown|AwayFromZero|Midpoint, default:RoundUp)[-Rounding awayfromzero]")]
                    [ValidateSet('RoundUp','RoundDown','AwayFromZero','Midpoint')]
                    [string]$Rounding = 'RoundUp',
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ;
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;
                write-verbose "$($CmdletName): Using `$PadIncrement:`'$($PadIncrement)`'" ;
                switch($Rounding){
                    'RoundUp' {
                        # always round up (to next higher multiple)
                        $Spaces = ([system.math]::ceiling($Spaces/$PadIncrement))*$PadIncrement  ;
                        write-verbose "Rounding:Roundup specified: Rounding to: $($Spaces)" ;
                        }
                    'RoundDown' {
                        # always round down (to next lower multiple)
                        $Spaces = ([system.math]::floor($Spaces/$PadIncrement))*$PadIncrement  ;
                        write-verbose "Rounding:RoundDown specified: Rounding to: $($Spaces)" ;
                        }
                    'AwayFromZero' {
                        # traditional school: 'when remainder is 5 round up'
                        $Spaces = ([system.math]::round($_/$PadIncrement,0,1))*$PadIncrement  ;
                        write-verbose "Rounding:AwayFromZero specified: Rounding to: $($Spaces)" ;
                    }
                    'Midpoint' {
                        # default programatic/banker's rounding: if midpoint 5, round to the *nearest even number*'
                        $Spaces = ([system.math]::round($_/$PadIncrement))*$PadIncrement  ;
                        write-verbose "Rounding:Midpoint specified: Rounding to: $($Spaces)" ;
                    }
                } ;
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                if(($smsg = Get-Item -Path "Env:HostIndentSpaces$($PID)" -erroraction SilentlyContinue).value){
                  write-verbose $smsg ; 
                } ; 
            
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ;
                } ;
                write-verbose "$($CmdletName): Discovered `$$($HISName):$($CurrIndent)" ;
                $pltSV=[ordered]@{
                    Path = $HISName ;
                    Value = $Spaces;
                    Force = $true ;
                    erroraction = 'STOP' ;
                } ;
                $smsg = "$($CmdletName): Set 1 lvl:Set-Variable w`n$(($pltSV|out-string).trim())" ;
                write-verbose $smsg  ;
                TRY{
                    Set-Item @pltSV #-verbose ;
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    BREAK ;
                } ;
            } ;  
        } ;
        #*------^ END Function set-HostIndent ^------
    } ; 
    if(-not(get-command write-HostIndent -ea 0)){
        #*------v Function write-HostIndent v------
        function write-HostIndent {
            <#
                    * 2:01 PM 2/1/2023 add: -PID param
                    #>
            [CmdletBinding()]
            [Alias('w-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Specifies the background color. There is no default. The acceptable values for this parameter are:
            (Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | White)")]
                    [System.ConsoleColor]$BackgroundColor,
                [Parameter(
                    HelpMessage="Specifies the text color. There is no default. The acceptable values for this parameter are:
        (Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | White)")]
                    [System.ConsoleColor]$ForegroundColor,
                [Parameter(
                    HelpMessage="The string representations of the input objects are concatenated to form the output. No spaces or newlines are inserted between
        the output strings. No newline is added after the last output string.")]
                    [System.Management.Automation.SwitchParameter]$NoNewline,
                [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Objects to display in the host")]
                    [System.Object]$Object,
                [Parameter(
                    HelpMessage="Specifies a separator string to insert between objects displayed by the host.")]
                    [System.Object]$Separator,
                [Parameter(
                    HelpMessage="Character to use for padding (defaults to a space).[-PadChar '-']")]
                    [string]$PadChar = ' ',
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrment 8]")]
                [int]$PadIncrment = 4,
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ; 
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;     
                $pltWH = @{} ; 
                if ($PSBoundParameters.ContainsKey('BackgroundColor')) {
                    $pltWH.add('BackgroundColor',$BackgroundColor) ; 
                } ;
                if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
                    $pltWH.add('ForegroundColor',$ForegroundColor) ; 
                } ;
                if ($PSBoundParameters.ContainsKey('NoNewline')) {
                    $pltWH.add('NoNewline',$NoNewline) ; 
                } ;
                if ($PSBoundParameters.ContainsKey('Separator')) {
                    $pltWH.add('Separator',$Separator) ; 
                } ;
                write-verbose "$($CmdletName): Using `$PadChar:`'$($PadChar)`'" ; 
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                if(($smsg = Get-Item -Path "Env:HostIndentSpaces$($PID)" -erroraction SilentlyContinue).value){
                  write-verbose $smsg ; 
                } ; 
            
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ; 
                } ; 
                write-verbose "$($CmdletName): Discovered `$$($HISName):$($CurrIndent)" ; 
                $Object = $Object.Split([Environment]::NewLine)
                foreach ($obj in $object){
                    Write-Host -NoNewline $($PadChar * $CurrIndent)  ; 
                    write-host @pltWH -object $obj ; 
                } ; 

            } ; 
        } ; 
        #*------^ END Function write-HostIndent ^------
    } ; 
    if(-not(get-command clear-HostIndent -ea 0)){
        #*------v Function clear-HostIndent v------
        function clear-HostIndent {
            <#
            * 2:00 PM 2/2/2023 typo fix: (trailing block-comment end unmatched)
            #>
            [CmdletBinding()]
            [Alias('c-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Number of spaces to pad by default (defaults to 4).[-PadIncrement 8]")]
                [int]$PadIncrement = 4,
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ; 
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;     
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                if(($smsg = Get-Item -Path "Env:HostIndentSpaces$($PID)" -erroraction SilentlyContinue).value){
                  write-verbose $smsg ; 
                } ; 
            
                if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                    [int]$CurrIndent = 0 ; 
                } ; 
                $pltSV=[ordered]@{
                    Path = $HISName ; 
                    Force = $true ; 
                    erroraction = 'STOP' ;
                } ;
                $smsg = "$($CmdletName): Set 1 lvl:Set-Variable w`n$(($pltSV|out-string).trim())" ; 
                write-verbose $smsg  ;
                TRY{
                    Clear-Item @pltSV #-verbose ; 
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    BREAK ;
                } ;
            } ;  
        } ; 
        #*------^ END Function clear-HostIndent ^------
    } ; 
    if(-not(get-command get-HostIndent -ea 0)){

    #*------v Function get-HostIndent v------
        function get-HostIndent {
            <#
                * 2:13 PM 2/3/2023 init
            #>
            [CmdletBinding()]
            [Alias('s-hi')]
            PARAM(
                [Parameter(
                    HelpMessage="Switch to use the `$PID in the `$env:HostIndentSpaces name (Env:HostIndentSpaces`$PID)[-usePID]")]
                    [switch]$usePID
            ) ;
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose "$($CmdletName): `$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                $Verbose = ($VerbosePreference -eq 'Continue') ;
                if($usePID){
                    $smsg = "-usePID specified: `$Env:HostIndentSpaces will be suffixed with this process' `$PID value!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $HISName = "Env:HostIndentSpaces$($PID)" ;
                } else {
                    $HISName = "Env:HostIndentSpaces" ;
                } ;
                write-verbose "$($CmdletName): Discovered `$$($HISName):$($CurrIndent)" ; 
                $smsg = "$($CmdletName): get $($HISName) value)" ; 
                write-verbose $smsg  ;
                TRY{
                    if (-not ([int]$CurrIndent = (Get-Item -Path $HISName -erroraction SilentlyContinue).Value ) ){
                        [int]$CurrIndent = 0 ; 
                    } ; 
                    $CurrIndent | write-output ; 
                } CATCH {
                    $smsg = $_.Exception.Message ;
                    write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    $false  | write-output ; 
                    BREAK ;
                } ;
            } ;  # BEG-E
        } ;
        #*------^ END Function get-HostIndent ^------
    } ; 
    <# VERS: 2:17 PM 2/3/2023 add get-hostindent(); updates ; 2:28 PM 2/2/2023 init
    #>
    #endregion HostIndentS ; #*------^ END  ^------#*======^ HostIndent SIMPLIFIED (psb-psHostIndent.cbp) ^======

    #*------v Function get-colorcombo v------
    function get-colorcombo {
        <#
        .SYNOPSIS
        get-colorcombo - Return a readable console fg/bg color combo (commonly for use with write-host blocks to id variant datatypes across a series of tests)
        .NOTES
        Author: Todd Kadrie
        Website:	http://www.toddomation.com
        Twitter:	@tostka, http://twitter.com/tostka
        REVISIONS   :
        * 1:22 PM 5/10/2019 init version
        .DESCRIPTION
        .PARAMETER  Combo
        Combo Number (0-73)[-Combo 65]
        .PARAMETER Random
        Returns a random Combo [-Random]
        .PARAMETER  Demo
        Dumps a table of all combos for review[-Demo]
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.Collections.Hashtable
        .EXAMPLE
        $plt=get-colorcombo 70 ;
        write-host @plt "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" ;
        Pull and use get-colorcombo 72 in a write-host ;
        .EXAMPLE
        get-colorcombo -demo ;
        .EXAMPLE
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Pull Random get-colorcombo" ;
        $plt=get-colorcombo -Rand ; write-host  @plt "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" ;
        Run a demo
        .LINK
        #>

        Param(
            [Parameter(Position=0,HelpMessage="Combo Number (0-73)[-Combo 65]")][int]$Combo,
            [Parameter(HelpMessage="Returns a random Combo [-Random]")][switch]$Random,
            [Parameter(HelpMessage="Dumps a table of all combos for review[-Demo]")][switch]$Demo
        )
        if(-not($Demo) -AND -not($Combo) -AND -not($Random)){
            throw "No -Combo integer specified, no -Random, and no -Demo param. One of these must be specified" ;
            Exit ;
        } ;

        $colorcombo=[ordered]@{} ;
        $schemes="Black;DarkYellow","Black;Gray","Black;Green","Black;Cyan","Black;Red","Black;Yellow","Black;White","DarkGreen;Gray","DarkGreen;Green","DarkGreen;Cyan","DarkGreen;Magenta","DarkGreen;Yellow","DarkGreen;White","White;DarkGray","DarkRed;Gray","White;Blue","White;DarkRed","DarkRed;Green","DarkRed;Cyan","DarkRed;Magenta","DarkRed;Yellow","DarkRed;White","DarkYellow;Black","White;DarkGreen","DarkYellow;Blue","DarkYellow;Green","DarkYellow;Cyan","DarkYellow;Yellow","DarkYellow;White","Gray;Black","Gray;DarkGreen","Gray;DarkMagenta","Gray;Blue","Gray;White","DarkGray;Black","DarkGray;DarkBlue","DarkGray;Gray","DarkGray;Blue","Yellow;DarkGreen","DarkGray;Green","DarkGray;Cyan","DarkGray;Yellow","DarkGray;White","Blue;Gray","Blue;Green","Blue;Cyan","Blue;Red","Blue;Magenta","Blue;Yellow","Blue;White","Green;Black","Green;DarkBlue","White;Black","Green;Blue","Green;DarkGray","Yellow;DarkGray","Yellow;Black","Cyan;Black","Yellow;Blue","Cyan;Blue","Cyan;Red","Red;Black","Red;DarkGreen","Red;Blue","Red;Yellow","Red;White","Magenta;Black","Magenta;DarkGreen","Magenta;Blue","Magenta;DarkMagenta","Magenta;Blue","Magenta;Yellow","Magenta;White" ;
        $i=0 ;
        foreach($scheme in $schemes){
            $colorcombo["$($i)"]=@{BackgroundColor=$scheme.split(";")[0] ; foregroundcolor=$scheme.split(";")[1] ; } ;
            $i++ ;
        } ;
        if($Demo){
            write-verbose -verbose:$true  "-Demo specified: Dumping a table of range from Combo 0 to $($colorcombo.count)" ;
            $a=00 ;
            Do {
                $plt=$colorcombo[$a].clone() ;
                write-host -object "Combo $($a):$($plt.foregroundcolor):$($plt.backgroundcolor)" @plt ;
                $a++ ;
            }  While ($a -lt $colorcombo.count) ;
        } elseif ($Random){
            $colorcombo[(get-random -minimum 0 -maximum $colorcombo.count)] | write-output ;
        } else {
            $colorcombo[$Combo] | write-output ;
        } ;
    } ; #*------^ END Function get-colorcombo() ^------

    if(!(get-command Initialize-AADSignErrorsHash -ea 0)){
        #*------v Initialize-AADSignErrorsHash v------
        function Initialize-AADSignErrorsHash {
            <#
            .SYNOPSIS
            Initialize-AADSignErrorsHash - Builds a hash object containing AzureAD Sign-on Error codes & matching description
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2021-06-15
            FileName    : Initialize-AADSignErrorsHash.ps1
            License     : MIT License
            Copyright   : (c) 2020 Todd Kadrie
            Github      : https://github.com/tostka/verb-AAD
            Tags        : Powershell,AzureAD,Errors,Reference
            AddedCredit : Sign-in activity report error codes in the Azure Active Directory portal
            AddedWebsite: https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
            AddedTwitter: URL
            REVISIONS   :
            * 11:01 AM 6/15/2021 Ren'd Build-AADSignErrorsHash -> Initialize-AADSignErrorsHash (compliant verb) ; copied over vers from profile-AAD-Signons.ps1 ; kept updated CBH. 
            * 8:50 PM 1/12/2020 expanded aliases
            * 9:53 AM 8/29/2019 amended 50135, 50125, with MS support comments, and reserached 50140 a bit
            * 2:49 PM 8/27/2019 updated errornumber 0 to be (undocumented - successful), as it is the code on a non-error logon
            * 10:41 AM 5/13/2019 init vers
            .DESCRIPTION
            Build-AADSignErrorsHas.ps1 - Builds a hash object containing AzureAD Sign-on Error codes & matching description: [Sign-in activity report error codes in the Azure Active Directory portal | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
            .INPUTS
            None. Does not accepted piped input.
            .OUTPUTS
            Returns a populated hashtable of AAD signon error codes & descriptions
            .EXAMPLE
            $AADSignOnErrors = Initialize-AADSignErrorsHash ; 
            $ErrDetail = $AADSignOnErrors[$errorCode] ; 
            Populate hash and lookup errorcode
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
            #>
            [CmdletBinding()]
            [Alias('Build-AADSignErrorsHash')]
            PARAM() ;
             #Error 	Description
            $AADSignOnError = [ordered]@{ } ;
            $AADSignOnError.add("0", "(undocumented - ((Successful)))") ;
            $AADSignOnError.add("16000", "This is an internal implementation detail and not an error condition. You can safely ignore this reference.") ;
            $AADSignOnError.add("20001", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("20012", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("20033", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40008", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40009", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("40014", "There is an issue with your federated Identity Provider. Contact your IDP to resolve this issue.") ;
            $AADSignOnError.add("50000", "There is an issue with our sign-in service. Open a support ticket to resolve this issue.") ;
            $AADSignOnError.add("50001", "The service principal name was not found in this tenant. This can happen if the application has not been installed by the administrator of the tenant, or if the resource principal was not found in the directory or is invalid.") ;
            $AADSignOnError.add("50002", "Sign-in failed due to restricted proxy access on tenant. If its your own tenant policy, you can change your restricted tenant settings to fix this issue.") ;
            $AADSignOnError.add("50003", "Sign-in failed due to missing signing key or certificate. This might be because there was no signing key configured in the application. Check out the resolutions outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#certificate-or-key-not-configured. If the issue persists, contact the application owner or the application administrator.") ;
            $AADSignOnError.add("50005", "User tried to login to a device from a platform thats currently not supported through conditional access policy.") ;
            $AADSignOnError.add("50006", "Signature verification failed due to invalid signature. Check out the resolution outlined at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery. If the issue persists, contact the application owner or application administrator.") ;
            $AADSignOnError.add("50007", "Partner encryption certificate was not found for this application. Open a support ticket with Microsoft to get this fixed.") ;
            $AADSignOnError.add("50008", "SAML assertion is missing or misconfigured in the token. Contact your federation provider.") ;
            $AADSignOnError.add("50010", "Audience URI validation for the application failed since no token audiences were configured. Contact the application owner for resolution.") ;
            $AADSignOnError.add("50011", "The reply address is missing, misconfigured, or does not match reply addresses configured for the application. Try the resolution listed at https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#the-reply-address-does-not-match-the-reply-addresses-configured-for-the-application. If the issue persists, contact the application owner or application administrator.") ;
            $AADSignOnError.add("50012", "This is a generic error message that indicates that authentication failed. This can happen for reasons such as missing or invalid credentials or claims in the request. Ensure that the request is sent with the correct credentials and claims.") ;
            $AADSignOnError.add("50013", "Assertion is invalid because of various reasons. For instance, the token issuer doesnt match the api version within its valid time range, the token is expired or malformed, or the refresh token in the assertion is not a primary refresh token.") ;
            $AADSignOnError.add("50017", "Certification validation failed, reasons for the following reasons:, Cannot find issuing certificate in trusted certificates list , Unable to find expected CrlSegment , Cannot find issuing certificate in trusted certificates list , Delta CRL distribution point is configured without a corresponding CRL distribution point , Unable to retrieve valid CRL segments due to timeout issue , Unable to download CRL , Contact the tenant administrator.") ;
            $AADSignOnError.add("50020", "The user is unauthorized for one of the following reasons. The user is attempting to login with an MSA account with the v1 endpoint , The user doesnt exist in the tenant. , Contact the application owner.") ;
            $AADSignOnError.add("50027", "Invalid JWT token due to the following reasons:, doesnt contain nonce claim, sub claim , subject identifier mismatch , duplicate claim in idToken claims , unexpected issuer , unexpected audience , not within its valid time range , token format is not proper , External ID token from issuer failed signature verification. , Contact the application owner , ") ;
            $AADSignOnError.add("50029", "Invalid URI - domain name contains invalid characters. Contact the tenant administrator.") ;
            $AADSignOnError.add("50034", "User does not exist in directory. Contact your tenant administrator.") ;
            $AADSignOnError.add("50042", "The salt required to generate a pairwise identifier is missing in principle. Contact the tenant administrator.") ;
            $AADSignOnError.add("50048", "Subject mismatches Issuer claim in the client assertion. Contact the tenant administrator.") ;
            $AADSignOnError.add("50050", "Request is malformed. Contact the application owner.") ;
            $AADSignOnError.add("50053", "Account is locked because the user tried to sign in too many times with an incorrect user ID or password.") ;
            $AADSignOnError.add("50055", "Invalid password, entered expired password.") ;
            $AADSignOnError.add("50056", "Invalid or null password - Password does not exist in store for this user.") ;
            $AADSignOnError.add("50057", "User account is disabled. The account has been disabled by an administrator.") ;
            $AADSignOnError.add("50058", "The application tried to perform a silent sign in and the user could not be silently signed in. The application needs to start an interactive flow giving users an option to sign-in. Contact application owner.") ;
            $AADSignOnError.add("50059", "User does not exist in directory. Contact your tenant administrator.") ;
            $AADSignOnError.add("50061", "Sign-out request is invalid. Contact the application owner.") ;
            $AADSignOnError.add("50072", "User needs to enroll for two-factor authentication (interactive).") ;
            $AADSignOnError.add("50074", "User did not pass the MFA challenge.") ;
            $AADSignOnError.add("50076", "User did not pass the MFA challenge (non interactive).") ;
            $AADSignOnError.add("50079", "User needs to enroll for two factor authentication (non-interactive logins).") ;
            $AADSignOnError.add("50085", "Refresh token needs social IDP login. Have user try signing-in again with their username and password.") ;
            $AADSignOnError.add("50089", "Flow token expired - Authentication failed. Have user try signing-in again with their username and password") ;
            $AADSignOnError.add("50097", "Device Authentication Required. This could occur because the DeviceId or DeviceAltSecId claims are null, or if no device corresponding to the device identifier exists.") ;
            $AADSignOnError.add("50099", "JWT signature is invalid. Contact the application owner.") ;
            $AADSignOnError.add("50105", "The signed in user is not assigned to a role for the signed in application. Assign the user to the application. For more information: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery#user-not-assigned-a-role") ;
            $AADSignOnError.add("50107", "Requested federation realm object does not exist. Contact the tenant administrator.") ;
            $AADSignOnError.add("50120", "Issue with JWT header. Contact the tenant administrator.") ;
            $AADSignOnError.add("50124", "Claims Transformation contains invalid input parameter. Contact the tenant administrator to update the policy.") ;
            $AADSignOnError.add("50125", "Sign-in was interrupted due to a password reset or password registration entry.(This error may come up due to an interruption in the network while the password was being changed/reset)") ;
            $AADSignOnError.add("50126", "Invalid username or password, or invalid on-premises username or password.") ;
            $AADSignOnError.add("50127", "User needs to install a broker application to gain access to this content.") ;
            $AADSignOnError.add("50128", "Invalid domain name - No tenant-identifying information found in either the request or implied by any provided credentials.") ;
            $AADSignOnError.add("50129", "Device is not workplace joined - Workplace join is required to register the device.") ;
            $AADSignOnError.add("50130", "Claim value cannot be interpreted as known auth method.") ;
            $AADSignOnError.add("50131", "Used in various conditional access errors. E.g. Bad Windows device state, request blocked due to suspicious activity, access policy, and security policy decisions.") ;
            $AADSignOnError.add("50132", "Credentials have been revoked due to the following reasons: , SSO Artifact is invalid or expired , Session not fresh enough for application , A silent sign-in request was sent but the users session with Azure AD is invalid or has expired. , ") ;
            $AADSignOnError.add("50133", "Session is invalid due to expiration or recent password change.`n(Once a Password is changed, it is advised to close all the open sessions and re-login with the new password, else this error might pop-up)") ;
            $AADSignOnError.add("50135", "Password change is required due to account risk.") ;
            $AADSignOnError.add("50136", "Redirect MSA session to application - Single MSA session detected.") ;
            $AADSignOnError.add("50140", "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.`n(if user is functional, this error may be a log anomaly that can be safely ignored)") ;
            $AADSignOnError.add("50143", "Session mismatch - Session is invalid because user tenant does not match the domain hint due to different resource. Open a support ticket with Correlation ID, Request ID, and Error code to get more details.") ;
            $AADSignOnError.add("50144", "Users Active Directory password has expired. Generate a new password for the user or have the end user using self-service reset tool.") ;
            $AADSignOnError.add("50146", "This application is required to be configured with an application-specific signing key. It is either not configured with one, or the key has expired or is not yet valid. Contact the application owner.") ;
            $AADSignOnError.add("50148", "The code_verifier does not match the code_challenge supplied in the authorization request for PKCE. Contact the application developer.") ;
            $AADSignOnError.add("50155", "Device authentication failed for this user.") ;
            $AADSignOnError.add("50158", "External security challenge was not satisfied.") ;
            $AADSignOnError.add("50161", "Claims sent by external provider is not sufficient, or missing claim requested to external provider.") ;
            $AADSignOnError.add("50166", "Failed to send request to claims provider.") ;
            $AADSignOnError.add("50169", "The realm is not a configured realm of the current service namespace.") ;
            $AADSignOnError.add("50172", "External claims provider is not approved. Contact the tenant administrator") ;
            $AADSignOnError.add("50173", "Fresh auth token is needed. Have the user sign-in again using fresh credentials.") ;
            $AADSignOnError.add("50177", "External challenge is not supported for passthrough users.") ;
            $AADSignOnError.add("50178", "Session Control is not supported for passthrough users.") ;
            $AADSignOnError.add("50180", "Windows Integrated authentication is needed. Enable the tenant for Seamless SSO.") ;
            $AADSignOnError.add("51001", "Domain Hint is not present with On-Premises Security Identifier - On-Premises UPN.") ;
            $AADSignOnError.add("51004", "User account doesnt exist in the directory.") ;
            $AADSignOnError.add("51006", "Windows Integrated authentication is needed. User logged in using session token that is missing via claim. Request the user to re-login.") ;
            $AADSignOnError.add("52004", "User has not provided consent for access to LinkedIn resources.") ;
            $AADSignOnError.add("53000", "Conditional Access policy requires a compliant device, and the device is not compliant. Have the user enroll their device with an approved MDM provider like Intune.") ;
            $AADSignOnError.add("53001", "Conditional Access policy requires a domain joined device, and the device is not domain joined. Have the user use a domain joined device.") ;
            $AADSignOnError.add("53002", "Application used is not an approved application for conditional access. User needs to use one of the apps from the list of approved applications to use in order to get access.") ;
            $AADSignOnError.add("53003", "Access has been blocked due to conditional access policies.") ;
            $AADSignOnError.add("53004", "User needs to complete Multi-factor authentication registration process before accessing this content. User should register for multi-factor authentication.") ;
            $AADSignOnError.add("65001", "Application X doesnt have permission to access application Y or the permission has been revoked. Or The user or administrator has not consented to use the application with ID X. Send an interactive authorization request for this user and resource. Or The user or administrator has not consented to use the application with ID X. Send an authorization request to your tenant admin to act on behalf of the App : Y for Resource : Z.") ;
            $AADSignOnError.add("65004", "User declined to consent to access the app. Have the user retry the sign-in and consent to the app") ;
            $AADSignOnError.add("65005", "The application required resource access list does not contain applications discoverable by the resource or The client application has requested access to resource, which was not specified in its required resource access list or Graph service returned bad request or resource not found. If the application supports SAML, you may have configured the application with the wrong Identifier (Entity). Try out the resolution listed for SAML using the link below: https://docs.microsoft.com/azure/active-directory/application-sign-in-problem-federated-sso-gallery?/?WT.mc_id=DMC_AAD_Manage_Apps_Troubleshooting_Nav#no-resource-in-requiredresourceaccess-list") ;
            $AADSignOnError.add("70000", "Invalid grant due to the following reasons:, Requested SAML 2.0 assertion has invalid Subject Confirmation Method , App OnBehalfOf flow is not supported on V2 , Primary refresh token is not signed with session key , Invalid external refresh token , The access grant was obtained for a different tenant. , ") ;
            $AADSignOnError.add("70001", "The application named X was not found in the tenant named Y. This can happen if the application with identifier X has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have misconfigured the Identifier value for the application or sent your authentication request to the wrong tenant.") ;
            $AADSignOnError.add("70002", "The application returned invalid client credentials. Contact the application owner.") ;
            $AADSignOnError.add("70003", "The application returned an unsupported grant type. Contact the application owner.") ;
            $AADSignOnError.add("70004", "The application returned an invalid redirect URI. The redirect address specified by the client does not match any configured addresses or any addresses on the OIDC approve list. Contact the application owner.") ;
            $AADSignOnError.add("70005", "The application returned an unsupported response type due to the following reasons: , response type token is not enabled for the application , response type id_token requires the OpenID scope -contains an unsupported OAuth parameter value in the encoded wctx , Contact the application owner.") ;
            $AADSignOnError.add("70007", "The application returned an unsupported value of response_mode when requesting a token. Contact the application owner.") ;
            $AADSignOnError.add("70008", "The provided authorization code or refresh token is expired or has been revoked. Have the user retry signing in.") ;
            $AADSignOnError.add("70011", "The scope requested by the application is invalid. Contact the application owner.") ;
            $AADSignOnError.add("70012", "A server error occurred while authenticating an MSA (consumer) user. Retry the sign-in, and if the issue persists, open a support ticket") ;
            $AADSignOnError.add("70018", "Invalid verification code due to User typing in wrong user code for device code flow. Authorization is not approved.") ;
            $AADSignOnError.add("70019", "Verification code expired. Have the user retry the sign-in.") ;
            $AADSignOnError.add("70037", "Incorrect challenge response provided. Remote auth session denied.") ;
            $AADSignOnError.add("75001", "An error occurred during SAML message binding.") ;
            $AADSignOnError.add("75003", "The application returned an error related to unsupported Binding (SAML protocol response cannot be sent via bindings other than HTTP POST). Contact the application owner.") ;
            $AADSignOnError.add("75005", "Azure AD doesnt support the SAML Request sent by the application for Single Sign-on. Contact the application owner.") ;
            $AADSignOnError.add("75008", "The request from the application was denied since the SAML request had an unexpected destination. Contact the application owner.") ;
            $AADSignOnError.add("75011", "Authentication method by which the user authenticated with the service doesnt match requested authentication method. Contact the application owner.") ;
            $AADSignOnError.add("75016", "SAML2 Authentication Request has invalid NameIdPolicy. Contact the application owner.") ;
            $AADSignOnError.add("80001", "Authentication Agent unable to connect to Active Directory. Make sure the authentication agent is installed on a domain-joined machine that has line of sight to a DC that can serve the users login request.") ;
            $AADSignOnError.add("80002", "Internal error. Password validation request timed out. We were unable to either send the authentication request to the internal Hybrid Identity Service. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80003", "Invalid response received by Authentication Agent. An unknown error occurred while attempting to authentication against Active Directory on-premises. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80005", "Authentication Agent: An unknown error occurred while processing the response from the Authentication Agent. Open a support ticket to get more details on the error.") ;
            $AADSignOnError.add("80007", "Authentication Agent unable to validate users password.") ;
            $AADSignOnError.add("80010", "Authentication Agent unable to decrypt password.") ;
            $AADSignOnError.add("80011", "Authentication Agent unable to retrieve encryption key.") ;
            $AADSignOnError.add("80012", "The users attempted to log on outside of the allowed hours (this is specified in AD).") ;
            $AADSignOnError.add("80013", "The authentication attempt could not be completed due to time skew between the machine running the authentication agent and AD. Fix time sync issues") ;
            $AADSignOnError.add("80014", "Authentication agent timed out. Open a support ticket with the error code, correlation ID, and Datetime to get more details on this error.") ;
            $AADSignOnError.add("81001", "Users Kerberos ticket is too large. This can happen if the user is in too many groups and thus the Kerberos ticket contains too many group memberships. Reduce the users group memberships and try again.") ;
            $AADSignOnError.add("81005", "Authentication Package Not Supported.") ;
            $AADSignOnError.add("81007", "Tenant is not enabled for Seamless SSO.") ;
            $AADSignOnError.add("81012", "This is not an error condition. It indicates that user trying to sign in to Azure AD is different from the user signed into the device. You can safely ignore this code in the logs.") ;
            $AADSignOnError.add("90010", "The request is not supported for various reasons. For example, the request is made using an unsupported request method (only POST method is supported) or the token signing algorithm that was requested is not supported. Contact the application developer.") ;
            $AADSignOnError.add("90014", "A required field for a protocol message was missing, contact the application owner. If you are the application owner, ensure that you have all the necessary parameters for the login request.") ;
            $AADSignOnError.add("90051", "Invalid Delegation Token. Invalid national Cloud ID ({cloudId}) is specified.") ;
            $AADSignOnError.add("90072", "The account needs to be added as an external user in the tenant first. Sign-out and sign-in again with a different Azure AD account.") ;
            $AADSignOnError.add("90094", "The grant requires administrator permissions. Ask your tenant administrator to provide consent for this application.") ;
            $AADSignOnError.add("500021", "Tenant is restricted by company proxy. Denying the resource access.") ;
            $AADSignOnError.add("500121", "Authentication failed during strong authentication request.") ;
            $AADSignOnError.add("500133", "The assertion is not within its valid time range. Ensure that the access token is not expired before using it for user assertion, or request a new token.") ;
            $AADSignOnError.add("530021", "Application does not meet the conditional access approved app requirements.") ;
            $AADSignOnError | write-output ;
        }
        #*------^ Initialize-AADSignErrorsHash ^------
    }

    #-------v Function Cleanup v-------
    function Cleanup {
        # clear all objects and exit
        # Clear-item doesn't seem to work as a variable release

        # 12:40 PM 10/23/2018 added write-log trainling bnr
        # 2:02 PM 9/21/2018 missing $timestampnow, hardcode
        # 8:45 AM 10/13/2015 reset $DebugPreference to default SilentlyContinue, if on
        # # 8:46 AM 3/11/2015 at some time from then to 1:06 PM 3/26/2015 added ISE Transcript
        # 8:39 AM 12/10/2014 shifted to stop-transcriptLog function
        # 7:43 AM 1/24/2014 always stop the running transcript before exiting
        if ($showdebug) {"CLEANUP"}
        #stop-transcript
        # 11:16 AM 1/14/2015 aha! does this return a value!??
        if($host.Name -eq "Windows PowerShell ISE Host"){
            # 8:46 AM 3/11/2015 shift the logfilename gen out here, so that we can arch it
            #$Logname= (join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + (get-date -uformat "%Y%m%d-%H%M" ) + "-ISEtrans.log")) ;
            # 2:16 PM 4/27/2015 shift to static timestamp $timeStampNow
            #$Logname= (join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + $timeStampNow + "-ISEtrans.log")) ;
            # 2:02 PM 9/21/2018 missing $timestampnow, hardcode
            $Logname=(join-path -path (join-path -path $scriptDir -childpath "logs") -childpath ($scriptNameNoExt + "-" + (get-date -format 'yyyyMMdd-HHmmtt') + "-ISEtrans.log")) ;
            $smsg = "H`$Logname: $Logname";
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            Start-iseTranscript -logname $Logname ;
            #Archive-Log $Logname ;
            # 1:23 PM 4/23/2015 standardize processing file so that we can send a link to open the transcript for review
            $transcript = $Logname
        } else {
            if($showdebug){ write-debug "$(get-timestamp):Stop Transcript" };
            Stop-TranscriptLog ;
            #if($showdebug){ write-debug "$(get-timestamp):Archive Transcript" };
            #Archive-Log $transcript ;
        } # if-E

        # 4:05 PM 10/11/2018 add trailing notifc
        # 12:09 PM 4/26/2017 need to email transcript before archiving it
        if($showdebug){ write-host -ForegroundColor Yellow "Mailing Report" };

        #$smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;

        #Load as an attachment into the body text:
        #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
        #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
        # 4:07 PM 10/11/2018 giant transcript, no send
        #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
        $SmtpBody += "Pass Completed $([System.DateTime]::Now)`nTranscript:($transcript)" ;
        $SmtpBody += "`n$('-'*50)" ;
        #$SmtpBody += (gc $outtransfile | ConvertTo-Html) ;
        # name $attachment for the actual $SmtpAttachment expected by Send-EmailNotif
        #$SmtpAttachment=$transcript ;
        # 1:33 PM 4/28/2017 test for ERROR|CHANGE
        #if($PassStatus ){
            Send-EmailNotif ;
        #} else {
         #   write-host -foregroundcolor green "No Email Report: `$Passstatus is $null ; " ;
        #}  ;


        #11:10 AM 4/2/2015 add an exit comment
        Write-Verbose "END $BARSD4 $scriptBaseName $BARSD4" -Verbose:$verbose
        Write-Verbose "$BARSD40" -Verbose:$verbose
        # finally restore the DebugPref if set
        if ($ShowDebug -OR ($DebugPreference = "Continue")) {
            Write-Verbose -Verbose:$true "Resetting `$DebugPreference from 'Continue' back to default 'SilentlyContinue'" ;
            $showdebug=$false
            # 8:41 AM 10/13/2015 also need to enable write-debug output (and turn this off at end of script, it's a global, normally SilentlyContinue)
            $DebugPreference = "SilentlyContinue" ;
        } # if-E

        $smsg= "#*======^ END PASS:$($ScriptBaseName) ^======" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        break;

    } #*------^ END Function Cleanup ^------



    #*======^ END FUNCTIONS ^======

    #*======v SUB MAIN v======

    # 9:38 AM 8/29/2019 some errors say open a ticket with: Correlation ID, Request ID, and Error code, added to both prop sets
    $failprops = "createdDateTime", "userPrincipalName", "appDisplayName", "resourceDisplayName", "clientAppUsed", "ipAddress", "deviceDetail", "location","riskState","riskLevelAggregated","riskLevelDuringSignIn","riskDetail","riskEventTypes","riskLevel","status","correlationId","originalRequestId","status.errorCode" ;
    $recentevtprops = "createdDateTime", "userPrincipalName", "appDisplayName", "resourceDisplayName", "clientAppUsed", "ipAddress", "deviceDetail", "location", "riskState", "riskLevelAggregated", "riskLevelDuringSignIn", "riskDetail", "riskEventTypes", "riskLevel", "status","correlationId","originalRequestId" ;
    #aad serviceprincipal useful reporting fields
    $prpAADSvcP = 'AppDisplayName','DisplayName','ObjectId','PublisherName','AppOwnerTenantId','Homepage','LogoutUrl','ReplyUrls' ; 

    $AADSignOnError = Initialize-AADSignErrorsHash ;

    <#, no mods at this point, it's all simple json data parsi
    #[array]$reqMods=$null ; # force array, otherwise single first makes it a [string]
    # these are the one's that don't have explicit $reqMods+=, above their load blocks (below):
    # Most verb-module PSS's require these two as well
    $reqMods+="Add-PSTitleBar;Remove-PSTitleBar".split(";") ;
    #Disconnect-EMSR (variant name in some ps1's for Disconnect-Ex2010)
    #$reqMods+="Reconnect-CCMS;Connect-CCMS;Disconnect-CCMS".split(";") ;
    #$reqMods+="Reconnect-SOL;Connect-SOL;Disconnect-SOL".split(";") ;
    $reqMods+="Test-TranscriptionSupported;Test-Transcribing;Stop-TranscriptLog;Start-IseTranscript;Start-TranscriptLog;get-ArchivePath;Archive-Log;Start-TranscriptLog".split(";") ;
    # 12:15 PM 9/12/2018 remove dupes
    $reqMods=$reqMods| select -Unique ;
    #>
    #$ofile = join-path -path (Split-Path -parent $MyInvocation.MyCommand.Definition) -ChildPath "logs" ;
    $ofile = join-path -path $ScriptDir -ChildPath "logs" ;
    if(!(test-path -path $ofile)){ "Creating missing log dir $($ofile)..." ; mkdir $ofile  ; } ;

    #$transcript= join-path -path $ofile -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))-Transcript-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-trans-log.txt"  ;
    $transcript= join-path -path $ofile -childpath "$($ScriptNameNoExt)-Transcript-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-trans-log.txt"  ;
    # 10:21 AM 10/18/2018 add log file variant as target of Write-Log:
    #$logfile = join-path -path $ofile -childpath "$([system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName))-BATCH-$(get-date -format 'yyyyMMdd-HHmmtt')-LOG.txt"  ;
    $logfile = $transcript.replace("-trans-log.txt","-log.txt");
    $logging = $True ;
    #$smsg= "#*======v START PASS:$($ScriptBaseName) v======" ;
    #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } #Error|Warn|Debug 
    #else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $smsg = $sBnr="#*======v  $(${CmdletName}): v======" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    
    #start-TranscriptLog $Transcript


    # Clear error variable
    $Error.Clear() ;
    <##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    # SCRIPT-CLOSE MATERIAL TO CLEAR THE UNDERLYING $DBGPREF & $EAPREF TO DEFAULTS:
    if ($ShowDebug -OR ($DebugPreference = "Continue")) {
            Write-Verbose -Verbose:$true "Resetting `$DebugPreference from 'Continue' back to default 'SilentlyContinue'" ;
            $showDebug=$false
            # 8:41 AM 10/13/2015 also need to enable write-debug output (and turn this off at end of script, it's a global, normally SilentlyContinue)
            $DebugPreference = "SilentlyContinue" ;
    } # if-E ;
    if($ErrorActionPreference -eq 'Stop') {$ErrorActionPreference = 'Continue' ; write-debug "(Restoring `$ErrorActionPreference:$ErrorActionPreference;"};
    #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    #>


    $rgxSID="^S-\d-\d+-(\d+-){1,14}\d+$" ;

    $smsg = "H5Net:$(($Files|measure).count) Json Files" ;
    $ttl=($Files|measure).count ;
    $Procd=0 ;
    foreach ($File in $Files){
        $Procd++ ;
        reset-HostIndent ; 

        #Connect-AzureAD ; 
        connect-aad ; 

        # 9:20 AM 2/25/2019 Tickets will be an array of nnn's to match the mbxs, so use $Procd-1 as the index for tick# in the array

        # build outfile on the $file fullname
        $ofileobj=gci $File ;
        # $ofileobj=gci "c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json" ;
        $logfile = $ofileobj.fullname.replace(".json","-parsed-json-rpt.txt") ;

        $sBnr2="#*======v `$File:($($Procd)/$($ttl)):$($File) v======" ;
        $smsg="$($sBnr)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $smsg="Processing output into: $($logfile)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        $bConfirmDo=$true ;
        #if($showDebug){Write-Verbose -Verbose:$true "$($File):is present on the `$ConfirmList" };

        if($bConfirmDo){

            #$jFile="c:\usr\work\incid\9999-USER-SignIns__2019-07-21__2019-08-20.json" ;
            if ($EVTS = gc $File | Convertfrom-json) {

                # oddity, get-host in ISE returns -1,-1 for fg & bg colors, but the color names in any other host
                $hostsettings = get-host ;
                if ($hostsettings.name -eq 'Windows PowerShell ISE Host') {
                    $bgcolordefault = "Black" ;
                    $fgcolordefault = "gray" ;
                }
                else {
                    $bgcolordefault = $hostsettings.ui.rawui.BackgroundColor ;
                    $fgcolordefault = $hostsettings.ui.rawui.ForegroundColor ;
                } ;
                $evtsProfiled = $evts | ? { $_.status.signinstatus -eq 'Failure' };
                $fltrDesc = "(`$_.status.signinstatus -eq 'Failure')" ;
                #$colors = (get-colorcombo -random) ;

                push-HostIndent ; 

                $smsg = "`n`n==Json Parsing AAD Sign-ins`nin file:$($File)`n`n$((($EVTS|measure).count|out-string).trim()) events found in file`n" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                write-host "`n`n" ;

                $smsg = "`n`n==ALL Grouped Status.signinstatus (if populated):`n$(($EVTS.status.signinstatus | group| sort count -des | format-table -auto count,name|out-string).trim())`t" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                write-host "`n`n" ; 

                $smsg = "`n`n==ALL Grouped Status.errorCode :`n$(($EVTS.status.errorCode | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $grpd = $EVTS | group appDisplayName | sort count -des ; 
                $smsg = "`n`n==ALL Grouped Appdisplaynames:`n$(($grpd | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                # stock desc for Office365 Shell WCSS-Client
                $hsO365ShellWCssClient = @"
Office 365 Shell WCSS-Client: Browser code that runs whenever a user navigates to (most) Office365 applications in the browser.  
The shell, also known as the suite header, is shared code that loads as part of almost all Office365 workloads, 
including SharePoint, OneDrive, Outlook, Yammer, and many more.
"@ ; 
                # Office Online Core SSO, likewise
                $hsOfficeOnlineCoreSSO = @"
The Microsoft Office Online Single-Sign-on application. 
(avoids repeated logon prompts by using a single authentication token for all Office applications)
"@ ; 
                # OfficeHome, which is the www.office.com page
                $hsOfficeHome = @"
OfficeHome: The www.office.com page
"@ ; 
                # Windows Sign In
                $hsWindowsSignIn = @"
Windows Sign In: A user has logged into an Azure joined windows 10 device with the password or Windows hello, 
"@ ; 
                # Microsoft Account Controls V2
                $hsMicrosoftAccountControlsV2 = @"
Microsoft Account Controls V2: mysignins.microsoft.com
"@ ; 
                #
                $hsMicrosoft365SupportService = @"
Microsoft 365 Support Service: Authentication in Microsoft Office applications.
"@ ; 

                # DynPull the above unique names ; 
                push-hostindent  ; 

                write-host "`n`n" ; 

                $smsg = "`nExpanding the above AppdisplayNames..." ; 
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt -Indent -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                foreach($apd in ($grpd | select -expand name)){
                    write-host "`n`n" ; 
                    $smsg = "`n==Get-AzureADServicePrincipal $($apd):" ; 
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    
                    switch($apd){
                        'Office365 Shell WCSS-Client'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            $smsg = $hsO365ShellWCssClient ;
                            $bFound = $true ; 
                        } ; 
                        'Office Online Core SSO'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            $smsg = $hsOfficeOnlineCoreSSO ;
                            $bFound = $true ; 
                        } 
                        'OfficeHome'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            $smsg = $hsOfficeHome ;
                            $bFound = $true ; 
                        } ; 
                        'Windows Sign In'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            # [Azure AD Signin logs -- User on an average locks the laptop or PC 10+ times, so every time user logs back, will the sign in log be recorded for 10times? - Microsoft Q&A - learn.microsoft.com/](https://learn.microsoft.com/en-us/answers/questions/451777/azure-ad-signin-logs-user-on-an-average-locks-the)
                            $smsg = $hsWindowsSignIn ;
                            $bFound = $true ; 
                        } ; 
                        'Microsoft Account Controls V2'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            # [Azure AD Signin logs -- User on an average locks the laptop or PC 10+ times, so every time user logs back, will the sign in log be recorded for 10times? - Microsoft Q&A - learn.microsoft.com/](https://learn.microsoft.com/en-us/answers/questions/451777/azure-ad-signin-logs-user-on-an-average-locks-the)
                            $smsg = $hsMicrosoftAccountControlsV2 ;
                            $bFound = $true ; 
                        } ; 
                        'Microsoft 365 Support Service'{
                            # doesn't traditionally return on SP qry, has a stock def per internal MS support 
                            # [Azure AD Signin logs -- User on an average locks the laptop or PC 10+ times, so every time user logs back, will the sign in log be recorded for 10times? - Microsoft Q&A - learn.microsoft.com/](https://learn.microsoft.com/en-us/answers/questions/451777/azure-ad-signin-logs-user-on-an-average-locks-the)
                            $smsg = $hsMicrosoft365SupportService ;
                            $bFound = $true ; 
                        } ; 
                        default{
                            $bFound = $false ; 
                            if($AADSP = Get-AzureADServicePrincipal -Filter "DisplayName eq '$($apd)'"){
                                $bFound = $true ; 
                        
                                $smsg = $(($AADSP | ft -a  $prpAADSvcP[0..3]|out-string).trim()) ; 
                                $smsg += "`n$(($AADSP |  fl  $prpAADSvcP[4..7] |out-string).trim())" ; 
                        
                        
                            } else { 
                                $smsg = "No match returned on `$apd:$($apd)" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                            } ; 
                        }
                    } ; 
                    
                    if($bFound){
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                        else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    } ; 
                }  ; 
                pop-hostindent  ; 

                write-host "`n`n" ; 

                $smsg = "`n`n==ALL Grouped Resourcedisplayname :`n$(($EVTS | group resourceDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $smsg = "`n`n==ALL Grouped Clientappused:`n$(($EVTS | group clientAppUsed | sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $smsg = "`n`n==ALL Grouped devicedetail.operatingsystem:`n$((($evts|?{$_.deviceDetail}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped on devicedetail.operatingsystem:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped on deviceDetail.browser:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).deviceDetail.browser | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                
                write-host "`n`n" ; 

                $smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nGrouped Clientappused:`n$((($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'}).Clientappused | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                $colors = (get-colorcombo -random) ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                pop-HostIndent ; 

                #$smsg= "`n`n==resourcedisplayname:'office 365 exchange online'`nDumped where non-zero status.errorcode:`n`n$(($evts |?{$_.resourcedisplayname -eq 'office 365 exchange online'} | ?{$_.status.errorCode -ne 0} | fl createdDateTime, userPrincipalName, appDisplayName, resourceDisplayName, clientAppUsed, ipAddress, deviceDetail, location,risk*,status|out-string).trim())`n`n" ;

                # 8:32 AM 8/21/2019 profile fails
                if ($evtsfail = $evts | ? { $_.status.errorcode -ne '0' } ) {
                    
                    $smsg = "`n`n==FAILED (errorcode -ne 0) EVTS FOUND. PROFILING...`n`n " ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor YELLOW "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    # collect resourceDisplayNames
                    $resDnames = $evtsfail | select -unique resourceDisplayName | select -expand resourceDisplayName ;
                    # collect Appdisplaynames
                    $AppDnames = $evtsfail | select -unique Appdisplaynames | select -expand Appdisplaynames ;
                    # collect clientAppUsed
                    $ClientAppUseds = $evtsfail | select -unique clientAppUsed | select -expand clientAppUsed ;

                    push-hostindent 

                    <#
                    foreach ($resDname in $resDnames) {
                        $smsg = "`n`n--Profiling resourceDisplayNames:$($resDname)..`n`n " ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } #Error|Warn|Debug 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    }
                    #>
                    $smsg = "`n`n==FAILED Grouped Appdisplaynames:`n$(($evtsfail | group appDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    
                    write-host "`n`n" ; 

                    $smsg = "`n`n==FAILED Grouped Resourcedisplayname :`n$(($evtsfail | group resourceDisplayName | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    write-host "`n`n" ; 
                    $smsg = "`n`n==FAILED Grouped Clientappused:`n$(($evtsfail | group clientAppUsed | sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    write-host "`n`n" ; 
                    $smsg = "`n`n==FAILED Grouped devicedetail.operatingsystem:`n$((($evtsfail|?{$_.deviceDetail}).devicedetail.operatingsystem | group| sort count -des | format-table -auto count,name|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    write-host "`n`n" ; 
                    # geo profile
                    $smsg = "`n`n==FAILED Grouped location.city:`n$(($evtsfail.location.city | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    $smsg = "`n`n==FAILED Grouped location.state:`n$(($evtsfail.location.state | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $smsg = "`n`n==FAILED Grouped location.countryOrRegion:`n$(($evtsfail.location.countryOrRegion | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    
                    write-host "`n`n" ; 

                    # status details
                    $smsg = "`n`n==FAILED Grouped status.failurereason:`n$(($evtsfail.status.failurereason | group| sort count -des | format-table -auto count,name|out-string|out-string).trim())" ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                    <#
                    #$smsg = "`n`n==resourcedisplayname:'office 365 exchange online'`nDumped where non-zero status.errorcode:`n`n" ;
                    $smsg = "`n`n==Dumped Failures (status.errorcode -ne 0):`n`n" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } ; #Error|Warn|Debug

                    #$dumpevts = $evtsfail | ? { $_.resourcedisplayname -eq 'office 365 exchange online' }  ;
                    $dumpevts = $evtsfail | sort Resourcedisplayname, Appdisplaynames, Clientappused  ;
                    foreach ($devt in $dumpevts) {
                        $sBnrS = "`n#*------v $($devt.createdDateTime): v------"
                        $smsg = "$($sBnrS)`n$(($devt| fl $failprops |out-string).trim())`b$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                        # "riskState","riskLevelAggregated","riskLevelDuringSignIn","riskDetail","riskEventTypes","riskLevel"
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } ; #Error|Warn|Debug
                    } ;
                    #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent } ; #Error|Warn|Debug
                    #>
                    pop-hostindent 
                }
                else {
                    $smsg = "`n`n==(no fail/errorcode <> 0 evts found" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;


                # SignOns  profiled
                #$profTag="OWA" ;
                $profTags = "FAIL", "ErrNon0", "Exo-OWA", "Exo-MobileAndDesktopClients", "OlderOfcClients", "ActiveSync", "IMAP", "POP", "MAPI", "SMTP" ;

                foreach ($profTag in $profTags) {
                    switch ($profTag) {
                        "FAIL" {
                            $evtsProfiled = $evts | ? { $_.status.signinstatus -eq 'Failure' };
                            $fltrDesc = "(`$_.status.signinstatus -eq 'Failure')" ;
                            $colors = (get-colorcombo -random) ;
                            <# $_.status.signinstatus -eq 'Failure'
                            #>
                        } ;
                        "ErrNon0" {
                            $evtsProfiled = $evts | ? { $_.status.errorcode -ne '0' };
                            $fltrDesc = "(`$_.status.errorcode -ne '0')" ;
                            $colors = (get-colorcombo -random) ;

                        } ;
                        "Exo-OWA" {
                            $evtsProfiled = $evts | ? { ($_.resourceDisplayName -eq 'office 365 exchange online') -AND ($_.clientAppUsed -eq 'Browser') };
                            $fltrDesc = "(`$_.resourceDisplayName -eq 'office 365 exchange online') -AND (`$_.clientAppUsed -eq 'Browser')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "Exo-MobileAndDesktopClients" {
                            $evtsProfiled = $evts | ? { ($_.resourceDisplayName -eq 'office 365 exchange online') -AND ($_.clientAppUsed -eq 'Mobile Apps and Desktop clients') };
                            $fltrDesc = "(`$_.resourceDisplayName -eq 'office 365 exchange online') -AND (`$_.clientAppUsed -eq 'Mobile Apps and Desktop clients')" ;
                            $colors = (get-colorcombo -random) ;

                        } ;
                        "OlderOfcClients" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; Older Office clients') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; Older Office clients')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "ActiveSync" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Exchange ActiveSync') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Exchange ActiveSync')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "IMAP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; IMAP') };
                            $fltrDesc = "`$_.clientAppUsed -eq 'Other clients; IMAP') " ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "POP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; POP') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; POP')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "MAPI" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; MAPI') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; MAPI')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;
                        "SMTP" {
                            $evtsProfiled = $evts | ? { ($_.clientAppUsed -eq 'Other clients; SMTP') };
                            $fltrDesc = "(`$_.clientAppUsed -eq 'Other clients; SMTP')" ;
                            $colors = (get-colorcombo -random) ;
                        } ;

                    } ;
                    $sBnrS = "`n#*------v $($profTag) SignOns Profiled  - $(($evtsProfiled|measure).count) events: : v------`n" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    write-host "`n`n" ; 

                    $smsg = $fltrDesc ;
                    $colors = (get-colorcombo -random) ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                    else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    
                    if ($evtsProfiled ) {

                        if ($profTag -match '(FAIL|ErrNon0)') {
                            #status
                            #deviceDetail
                            #location
                            $iDumpd = 0 ;
                            $ittl = ($evtsProfiled | measure).count ;
                            if ($evtsProfiled) {
                                foreach ($evt in $evtsProfiled) {
                                    $iDumpd++ ;
                                    write-host -foregroundcolor gray " - v Failure #$($iDumpd)/$($ittl) v -" ;
                                    $smsg =" - v Failure #$($iDumpd)/$($ittl) v -" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -foregroundcolor gray -indent -flatten} 
                                    else{ write-host -foregroundcolor gray "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                                    push-hostindent 

                                    $smsg = "$(($evt| fl $failprops|out-string).trim())" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten }  
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                    write-host "`n`n" ; 

                                    $smsg ="`nSTATUS:`n$(($evt| select -exp status|out-string).trim())" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -foregroundcolor cyan -indent -flatten} 
                                    else{ write-host -foregroundcolor cyan "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                                    push-hostindent 
                                    write-host "`n`n" ; 

                                    $smsg = "`nDEVICEDETAIL:`n$(($evt| select -exp devicedetail|out-string).trim())" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -foregroundcolor cyan -indent -flatten} 
                                    else{ write-host -foregroundcolor cyan "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                                    write-host "`n`n" ; 

                                    $smsg = "`nLOCATION:`n$(($evt | select -exp location|out-string).trim())" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -foregroundcolor darkgray -indent -flatten} 
                                    else{ write-host -foregroundcolor darkgray "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    write-host "`n`n" ; 

                                    $smsg = " - ^ Failure #$($iDumpd)/$($ittl)) ^ -" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -foregroundcolor gray -indent -flatten} 
                                    else{ write-host -foregroundcolor gray "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                    pop-hostindent 
                                    pop-hostindent 
                                    write-host "`n`n" ; 
                                } ;
                            }
                            else {
                                "(no matching events to profile)"
                            }
                        }
                        else {

                            $smsg = "$($profTag) SignOns grouped status.signInStatus" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = $evtsProfiled.status.signInStatus | group | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                                write-host "`n`n" ; 
                            } else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                                write-host "`n`n" ; 
                            };

                            $smsg = "$($profTag) SignOns grouped status.errorCode"
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            write-host "`n`n" ; 

                            $ret=$evtsProfiled.status.errorCode | group | sort count -des
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                                write-host "`n`n" ; 
                            } else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                                write-host "`n`n" ; 
                            } ;
                            if ($errorcodes = $evtsProfiled.status.errorCode | group | select name) {
                                foreach ($ec in $errorcodes) {
                                    $errstring = $aadsignonerror["$($ec.name)"] ;
                                    $smsg = "ErrorCode:$($ec.name):$($errstring)" ;
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                } ;

                            } else {
                                $smsg ="(no errorcodes to group)" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            }
                            write-host "`n`n" ; 

                            $smsg = "$($profTag) SignOns grouped status.failureReason" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            
                            $ret = $evtsProfiled.status.failureReason | group | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten }  #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "`n$($profTag) SignOns grouped location.countryOrRegion" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            $ret = $evtsProfiled | select -exp location | group countryOrRegion | sort count -des | format-table -auto count, name ;
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                pop-hostindent 
                            }else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "$($profTag) SignOns grouped location.state" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = $evtsProfiled | select -exp location | group state | sort count -desc | format-table -auto count, name ;
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }
                            else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "`n$($profTag) SignOns grouped ipAddress" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = $evtsProfiled | group ipAddress | sort Name | format-table -auto count, name ;
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"  ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }
                            else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name|out-string).trim() ;
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "`n$($profTag) SignOns grouped deviceDetail.browser" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = ($evtsProfiled.deviceDetail.browser | group $_ | sort count -des | format-table -auto count, name |out-string).trim();
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }else {
                                push-hostindent 
                                $smsg = ($ret | format-table -auto count, name |out-string).trim();
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "`n$($profTag) SignOns grouped devicedetail.operatingsystem" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = ($evtsProfiled.devicedetail.operatingsystem | group $_ | sort count -des | format-table -auto count, name | out-string).trim();
                            if (!$ret) {
                                push-hostindent
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten} #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }
                            else {
                                push-hostindent
                                #$smsg = $ret | format-table -auto count, name ;
                                # do the splat output, above is breaking split
                                $smsg = $(($ret | format-table -auto count, name|out-string).trim()) ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = "$($profTag) SignOns grouped deviceDetail.displayname" ;
                            $colors = (get-colorcombo -random) ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors -flatten } 
                            else{ write-host @colors  "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                            $ret = ($evtsProfiled.deviceDetail.displayname | group $_ | sort count -des |out-string).trim();
                            if (!$ret) {
                                push-hostindent 
                                $smsg = "(unpopulated field across data series)`n"
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            }
                            else {
                                push-hostindent
                                #$smsg = $ret | format-table -auto count, name ;
                                # do the splat output, above is breaking split
                                $smsg = $(($ret | format-table -auto count, name|out-string).trim()) ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } #Error|Warn|Debug 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                pop-hostindent 
                            };
                            write-host "`n`n" ; 

                            $smsg = $sBnrSx = "`n#*------v Most Recent $($profTag) Event: v------" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            push-hostindent 
                            $evtlast = ($evtsProfiled | sort createddatetime)[-1] ;
                            $smsg = "$(($evtlast| format-list $recentevtprops |out-string).trim())" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            write-host "`n`n" ; 

                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            $smsg = "`nStatus details:`n$(($evtlast| select -expand Status|out-string).trim())" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            $smsg = "`nLocation details:`n$(($evtlast| select -expand location|out-string).trim())" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            pop-hostindent
                            $smsg = "$($sBnrSx.replace('-v','-^').replace('v-','^-'))" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                             
                        } ;

                    } else {
                        #write-host @colors "(No signons matched traditional $($profTag) profile)" ;
                        $smsg = "(No signons matched traditional $($profTag) profile)" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent @colors} 
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                        write-host "`n`n" ; 
                    } ;
                    $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;

                $sBnrS="`n#*------v Most Recent Event in series: v------" ;
                $smsg = "$($sBnrS)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $evtlast=($evts| sort createddatetime)[-1] ;
                $dynprops = $evtlast.psobject.Properties | select -exp name |?{($_ -ne 'Status') -AND ($_ -ne 'Location') -ANd ($_ -ne 'deviceDetail')} ;
                push-hostindent
                $smsg = "$(($evtlast| select $dynprops | format-list|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $smsg = "`nStatus details:`n$(($evtlast| select -expand Status|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $smsg = "`ndeviceDetail details:`n$(($evtlast| select -expand deviceDetail|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $smsg = "`nLocation details:`n$(($evtlast| select -expand location|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT -Indent -flatten } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                pop-hostindent 
                $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H2 } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                $smsg = "`n`nresults logged to logfile:`n$($logfile)`n`n" ; 
                write-host -foregroundcolor yellow $smsg ; 

                $smsg = "`n$($sBnr2.replace('=v','=^').replace('v=','^='))`n" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

            } ;
        } else {
            $smsg="$($UPN):Not on Confirm List" ;  ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info -Indent -flatten } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
        # ========================================

        $smsg= "$($sBnr.replace('=v','=^').replace('v=','^='))`n`n" ;;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 -Indent -flatten } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        start-sleep -Milliseconds 500 ; # 2:51 PM 10/11/2018 add a throttle pause
    } ;  # loop-E

    #stop-transcript ;
    #Cleanup
    $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    #*======^ END SUB MAIN ^======
}

#*------^ End Function profile-AAD-Signons ^------