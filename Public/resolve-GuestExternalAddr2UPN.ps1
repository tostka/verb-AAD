#*------v resolve-GuestExternalAddr2UPN.ps1 v------
Function resolve-GuestExternalAddr2UPN {
    <#
    .SYNOPSIS
    resolve-GuestExternalAddr2UPN - Convert a given External Address into the equivelent Guest UPN, in the local Tenant.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 20200827-0342PM
    FileName    : resolve-GuestExternalAddr2UPN.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    REVISIONS   :
    * 3:26 PM 8/27/2020 init
    .DESCRIPTION
    resolve-GuestExternalAddr2UPN - Convert a given External Address into the equivelent Guest-format UPN, for local Tenant (or Tenant specified by the use of -Credential) .
    .PARAMETER ExternalEmailAddress
    External SMTP Email Address to be resolved to Guest UPN [-ExternalEmailAddress email@gmail.com]
    .PARAMETER Credential
    Credential to be used for connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a string containing the resolved Guest-format UPN
    .EXAMPLE
    resolve-GuestExternalAddr2UPN -Exte email@gmail.com ;
    Retrieve MSOL License details on specified UPN
    .EXAMPLE
    $EXOLicDetails = resolve-GuestExternalAddr2UPN -UPNs $exombx.userprincipalname -showdebug:$($showdebug) ; 
    Convert email@gmail.com into an equivelent local-Tenant Guest UPN
    .LINK
     https://github.com/tostka/verb-AAD/
    #>
    #Requires -Version 3
    #Requires -Modules AzureAD
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("USEA","GBMK","AUSYD")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)][ValidateCount(1,3)]
    # SMTP rgx: "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$"
    Param(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="External SMTP Email Address to be resolved to Guest UPN [-ExternalEmailAddress email@gmail.com]")]
        [ValidatePattern("^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")]
        [string]$ExternalEmailAddress,
        [Parameter()][System.Management.Automation.PSCredential]$Credential = $global:credo365TORSID
    ) ;
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        # Get parameters this function was invoked with
        $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        $Verbose = ($VerbosePreference -eq 'Continue') ;
        #$script:PassStatus = $null ;
    } ;
    PROCESS {
        $Error.Clear() ;
        #$ObjReturn=@() ;
        <#$hshRet=[ordered]@{
            Cred=$null ;
            credType=$null ;
        } ;
        #>

        Connect-AAD -Credential:$Credential -verbose:$($verbose) ;
        <#
        if($script:useEXOv2){
            reconnect-eXO2 -Credential:$Credential -verbose:$($verbose) ;
        } else {
            reconnect-EXO -Credential:$Credential -verbose:$($verbose) ;
        } ;
        #>
        $extDom = [regex]::match($ExternalEmailAddress,'@(\w+\.\w+)').captures[0].groups[1].value ;
        $extDom = ($extdom.substring(0,1).toupper())+($extdom.substring(1).tolower()) ;
        $error.clear() ;
        TRY {
            $TenDtl=Get-AzureADTenantDetail ;
        } CATCH {
            Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 
        $TenDom = $TenDtl.VerifiedDomains.name -match '^\w*\.onmicrosoft\.com' ;
        $tUPN = "$($ExternalEmailAddress.replace('@','_'))#EXT#@$($TenDom)" ;
        write-verbose "Converted $($ExternalEmailAddress) to equiv Guest UPN:`n$($tUPN)" ; 
    } ; # E-PROC
    END { $tUPN | write-output} ; 
} ;
#*------^ resolve-GuestExternalAddr2UPN.ps1 ^------

#resolve-GuestExternalAddr2UPN -Exte email@gmail.com ;
