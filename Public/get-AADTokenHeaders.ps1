
#*------v Function get-AADTokenHeaders v------
Function get-AADTokenHeaders {
    <#
    .SYNOPSIS
    get-AADTokenHeaders - Construct headers for an Azure access token
    .NOTES
    Version     : 1.0.0
    Author      : Alex Asplund
    Website     :	https://automativity.com
    Twitter     :	@AlexAsplund
    CreatedDate : 2019-08-12
    FileName    : 
    License     :
    Copyright   : 
    Github      : 
    Tags        : Powershell,AzureAD,Authentication,GraphAPI,Microsoft
    AddedCredit : 
    AddedWebsite:	
    AddedTwitter:	
    REVISIONS
    * 2019-08-12 posted version 
    .DESCRIPTION
    get-AADTokenHeaders - Construct Azure access token headers
    Uses code Alex Asplund demo'd at link below, wrapped into a func
    .PARAMETER  token
    Token[-Token (token obj)]
    .PARAMETER ShowDebug
    Parameter to display Debugging messages [-ShowDebug switch]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Returns a header hashtable
    .EXAMPLE
    $AADTokenHeaders = get-AADTokenHeaders -token $token -Verbose:($VerbosePreference -eq 'Continue')
    .LINK
    https://adamtheautomator.com/microsoft-graph-api-powershell/
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Token[-Token (token obj)]")]
        [ValidateNotNullOrEmpty()]$token,
        [Parameter(HelpMessage="Debugging Flag [-showDebug]")]
        [switch] $showDebug
    ) ;
    write-verbose "$((get-date).ToString('HH:mm:ss')):Provided token:`n$(($token|out-string).trim())" ; 
    $Header = @{
        Authorization = "$($token.token_type) $($token.access_token)"
    }
    write-verbose "$((get-date).ToString('HH:mm:ss')):Generated `$Header:`n$(($Header|out-string).trim())" ; 
    $Header | write-output ; 
}; #*------^ END Function get-AADTokenHeaders ^------
