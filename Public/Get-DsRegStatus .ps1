#*------v Get-DsRegStatus.ps1 v------
function Get-DsRegStatus {
    <#
    .SYNOPSIS
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject. 
    .NOTES
    Version     : 0.1.17
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-06-23
    FileName    : Get-DsRegStatus
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-aad
    REVISIONS
    * 9:54 AM 6/23/2021 added to verb-aad
    * 12:21 PM 8/8/2020 init
    .DESCRIPTION
    Get-DsRegStatus - Returns the output of dsregcmd /status as a PSObject. 
    Returns the output of dsregcmd /status as a PSObject. All returned values are accessible by their property name.
    Lifted from [PowerShell Gallery | Functions/Get-DsRegStatus.ps1 0.1.3 - www.powershellgallery.com/](https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.3/Content/Functions%5CGet-DsRegStatus.ps1)
    Alt to manual cmdline parsing:
    ```powershell
    $results = dsregcmd /status;
    $results|sls azureadjoined ; $results | sls domainjoined ; $results | sls workplacejoined ;
    ```
    Or remote exec: 
    ```powershell
     Invoke-Command -ComputerName MyComputerName -ScriptBlock {dsregcmd /status}
    ```
    .OUTPUTS
    List of the information in the token cache. 
    .Example
    Get-DsRegStatus 
    Displays a full output of dsregcmd / status.
    .LINK
    https://github.com/Canthv0/CloudAuthModule 
    .LINK
    https://github.com/tostka/verb-aad
    #>
    [CmdletBinding()] 
    Param() ;
    PROCESS {
        $dsregcmd = dsregcmd /status
        $o = New-Object -TypeName PSObject
        foreach($line in $dsregcmd){
            if($line -like "| *"){
                 if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
                      Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
                 }
                 $currentSection = $line.Replace("|","").Replace(" ","").Trim()
                 $so = New-Object -TypeName PSObject
            } elseif($line -match " *[A-z]+ : [A-z0-9\{\}]+ *"){
                 Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
            }
        }
        if(-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so){
            Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
        }
        return $o
    } ; 
}
#*------^ Get-DsRegStatus.ps1 ^------