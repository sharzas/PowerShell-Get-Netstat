Function Get-Netstat {
    #
    # Get a parsed and objectified version of Netstat -aon, with
    # extended Process information (if requested)
    #
    # -NetstatObject : Output from netstat to be parsed.
    # -ProcessObject : Output from Get-Process to be used for process resolution.
    #
    #                  NOTE: Select below properties to make it work if you get processes from a remote system!
    #
    #                  $ProcessProperties = @("ProcessName", "Id", @{N="FileName"; E={$_.MainModule.FileName}}, @{N="Description"; E={$_.MainModule.Description}})
    #                  $Processes = Get-Process|Select-Object $ProcessProperties
    #
    #
    # -ResolveProcesses : Get extended processinformation, including executable path (takes longer to complete)
    #
    # IMPORTANT: There is no validation between NetstatObject and ProcessObject. It is up to YOU
    #            to ensure they are from the same computer, at roughly the same time!
    #

    [CmdLetBinding()]
    Param (
        [switch]$DoDebug = $false,
        [switch]$ListMatches = $false,
        [switch]$ResolveProcesses = $false,
        [array]$NetstatObject,
        [array]$ProcessObject
    )

    if ($PSBoundParameters.ContainsKey("NetstatObject")) {
        #
        # NetstatObject supplied - use this instead of calling Netstat on local computer.
        #
        $Netstat = $NetstatObject
    } else {
        #
        # NetstatObject NOT supplied - get output from Netstat on local computer.
        #
        $Netstat=Netstat -aon
    }

    if ($ResolveProcesses) {
        #
        # Resolve processes requested
        #
        if ($PSBoundParameters.ContainsKey("ProcessObject")) {
            #
            # Process object supplied - use that for process resolution
            #
            $Processes = $ProcessObject
        } else {
            #
            # Set Properties to grab.
            #
            $ProcessProperties = @("ProcessName", "Id", @{N="FileName"; E={$_.MainModule.FileName}}, @{N="Description"; E={$_.MainModule.Description}})

            #
            # Grab processes.
            #
            $Processes = Get-Process|Select-Object $ProcessProperties
        }
    }

    $Result = ForEach ($line in $Netstat) {
        $Match = $false

        If ($line -match "^\s+(?<protocol>[A-Za-z]+)\s+(?<localip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<localport>\d{1,5})\s+(?<remoteip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<remoteport>\d{1,5})\s+(?<state>[A-Za-z_\-]+)\s+(?<pid>\d+)$" -or
            $line -match "^\s+(?<protocol>UDP)\s+(?<localip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<localport>\d{1,5})\s+\*:\*\s+(?<pid>\d+)$" -or
            $line -match "^\s+(?<protocol>[A-Za-z]+)\s+\[(?<localip>.+)\]:(?<localport>\d{1,5})\s+\[(?<remoteip>.+)\]:(?<remoteport>\d{1,5})\s+(?<state>[A-Za-z_\-]+)\s+(?<pid>\d+)$" -or
            $line -match "^\s+(?<protocol>[A-Za-z]+)\s+\[(?<localip>.+)\]:(?<localport>\d{1,5})\s+\*:\*\s+(?<pid>\d+)$") {

            if (!$DoDebug) {

                $m = [PSCustomObject]@{
                    IPVersion = ""
                    Protocol = if ($Matches.protocol) {$Matches.protocol} else {"Unknown"}
                    LocalIP = if ($Matches.localip) {$Matches.localip} else {"Undetermined"}
                    LocalPort = if ($Matches.localport) {$Matches.localport} else {"Undetermined"}
                    RemoteIP = if ($Matches.remoteip) {$Matches.remoteip} else {if ($Matches.protocol -eq "UDP") {""} else {"Undetermined"}}
                    RemotePort = if ($Matches.remoteport) {$Matches.remoteport} else {if ($Matches.protocol -eq "UDP") {""} else {"Undetermined"}}
                    ConnectionState = if ($Matches.state) {$Matches.state} else {if ($Matches.protocol -eq "UDP") {"LISTENING"} else {"Undetermined"}}
                    ProcessID = if ($Matches.pid) {$Matches.pid} else {"Undetermined"}
                    }

                $m.IPVersion =  if ($m.localip -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
                    "IPv4"
                } elseif ($m.localip -match ":+.*:+") {
                    "IPv6"
                } else {
                    "Undetermined"
                } 

                if ($ResolveProcesses) {
                    if ($m.ProcessID -match "^\d+$") {
                        #
                        # ProcessID matches a numeric value.
                        #
                        $Proc = @($Processes|Where-Object {$_.Id -eq $m.ProcessID})

                        if ($Proc.Count -gt 0) {
                            $m|Add-Member -Name "ProcessName" -MemberType NoteProperty -Value $Proc[0].ProcessName -Force
                            $m|Add-Member -Name "ProcessDescription" -MemberType NoteProperty -Value $Proc[0].Description -Force
                            $m|Add-Member -Name "ProcessFileName" -MemberType NoteProperty -Value $Proc[0].FileName -Force
                        }
                    }

                }

                $m
            } else {
                if ($ListMatches) {
                    Write-Host "MATCH: $line"
                    $Matches
                }
            }
        $Match = $true
        }

        if (!$Match -and $DoDebug) {
            Write-Host "NO MATCH: $line"
        }       
    }

    Return $Result
}