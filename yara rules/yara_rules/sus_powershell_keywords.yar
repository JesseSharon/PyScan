rule Suspicious_PowerShell_Keywords
{
    meta:
        description = "Detects common keywords used by PowerShell malware"
        severity = "high"

    strings:
        $d1 = "Invoke-Expression"
        $d2 = "DownloadString"
        $d3 = "IEX"
        $d4 = "New-Object Net.WebClient"

    condition:
        any of them
}
