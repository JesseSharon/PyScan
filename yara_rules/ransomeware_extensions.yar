rule Ransomware_Extension_Patterns
{
    meta:
        description = "Detects common ransomware file extensions"
        severity = "high"

    strings:
        $e1 = ".locked"
        $e2 = ".encrypted"
        $e3 = ".pay"
        $e4 = ".ransom"

    condition:
        any of them
}
