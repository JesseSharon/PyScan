rule Suspicious_WinAPI_Calls
{
    meta:
        description = "Detects common suspicious API calls"
        author = "PyScan"
        severity = "medium"

    strings:
        $a1 = "VirtualAlloc"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "LoadLibraryA"

    condition:
        2 of ($a*)
}
