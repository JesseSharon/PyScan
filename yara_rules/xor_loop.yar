rule XOR_Loop_Signature
{
    meta:
        description = "Detects common XOR decryption loops in malware"
        severity = "medium"

    strings:
        $xor = { 31 C0 83 C0 ?? 31 ?? 88 07 47 } 
    condition:
        $xor
}
