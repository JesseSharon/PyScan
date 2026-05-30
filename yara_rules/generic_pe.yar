rule Generic_PE_File
{
    meta:
        description = "Detects generic Windows PE files"
        author = "PyScan"
        severity = "low"

    strings:
        $mz = { 4D 5A }    // MZ header
        $pe = "PE"

    condition:
        $mz at 0 and $pe
}
