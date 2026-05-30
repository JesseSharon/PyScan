rule Detect_UPX_Packer
{
    meta:
        description = "Detects UPX-packed executables"
        author = "PyScan"
        severity = "medium"

    strings:
        $upx1 = "UPX!"
        $upx2 = ".UPX"

    condition:
        any of them
}
