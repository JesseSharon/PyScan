rule PyInstaller_Packed
{
    meta:
        description = "Detects PyInstaller-packed executables"
        severity = "medium"

    strings:
        $py1 = "pyi-windows-manifest-filename"
        $py2 = "pyi_rth"
        $py3 = "PYZ"

    condition:
        2 of them
}
