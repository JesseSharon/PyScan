rule C2_Communication_Strings
{
    meta:
        description = "Detects suspicious C2 style communication patterns"
        severity = "medium"

    strings:
        $s1 = "cmd="
        $s2 = "upload="
        $s3 = "download="
        $s4 = "execute="
        $s5 = "auth_token"

    condition:
        any of them
}
