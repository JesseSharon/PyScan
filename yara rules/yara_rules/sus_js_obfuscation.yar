rule Suspicious_JS_Obfuscation
{
    meta:
        description = "Detects very common JS obfuscation patterns"
        severity = "medium"

    strings:
        $s1 = /var\s*[A-Za-z0-9_]{1,10}\s*=\s*unescape\(/ nocase
        $s2 = /eval\(function/ nocase
        $s3 = "String.fromCharCode"

    condition:
        any of them
}
