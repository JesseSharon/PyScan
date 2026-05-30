rule Large_Base64_Block
{
    meta:
        description = "Detects suspicious large Base64 encoded payloads"
        severity = "medium"

    strings:
        $b64 = /[A-Za-z0-9\/+=]{150,}/

    condition:
        $b64
}
