rule Hardcoded_IP_Address
{
    meta:
        description = "Detects embedded IPv4 addresses (possible C2)"
        severity = "medium"

    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/

    condition:
        #ip > 5
}
