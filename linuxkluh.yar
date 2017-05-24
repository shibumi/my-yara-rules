rule LinuxKluh
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-15"
        description = "Rules for Linux/Kluh"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $attack1 = "HULK"
        $attack2 = "RAND"
        $attack3 = "HTTP"
        $attack4 = "SSYN"
        $attack5 = "DNSQ"
        $attack6 = "TCPM"
        $attack7 = "DNSL"
        $attack8 = "STOP"
        $s1      = "Try Exec Poc GetRoot!!!"
        $s2      = "LOGIN_FREE:%s%s@%s@%s@%s@%s"
        $s3      = "/dev/null"
        $s4      = "1..."
        $s5      = "2..."

    condition:
        5 of ($attack*) and 3 of ($s*)
}
