rule LinuxChinaZ
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-15"
        description = "Rules for Linux/ChinaZ"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $chinaz = "ChinaZ"
        $s1 = "%s: line %d: expected `on' or `off', found `%s'\n"
        $s2 = "%s: line %d: bad command `%s'\n"
        $s3 = "passwd"
        $s4 = "shadow"
        $s5 = "ORIGIN"
        $s6 = "/etc/resolv.conf"
        $s7 = "gethostbyname_r"
        $s8 = "LOCALDOMAIN"
        $s9 = "edns0"
        $s10= "i18n:1999"

    condition:
        $chinaz and 7 of ($s*)
}
