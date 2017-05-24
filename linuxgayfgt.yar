rule LinuxGayfgt
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-16"
        description = "Rules for Linux/Gayfgt"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $s1 = { 2f 62 69 6e 2f 62 75 73 79 62 6f 78 3b 65 63 68 6f 20 2d 65 20
                27 67 61 79 66 67 74 27 }
        $s2 = "gayfgt"
        $s3 = "REPORT %s:%s:%s"
        $s4 = "SCANNER ON | OFF"
        $s5 = "KILLATTK"
        $s6 = "JUNK"
        $s7 = "Killed %d."
        $s8 = "LOLNOGTFO"
        $s9 = "None Killed."
        $s10= "\t00000000\t"
        $s11= { 07 00 08 00 09 00 0a 00 0b 00 0c 00 0d 00 0e 00 0f 00 }
        $s12= "/etc/hosts"
        $s13= "/etc/config/hosts"

    condition:
        6 of them
}
