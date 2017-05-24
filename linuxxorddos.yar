rule LinuxXorDDoS
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-12"
        description = "Rules for Linux/Xor.DDoS"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $xorkey = { 42 42 32 46 41 33 36 41 41 41 39 35 34 31 46 30 }
        $s1 = "HOME=/"
        $s2 = "HISTFILE=/dev/null"
        $s3 = "MYSQL_HISTFILE=/dev/null"
        $s4 = "#!/bin/sh"
        $s5 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done"

    condition:
        $xorkey or 4 of ($s*)
}
