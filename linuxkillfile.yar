rule LinuxKillFile
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-15"
        description = "Rules for Linux/KillFile alias slexec"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $s1 = "/getsetup.rar"
        $s2 = "KillProcess"
        $s3 = "/kill.txt"
        $s4 = "/run.txt"
        $s5 = "MlCROS0FT|%s %s %s|%s"
        $s6 = "/tmp/helloworld"
        $s7 = "/usr/bin/btdaemon"
        $s8 = ".IptabLes|.IptabLex"
        $s9 = "/etc/init.d/bluetoothdaemon"
        $s10= "#!/bin/sh\n/usr/bin/btdaemon"
        $s11= { 2f65 7463 2f72 633? 2e64 2f53 3930 626c 
                7565 746f 6f74 68 }
        $s12= "/tmp/.flush"
        $s13= "select:\n"

    condition:
        9 of them
}
