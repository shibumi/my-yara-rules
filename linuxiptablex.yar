rule LinuxIptabLeX
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-15"
        description = "Rules for Linux/IptabLe{s|x}"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $s1 = { 49 70 74 61 62 4c 65 ( 73 | 78 ) }
        $s2 = "#!/bin/sh\n%s\nexit 0\n"
        $s3 = "nohup sh /delxxaazz>/dev/null&"
        $s4 = "face"
        $s5 = "GETFILE_%08X"
        $s6 = { 2321 2f62 696e 2f62 6173 680a 736c 6565 
                7020 330a 6b69 6c6c 2025 640a 736c 6565
                7020 310a 726d 202d 6620 2573 0a72 6d20
                2d72 6620 2224 3022 0a00 }
        $s7 = { 2f65 7463 2f72 632e 642f 696e 6974 2e64
                2f49 7074 6162 4c65 ( 73 | 78 ) }
        $s8 = { 2f65 7463 2f72 632e 642f 4970 7461 624c
                65 ( 73 | 78 ) }
        $s9 = { 2f62 6f6f 742f 4970 7461 624c 65 ( 73 | 78 ) }
        $s10= { 2f49 7074 6162 4c65 ( 73 | 78 ) }
        $s11= { 2f62 6f6f 742f 2e49 7074 6162 4c65 ( 73 | 78 ) }
        $s12= { 2f75 7372 2f2e 4970 7461 624c 65 ( 73 | 78 ) }
        $s13= { 2f2e 4970 7461 624c 65 ( 73 | 78 ) }
        $s14= "xxxx"
        $s15= "/delallmykkk>/dev/null"
        $s16= "/delallmykkk"

    condition:
        12 of them
}
