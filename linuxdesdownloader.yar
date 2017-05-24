rule LinuxDESDownloader
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-15"
        description = "Rules for Linux/DES.Downloader"
        in_the_wild = true
        family = "ELF-Malware"

    strings:
        $s1 = "main. plain text : ~%s~\n"
        $s2 = "Leaving...\n"
        $s3 = "downloader exit ..."
        $s4 = "main . execl (%s) error!\n"
        $s5 = "main . connect is ok!"
        $s6 = "main . connect error"
        $s7 = "main . send is error!"
        $s8 = "main . fork error."
        $s9 = "main . fork error 2."
        $s10= "main . waitpid error."

    condition:
        7 of them
}
