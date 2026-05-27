rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = 90
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download or encoded command pattern"
        severity = 50
    strings:
        $a = "EncodedCommand" nocase
        $b = "DownloadString" nocase
        $c = "Invoke-WebRequest" nocase
        $d = "FromBase64String" nocase
    condition:
        any of them
}

rule Suspicious_Windows_API_Strings
{
    meta:
        description = "Suspicious Windows API names in a binary or script"
        severity = 35
    strings:
        $a = "CreateRemoteThread" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "URLDownloadToFile" ascii wide
        $d = "RegSetValueEx" ascii wide
    condition:
        any of them
}
