rule Win32_RansomX_Ransomware : malicious
{
	meta:
		description 	= "YARA Rule for Ransom X Ransomware"
		author          = "Suraj Mundalik"
		last_updated    = "2020-12-15"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Ransomware"
		malware         = "Ransom X"
	strings:
        $s1 = "!TXDOT_READ_ME!.txt" wide
        $s2 = "ransom.exx"
        $s3 = "/set {default} recoveryenabled no" wide
	condition:
		(uint16(0) == 0x5A4D and all of them)
}