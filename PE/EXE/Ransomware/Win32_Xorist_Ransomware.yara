rule Win32_Xorist_Ransomware : malicious
{
	meta:
		description 	= "Yara Rule for Xorist Ransomware"
		author          = "Suraj Mundalik"
		last_updated    = "2020-11-29"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Ransomware"
		malware         = "Xorist"
	strings:
		$s1 = "0p3nSOurc3 X0r157"
		$s2 = "HOW TO DECRYPT FILES.txt"
	condition:
		(uint16(0) == 0x5A4D and all of them)
}