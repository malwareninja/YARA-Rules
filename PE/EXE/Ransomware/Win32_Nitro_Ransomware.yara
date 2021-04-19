rule Win32_Nitro_Ransomware : malicious
{
	meta:
		description 	= "YARA Rule for Nitro Ransomware"
		author          = "Suraj Mundalik"
		last_updated    = "2021-04-20"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Ransomware"
		malware         = "Nitro"
	strings:
		$s1 = "NitroRansomware" wide ascii
		$s2 = "NitroValid" wide ascii
		$s3 = "All of your important documents have been locked and have been AES encrypted" wide ascii
	condition:
		(uint16(0) == 0x5A4D and all of them)
}