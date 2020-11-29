rule Win32_LockBit_Ransomware : malicious
{
	meta:
		description 	= "YARA Rule for LockBit Ransomware"
		author          = "Suraj Mundalik"
		last_updated    = "2020-11-29"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Ransomware"
		malware         = "LockBit"
	strings:
		$s1 = "LockBit"
        $s2 = "/c vssadmin Delete Shadows /All /Quiet"
		$s3 = "Elevation:Administrator!new:"
	condition:
		(uint16(0) == 0x5A4D and all of them)
}