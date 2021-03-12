rule Win32_DearCry_Ransomware : malicious
{
	meta:
		description 	= "YARA Rule for DearCry a.k.a DoejoCrypt Ransomware"
		author          = "Suraj Mundalik"
		last_updated    = "2021-03-13"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Ransomware"
		malware         = "DearCry"
	strings:
        	$s1 = "DEARCRY!"
		$s2 = "Your file has been encrypted"
		$s3 = "If you want to decrypt, please contact us"
		$s4 = "And please send me the following hash!"
		$s5 = "C:\\Users\\john\\"
	condition:
		(uint16(0) == 0x5A4D and all of them)
}
