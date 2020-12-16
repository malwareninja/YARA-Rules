rule JS_Dropper_Loda_RAT : malicious
{
	meta:
		description 	= "YARA Rule for Loda RAT aka Nymeria"
		author          = "Suraj Mundalik"
		last_updated    = "2020-12-15"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Dropper"
		malware         = "Loda RAT"
	strings:
		$s1 = "function basebase(_0x" nocase
		$s2 = "new ActiveXObject"
		$s3 = "\\x54\\x56\\x71\\x51\\x41\\x41\\x4D\\x41\\x41\\x41\\x41"
	condition:
		all of them
}