import "pe"

rule Win32_FickerStealer_Trojan : malicious
{
	meta:
		description 	= "YARA Rule for Ficker Stealer Trojan"
		author          = "Suraj Mundalik"
		last_updated    = "2020-12-15"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Trojan"
		malware         = "Ficker Stealer"
	strings:
		$s1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x"
		$s2 = "MASSLoader.dll"
		$s3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
	condition:
		(
			pe.characteristics & pe.DLL and
			pe.imports("IPHLPAPI.DLL", "GetAdaptersAddresses") and 
			pe.imports("WININET.dll") and 
			all of them
		)
}