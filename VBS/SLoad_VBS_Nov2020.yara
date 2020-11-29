rule SLoad_VBS_Nov2020 : malicious
{
	meta:
		description 	= "YARA Rule for SLoad VBS Downloader November 2020"
		author          = "Suraj Mundalik"
		last_updated    = "2020-11-24"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Downloader"
		malware         = "SLoad"
	strings:
		$s1 = "WScript.Shell"
		$s2 = "Pattern=\"(UryC|bbpuhx|LOMw|DqRJYg|TYXT|PXFO|FOrhd|vMkk|LCvWQ|PpVx|fKiY|"
	condition:
		all of them
}