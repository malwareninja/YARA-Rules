rule Gozi_VBS_Dropper : malicious
{
	meta:
		description 	= "YARA Rule for Gozi/Ursnif VBS Dropper"
		author          = "Suraj Mundalik"
		last_updated    = "2020-12-01"
		sharing         = "TLP:WHITE"
		category        = "Malware"
		type            = "Dropper"
		malware         = "Gozi"
	strings:
		$s1 = "WScript.Shell"
		$s2 = "MsgBox(\"Cant start because MSVCR101.dll is missing from your computer."
		$s3 = /rundll32.{1,500},DllRegisterServer/
	condition:
		all of them
}