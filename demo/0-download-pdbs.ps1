# py -m pip install requests pefile

$r = $PsScriptRoot
$edrs = "$r\..\helpers\EDRSandblast"
$eoffs = "$edrs\ExtractOffsets.py"
$offsets = "$edrs\offsets\"

if(!(Test-Path $offsets)) {
	mkdir $offsets
}
copy C:\Windows\System32\ntoskrnl.exe $offsets
copy C:\Windows\System32\drivers\fltmgr.sys $offsets
py $eoffs ntoskrnl -i $offsets
py $eoffs fltmgr -i $offsets

mv "$r\NtoskrnlOffsets.csv" $offsets -Force
mv "$r\FltmgrOffsets.csv" $offsets -Force