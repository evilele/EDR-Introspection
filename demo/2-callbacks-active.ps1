$root = "$PSScriptRoot\.."
$rel = "$root\x64\Release"
$injectLoader = "$rel\InjectLoader.exe"
$monitorDLL = "$rel\EDRReflectiveHooker.dll"
$pplQuery = "$root\helpers\pplQuery.exe"

$mdePID = (Get-Process -Name "MsMpEng").ID

# inject params
$injArgs = "$monitorDLL $mdePID L D"
$injCMD = "$injectLoader $injArgs"

# inject DLL with PPL
$kdu = "$root\helpers\KDU\kdu.exe"
$kduArgs = "-pse `"$injCMD`" -prv 54"

Start-Process $kdu -Args $kduArgs -NoNewWindow -Wait

# KDU cleanup
rm "NeacSafe64.inf"
rm "NeacSafe64.sys"