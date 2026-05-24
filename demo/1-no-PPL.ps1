$root = "$PSScriptRoot\.."
$rel = "$root\x64\Release"
$injectLoader = "$rel\InjectLoader.exe"
$monitorDLL = "$rel\EDRReflectiveHooker.dll"
$pplQuery = "$root\helpers\pplQuery.exe"

# query PPL level of EDR
$edrProc = "MsMpEng"
$mdePID = (Get-Process -Name $edrProc).ID
Write-Host "$edrProc -> " -NoNewLine
Start-Process $pplQuery -Args $mdePID -NoNewWindow -Wait

# inject DLL
$args = "$monitorDLL $mdePID L D"
Start-Process $injectLoader -Args $args -NoNewWindow -Wait