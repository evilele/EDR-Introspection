$root = "$PSScriptRoot\.."
$rel = "$root\x64\Release"
$injectLoader = "$rel\InjectLoader.exe"
$monitorDLL = "$rel\EDRReflectiveHooker.dll"

$mdePID = (Get-Process -Name "MsMpEng").ID

# params to stop injection
$injArgs = "$monitorDLL $mdePID S D"

Start-Process $injectLoader -Args $injArgs -NoNewWindow -Wait