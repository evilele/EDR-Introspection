# EDR-Introspection
This project enables the Introspection into EDR products, i.e. what the EDR is doing at a given step for malware analysis. 
The enabling technologies of this projects are:
- ETW and ETW-TI tracing and filtering for relevant events (related to malware and EDR operations)
- hooking of the EDR's ntdll to inspect the EDRs actions

## Results
- enourmous visibility into all relevant EDR actions, able to determine the active detection stage of the EDR at each point in time
- low level operations like file read with WdFilter.sys remain hidden (but all events before and after can hint to it when it happens)
- no insights into emulation engine and exact signature matching (but result, i.e. block / non-block can be seen right after this)

### Attacks
see /attacks/
- Proc Inject: allocates mem in own process, writes raw bytes of `msfvenom -p windows/x64/exec CMD="calc.exe"` and executes it
- C2 Loader: allocates mem in own process, writes raw bytes of default CobaltStrike beacon and executes it
- Lsass Read: calls `MiniDumpWriteDump` from `dbghelp.dll` on lsass.exe, like mimikatz.exe (LSASS' PPL must be stripped before)

### Number of Events Unfiltered
|    Attack   | Data Source |              |        |             | Total |
|:-----------:|:-----------:|:------------:|:------:|:-----------:|:-----:|
|             | Antimalware | Threat Intel | Kernel | EDR Monitor |       |
| Proc Inject |       12973 |          183 |   4942 |        5712 | 23834 |
| C2 Loader   |        4695 |          728 |   3375 |       10569 | 19386 |
| Lsass Read  |        3287 |         2598 |   2204 |        7983 | 16096 |

### Number of Events Filtered
|    Attack   | Data Source |              |        |             | Total |
|:-----------:|:-----------:|:------------:|:------:|:-----------:|:-----:|
|             | Antimalware | Threat Intel | Kernel | EDR Monitor |       |
| Proc Inject |         855 |           21 |    132 |         165 |  1197 |
| C2 Loader   |         153 |           24 |    288 |        1283 |  1767 |
| Lsass Read  |        1526 |            8 |     53 |         169 |  1780 |

### Captured Events
*color legend see Visibility Overview below, https://github.com/cailllev/EDR-Introspection/edit/master/README.md#visibility-overview*

#### Events at Malware Store-Time
<img width="1977" height="646" alt="image" src="https://github.com/user-attachments/assets/d3c6b9d4-87a5-49fd-ab5b-467314b57edd" />

#### Events at Malware Startup-Time
<img width="1980" height="635" alt="image" src="https://github.com/user-attachments/assets/fcc80e91-ea3b-4029-b70b-2c3b673879ac" />
<img width="1981" height="474" alt="image" src="https://github.com/user-attachments/assets/5cb35d8c-d530-4a95-868b-3bfd1cce1faf" />
<img width="1980" height="747" alt="image" src="https://github.com/user-attachments/assets/80f8dc92-c814-4da8-889b-5a382ab9179a" />

#### Events at Malware Run-Time
<img width="1981" height="647" alt="image" src="https://github.com/user-attachments/assets/4a755b8a-979c-4a47-947f-686912cdfc7c" />

## How
- krabsETW to parse all relevant ETW providers
- EDRi.exe to 
	- filter the ETW events
	- decrypt and run predefined attacks
	- hook ntdll of EDR procs
- [kdu.exe](https://github.com/hfiref0x/KDU) to run procs as PPL-AntiMalware
- [EDRSandblast](https://github.com/cailllev/EDRSandblast) to disable kernel callbacks

### Architecture
<img width="2619" height="1311" alt="image" src="https://github.com/user-attachments/assets/c236dc0b-a0b7-4683-8954-672bd1bfc81b" />

### Hooking the EDR
*needs PPL (see KDU.exe) and kernel callbacks of WdFilter.sys removed (see EDRSandblast.exe -toggle_callback)*
#### Example
<img width="1791" height="864" alt="image" src="https://github.com/user-attachments/assets/69159723-a315-4c87-aab6-551792171d85" />

### Visibility Overview
<img width="1484" height="744" alt="image" src="https://github.com/user-attachments/assets/cfb3d3ce-d582-4bf2-bc57-3ff321859055" />

## How To
### Run the Framework
Depends on the EDR, harderning, etc. Generally, loading of vulnerable signed drivers and memory integrity (both in Device Security > Core Isolation) must be disabled for KDU and EDRSandblast to work.
Without EDRSandblast (without disabling kernel callbacks) the hooks cannot be injected. Without KDU (without PPL) no ETW-TI can be consumed and no hooks can be injected.<br><br>
It is recomended to **make an exclusion** for the EDR-Introspection folder, and **then** clone the repo to this folder!
```powershell
# print help
.\x64\Release\EDRi.exe -h

# run simplest attack: no ETW-TI, no hooking, minimal traces, run attack as child proc, no debug
.\x64\Release\EDRi.exe --edr-profile MDE --attack ProcInject_standard -r

# all visibility: ETW-TI, hooking ntdll, all traces, debug
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\EDRi.exe --edr-profile MDE --attack ProcInject_deconditioning -t -d" -prv 54

# alternative: first just hook, then do attacks (the hooks persist until restart)
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\EDRi.exe --just-hook" -prv 54
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\EDRi.exe --edr-profile MDE --attack ProcInject_deconditioning -t -d" -prv 54
```

### Create own attack
1. Copy folder `.\attacks\ProcInject` to `.\attacks\YourAttack`
2. rename all `.\attacks\YourAttack\ProcInject.vcxproj*` to `.\attacks\YourAttack\YourAttack.vcxproj*`
3. rename both references in `.\attacks\YourAttack\YourAttack.vcxproj` from `ProcInject` to `YourAttack`
4. rename both references in `.\attacks\YourAttack\build-features.bat` from `ProcInject.vcxproj` to `YourAttack.vcxproj` and both `ProcInject-%%C.exe` to `YourAttack-%%C.exe`
5. build YourAttack with all features: `.\attacks\YourAttack\build-features.bat`
6. the created (encrypted) exes should now be visible in the EDRi under available attacks
```powershell
# print just the attacks
.\x64\Release\EDRi.exe --edr-profile MDE --attack 
```

## Requirements
* Windows 10 / 11 (others not tested)
* ability to load vulnerable drivers (when testing with ETW-TI or ntdll hooking)
* excluding the `EDR-Introspection/` folder from your EDR

## Misc Tools
To play around or test stuff, helper exes are provided for the following actions.
All tools below must be run as Administrator.

### Start a Proc as PPL-AntiMalware
Normally EDR processes run as PPL-AntiMalware. The kernel only allows opening of these processes via `OpenProcess("edr.exe")` from other PPL-AntiMalware procs (or higher).
To run any process as PPL-AntiMalware:
```powershell
.\helpers\KDU\kdu.exe -pse "powershell.exe" -prv 54
```
Hint: When running a subprocess from these powershell procs, the subprocesses have no PPL flag anymore. If needed, run these subprocesses directly with kdu.exe, not via powershell.exe.
Example for opening an EDR proc and reading the loaded DLLs:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\ReadPEB.exe $((Get-Process MsMpEng).Id)" -prv 54
# [*] Reading PEB from process pid=3292
# [*] Got PBI.PebBaseAddress = 0x0000003EEDA3F000
# [*] Got remote PEB.LDR     = 0x00007FFBA1192920
# [*] Got remote remoteHead  = 0x00007FFBA1192940
# [+] Found entry: base=0x00007FF7AAE50000, size=0x0000000000043000, ldr=0x0000020C7B1056F0, name=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MsMpEng.exe
# [+] Found entry: base=0x00007FFBA0FC0000, size=0x0000000000268000, ldr=0x0000020C7B105540, name=C:\WINDOWS\SYSTEM32\ntdll.dll
# [+] Found entry: base=0x00007FFB9FD20000, size=0x00000000000C9000, ldr=0x0000020C7B105D20, name=C:\WINDOWS\SYSTEM32\KERNEL32.DLL
# [+] Found entry: base=0x00007FFB9E6B0000, size=0x00000000003F8000, ldr=0x0000020C7B1064A0, name=C:\WINDOWS\SYSTEM32\KERNELBASE.dll
# ...
```

### Disabling kernel callbacks
EDR products usually downgrad access to their processes, meaning even after a successful `OpenProcess("edr.exe")` via a PPL-AntiMalware process, the final GrantedAccess is downgraded.
MDE example:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process MsMpEng).Id) R" -prv 54
# OpenProcess(MsMpEng) succeeds
# VirtualAlloc fails:
# 0x1ff7d4 -> PROCESS_SET_SESSIONID | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION, not including: PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
```
Cortex EDR example:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process cyserver).Id) R" -prv 54
# OpenProcess(cyserver) succeeds
# VirtualAlloc fails:
# 0x101400 -> PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, not including: PROCESS_SET_SESSIONID | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SET_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
```
Therefore the callbacks must be removed, this can be done with (my fork of) [EDRSandblast](https://github.com/cailllev/EDRSandblast):
```powershell
.\x64\Release\tools\EDRSandblast.exe toggle_callbacks 0e1 --kernelmode -i
# ...
# [+] [ObjectCallblacks]          Callback at FFFFBB034F3F8E00 for handle creations & duplications:
# [+] [ObjectCallblacks]                  Status: Enabled
# [+] [ObjectCallblacks]                  Preoperation at 0xfffff8053aa2e540 [WdFilter.sys + 0x2e540]
# [+] [ObjectCallblacks]                  Callback belongs to an EDR and is enabled!
# ...
# [+] [ObjectCallblacks]  Disabling WdFilter.sys callback at 0xFFFFBB034F3F8E00 ...
# [+] Press ENTER to enable callbacks again:
```

### Ntdll hooking of any process
Now the same command from above works when the relevant callbacks got disabled:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process MsMpEng).Id) R" -prv 54
# [*] InjectLoader: Attempting to inject DLL 'C:\Users\hacker\source\repos\EDR-Introspection\x64\Release\EDRReflectiveHooker.dll' into PID=3292 using Reflective injection method.
# [+] Hooker: GrantedAccess to pid 3292: 0x1fffff -> full access
```

### Reading custom ETW events
The EDRReflectiveHooker.dll emits basic ETW events to track the actions of the EDR:
```powershell
.\x64\Release\ETWDump.exe Hooks
```

### Example attacks
`\attacks\` contains some (encrypted) attacks, which also emit basic ETW events to track the attacks actions.
To decrypt and use the attacks: 
```powershell
.\x64\Release\EDRi.exe -c "$(pwd)\x64\Release\attacks\attackX.exe.enc"
```
This drops an `attackX.exe` into `\x64\Release\attacks\`.

### Terminating a process
When you just want to terminate a process because it's buggy, something broke, etc., use this:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\ProcTerminator.exe <pid>" -prv 54
```
Hint: If it's an EDR proc, you might also want to disable kernel callbacks to get full access to the proc, see above.
