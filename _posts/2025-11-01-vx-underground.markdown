---
layout: post
title: Huntress CTF 2025 - vx-underground
categories: writeup cryptography
permalink: :categories:title
---

## Challenge Prompt

>vx-underground, widely known across social media for hosting the largest collection and
>library of cat pictures, has been plagued since the dawn of time by people asking: _"what's the password?"_
>
>Today, we ask the same question. We believe there are secrets shared amongst the cat pictures... but perhaps these also lead to just more cats.
>
>Uncover the flag from the file provided.

Provided: vx-underground.zip

after extracting everything we have this folder structure:
```
.
├── Cat Archive
│   ├── 000b8a1b1806920c5cec4a0ae10ec048209dad7596cfce219b9c2c3e1dc7f5f4.jpg
│   ├── 000c18880dc4af8a046aa78daeedf08e3fd575614df8e66e4cfbfd50a740ea77.jpg
│   ├── 000cb28f57ae572ba83149b2163f9076cdb9660310a8bf2547a19816cf611775.jpg
│   ├── 000cf1b3e38af81f673ca4ae37e0666137f84edd67f172c1f17d2333c3d521c0.jpg
│   ├── 00a7c5ac8139f72f15ac31130effd5c3619561635f8b13ec4a2ee626fb627ab4.jpg
│   ├── 00a91bd436455d4c73303f0d0a784660771dcc895989ad13942603d58ff798fe.jpg
│   ├── 00a9a9bb5d68ed994e4ecdc69e550dfdd38d1b673b1bac2909de9901318b4627.jpg
...
...
...
│   ├── 0fec6482e1d3ca80d56675347e455f89149be2cd80d73d1e7a0c7e33876f8d21.jpg
│   ├── 0fed52c4cae8b2f46e75b04d39c3767bf26defe90aaef808afa6a1e0c944c0d4.jpg
│   └── 0ff8658055ea93f30482de8a990600c2f8a301a1a2632afbffda5f60cac2e1c5.jpg
├── flag.zip
├── prime_mod.jpg
```

Lots of images with cats and all of them are named 0-9a-f, hex digits.

also there is one "special" image called prime_mod.jpg

lets see metadata in that image:

```
exiftool prime_mod.jpg
ExifTool Version Number         : 13.36
File Name                       : prime_mod.jpg
Directory                       : .
File Size                       : 43 kB
File Modification Date/Time     : 2025:09:21 17:31:54+02:00
File Access Date/Time           : 2025:10:17 16:25:15+02:00
File Inode Change Date/Time     : 2025:10:17 16:25:15+02:00
File Permissions                : -rw-------
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Exif Byte Order                 : Big-endian (Motorola, MM)
User Comment                    : Prime Modulus: 010000000000000000000000000000000000000000000000000000000000000129
Image Width                     : 400
Image Height                    : 400
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 400x400
Megapixels                      : 0.160
```

Interestingly, there is a User Comment with the following content:

`Prime Modulus: 010000000000000000000000000000000000000000000000000000000000000129`

I will write it down maybe it will have some meaning later. Lets check if file is `Cat Archive`
has anything interesting. Looking at exif data we see the pictures in `Cat Archive` also have User Comment. Lets use a little bash magic to get them:

```
exiftool -UserComment Cat\ Archive/*

.
.
.
======== Cat Archive/0fed52c4cae8b2f46e75b04d39c3767bf26defe90aaef808afa6a1e0c944c0d4.jpg
User Comment                    : 67-b24985d2b7c52aab8ccb58695c15d92c117936657f3fc0759cf94d3355e2f721
.
.
.
```

Lets clean it a little and get just the comment:

```
exiftool -UserComment Cat\ Archive/* | awk -F': ' '/User Comment/{print $2}'

.
.
.
145-2d9ab042a4bf21369ed72897366204feff54359585275a09ab64975c43304962
415-0551477bacb1ac94a91466ffa3d96e67940afde60ff0dc79d928609a55fccfe2
363-49387f88c14c828683bdd189bcf975e384a6ae2f897e1d135814a92e539da785
35-fd90c306d0873404616dfee1bc087a4a57e7ba39983465f9f560359049344e5b
.
.
.
```

They all follow similar pattern

[decimal number 1-457] - [hex digit]

lets sort them by "index", that first number before the `-`

```
exiftool -UserComment Cat\ Archive/* | awk -F': ' '/User Comment/{print $2}' | sort -n -t'-' -k1

Full output:
1-d278c2aad8f1c0de7023b4ec81df35fd9515a4330d5db48fda746c0548c200f5
2-60cf3885dabd878c2f24cd503b02db29c7c2dfdad310a8ec9c0d826b8d84ff2f
3-f84c72ebf84336085a6f1013ccff8cd987a0baa1c6d5c0fb650b14b4daf6ca2f
4-b2ebc1f2cc12460fbafb34975e12ecb4e0d5c6fde61ed64ae8c6c99a97c11cb3
...
...
...
455-56eaeded414bf121289177661c058aa1e8deb3a89a19885f7fa5e913975ba88a
456-4fefbf3da59a94e75643e606e20ca5964127b18132256086f25befaaf18207d7
457-0226a02be955ed20683f76e4ff7f3358c9657e73d210c874d0c0fec0de8d9dc5
```

So after knowing that we have Prime modulus, and lots of hex strings, there is one really important hint in the description of the challenge: `there are secrets shared`
After researching google for sometime and combining multiple keywords we come accross something really interesting: `Shamir's Secret Sharing`:
```
Shamir's Secret Sharing (SSS) is ==a cryptographic method that divides a secret into multiple parts, or "shares," which are distributed among different parties==. The secret can only be reconstructed when a minimum, predetermined number of shares (the "threshold") are combined, ensuring that no single party can access the secret on its own.
```

This really looks like our problem: one prime modulus and multiple secrets (hex values).

After saving those hex values to a file, we can implement the algorithm above to see if this is the case:

```python
#!/usr/bin/env python3
from functools import reduce

shares = {}

with open("hash.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if '-' in line:
            idx_str, hex_val = line.split('-', 1)
            idx = int(idx_str)
            shares[idx] = int(hex_val, 16)
        else:
            # Fallback if line is hex only
            shares[len(shares) + 1] = int(line, 16)

prime = int("010000000000000000000000000000000000000000000000000000000000000129", 16)

def modinv(a, p):
    return pow(a, -1, p)

def recover_secret(shares, prime):
    keys = sorted(shares.keys())
    secret = 0
    for i in keys:
        xi, yi = i, shares[i]
        num = 1
        den = 1
        for j in keys:
            if j != i:
                num = (num * -j) % prime
                den = (den * (xi - j)) % prime
        term = yi * num * modinv(den, prime)
        secret = (secret + term) % prime
    return secret

secret = recover_secret(shares, prime)
secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, "big")

print("Recovered secret (hex):", hex(secret))
print("Recovered secret (bytes):", secret_bytes)

# Output:
Recovered secret (hex): 0x2a5a49502070617373776f72643a20464170656b4a21794a363959616a5773
Recovered secret (bytes): b'*ZIP password: FApekJ!yJ69YajWs'

```

After we run it the output is `ZIP password: FApekJ!yJ69YajWs` so we can now unzip the file and get our flag

But when we `cat` flag.txt we are met with lots of line like this

```
MeowMeow;MeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeow;Meow;;MeowMeow;MeowMeow;MeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeow;Meow;;MeowMeow;MeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeowMeow;Meow;;
```

After researching what it could mean we find out it is some kind of esoteric language:

There are probably decoders for esoteric languages online, but I wrote my own script:

```
#!/usr/bin/env python3
from pathlib import Path

def decode_meowmeow(code):
    """
    MeowMeow esoteric language decoder
    Meow = instruction separator
    ; = statement separator
    Number of 'Meow's = different instructions
    """
    statements = code.split(';;')
    output = []

    for statement in statements:
        parts = statement.split(';')
        if len(parts) >= 2:
            meow_count = parts[1].count('Meow') // 4  # Count groups of 'Meow'
            if meow_count > 0:
                output.append(chr(meow_count))

    return ''.join(output)


def simple_meow_decode(code):
    """Count 'Meow' occurrences between semicolons"""
    parts = code.split(';;')
    result = []

    for part in parts:
        sections = part.split(';')
        for section in sections:
            if section.strip():
                count = section.count('Meow')
                if 32 <= count <= 126:  # Printable ASCII range
                    result.append(chr(count))

    return ''.join(result)


# Use pathlib for a safe, cross-platform path
file_path = Path.cwd() / 'cute-kitty-noises.txt'

with file_path.open('r') as f:
    meow_code = f.read()

print("[*] Decoding MeowMeow language...")

decoded = simple_meow_decode(meow_code)
print(f"[+] Decoded password: {decoded}")
```

After running it, we get:

```
[*] Decoding MeowMeow language...
[+] Decoded password: malware is illegal and for nerdscats are cool and badass
flag{35dcba13033459ca799ae2d990d33dd3}
```
