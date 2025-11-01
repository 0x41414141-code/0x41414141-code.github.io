---

layout: post
title: "PicoCTF - DISKO1"
categories: writeup forensics 
permalink: :categories/:title

---

# Writeup: DISKO 1

## Challenge Description
> *Can you find the flag in this disk image?*

**Challenge Files:** `disk-1.dd`

## Initial Recon & Analysis
* **Tools needed:** grep, strings

## Solution Walkthrough

### Step 1: Understanding the Challenge
```bash
# Initial reconnaissance commands
file disko-1.dd

disko-1.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", Media descriptor 0xf8, sectors/track 32, heads 8, sectors 102400 (volumes > 32 MB), FAT (32 bit), sectors/FAT 788, serial number 0x241a4420, unlabeled

```

### Step 2: 
```bash
strings disko-1.dd | grep 'picoCTF{.*}$'
picoCTF{1t5_ju5t_4_5tr1n9_be6031da}
```

## Flag

`picoCTF{1t5_ju5t_4_5tr1n9_be6031da}`

## Tools & References Used
* strings
* grep
