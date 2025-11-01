---

layout: post
title: "Huntress CTF 2025 - Bussing Around"
categories: writeup forensics network 
permalink: :categories/:title

---

## Challenge Description

>One of the engineers noticed that an HMI was going haywire.
>
>He took a packet capture of some of the traffic but he can't make any sense of it... it just looks like gibberish!
>
>For some reason, some of the traffic seems to be coming from someone's computer. Can you help us figure out what's going on?

Provided files: `bussing_around.pcapng`

----

When we open a file `bussing_around.pcapng` with the tool wireshark we see that there are a lot of `modbus` packages recorded. Because this challenge will be done easier with tshark we should get familiar with it:

```
tshark -r capture.pcapng -z io,phs

===================================================================  
Protocol Hierarchy Statistics  
Filter:    
  
frame                                    frames:16909 bytes:1251252  
 eth                                    frames:16909 bytes:1251252  
   ipv6                                 frames:1 bytes:142  
     icmpv6                             frames:1 bytes:142  
   arp                                  frames:2 bytes:102  
   ip                                   frames:16906 bytes:1251008  
     tcp                                frames:16906 bytes:1251008  
       mbtcp                            frames:11266 bytes:878748  
         modbus                         frames:11266 bytes:878748  
===================================================================
```

This shows a hierarchical breakdown of all protocols in the capture file with percentages.

After some googling to understand how Modbus works:

```
Modbus is an industrial communication protocol that enables data exchange between electronic devices, most commonly in building and manufacturing automation. It works on a request-response model where a client device sends a request to one or more server devices, which then respond with the requested data or a status acknowledgment
```

After looking at the provided file we can notice that there are only 3 registers used: 0,4 and 10. 

```
eurus@archlinux:~/Documents/day18$ tshark -r capture.pcapng -Y "modbus" -T fields -e modbus.regnum16 | sort | uniq -c |  
sort -nr  
  4528 0  
  2274 10  
  2240 4  
  2224
  ```


After analyzing all three registers:
- Register 4: Had diverse values but no obvious pattern
- Register 10: Values were in ASCII range but didn't form coherent text
- Register 0: Only two values with high frequency


The binary nature of Register 0 stood out as the most likely candidate for hidden data, since binary is the fundamental language of computers and perfect for encoding files.

I concatenated the sequential 0 and 1 values into a continuous binary string, then grouped them into 8-bit chunks (bytes). Each byte was converted from binary to its decimal value, creating a byte array that was written directly to disk as a file.

```
tshark -r capture.pcapng -Y "modbus.regnum16 == 0 and tcp.dstport==502" -T fields -e  
modbus.regval_uint16 | tr -d '\n' > binary.txt
```

added the destination port to not get duplicates with same value in both request and response.

Then I wrote a simple script that will get the 0s and 1s and save them to a file:

```bash
python3 -c "b=open('binary.txt').read().replace(' ','').replace('\n',''); open('flag','wb').write(int(b,2).to_bytes(len(b)//8,'big'))"
```

Running a [[file]] command we see this:

```
file flag  
flag: Zip archive data, at least v1.0 to extract, compression method=store
```

When we try to extract it we also see this comment:
```Comment = The password is 5939f3ec9d820f23df20948af09a5682 .```

And `flag.txt` gets extracted - `flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}` :)