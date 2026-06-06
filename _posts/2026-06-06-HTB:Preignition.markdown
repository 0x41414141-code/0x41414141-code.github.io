---
title: "HTB: Preignition"
date: 2026-06-06 23:00:00 +02:00
categories: [hackthebox, web]
tags: [nginx, gobuster, dir-busting, default-credentials, ctf]
excerpt: "Very easy Linux machine. Web enumeration leads to a hidden admin panel exploitable via default credentials."
---

## Overview

Preignition is a beginner-friendly Linux machine focused on web enumeration and directory fuzzing. The goal is to discover a hidden admin panel and exploit a misconfiguration — default credentials left unchanged. Simple concept, but it reflects a surprisingly common real-world vulnerability.

**Difficulty:** Very Easy  
**OS:** Linux  
**IP:** 10.129.12.203

---

## Reconnaissance

### Port Scan

Starting with a basic Nmap scan to see what's exposed:

```bash
nmap $IP
```

```
PORT   STATE SERVICE
80/tcp open  http
```

Only port 80 open. Running a version scan to get more detail:

```bash
nmap -sV $IP
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
```

The target is running **nginx 1.14.2** on port 80.

---

## Enumeration

### Directory Fuzzing

With only a web server exposed, the next step is directory brute-forcing — systematically checking paths to find hidden pages.

Using Gobuster in `dir` mode with a basic wordlist, specifying the `.php` extension:

```bash
gobuster dir -u http://$IP -w wordlist.txt -x php
```

```
===============================================================
Gobuster v3.8.2
===============================================================
[+] Url:       http://10.129.12.203
[+] Wordlist:  wordlist.txt
===============================================================

admin.php   (Status: 200) [Size: 999]

===============================================================
Finished
===============================================================
```

Gobuster finds **admin.php** with a `200 OK` response — the page exists and is accessible.

---

## Exploitation

### Default Credentials

Navigating to `http://$IP/admin.php` reveals a login form.

![admin.php login page](../../assets/admin-page.png)

Before reaching for any brute-forcing tool, it's worth testing default credentials. Many web applications ship with default admin logins that never get changed — a misconfiguration that causes real breaches in production environments.

Testing `admin` / `admin` — it works. The flag is displayed after login.

---

## Key Takeaways

- **Directory busting** is a fundamental enumeration technique. Tools like Gobuster, Feroxbuster, or ffuf can surface hidden endpoints that aren't linked anywhere visible.
- **Default credentials** remain one of the most exploited misconfigurations in real-world systems. Trivial to overlook during setup, trivial to exploit afterward.
- Always check service versions during recon — nginx 1.14.2 is outdated, and knowing the exact version can open doors to known CVEs in real engagements.
