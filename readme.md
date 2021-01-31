<h1>Warheader</h1>

This is just a small project for retrieving HTTP response headers based upon the OWASP Secure Headers Project.
(https://owasp.org/www-project-secure-headers/)

```
Usage:
\
 __      __                  __  __                      __
/\ \  __/\ \                /\ \/\ \                    /\ \
\ \ \/\ \ \ \     __    _ __\ \ \_\ \     __     __     \_\ \     __   _ __
 \ \ \ \ \ \ \  /'__`\ /\`'__\ \  _  \  /'__`\ /'__`\   /'_` \  /'__`\/\`'__\
  \ \ \_/ \_\ \/\ \L\.\\ \ \/ \ \ \ \ \/\  __//\ \L\.\_/\ \L\ \/\  __/\ \ \/
   \ `\___x___/\ \__/.\_\ \_\  \ \_\ \_\ \____\ \__/.\_\ \___,_\ \____\\ \_\
    '\/__//__/  \/__/\/_/\/_/   \/_/\/_/\/____/\/__/\/_/\/__,_ /\/____/ \/_/
                                                by P4nr4ge (Dean McKinnel)

Check for the exsitence of security headers (including deprecated headers)

usage: warheader.py [-h] -u URL [URL ...] [-p PROXY [PROXY ...]]

Retrieve HTTP Response Headers

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY [PROXY ...], --proxy PROXY [PROXY ...]
                        Proxy (http://x.x.x.x)

required named arguments:
  -u URL [URL ...], --url URL [URL ...]
                        The URL to request the HTTP Response Headers from...
```
Example:

```
python warheader.py --url http://www.example.com
```

Proxy:
```
python warheader.py --url http://www.google.com -p http://127.0.0.1:8080
```
