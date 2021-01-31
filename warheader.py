#!/usr/bin/python
#WARHEADER - by P4nr4ge (Dean McKinnel)
import sys
import os
import socket
import requests
import argparse
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BANG = '\033[35m]'
    FAIL = '\033[91m'
    DRED = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYANBK = '\033[46m'
    REDBK = '\033[41m'

print(bcolors.DRED + r'''\
 __      __                  __  __                      __
/\ \  __/\ \                /\ \/\ \                    /\ \
\ \ \/\ \ \ \     __    _ __\ \ \_\ \     __     __     \_\ \     __   _ __
 \ \ \ \ \ \ \  /'__`\ /\`'__\ \  _  \  /'__`\ /'__`\   /'_` \  /'__`\/\`'__\
  \ \ \_/ \_\ \/\ \L\.\\ \ \/ \ \ \ \ \/\  __//\ \L\.\_/\ \L\ \/\  __/\ \ \/
   \ `\___x___/\ \__/.\_\ \_\  \ \_\ \_\ \____\ \__/.\_\ \___,_\ \____\\ \_\
    '\/__//__/  \/__/\/_/\/_/   \/_/\/_/\/____/\/__/\/_/\/__,_ /\/____/ \/_/
                                                by P4nr4ge (Dean McKinnel)

Check for the exsitence of security headers (including deprecated headers)

Inspired by OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
''' + bcolors.ENDC)

# Create the parser
my_parser = argparse.ArgumentParser(description='Retrieve HTTP Response Headers')

required = my_parser.add_argument_group('required named arguments')
required.add_argument('-u','--url',nargs="+",help='The URL to request the HTTP Response Headers from...',required=True)

my_parser.add_argument('-p','--proxy',nargs="+",help='Proxy (http://x.x.x.x)')

args = my_parser.parse_args()
host = args.url[0]
if args.proxy:
    proxy = str(args.proxy[0])
    proxydict = {"http": proxy}
    print(bcolors.BOLD + "Proxy set to " + str(proxy) + bcolors.ENDC + "\n")

headers = {'User-Agent':'WarHeader v1.0 - by P4nr4ge'}
print(bcolors.BOLD + "Requesting Headers " + str(host) + bcolors.ENDC + "\n")

#Timeout
if args.proxy:
    response = requests.get(str(host),verify=True, timeout=120.0, proxies=proxydict, headers=headers)
else:
    response = requests.get(str(host),verify=True, timeout=3.0, headers=headers)

#Header Array
SecHeader = [
"Strict-Transport-Security",
"Content-Security-Policy",
"X-Frame-Options",
"X-Content-Type-Options",
"X-Permitted-Cross-Domain-Policies",
"Referrer-Policy",
]

DeprHeader = {
"Expect-CT":"This header will likely become obsolete in June 2021. Since May 2018 new certificates are expected to support SCTs by default. Certificates before March 2018 were allowed to have a lifetime of 39 months, those will all be expired in June 2021.",
"Public-Key-Pins":"Warning: This header has been deprecated by all major browsers and is no longer recommended. Avoid using it, and update existing code if possible",
"Feature-Policy":"This header was split into Permissions-Policy and Document-Policy and will be considered deprecated once all impacted features are moved off of feature policy.",
}

for head in SecHeader:
    if  head in response.headers:
        print (bcolors.OKCYAN + head + " - FOUND" + bcolors.ENDC + "\n")
        print("Value: " + str(head) + ":" + str(response.headers[head]) + "\n")
        time.sleep(0.5)
    else:
        print(bcolors.FAIL + head + " - NOT FOUND" + bcolors.ENDC + "\n")
        time.sleep(0.5)
#Search for deprecated headers
print(bcolors.BOLD + "Searching for Deprecated Headers..." + bcolors.ENDC + "\n")
ignorehead = {"X-XSS-Protection":"\nThe X-XSS-Protection header has been deprecated by modern browsers and its use can introduce additional security issues on the client side. As such, it is recommended to set the header as X-XSS-Protection: 0 in order to disable the XSS Auditor, and not allow it to take the default behavior of the browser handling the response. Please use Content-Security-Policy instead."}

for key in DeprHeader:
    if key in response.headers:
        print(bcolors.REDBK + key + " - (Deprecated)" + bcolors.ENDC)
        print(str(key) + " " + str(response.headers[key] + "\n"))
        print(str(key) + ": " + str(DeprHeader[key]) + "\n")
        time.sleep(0.5)
    else:
        print(str(key) + " Not detected \n")
        time.sleep(0.5)

if response.headers['X-XSS-Protection'] == str(1):
    print (bcolors.REDBK + key + " - Deprecated key value not recommended" + bcolors.ENDC + "\n")
    print (ignorehead['X-XSS-Protection'] + "\n")
    time.sleep(0.5)
elif response.headers['X-XSS-Protection'] == str(0):
    print (bcolors.OKCYAN + 'X-XSS-Protection deprecated header value set to recommended 0' + bcolors.ENDC) + "\n"
    print ("X-XSS-Protection: " + (response.headers['X-XSS-Protection']) + "\n")
    time.sleep(0.5)
else:
    print(str(key) + " Not detected \n")
    time.sleep(0.5)
