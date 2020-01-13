# Written by: Eoin Finney
# Date: 09-01-20 <-> 10-01-20
# Contact Info: B00003420@mytudublin.ie | finneyyy@protonmail.com | Spectr3#1389 @ Discord
# Documentation used: https://developers.virustotal.com/reference
# Notes:
'''
    Hey! You're looking at the source of this little tool. Hope you won't be surprised to hear
    that this tool was relatively easy to code, but not when you're rushing for time. 
    Separate functions for each option? Easy mode! The VirusTotal documentation is a 
    really good starting point for this tool.

    This is the 0.1 of the tool.

    There were plenty of problems getting this tool written. On the 8th of Jan, I had a blue screen
    on the laptop, and soon realised that I lost a completed version of this tool and report. 
    So the scramble to get the tool and report rewritten began. See, I started on one drive, but had my working
    project on the ssd. Weird way of doing things? Perhaps, but that's the way I work, and it's
    a good system for the most part.

    Notes for me: Because of the way requests() works, parameters has to be called params,
    otherwise error is thrown.
'''

import json
import tkinter as tk
from tkinter import filedialog
import sys, time, os
try:
    import requests
except:
    raise ImportError('This program needs the requests package to work. Install it using the command "pip install requests"')

def banner():
    print("\n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=")
    print("\n *** VirusTotalParser  -  By Eoin Finney/B00093420 ***")
    print("\n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=")

def main():
    while True:
        option=menu()
        if option=="1":
            file_report()
        elif option=="2":
            file_scan()
        elif option=="3":
            url_upload()
        elif option=="4":
            url_report()
        elif option=="5":
            stats_on_report()
        elif option=="6":
            exit()
        else:
            error()

def menu():
    '''
    Menu looks something like:
        [1] -> Get a File Report
        [2] -> Scan a File
        [3] -> Upload a URL
        [4] -> Get a URL Report
        [5] -> Get Stats on a Report
        [6] -> Upload a file/url larger than 32MB
        [7] -> Exit

    bla bla bla
    '''
    #os.system("cls")
    banner()

    print("[1] Get a File Report")
    print("")
    print("[2] Scan a File")
    print("")
    print("[3] Upload a URL")
    print("")
    print("[4] Get a URL Report")
    print("")
    print("[5] Get Stats on a Report (Not working as intended)")
    print("")
    print("[6] Exit")
    return input("\nChoice: ")

def file_report():
    #Get a scan report from VT for a file/ The resource can be md5/sha1/sha256 hashes
    url="https://www.virustotal.com/vtapi/v2/file/report"
    params={"apikey": input("API key: "), "resource": input("Hash: ")}
    response=requests.get(url,params=params)
    print("")
    print(response.json())
    return response.json()

def file_scan():
    #Read in a file, and get response back
    url="https://www.virustotal.com/vtapi/v2/file/scan"
    params={"apikey": input("API key: ")}
    root=tk.Tk()
    root.withdraw()
    file={'file':(filedialog.askopenfilename(initialdir="C:/", title="Select File", defaultextension=".py"))}
    response=requests.post(url, files=file,params=params)
    print(response.json())
    return response.json()

def url_upload():
    url='https://www.virustotal.com/vtapi/v2/url/scan'
    params={'apikey': input("API key: "), 'url':input("URL: ")}
    response=requests.post(url,data=params)
    print(response.json())
    return response.json()

def url_report():
    url='https://www.virustotal.com/vtapi/v2/url/report'
    params={"apikey": input("API key: "), "resource": input("Scan_Id: ")} #Id comes from the search bar
    response=requests.get(url,params=params)
    print("")
    print(response.json())
    return response.json()

def stats_on_report():
    #Get a report using a previous hash, i guess
    url='https://www.virustotal.com/vtapi/v2/file/report'
    params={"apikey": input("API key: "), "resource": input("Hash: ")}
    response=requests.get(url, params=params)
    print(response.json())
    return response.json()

def exit():
    print("See you later!")
    time.sleep(1)
    sys.exit(0)

def error():
    print("Invalid entry or choice. Please enter again")
    time.sleep(1)

if __name__ == '__main__':
    main()