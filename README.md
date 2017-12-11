# CheckMail
Detect malicious contents in mail and notify User


CheckMail

A simple application to check mails for malicious contents. Many organisation have similar applications that trap malicious mail in a sandbox and do a thorough  analysis, while it not possible or rather not feasible to analyze mail for a single mail account. Setting up a virtual sandbox to do analysis is also quite expensive. 

CheckMail is a simple yet elegant solution! Anybody can link an account their personnel gmail account and it performs analysis on macros, pdfs and malicious links to detect malware and notify the user that the mail contains malicious contents and warns the user to delete the mail immediately

Requirements:
  Kali Linux
  Oletools installed
    pip install oletools
  Python 2.7
  peepdf 
    Pre-installed on Kali
  VirusTotal API key
    https://community.mcafee.com/docs/DOC-6456
  Gmail Account

