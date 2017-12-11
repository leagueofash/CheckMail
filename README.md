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
    Libraries that are required!
      a. easygui
      b. requests
      c. subprocess, os
      d. zipfile
      e. urlextract
            https://pypi.python.org/pypi/urlextract
      
  peepdf 
    Pre-installed on Kali
  VirusTotal API key
    https://community.mcafee.com/docs/DOC-6456
  Gmail Account

Working

 1. https://github.com/leagueofash/CheckMail.git
 2. Go to CheckMail folder
 3. run the command
        python get_mail.py

Overview
1. Extracts email from gmail
2. Parses the text and attachements and save them
3. Extarcted URL's would be text and sends it to VirusTotal for analysis
4. Extracted Macro files are run against mraptop and olevba to detect for malicious content
5. Extracted PDF is run against pdfid to see for JS code and Auto open fields, and peepdf to extract the macro's for further    analysis by the user
6. Generates a sample report containing 

        
This would create a few folder and will contain all the documents! You might want to clean it up often to save the space and also do not open any documents expecially extracted_macro, extracted_data, and files from unzip_dir


Work in Progress! needs more work and more analysis to detect more efficiently
