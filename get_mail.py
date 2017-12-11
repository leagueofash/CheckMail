import email
import imaplib
import easygui
import os
import time
from easygui import multpasswordbox, multenterbox
from urlextract import URLExtract
import zipfile


from check_docs import check_docs
from check_pdf import check_pdf
from report import create_report
from scan_urls import scan_urls



def login(emailid, password):
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(emailid, password)
    mail.list()

    mail.select("inbox")  # connect to inbox.

    result, data = mail.uid('search', None, "ALL")
    latest_email_uid = data[0].split()[-1]
    result, data = mail.uid('fetch', latest_email_uid, '(RFC822)')
    raw_email = data[0][1]

    email_message = email.message_from_string(raw_email)


    from_addr =  email.utils.parseaddr(email_message['From'])
    #print email_message.items() # print all headers

    return latest_email_uid,from_addr,email_message

def get_first_text_block(email_message_instance, sender_addr, api_key):
    count = 0
    password = None
    types = ["doc","sheet","presentation"]
    maintype = email_message_instance.get_content_type()
    
    #parse the documents in the mail and saves them based on type! 
    #since we are anlalyzing only pdf and macro we are looking for those types alone!
    for part in email_message_instance.walk():
        if part.get_content_type() == "text/plain":
            text = part.get_payload(decode=True)
            password = extract_text(text,sender_addr, api_key)
        else:
            attachments = part.get_content_type()
            if "application" in attachments:
                count+=1
                if "pdf" in attachments:
                    pdf = part.get_payload(decode=True)
                    extract_pdf(pdf)
                elif "macro" in attachments:
                    macro = part.get_payload(decode=True)
                    extract_macro(macro)
                elif any(x in attachments for x in types):
                    data = part.get_payload(decode=True)
                    extract_data(data)
                elif "zip" in attachments:
                    if password != None:
                        zipfile = part.get_payload(decode=True)
                        extract_zip(data=zipfile, pwd=password)
                else:
                    continue

    return

#License agreement
def instruction():
    a =  "Welcome to Automated Mail Check!!\nLeave it to us to detect malicious mail and enjoy your mail worry free!!\n"
    b = "\n\nLicense Agreement Policy\n"
    c = "This software asks for your gmail username and password\n"
    d = "All passwords are stored locally and we are not responsible for any loss of data\n"
    e = "If you approve to this click Yes else click No\n"
    value = a+b+c+d+e
    if easygui.boolbox(msg=value, title='License Agreement', choices=('[<F1>]Yes', '[<F2>]No'), image=None, default_choice='[<F1>]Yes', cancel_choice='[<F2>]No'):
        return
    else:
        exit(0)

#Extracting the URL and password if any from the text body of the mail 
def extract_text(text,sender_addr,api):
    password = None
    extractor=URLExtract()
    urls = extractor.find_urls(text)
    scan_urls(urls,sender_addr,api)
    if 'password' in text:
        msg = text
        title = "Enter ZIP password"
        fieldNames = ["Name"]
        fieldValues = []
        fieldValues = multenterbox(msg, title, fieldNames)
        password = fieldValues[0]
    return password

#extract the PDF and save it in the extracted_data.pdf
def extract_pdf(pdf_data):
    #print pdf_data
    fd = open("extracted_data.pdf","wb")
    fd.write(pdf_data)
    fd.close()
    check_pdf()
    return True

#extract macros
def extract_data(data):
    #print sheet_data
    fd = open("extracted_macro", "wb")
    fd.write(data)
    fd.close()
    return True

#UNZIP the file and store the zipped content for analysis
def extract_zip(data, pwd):
    #print doc_data
    fd = open("extracted_data.zip", "wb")
    fd.write(data)
    fd.close()
    with zipfile.ZipFile('extracted_data.zip') as zf:
        zf.extractall("unzip_dir", pwd=pwd)
    filename = os.listdir("unzip_dir")
    for name in filename:
        if "pdf" in name:
            filepath = "unzip_dir/"+name
            fd = open(filepath,"r")
            extract_pdf(fd.read())
        malicious_names = ['doc','ppt','xls']
        if any(x in name for x in malicious_names):
            fd = open(filepath,"r")
            extract_macro(fd.read())
    return True

def extract_macro(macro_data):
    fd = open("extracted_macro","wb")
    fd.write(macro_data)
    fd.close()
    check_docs()
    return True

def main():
    instruction()
    msg = "Enter your GMAIL Username and Password"
    title = "Welcome to CheckMail"
    fieldNames = ["VirusTotal API key","Gmail Username", "Gmail Password", ]
    fieldValues = []
    
    #easygui box for password box to get the API key, gmail username and password!
    fieldValues = multpasswordbox(msg, title, fieldNames)
    emailid = fieldValues[1]
    password = fieldValues[2]
    api = fieldValues[0]
    latest_mail_uid = 0
    while(1):
        try:
            uid = latest_mail_uid
            latest_mail_uid,from_addr,email_message = login(emailid=emailid, password=password)
            if latest_mail_uid > uid:
                get_first_text_block(email_message_instance=email_message, sender_addr=from_addr, api_key = api)
                create_report(from_addr=from_addr)
            time.sleep(1)
        except:
            continue
if __name__== "__main__" :
    main()
