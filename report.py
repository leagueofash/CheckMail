import easygui

pdf_results = None
macro_data = None
scan_data = None

def warning_box(warning):
    message = "You received an email from\n" + str(warning) +"\n It might be a malicious message! DO NOT OPEN the message(DELETE IT!!!)"
    easygui.msgbox(message, title="WARNING! WARNING! WARNING!")
    return True

def collect_data(type, result):
    if type == "pdf":
        global pdf_results
        pdf_results = result
    if type == "macro":
        global macro_data
        macro_data = result
    if type == "url":
        global scan_data
        scan_data = str(result)
    return True

def create_report(from_addr):
    if pdf_results != None or macro_data!=None or scan_data!= None:
        warning_box(warning=from_addr)
        report_file = "Report--" + str(from_addr)
        fd = open(report_file,"w")
        fd.write("=============================================================\n")
        fd.write("Forensics Report for further Analysis\n")
        fd.write("=============================================================\n")
        fd.write("\n\nMail that was recieved recently was malicious and needs further attention!!")
        fd.write("\n\n______________________________________________________________\n")
        fd.write("Scan results from URL that were enbedded in the mail\n")
        fd.write("______________________________________________________________\n")
        fd.write(str(scan_data))
        fd.write("\n\n\n\n")
        fd.write("\n\n______________________________________________________________\n")
        fd.write("Javascript elements inside the PDF documents\n")
        fd.write("______________________________________________________________\n")
        fd.write(str(pdf_results))
        fd.write("\n\n\n\n")
        fd.write("\n\n______________________________________________________________\n")
        fd.write("Macros extracted from malicious document\n")
        fd.write("______________________________________________________________\n")
        fd.write(str(macro_data))
        fd.write("\n\n\n")

        global pdf_results
        pdf_results = None
        global scan_data
        scan_data = None
        global macro_data
        macro_data = None
    return

