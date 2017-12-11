import subprocess
import re
from report import collect_data


def subprocess_call(cmd):
    p = subprocess.Popen(args=cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out

def check_pdf():
    #command to see the contents of PDF
    cmd = ['pdfid','extracted_data.pdf']
    results = subprocess_call(cmd=cmd)
    list1 = results.split("\n")
    value = 0
    malicious = False
    #checking for JS tags
    malicious_words = ['JS', 'JavaScript']
    for items in list1:
        #checking for autoopen tags!
        if "/OpenAction" in items:
            value = int(items.split()[1])
        if any(x in items for x in malicious_words):
            malicious = True
    if value != 0 and malicious == True:
        cmd = ['peepdf', 'extracted_data.pdf']
        results = subprocess_call(cmd)
        results = results.split("\n")
        for items in results:
            if "JS code" in items:
                num = items.split()
                obj_num = ''.join(num[-2:])
                numbers  = re.findall('\d+', obj_num)
                fd = open("commands", "w")
                for n in numbers:
                    fd.writelines("object " + n + "\n")
                fd.close()
        #extract the macros from the malicious PDF
        cmd = ['peepdf', 'extracted_data.pdf', '-s', 'commands']
        results = subprocess_call(cmd)
        collect_data(type="pdf", result=results)
    return True
