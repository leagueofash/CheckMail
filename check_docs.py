import subprocess
from report import collect_data
import os


def subprocess_call(cmd):
    p = subprocess.Popen(args=cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out

def check_docs():
    cmd = ['mraptor','extracted_macro']
    result = subprocess_call(cmd)
    if "No Macro" in result:
        return True
    if "SUSPICIOUS" in result:
        list1 = result.split("\n")
        for items in list1:
            if "SUSPICIOUS" in items:
                if "|" in items:
                    elements = items.split("|")
                    if "A" or "X" in elements[1]:
                        command = ['olevba', ' -c','extracted_macro']
                        results = subprocess_call(cmd=command)
                        collect_data(type="macro",result=results)
    return True