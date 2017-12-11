import requests
from easygui import multenterbox

from report import warning_box, collect_data


def scan_urls(urls,sender_addr,api):
    #print urls
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My_project"
    }
    scan_ids = []
    urls = list(set(urls))
    for url in urls:
        params = {'apikey': api, 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        json_response = response.json()
        #print json_response
        scan_ids.append(json_response['scan_id'])

    #print scan_ids
    for id in scan_ids:
        #print id
        params = {'apikey': api, 'resource': scan_ids }
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',params=params, headers=headers)
        json_response = response.json()
        result = json_response
        scans = result['scans']
        for k,v in scans.items():
            for key,value in v.items():
                if key == 'detected':
                    if value == True:
                        collect_data(type='url',result=k)




    return True
