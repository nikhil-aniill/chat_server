import subprocess
import os
import json
from pprint import pprint

def cuckoo_monitor():
	print "The watchdog is active now, waiting for any new Malware analysis..."
	reports_dir = '/home/kali/Desktop/Cuckoo/storage/analyses/'
	latest_report='latest/reports/report.json'
	with open(reports_dir+latest_report) as f:
		latest_report = json.load(f)
    	print "\nPrinting info section only:"
    	pprint(latest_report["info"])
    	latest_score = latest_report["info"]["score"]
    	print "\nRisk score is :", latest_score 
    	md5_hash = latest_report["target"]["file"]["md5"]
    	print "\nThe md5 hash of the analyzed file is :", md5_hash
    	if latest_score > 1:
    		print "\nRisk score is high ! i'll call the API script"
    		md5_hash = latest_report["target"]["file"]["md5"]
    		print "\nHash of scanned file is :", md5_hash
    		fileName = latest_report["target"]["file"]["md5"]
    		print "fileName is :", fileName

cmd ='sudo curl -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryW9b2lGAP" -H "Accept-Encoding: gzip, deflate, br" -F "file=@folder/obfus1.png" -X POST localhost:5000/analyze'
out = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stdout,stderr = out.communicate()
output = stdout.split()[-1]
if output == '{"result":"benign"}':
	cuckoo_monitor()

else:
	print "Malware blocked"