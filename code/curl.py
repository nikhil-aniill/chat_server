import subprocess
import os
import json
from pprint import pprint
import numpy
import scipy.misc
import array

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

def rb_to_png(i):
	print "Converting .exe to 8 bit vector greyscale .png file"
	file=i.split('.')[0]+'.png'
	filename = i;
	f = open(filename,'rb');
	ln = os.path.getsize(filename);width = 256;
	rem = ln%width;
	a = array.array("B");
	a.fromfile(f,ln-rem);
	f.close();
	g = numpy.reshape(a,(len(a)/width,width));
	g = numpy.uint8(g);
	scipy.misc.imsave("folder/"+file,g);


file_exe="AERTSr64.exe"
file_png=file_exe.split('.')[0]+".png"
print file_png
rb_to_png(file_exe)

folder_name = '"' + "file=@folder/" +  file_png + '"'
print folder_name
cmd = 'sudo curl -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryW9b2lGAP" -H "Accept-Encoding: gzip, deflate, br" -F ' + folder_name + ' -X POST localhost:5000/analyze'
out = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stdout,stderr = out.communicate()
output = stdout.split()[-1]
if output == '{"result":"benign"}':
	cuckoo_monitor()

else:
	print output