# Written by beann.wu@hotmail.com

"""
This script is used for replaying http response from pcap file. It has 3 mode:

1. hex mode (when args -u = 0 and -d = 0), only return matched replay when received http request (header and content) is exactly same as request in pcap file.
2. url check mode (when args -u = 1 and -d = 0), return http reply when url and request method matches request in pcap.
3. url and post data check mode (when args -u = 1 and -d = 1), return http reply when url, request method and post data (post data check if request is post) matches request in pcap


Other features:

1. supports both http and https
2. supports option --ignore to ignore request frame matching for specified frame number


How to use:

1. install python2.7 and tshark on your linux.
2. download attached pyton script to your linux.
3. you'd better run a pre-filter on your pcap file -- only save the http request and response you want to replay in the pcap file.
4. run scritp "python http_replay.py" with options
5. For mode "url check" and "url + post data check". You can use browser to access. Note: you may need to edit the host file to set all of domain name in that pcap file to your linux

Example:

root@kali:~/Desktop# python http_replay.py -f replay_https.cap -m replay_https.cap_pms -l 8880 -i 353,502 -u 1 -d 0

6. For hex mode, can use tshark and nc to send request to your linux

	a. extract all get and post request hex string. 47455420 is "GET ", and 504f535420 is "POST "
	tshark -nnr  replay_test.cap -Y "http.request "  -x|cut -b 7-54|tr -d ' '|awk 'BEGIN{FS="\n";  RS="\n[ \t\n]*\n|^\n+"} {gsub(/\n/, ""); print $0}'|grep -Po "47455420\w+|504f535420\w+" > hex

	b. sent each hex string by nc.
	for i in `cat hex`; do echo $i|xxd -r -p |nc 10.154.159.171 80& done
	
	
Limitation

	a. If tshark can't decode the entire http response, this script can't replay them. So before capture packets, please use private mode in browser (disable cache and ignore current cookie) to capture all http content. And please check if any packet loss or ssl decrypton issue can cause tshark can't parse all http request and reply.
	
	b. if in the pcap file, for same url server responded different content (for example different security token set every time you browser the same url). This script may not know which response should be used. You can 

		* skip this url. Jump to the url you are interested directly.
		* use --ignore option to disable request frame matching
"""


#!/usr/bin/python
import re
import commands
import os
import sys
import time
import socket
import threading
import SocketServer
import binascii
import argparse
import logging
import time
logging.basicConfig(format='%(asctime)s %(message)s')

#set args
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--pcapfile", type=str, help="set pcap file when you replay any pcap first time. Tshark output will save to a file and you do not need to set -f next time if no tshark command change")
parser.add_argument("-p", "--httpport", type=str, help="http protocol port, example: -p 80,8080   default is 80", default="80")
parser.add_argument("-s", "--httpsport", type=str, help="https protocol port, example: -s 443,8443 default is 443", default="443")
parser.add_argument("-m", "--pmsfile", type=str, help="set ssl pms file name, need full path. example: /var/tmp/test.pms")
parser.add_argument("-u", "--urlcheck", type=str, choices=["0", "1"], help="if enalbe URL check, enable=1, disable=0, default is 1", default="1")
parser.add_argument("-d", "--postdacacheck", type=str, choices=["0", "1"], help="if enalbe post data check when URL check is enabled, enable=1, disable=0, default is 1", default="1")
parser.add_argument("-l", "--listenport", type=int, help="set local port this script listnes on, example: -p 80 default is 80", default="80")
parser.add_argument("-i", "--ignore", type=str, help="ignore request matching for specified request frame number in pcap, example: -i 20,25 ")
parser.add_argument("-r", "--replace_redirect", type=str, help="strip hostname in redirect Location header, enable=1, default is 1", default="1")
args = parser.parse_args()
#set tshark command
if args.pcapfile !=  None:
	if args.pmsfile !=  None:
		tshark_command = "tshark -nnnr " +  args.pcapfile + ' -Y "http"  -V -x -o http.decompress_body:"FALSE" -o http.dechunk_body:"FALSE" -o ssl.keylog_file:' +  args.pmsfile + " -o http.ssl.port:" + args.httpsport + " -o http.tcp.port:" + args.httpport + '|cut -b 1-56|grep -Po "Frame\s\d+:|Request in frame:\s\d+]|(\s\w{2})+\s\s"|sed \'s/Request in frame:/Request in frame/g\'|tr -d \'\n\'|tr -s \':]\' \'\n\'|sed \'s/Frame/\\nFrame/g\' replay_tmp.txt'
	else:
		tshark_command = "tshark -nnnr " +  args.pcapfile + ' -Y "http"  -V -x -o http.decompress_body:"FALSE" -o http.dechunk_body:"FALSE" -o http.tcp.port:' + args.httpport + '|cut -b 1-56|grep -Po "Frame\s\d+:|Request in frame:\s\d+]|(\s\w{2})+\s\s"|sed \'s/Request in frame:/Request in frame/g\'|tr -d \'\n\'|tr -s \':]\' \'\n\'|sed \'s/Frame/\\nFrame/g\' > replay_tmp.txt'
	print "\n================ Run tshark =============="
#run tshark command to get frame number, http response in request frame number and hex of request and reply
	ret = commands.getoutput(tshark_command)
	print ret
else:
	print "\n============== Skip tshark =============="
pre_frame_id = "none"
frame_id = ""
pre_request_frame_id = "refresh"
request_frame_id = "none"
request = {}
reply = {}
urlmatch = {}
postdata = {}
cookiematch = {}
hascookielist = []
nocookielist = []
urlmode = args.urlcheck
post_data_check = args.postdacacheck
global cookie_check_keyword
cookie_check_keyword = 'TS'


#parse tshark output file, generate 4 dictionary: request url, post data, hex request and hex reply. All use request frame number as key.
print "\n========================================"
logging.warning( " loading HTTP request and response " )

#checking if previously replayed 
if os.path.isfile('replay_tmp.txt') == False:
	print "!!!!! first time replay? No previous file found, Please use -f option"
	os._exit(0)

with open('replay_tmp.txt') as fp:
	for line in fp:
		if "Frame" in line:
			frame_id = line.replace('Frame ', '').replace('\n','')
			if frame_id != pre_frame_id:
				request[frame_id] = ""
				pre_frame_id = frame_id
				pre_request_frame_id = "refresh"
#			print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id
		elif 'Request in frame' in line:
			request_frame_id = line.replace('Request in frame ', '').replace('\n','')
			if request_frame_id != pre_request_frame_id:
				reply[request_frame_id] = ""
				pre_request_frame_id = request_frame_id
#		   print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id
		elif not line.startswith('\n'):
			if request_frame_id != pre_request_frame_id:
				request[frame_id] = request[frame_id] + line.replace(' ', '').replace('\n','')
#				print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id + " request data " + request[frame_id]
			else:
				reply[request_frame_id] = reply[request_frame_id] + line.replace(' ', '').replace('\n','')
#				print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id + " reply data " + reply[request_frame_id]

if args.ignore != None:
	for i in args.ignore.split(','):
		try:
			del reply[i]
			del request[i]
			del urlmatch[i]
			del postdata[i]
			del cookiematch[i]
		except:
			pass
		print "!!!!! ignore frame " + i
		
for k in sorted(reply.keys(),key=int):
	if request[k] != "":
		match = re.search(r'(47455420|504f535420|50555420|504154434820|44454c45544520|434f4e4e45435420|4f5054494f4e5320|545241434520).*',request[k])
		if match is None:
			continue
		request_payload = match.group().replace('\s', '')
		request_raw = binascii.unhexlify(request_payload)
		match = re.search(r'\s.+?\s',request_raw)
		urlmatch[k] = match.group().replace('\s', '')

		match = re.search(r'\w+\s',request_raw)
		method = match.group().replace('\s', '')
		
		match = re.search(r'Cookie:.+?\r\n',request_raw)
		if match:
			cookiematch[k] = match.group()
			hascookielist.append(k)
		else:
			cookiematch[k] = "Cookie: nocookie=nocookie"
			nocookielist.append(k)
		if "POST" in method or "PATCH" in method or "PUT" in method:
			match = re.search(r'\n.+$',request_raw)
			postdata[k] = method + ':' + match.group().replace('\n', '')
			print "request_frame: " + k + " method: " + method + " url: " + urlmatch[k]  + " postdata: " + postdata[k] + " " + cookiematch[k]
		else:
			print "request_frame: " + k + " method: " + method + " url: " + urlmatch[k] + " " + cookiematch[k]

def find_responese(receive_method,post_data_check,postdata,request,reply,k,receive_url,receive_data):
#	match_flag = "1"
	if "POST" in receive_method or "PATCH" in receive_method or "PUT" in receive_method:
		time.sleep(0.3)
		if k in postdata.keys():
			if post_data_check == "1":
				if receive_method + ':' + receive_data == postdata[k]:
					if k in reply.keys():
						response = ''.join(re.findall("485454502f.*", reply[k]))
						#self.request.sendall(binascii.unhexlify(response))
						logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url +  "received data" + receive_data + " with POST data check")
						match_flag = "1"
						return binascii.unhexlify(response),match_flag
					else:
						return 'Nomatch_continue_ASDFGHJ','0'
				else:
					return 'Nomatch_continue_ASDFGHJ','0'
						
			else:
				if k in reply.keys():
					logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url +  "received data" + receive_data + " WITHOUT POST data check")
					response = ''.join(re.findall("485454502f.*", reply[k]))
					#self.request.sendall(binascii.unhexlify(response))
					match_flag = "1"
					return binascii.unhexlify(response),match_flag
				else:
					return 'Nomatch_continue_ASDFGHJ','0'
					
		else:
			return 'Nomatch_continue_ASDFGHJ','0'
	else:
		if k in postdata.keys():
			return 'Nomatch_continue_ASDFGHJ','0'
		else:
			if k in reply.keys():
				logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
				response = ''.join(re.findall("485454502f.*", reply[k]))
				#self.request.sendall(binascii.unhexlify(response))
				logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url)
				match_flag = "1"
				return binascii.unhexlify(response),match_flag
				
			else: 
				logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
				#self.request.sendall('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
				logging.warning( " Send >>>>>>> No matched")
				match_flag = "1"
				return 'HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n',match_flag
	
class MySockServer(SocketServer.BaseRequestHandler):
	def handle(self):
		try:		
			while 1:
				receive = self.request.recv(4096)
				sent_flag = '0'
				if len(receive) > 3:
					match_flag = "0"
					if urlmode == "1":
						#print receive
						receive_match = re.search(r'\s.+?\s',receive)
						if not receive_match:
							logging.warning( " Receive <<<<<<<<< No http url, maybe a request splited in multiple packets." )
							continue
						receive_url = receive_match.group().replace('\s', '')
		
						receive_match = re.search(r'\w+\s',receive)
						receive_method = receive_match.group().replace('\s', '')
	
						match = re.search(r'Cookie:.+?\r\n',receive)
						cookie_match_flag = '0'
						check_order = nocookielist + hascookielist
						if match:	
							receive_cookie = match.group()
							receive_cookie_name_list = receive_cookie.split(';')
							
							for z in receive_cookie_name_list :
								receive_cookie_name = re.compile('.*?=')
								if cookie_check_keyword in ','.join(receive_cookie_name.findall(z)):
									cookie_match_flag = '1'
							if cookie_match_flag == '1':
								check_order = hascookielist + nocookielist
						if "POST" in receive_method:
							receive_match = re.search(r'\n.+$',receive)
							receive_data = receive_match.group().replace('\n', '')
							logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url + " receive_data " + receive_data )
						else:
							receive_data = ''
						#print 'check order ' + str(check_order)
						for k in check_order:
							if receive_url == urlmatch[k]:
		
								response, match_flag = find_responese(receive_method,post_data_check,postdata,request,reply,k,receive_url,receive_data)
								if 'Nomatch_continue_ASDFGHJ' in response:
									continue
								else:
									#print response
									#print args.replace_redirect
									#print type(args.replace_redirect)
									if not args.replace_redirect == '1':
										self.request.sendall(response)
									else:
										self.request.sendall(re.sub(r'Location: (http|https)://.*?/','Location: /', response))
									sent_flag = '1'
									break
	
						if match_flag == "0":
							logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
							self.request.sendall('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
							logging.warning( " Send >>>>>>> No matched")
					else:
						for k in reply.keys():
							if binascii.hexlify(receive) == request[k]:
								match_flag = "1"
								if k in reply.keys():
									logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
									response = ''.join(re.findall("485454502f.*", reply[k]))
									self.request.sendall(binascii.unhexlify(response))
									logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url ")
									break
								else: 
									logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
									self.request.sendall('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
									logging.warning( " Send >>>>>>> No matched")
									break
						if match_flag == "0":
							logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
							self.request.sendall('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
							logging.warning( " Send >>>>>>> No matched")
		except KeyboardInterrupt:
			print "Stop ......"
			server.shutdown()
			server.server_close()
			os._exit(0)
							
if __name__ == "__main__":		
	#create socket to receive and send data
	print "\n========================================"
	logging.warning(" READY! Listen on port " + str(args.listenport) +" Waiting for request")					
	server = SocketServer.ThreadingTCPServer(('0.0.0.0', args.listenport), MySockServer)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		print "Stop ......"
		server.shutdown()
		server.server_close()
		os._exit(0)
