# Written by Beann.wu@hotmail.com

"""
This script is used for replaying http response from pcap file. Only supports GET and POST. It has 3 mode:

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
import binascii
import argparse
import logging
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
args = parser.parse_args()
#set tshark command
if args.pcapfile !=  None:
	if args.pmsfile !=  None:
		tshark_command = "tshark -nnnr " +  args.pcapfile + ' -Y "http"  -V -x -o http.decompress_body:"FALSE" -o ssl.keylog_file:' +  args.pmsfile + " -o http.ssl.port:" + args.httpsport + " -o http.tcp.port:" + args.httpport + '|grep -Po "Frame\s\d+|Request in frame:\s\d+|(\s([0-9]|[a-f]){2})+\s\s" > replay_tmp.txt'
	else:
		tshark_command = "tshark -nnnr " +  args.pcapfile + ' -Y "http"  -V -x -o http.decompress_body:"FALSE" -o http.tcp.port:' + args.httpport + '|grep -Po "Frame\s\d+|Request in frame:\s\d+|(\s\w{2})+\s\s" > replay_tmp.txt'
	print "\n========================================"
	print "Tshark command: " + tshark_command
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
urlmode = args.urlcheck
post_data_check = args.postdacacheck

#parse tshark output file, generate 4 dictionary: request url, post data, hex request and hex reply. All use request frame number as key.
print "\n========================================"
logging.warning( " loading HTTP request and response " )
with open('replay_tmp.txt') as fp:
    for line in fp:
        if "Frame" in line:
            frame_id = line.replace('Frame ', '').replace('\n','')
            if frame_id != pre_frame_id:
                request[frame_id] = ""
                pre_frame_id = frame_id
                pre_request_frame_id = "refresh"
#            print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id
        elif 'Request in frame' in line:
            request_frame_id = line.replace('Request in frame: ', '').replace('\n','')
            if request_frame_id != pre_request_frame_id:
                reply[request_frame_id] = ""
                pre_request_frame_id = request_frame_id
#           print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id
        else:
            if request_frame_id != pre_request_frame_id:
                request[frame_id] = request[frame_id] + line.replace(' ', '').replace('\n','')
#                print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id + " request data " + request[frame_id]
            else:
                reply[request_frame_id] = reply[request_frame_id] + line.replace(' ', '').replace('\n','')
#                print "frame number" + frame_id + " pre_frame_id " + pre_frame_id + "request number" + request_frame_id + " pre_request_frame_id " + pre_request_frame_id + " reply data " + reply[request_frame_id]

for k in sorted(reply.keys(),key=int):
	if request[k] != "":
		match = re.search(r'(47455420|504f535420).*',request[k])
		request_payload = match.group().replace('\s', '')
		request_raw = binascii.unhexlify(request_payload)
		match = re.search(r'\s.+?\s',request_raw)
		urlmatch[k] = match.group().replace('\s', '')

		match = re.search(r'\w+\s',request_raw)
		method = match.group().replace('\s', '')
		if "POST" in method:
			match = re.search(r'\n.+$',request_raw)
			postdata[k] = match.group().replace('\n', '')
			print "request_frame: " + k + " method: " + method + " url: " + urlmatch[k] + " postdata: " + postdata[k]
		else:
			print "request_frame: " + k + " method: " + method + " url: " + urlmatch[k]

#delete ignore list specfied frame number from reply
if args.ignore != None:
	for i in args.ignore.split(','):
		del reply[i]
		print "!!!!! ignore frame " + i

#create socket to receive and send data
print "\n========================================"
logging.warning(" READY! Listen on port " + str(args.listenport) +" Waiting for request")
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
server.bind(('0.0.0.0', args.listenport))
server.listen(32)
def handler():
        while True:
                client, clientaddr = server.accept()
                while 1:
			receive = client.recv(4096)
			if len(receive) > 3:
				match_flag = "0"
				#logging.warning( receive )
				if urlmode == "1":
					receive_match = re.search(r'\s.+?\s',receive)
					receive_url = receive_match.group().replace('\s', '')

					receive_match = re.search(r'\w+\s',receive)
					receive_method = receive_match.group().replace('\s', '')
					if "POST" in receive_method:
						receive_match = re.search(r'\n.+$',receive)
						receive_data = receive_match.group().replace('\n', '')
						logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url + " receive_data " + receive_data )
					for k in sorted(urlmatch.keys(),key=int):
						if receive_url in urlmatch[k]:
#							match_flag = "1"
							if "POST" in receive_method:
								if k in postdata.keys():
									if post_data_check == "1":
										if receive_data in postdata[k]:
											if k in reply.keys():
												logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url +  "received data" + receive_data + " with POST data check")
												response = ''.join(re.findall("485454502f.*", reply[k]))
												client.send(binascii.unhexlify(response))
												match_flag = "1"
												break
									else:
										if k in reply.keys():
											logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url +  "received data" + receive_data + " WITHOUT POST data check")
											response = ''.join(re.findall("485454502f.*", reply[k]))
											client.send(binascii.unhexlify(response))
											match_flag = "1"
											break
								else:
									continue
							else:
								if k in postdata.keys():
									continue
								else:
									if k in reply.keys():
										logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
										response = ''.join(re.findall("485454502f.*", reply[k]))
										client.send(binascii.unhexlify(response))
										logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url " + receive_url)
										match_flag = "1"
										break
									else: 
										logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
										client.send('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
										logging.warning( " Send >>>>>>> No matched")
										match_flag = "1"
										break
					if match_flag == "0":
						logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
						client.send('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
						logging.warning( " Send >>>>>>> No matched")
				else:
					for k in reply.keys():
						if binascii.hexlify(receive) in request[k]:
							match_flag = "1"
							if k in reply.keys():
								logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
								response = ''.join(re.findall("485454502f.*", reply[k]))
								client.send(binascii.unhexlify(response))
								logging.warning( " Send >>>>>>> Found matched replay in request_frame " + k  + " method " + receive_method  + "receive_url ")
								break
							else: 
								logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
								client.send('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
								logging.warning( " Send >>>>>>> No matched")
								break
					if match_flag == "0":
						logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url )
						client.send('HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n')
						logging.warning( " Send >>>>>>> No matched")
		client.close()
        thread.exit()
threads = []
for i in range(0, 300):
        thread = threading.Thread(target=handler, args=())
        thread.start()
        threads.append(thread)
for thread in threads:
        thread.join()
