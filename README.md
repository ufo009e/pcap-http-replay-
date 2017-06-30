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
  	3. you'd better run a pre-filter on your pcap file — only save the http request and response you want to replay in the pcap file. 
  	4. run scritp "python http_replay.py" with options. help is available.
  	5. For mode "url check" and "url + post data check". You can use browser to access. Note: you may need to edit the host file to set all of domain name in that pcap file to your linux

Example:

root@kali:~/Desktop# python http_replay.py -f replay_https.cap -m replay_https.cap_pms -l 8880 -i 353,502 -u 1 -d 

 

    6. For hex mode, can use tshark and nc to send request to your linux

        a. extract all get and post request hex string. 47455420 is "GET ", and 504f535420 is "POST "
    tshark -nnr  replay_test.cap -Y "http.request "  -x|cut -b 7-54|tr -d ' '|awk 'BEGIN{FS="\n";  RS="\n[ \t\n]*\n|^\n+"} {gsub(/\n/, ""); print $0}'|grep -Po "47455420\w+|504f535420\w+" > hex

        b. sent each hex string by nc.
    for i in `cat hex`; do echo $i|xxd -r -p |nc 10.154.159.171 80& done

 

Limitation

    1. If tshark can't decode the entire http response, this script can't replay them. So before capture packets, please use private mode in browser (disable cache and ignore current cookie) to capture all http content. And please check if any packet loss or ssl decrypton issue can cause tshark can't parse all http request and reply.
    2. if in the pcap file, for same url server responded different content (for example different security token set every time you browser the same url). This script may not know which response should be used. You can

      a. skip this url. Jump to the url you are interested directly.
      b. use --ignore option to disable request frame matching
