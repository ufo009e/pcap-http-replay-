
Skip to end of metadata

    Created by Bean Wu, last modified about an hour ago

Go to start of metadata

 

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
   3 you'd better run a pre-filter on your pcap file — only save the http request and response you want to replay in the pcap file. 
   4. run scritp "python http_replay.py" with options. help is available.
   5. For mode "url check" and "url + post data check". You can use browser to access. Note: you may need to edit the host file to set all of domain name in that pcap file to your linux

Example:

root@kali:~/Desktop# python http_replay.py -f replay_https.cap -m replay_https.cap_pms -l 8880 -i 353,502 -u 1 -d 0

========================================
Tshark command: tshark -nnnr replay_https.cap -Y "http"  -V -x -o http.decompress_body:"FALSE" -o ssl.keylog_file:replay_https.cap_pms -o http.ssl.port:443 -o http.tcp.port:80|grep -Po "Frame\s\d+|Request in frame:\s\d+|(\s\w{2})+\s\s" > replay_tmp.txt

================ Run tshark ==============
Running as user "root" and group "root". This could be dangerous.
tshark: Lua: Error during loading:
 [string "/usr/share/wireshark/init.lua"]:44: dofile has been disabled due to running Wireshark as superuser. See https://wiki.wireshark.org/CaptureSetup/CapturePrivileges for help in running Wireshark as an unprivileged user.

========================================
2017-06-29 04:48:53,263  loading HTTP request and response
request_frame: 122 method: GET  url:  /dvwa/login.php
request_frame: 127 method: GET  url:  /dvwa/dvwa/css/login.css
request_frame: 139 method: GET  url:  /dvwa/dvwa/images/login_logo.png
request_frame: 194 method: POST  url:  /dvwa/login.php  postdata: username=admin&password=password&Login=Login&user_token=f7c1262280ab5280903bbba8e9800009
request_frame: 197 method: GET  url:  /dvwa/index.php
request_frame: 204 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 216 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 237 method: GET  url:  /dvwa/dvwa/images/logo.png
request_frame: 258 method: GET  url:  /dvwa/favicon.ico
request_frame: 283 method: GET  url:  /dvwa/vulnerabilities/exec/
request_frame: 288 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 290 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 318 method: POST  url:  /dvwa/vulnerabilities/exec/  postdata: ip=127.0.0.1&Submit=Submit&user_token=59ffd5308269eb43d67e9c7040340562
request_frame: 343 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 347 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 353 method: GET  url:  /dvwa/vulnerabilities/fi/?page=include.php
request_frame: 358 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 360 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 368 method: GET  url:  /dvwa/vulnerabilities/upload/
request_frame: 393 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 395 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 403 method: GET  url:  /dvwa/vulnerabilities/sqli/
request_frame: 408 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 410 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 418 method: GET  url:  /dvwa/vulnerabilities/sqli_blind/
request_frame: 423 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 425 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 433 method: GET  url:  /dvwa/vulnerabilities/xss_r/
request_frame: 438 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 440 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 467 method: GET  url:  /dvwa/vulnerabilities/xss_r/?name=haha&user_token=dca8f91260b6a834a1039025e3cb390f
request_frame: 472 method: GET  url:  /dvwa/dvwa/css/main.css
request_frame: 474 method: GET  url:  /dvwa/dvwa/js/dvwaPage.js
request_frame: 502 method: GET  url:  /dvwa/logout.php
request_frame: 505 method: GET  url:  /dvwa/login.php
request_frame: 510 method: GET  url:  /dvwa/dvwa/css/login.css
!!!!! ignore frame 353
!!!!! ignore frame 502

========================================
2017-06-29 04:48:53,275  READY! Listen on port 8880 Waiting for request
2017-06-29 04:49:01,170  Receive <<<<<<<<< method GET  receive_url  /dvwa/vulnerabilities/xss_r/
2017-06-29 04:49:01,170  Send >>>>>>> Found matched replay in request_frame 433 method GET receive_url  /dvwa/vulnerabilities/xss_r/
2017-06-29 04:49:01,217  Receive <<<<<<<<< method GET  receive_url  /dvwa/dvwa/js/dvwaPage.js
2017-06-29 04:49:01,217  Send >>>>>>> Found matched replay in request_frame 216 method GET receive_url  /dvwa/dvwa/js/dvwaPage.js
2017-06-29 04:49:01,217  Receive <<<<<<<<< method GET  receive_url  /dvwa/dvwa/css/main.css
2017-06-29 04:49:01,217  Send >>>>>>> Found matched replay in request_frame 204 method GET receive_url  /dvwa/dvwa/css/main.css
2017-06-29 04:49:01,219  Receive <<<<<<<<< method GET  receive_url  /dvwa/dvwa/images/logo.png
2017-06-29 04:49:01,221  Send >>>>>>> Found matched replay in request_frame 237 method GET receive_url  /dvwa/dvwa/images/logo.png
2017-06-29 04:49:01,288  Receive <<<<<<<<< method GET  receive_url  /dvwa/favicon.ico
2017-06-29 04:49:01,289  Send >>>>>>> Found matched replay in request_frame 258 method GET receive_url  /dvwa/favicon.ico
2017-06-29 04:49:03,530  Receive <<<<<<<<< method GET  receive_url  /dvwa/vulnerabilities/exec/
2017-06-29 04:49:03,532  Send >>>>>>> Found matched replay in request_frame 283 method GET receive_url  /dvwa/vulnerabilities/exec/
2017-06-29 04:49:05,957  Receive <<<<<<<<< method POST  receive_url  /dvwa/vulnerabilities/exec/  receive_data ip=127.0.0.1&Submit=Submit&user_token=59ffd5308269eb43d67e9c7040340562
2017-06-29 04:49:05,958  Send >>>>>>> Found matched replay in request_frame 318 method POST receive_url  /dvwa/vulnerabilities/exec/ received dataip=127.0.0.1&Submit=Submit&user_token=59ffd5308269eb43d67e9c7040340562 WITHOUT POST data check

 

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
