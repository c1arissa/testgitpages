---
layout: post
title:  "Lab 1: Covert Channels using Covert TCP"
author: Clarissa Podell
date:   2018-06-22
comments: false
categories: lab, networking
tags:
   - networking
   - exploit
   - security
---

<style>
.dump {
    background-color: #f8f8f8;
    border: 1px solid #e5e5e5;
    padding: 6px 10px;
    padding: 1.1em;
    border-radius: 3px;
    max-width: 100%;
    height: 300px;
    overflow: auto;
    overflow-x: auto;
    color: #6c696e;
    font-size: 14px;
    font-family: Courier, Consolas, Monaco, Bitstream Vera Sans Mono, "Segoe UI", Menlo, monospace;
    font-weight: 400;
    line-height: 1.1em;
    margin: 20px auto;
    white-space: pre-wrap;
}
b {
    color: #9b4dca;
    font-size: inherit;
    font-family: inherit;
    font-weight: bold;
}
div.pos {
    position: relative;
}
img {
    max-width: 100%;
    height: auto;
    margin: 20px auto;
}
</style>

This post is based on a lab assignment for my senior Capstone in Cybersecurity course called "Cryptography Lab Topic: Steganography".

# Embedding information into network traffic
## Description

>The program `covert_tcp` can hide data in TCP packets. Currently it is running on Linux only. You can run this in a Linux virtual machine guest, e.g. under VirtualBox or VMware.
- Create two endpoint hosts with the network steganography tool installed, or you can use the same host with two different terminal windows.
  1. Document the active connection with tcpdump data (pcap)
  2. Transmit the information (e.g. a small text ﬁle, remember that transmission is going to be slow)
- Prepare a report of your findings.

>Can you spot the embedded traffic? If so, point it out in your answers. If not, explain why.
Repeat the experiment with alternative encoding options in covert tcp.


## Solution
### Lab Setup & Requirements:

The purpose of this lab is to establish a covert channel to transfer information between two hosts by exploiting features of the TCP/IP protocol.  I'll show how to transmit the contents of a file over a covert channel using the program `covert_tcp`, a network steganography tool, that conceals data in the extra space of a TCP/IP header field.  I'll also demonstrate how to capture traffic on a covert channel and how to spot concealed data in a captured pcap file.

Covert_TCP is a proof-of-concept tool written in C by Craig H. Rowland.  You can find the source code [here]( https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c) and a supporting paper [here]( https://dunnesec.com/category/tools/covert_tcp/).

Here's what we need to complete this lab:

- Linux guest virtual machine
- [covert_tcp.c](https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c) source code file
- tcpdump to document the connection

First, we need to compile the source code:
```
clarissa@ubuntu:~$ gcc -o covert_tcp covert_tcp.c
```

The program must be run as the superuser or with sudo privileges.  Running the program without any commands will print usage information.

```console
clarissa@ubuntu:~/server$ sudo ../covert_tcp

Covert TCP usage:
../covert_tcp -dest dest_ip -source source_ip -file filename -source_port port -dest_port port -server [encode type]
```

Most of this is self-explanatory.  The required `-file` is the name of the file to encode and transfer.  The last option "encode type" provides optional encodings to choose from.

```
-ipid - Encode data a byte at a time in the IP packet ID.  [DEFAULT]
-seq  - Encode data a byte at a time in the packet sequence number.
-ack  - DECODE data a byte at a time from the ACK field.
        This ONLY works from server mode and is made to decode
        covert channel packets that have been bounced off a remote
        server using -seq. See documentation for details
```

This lab can either be set up on the same host machine or using two separate ones.  In this write-up, I set up the two endpoints on the same host using the loopback interface lo and its associated IP address of 127.0.0.1.  

The first section of this lab covers encoding the IP Identification field and the second section encodes the TCP Initial Sequence Number (ISN) field.

### 1. Encoding the IP Identification Field

Next, we set up the endpoint hosts. This experiment requires three terminal windows for the client, server, and tcpdump listener.  

#### In Terminal 1 (Client / Sender):

First, the client creates a text file with the secret message to send the server:

```console
clarissa@ubuntu:~/client$ echo "SECRET MESSAGE" > secret.txt
```

After the server is running, the client executes the below command to connect with the server and send a file via the IP Identification field encoding.  Many of the program's default values are used including the destination port 80 and the IP ID encoding type.

Above sends the file secret.c to the host hacker.evil.com a byte
at a time using the default IP packet ID encoding.

{% highlight console %}
clarissa@ubuntu:~/client$ sudo ../covert_tcp -source 127.0.0.1 -dest 127.0.0.1 -file secret.txt
[sudo] password for clarissa:
Covert TCP 1.0 (c)1996 Craig H. Rowland (crowland@psionic.com)
Not for commercial use without permission.
Destination Host: 127.0.0.1
Source Host     : 127.0.0.1
Originating Port: random
Destination Port: 80
Encoded Filename: secret.txt
Encoding Type   : IP ID

Client Mode: Sending data.

Sending Data: S
Sending Data: E
Sending Data: C
Sending Data: R
Sending Data: E
Sending Data: T
Sending Data:  
Sending Data: M
Sending Data: E
Sending Data: S
Sending Data: S
Sending Data: A
Sending Data: G
Sending Data: E
Sending Data:
{% endhighlight %}

#### In Terminal 2 (Server / Receiver):

The program writes the incoming secret message to a file, so the server has to create an empty text file to receive the data from our client:

```console
clarissa@ubuntu:~/server$ touch received-secret.txt
```

The server must launch first *before* the client runs to create a socket and listen for incoming connections.  The below command specifies the `-server` flag, a passive mode to allow receiving of data, and the source IP the data originates from.  Defaults for the decoding type and local port are kept the same.

Above listens passively for packets from  hacker.evil.com
destined for port 80. It takes the data and saves the file locally
as secret.c


{% highlight console %}
clarissa@ubuntu:~/server$ sudo ../covert_tcp -source 127.0.0.1 -server -file received-secret.txt
Covert TCP 1.0 (c)1996 Craig H. Rowland (crowland@psionic.com)
Not for commercial use without permission.
Listening for data from IP: 127.0.0.1
Listening for data bound for local port: Any Port
Decoded Filename: received-secret.txt
Decoding Type Is: IP packet ID

Server Mode: Listening for data.

Receiving Data: S
Receiving Data: E
Receiving Data: C
Receiving Data: R
Receiving Data: E
Receiving Data: T
Receiving Data:  
Receiving Data: M
Receiving Data: E
Receiving Data: S
Receiving Data: S
Receiving Data: A
Receiving Data: G
Receiving Data: E
Receiving Data:
{% endhighlight %}

At this point, we can send and receive packets with steganographic data.

#### In Terminal 3 (Listener):

To record traffic between the two hosts, we use `tcpdump` to listen on the lo interface with a snaplength of 1500 bytes and no DNS lookups.  We also write the output to a file covert-data.pcap.  This should be executed after the server is running, but before the client starts sending data, to ensure we capture all encoded packets.

```console
clarissa@ubuntu:~$ sudo tcpdump -i lo -s 1500 -n -w covert-data.pcap
[sudo] password for clarissa:
tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 1500 bytes
^C38 packets captured
76 packets received by filter
0 packets dropped by kernel
```

#### In Terminal 4 (Read pcap / Optional):

(This terminal is optional since the pcap data can be read from Terminal 3)

After the transmission is complete, we use `tcpdump` to read the pcap file and visualize the traffic stream we captured previously.  

The below `tcpdump` command extracts to the screen all traffic going to `dst` port 80, without making any DNS lookups.  It prints the packet's verbose contents with `-v` to display the id field in the IP header.

It prints the packet’s contents in both hex and ASCII with the `-X` switch.

```console
clarissa@ubuntu:~$ tcpdump -nvr covert-data.pcap dst port 80  
reading from file covert-data.pcap, link-type EN10MB (Ethernet)
```

At the end of the experiment, the final screen should look something like the following where the client terminal is on the top left, the server on the top right, the tcpdump listener on the bottom left, and tcpdump reader on the bottom right (click the photo to maximize).

<div class="pos">
  <a href="/testgitpages/images/covert-tcp-screenshot.PNG">
    <img src="/testgitpages/images/covert-tcp-screenshot.PNG" alt="Experiment screenshot">
  </a>
</div>


### Decoding the IP Identification Field:

#### Option One:

After reading the pcap file, the embedded data can be seen in the header of each packet in the "id" field.  Below is the output of the tcpdump read command with the ID's highlighted:

<pre class="dump">
04:44:41.417083 IP (tos 0x0, ttl 64, <b>id 21248</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.54800 > 127.0.0.1.80: Flags [S], cksum 0x4f68 (correct), seq 2316763136, win 512, length 0
04:44:42.418410 IP (tos 0x0, ttl 64, <b>id 17664</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.42756 > 127.0.0.1.80: Flags [S], cksum 0x5c6d (correct), seq 2887647232, win 512, length 0
04:44:43.419536 IP (tos 0x0, ttl 64, <b>id 17152</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.15120 > 127.0.0.1.80: Flags [S], cksum 0xd770 (correct), seq 2635005952, win 512, length 0
04:44:44.420965 IP (tos 0x0, ttl 64, <b>id 20992</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.48661 > 127.0.0.1.80: Flags [S], cksum 0x9078 (correct), seq 1627521024, win 512, length 0
04:44:45.422098 IP (tos 0x0, ttl 64, <b>id 17664</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.24083 > 127.0.0.1.80: Flags [S], cksum 0x707a (correct), seq 3775004672, win 512, length 0
04:44:46.422730 IP (tos 0x0, ttl 64, <b>id 21504</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.7944 > 127.0.0.1.80: Flags [S], cksum 0xc264 (correct), seq 3458400256, win 512, length 0
04:44:47.423541 IP (tos 0x0, ttl 64, <b>id 8192</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.47140 > 127.0.0.1.80: Flags [S], cksum 0x5155 (correct), seq 2786459648, win 512, length 0
04:44:48.424210 IP (tos 0x0, ttl 64, <b>id 19712</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.27158 > 127.0.0.1.80: Flags [S], cksum 0x526e (correct), seq 4077584384, win 512, length 0
04:44:49.424525 IP (tos 0x0, ttl 64, <b>id 17664</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.29983 > 127.0.0.1.80: Flags [S], cksum 0xfd5c (correct), seq 1024720896, win 512, length 0
04:44:50.427468 IP (tos 0x0, ttl 64, <b>id 21248</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.39169 > 127.0.0.1.80: Flags [S], cksum 0xcc76 (correct), seq 1243086848, win 512, length 0
04:44:51.428587 IP (tos 0x0, ttl 64, <b>id 21248</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.2317 > 127.0.0.1.80: Flags [S], cksum 0x9974 (correct), seq 219086848, win 512, length 0
04:44:52.429240 IP (tos 0x0, ttl 64, <b>id 16640</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.53531 > 127.0.0.1.80: Flags [S], cksum 0xd462 (correct), seq 168951808, win 512, length 0
04:44:53.430612 IP (tos 0x0, ttl 64, <b>id 18176</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.44300 > 127.0.0.1.80: Flags [S], cksum 0x455e (correct), seq 3173318656, win 512, length 0
04:44:54.430999 IP (tos 0x0, ttl 64, <b>id 17664</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.13069 > 127.0.0.1.80: Flags [S], cksum 0xeb64 (correct), seq 2434662400, win 512, length 0
04:44:55.431878 IP (tos 0x0, ttl 64, <b>id 2560</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.55824 > 127.0.0.1.80: Flags [S], cksum 0xf558 (correct), seq 3760586752, win 512, length 0
</pre>

The embedded text “SECRET MESSAGE” is transmitted one character per packet.  The IP packet identification field is encoded with the numerical ASCII representation of each character in the message.

To decode the message, the unsigned integer in the ID field needs to be converted to ASCII by dividing by 256.

Let's use the first packet as an example.

<pre class="dump" style="height: auto;">
04:35:59.919509 IP (tos 0x0, ttl 64, <b>id 21248</b>, offset 0, flags [none], proto TCP (6), length 40)
    127.0.0.1.28174 > 127.0.0.1.80: Flags [S], cksum 0x8978 (correct), seq 3087597568, win 512, length 0
</pre>

id <span style="font-weight: bold">21248</span>/256 = 83

The decimal value 83 converts to the character "S".

ASCII = 83 = <span style="font-weight: bold">S</span>

If we do this conversion for each packet, we spell out “SECRET MESSAGE”.

#### Option Two:

Another, easier way to identify the encoded data is to look directly at the packet's data.  This can be achieved with tcpdump's `-X` switch that displays the packet's contents in both hex and ASCII: `tcpdump -nXr covert-data.pcap dst port 80`.

The hex representation of the character's ASCII value is located at the third offset in the packet's payload.  These offsets are highlighted in the below output and spell out the encoded message.

<pre class="dump">
04:44:41.417083 IP 127.0.0.1.54800 > 127.0.0.1.80: Flags [S], seq 2316763136, win 512, length 0
	0x0000:  4500 0028 <b>5300</b> 0000 4006 29ce 7f00 0001  E..(<b>S</b>...@.).....
	0x0010:  7f00 0001 d610 0050 8a17 0000 0000 0000  .......P........
	0x0020:  5002 0200 4f68 0000                      P...Oh..
04:44:42.418410 IP 127.0.0.1.42756 > 127.0.0.1.80: Flags [S], seq 2887647232, win 512, length 0
	0x0000:  4500 0028 <b>4500</b> 0000 4006 37ce 7f00 0001  E..(<b>E</b>...@.7.....
	0x0010:  7f00 0001 a704 0050 ac1e 0000 0000 0000  .......P........
	0x0020:  5002 0200 5c6d 0000                      P...\m..
04:44:43.419536 IP 127.0.0.1.15120 > 127.0.0.1.80: Flags [S], seq 2635005952, win 512, length 0
	0x0000:  4500 0028 <b>4300</b> 0000 4006 39ce 7f00 0001  E..(<b>C</b>...@.9.....
	0x0010:  7f00 0001 3b10 0050 9d0f 0000 0000 0000  ....;..P........
	0x0020:  5002 0200 d770 0000                      P....p..
04:44:44.420965 IP 127.0.0.1.48661 > 127.0.0.1.80: Flags [S], seq 1627521024, win 512, length 0
	0x0000:  4500 0028 <b>5200</b> 0000 4006 2ace 7f00 0001  E..(<b>R</b>...@.*.....
	0x0010:  7f00 0001 be15 0050 6102 0000 0000 0000  .......Pa.......
	0x0020:  5002 0200 9078 0000                      P....x..
04:44:45.422098 IP 127.0.0.1.24083 > 127.0.0.1.80: Flags [S], seq 3775004672, win 512, length 0
	0x0000:  4500 0028 <b>4500</b> 0000 4006 37ce 7f00 0001  E..(<b>E</b>...@.7.....
	0x0010:  7f00 0001 5e13 0050 e102 0000 0000 0000  ....^..P........
	0x0020:  5002 0200 707a 0000                      P...pz..
04:44:46.422730 IP 127.0.0.1.7944 > 127.0.0.1.80: Flags [S], seq 3458400256, win 512, length 0
	0x0000:  4500 0028 <b>5400</b> 0000 4006 28ce 7f00 0001  E..(<b>T</b>...@.(.....
	0x0010:  7f00 0001 1f08 0050 ce23 0000 0000 0000  .......P.#......
	0x0020:  5002 0200 c264 0000                      P....d..
04:44:47.423541 IP 127.0.0.1.47140 > 127.0.0.1.80: Flags [S], seq 2786459648, win 512, length 0
	0x0000:  4500 0028 <b>2000</b> 0000 4006 5cce 7f00 0001  E..(....@.\.....
	0x0010:  7f00 0001 b824 0050 a616 0000 0000 0000  .....$.P........
	0x0020:  5002 0200 5155 0000                      P...QU..
04:44:48.424210 IP 127.0.0.1.27158 > 127.0.0.1.80: Flags [S], seq 4077584384, win 512, length 0
	0x0000:  4500 0028 <b>4d00</b> 0000 4006 2fce 7f00 0001  E..(<b>M</b>...@./.....
	0x0010:  7f00 0001 6a16 0050 f30b 0000 0000 0000  ....j..P........
	0x0020:  5002 0200 526e 0000                      P...Rn..
04:44:49.424525 IP 127.0.0.1.29983 > 127.0.0.1.80: Flags [S], seq 1024720896, win 512, length 0
	0x0000:  4500 0028 <b>4500</b> 0000 4006 37ce 7f00 0001  E..(<b>E</b>...@.7.....
	0x0010:  7f00 0001 751f 0050 3d14 0000 0000 0000  ....u..P=.......
	0x0020:  5002 0200 fd5c 0000                      P....\..
04:44:50.427468 IP 127.0.0.1.39169 > 127.0.0.1.80: Flags [S], seq 1243086848, win 512, length 0
	0x0000:  4500 0028 <b>5300</b> 0000 4006 29ce 7f00 0001  E..(<b>S</b>...@.).....
	0x0010:  7f00 0001 9901 0050 4a18 0000 0000 0000  .......PJ.......
	0x0020:  5002 0200 cc76 0000                      P....v..
04:44:51.428587 IP 127.0.0.1.2317 > 127.0.0.1.80: Flags [S], seq 219086848, win 512, length 0
	0x0000:  4500 0028 <b>5300</b> 0000 4006 29ce 7f00 0001  E..(<b>S</b>...@.).....
	0x0010:  7f00 0001 090d 0050 0d0f 0000 0000 0000  .......P........
	0x0020:  5002 0200 9974 0000                      P....t..
04:44:52.429240 IP 127.0.0.1.53531 > 127.0.0.1.80: Flags [S], seq 168951808, win 512, length 0
	0x0000:  4500 0028 <b>4100</b> 0000 4006 3bce 7f00 0001  E..(<b>A</b>...@.;.....
	0x0010:  7f00 0001 d11b 0050 0a12 0000 0000 0000  .......P........
	0x0020:  5002 0200 d462 0000                      P....b..
04:44:53.430612 IP 127.0.0.1.44300 > 127.0.0.1.80: Flags [S], seq 3173318656, win 512, length 0
	0x0000:  4500 0028 <b>4700</b> 0000 4006 35ce 7f00 0001  E..(<b>G</b>...@.5.....
	0x0010:  7f00 0001 ad0c 0050 bd25 0000 0000 0000  .......P.%......
	0x0020:  5002 0200 455e 0000                      P...E^..
04:44:54.430999 IP 127.0.0.1.13069 > 127.0.0.1.80: Flags [S], seq 2434662400, win 512, length 0
	0x0000:  4500 0028 <b>4500</b> 0000 4006 37ce 7f00 0001  E..(<b>E</b>...@.7.....
	0x0010:  7f00 0001 330d 0050 911e 0000 0000 0000  ....3..P........
	0x0020:  5002 0200 eb64 0000                      P....d..
04:44:55.431878 IP 127.0.0.1.55824 > 127.0.0.1.80: Flags [S], seq 3760586752, win 512, length 0
	0x0000:  4500 0028 <b>0a00</b> 0000 4006 72ce 7f00 0001  E..(....@.r.....
	0x0010:  7f00 0001 da10 0050 e026 0000 0000 0000  .......P.&......
	0x0020:  5002 0200 f558 0000                      P....X..
</pre>


### 2.  Encoding the TCP Initial Sequence Number Field

The lab setup and initial steps for encoding the TCP ISN field are the same as encoding the IP ID field with a few changes.

First, we need to specify the encoding type in the `covert_tcp` program.

Using `-seq` in the client and server terminals will encode data one byte at a time in the packet sequence number.

#### Client / Sender:

Using the same text file secret.txt.

```
clarissa@ubuntu:~/client$ sudo ../covert_tcp -source 127.0.0.1 -dest 127.0.0.1  -source_port 20 -dest_port 20 -seq -file secret.txt
```  

#### Server / Receiver:

```
clarissa@ubuntu:~/server$ sudo ../covert_tcp -source_port 20 -server -seq -file  received-secret.txt
```

### Decoding the TCP Initial Sequence Number Field

The embedded traffic can be spotted in the "seq" field of the TCP header. Using `tcpdump` to read the recorded pcap file, we can build syntax to isolate the specific type of traffic that contains our encoded seq fields.  This can be done with the below command:

<pre class="dump" style="height: auto;">
tcpdump -nr covert-data-seq.pcap 'tcp[13] & 2!=0'
</pre>

The data we're looking for appears in / encoded fields appear in packets with the synchronize (SYN) flag set.  In the packet's payload, this flag is found at offset 13 `tcp[13]` in the header and location 2 within the byte.  It checks if the flag is set with !=0.

The filters below find these various packets because tcp[13] looks at offset 13 in the TCP header, the number represents the location within the byte, and the !=0 means that the flag in question is set to 1, i.e. it’s on

<pre class="dump" style="height: auto">
00:03:23.068016 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
00:03:24.068412 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
00:03:25.072002 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1124073472, win 512, length 0
00:03:26.076922 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1375731712, win 512, length 0
00:03:27.078184 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
00:03:28.078901 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1409286144, win 512, length 0
00:03:29.080145 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 536870912, win 512, length 0
00:03:30.081145 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1291845632, win 512, length 0
00:03:31.081845 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
00:03:32.083638 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
00:03:33.084928 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
00:03:34.086324 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1090519040, win 512, length 0
00:03:35.087006 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1191182336, win 512, length 0
00:03:36.088617 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
00:03:37.089531 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 167772160, win 512, length 0
</pre>

Again, sending the same text file, the message “SECRET MESSAGE” is transmitted one character per packet.  

`covert_tcp` generates the encoded sequence number from each ASCII character in the text file.  To decode the message, the sequence numbers are converted to ASCII by dividing by 16777216 (which is 65536*256).

An example of decoding the TCP header in the first packet:

<pre class="dump" style="height: auto">
00:03:23.068016 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], <span style="font-weight: bold">seq 1392508928</span>, win 512, length 0
</pre>

First, divide by 16777216:

seq <span style="font-weight: bold">1392508928</span>/16777216 = 83

Next, convert the decimal to ASCII:

ASCII = 83 = <span style="font-weight: bold">S</span>

Alternatively, we can use tcpdump's `-X` option to print the contents in hex and ASCII and look at offset 13 in the packet's payload to identify each character in the encoded message.

<pre class="dump">
00:03:23.068016 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
	0x0000:  4500 0028 f700 0000 4006 85cd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>5300</b> 0000 0000 0000  ........S.......
	0x0020:  5002 0200 5cb8 0000                      P...\...
00:03:24.068412 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
	0x0000:  4500 0028 2d00 0000 4006 4fce 7f00 0001  E..(-...@.O.....
	0x0010:  7f00 0001 0014 0014 <b>4500</b> 0000 0000 0000  ........E.......
	0x0020:  5002 0200 6ab8 0000                      P...j...
00:03:25.072002 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1124073472, win 512, length 0
	0x0000:  4500 0028 da00 0000 4006 a2cd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>4300</b> 0000 0000 0000  ........C.......
	0x0020:  5002 0200 6cb8 0000                      P...l...
00:03:26.076922 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1375731712, win 512, length 0
	0x0000:  4500 0028 0a00 0000 4006 72ce 7f00 0001  E..(....@.r.....
	0x0010:  7f00 0001 0014 0014 <b>5200</b> 0000 0000 0000  ........R.......
	0x0020:  5002 0200 5db8 0000                      P...]...
00:03:27.078184 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
	0x0000:  4500 0028 5c00 0000 4006 20ce 7f00 0001  E..(\...@.......
	0x0010:  7f00 0001 0014 0014 <b>4500</b> 0000 0000 0000  ........E.......
	0x0020:  5002 0200 6ab8 0000                      P...j...
00:03:28.078901 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1409286144, win 512, length 0
	0x0000:  4500 0028 3f00 0000 4006 3dce 7f00 0001  E..(?...@.=.....
	0x0010:  7f00 0001 0014 0014 <b>5400</b> 0000 0000 0000  ........T.......
	0x0020:  5002 0200 5bb8 0000                      P...[...
00:03:29.080145 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 536870912, win 512, length 0
	0x0000:  4500 0028 0d00 0000 4006 6fce 7f00 0001  E..(....@.o.....
	0x0010:  7f00 0001 0014 0014 2000 0000 0000 0000  ................
	0x0020:  5002 0200 8fb8 0000                      P.......
00:03:30.081145 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1291845632, win 512, length 0
	0x0000:  4500 0028 9d00 0000 4006 dfcd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>4d00</b> 0000 0000 0000  ........M.......
	0x0020:  5002 0200 62b8 0000                      P...b...
00:03:31.081845 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
	0x0000:  4500 0028 d400 0000 4006 a8cd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>4500</b> 0000 0000 0000  ........E.......
	0x0020:  5002 0200 6ab8 0000                      P...j...
00:03:32.083638 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
	0x0000:  4500 0028 1400 0000 4006 68ce 7f00 0001  E..(....@.h.....
	0x0010:  7f00 0001 0014 0014 <b>5300</b> 0000 0000 0000  ........S.......
	0x0020:  5002 0200 5cb8 0000                      P...\...
00:03:33.084928 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1392508928, win 512, length 0
	0x0000:  4500 0028 a200 0000 4006 dacd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>5300</b> 0000 0000 0000  ........S.......
	0x0020:  5002 0200 5cb8 0000                      P...\...
00:03:34.086324 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1090519040, win 512, length 0
	0x0000:  4500 0028 4400 0000 4006 38ce 7f00 0001  E..(D...@.8.....
	0x0010:  7f00 0001 0014 0014 <b>4100</b> 0000 0000 0000  ........A.......
	0x0020:  5002 0200 6eb8 0000                      P...n...
00:03:35.087006 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1191182336, win 512, length 0
	0x0000:  4500 0028 d600 0000 4006 a6cd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 <b>4700</b> 0000 0000 0000  ........G.......
	0x0020:  5002 0200 68b8 0000                      P...h...
00:03:36.088617 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 1157627904, win 512, length 0
	0x0000:  4500 0028 2000 0000 4006 5cce 7f00 0001  E..(....@.\.....
	0x0010:  7f00 0001 0014 0014 <b>4500</b> 0000 0000 0000  ........E.......
	0x0020:  5002 0200 6ab8 0000                      P...j...
00:03:37.089531 IP 127.0.0.1.20 > 127.0.0.1.20: Flags [S], seq 167772160, win 512, length 0
	0x0000:  4500 0028 8900 0000 4006 f3cd 7f00 0001  E..(....@.......
	0x0010:  7f00 0001 0014 0014 0a00 0000 0000 0000  ................
	0x0020:  5002 0200 a5b8 0000                      P.......
</pre>

The following are some wrap-up / conclusion questions.

### Summary​ ​of​ ​TCP/IP​ ​Steganography​

The​ ​​program​ `covert_tcp`​ ​used​ ​for​ ​network​ ​steganography​ ​takes​ ​the​ ​ASCII​ ​value​ ​of our​ ​message​ ​and​ ​converts​ ​it​ ​to​ ​a​ ​usable​ ​number​ ​to​ ​be​ ​encoded​ ​into​ ​one​ ​of​ ​the​ ​TCP/IP packet​ ​header​ ​fields​ ​during​ ​the​ ​packet​ ​generation​ ​process.​ ​​ ​It constructs​ ​a​ ​forged​ ​packet​ ​with​ ​the​ ​destination​ ​host​ ​and​ ​source​ ​host​ ​information​ ​and​ ​the encoded​ ​TCP/IP​ ​field.​ ​The​ ​packet​ ​with​ ​the​ ​encoded​ ​data​ ​is​ ​sent​ ​to​ ​the​ ​remote​ ​host​ ​which grabs​ ​the​ ​field​ ​of​ ​each​ ​incoming​ ​packet​ ​and​ ​decodes​ ​the​ ​data​ ​to​ ​get​ ​the​ ​ASCII​ ​character number.

### Detecting​ ​TCP/IP​ ​Steganography​

The​ ​presence​ ​of​ ​steganographic​ ​data​ ​in​ ​TCP/IP​ ​headers​ ​can​ ​be​ ​detected​ ​by​ ​an anomaly​ ​or​ ​abnormal​ ​behavior​ ​that​ ​is​ ​not​ ​consistent​ ​with​ ​standards​ ​of​ ​known​ ​operating systems.​ ​​ ​A​ ​genuine​ ​TCP/IP​ ​stack​ ​is​ ​generated​ ​by​ ​each​ ​operating​ ​system​ ​and​ ​can​ ​be distinguished​ ​due​ ​to​ ​distinct,​ ​well-defined​ ​characteristics.​ ​​ ​One​ ​of​ ​these​ ​characteristics include​ ​the​ ​IP​ ​and​ ​ISN​ ​fields​ ​(exploited​ ​by​ ​covert_tcp).​ ​​ ​These​ ​fields​ ​will​ ​naturally exhibit​ ​structure​ ​when​ ​generated​ ​by​ ​the​ ​kernel.​ ​​ ​Therefore,​ ​the​ ​modified​ ​headers produced​ ​by​ ​TCP/IP​ ​steganography​ ​will​ ​not​ ​exhibit​ ​the​ ​expected​ ​structure​ ​and​ ​can​ ​be detected​ ​by​ ​observing​ ​that​ ​the​ ​field​ ​does​ ​not​ ​meet​ ​the​ ​required​ ​constraints,​ ​uniqueness, and​ ​other​ ​statistical​ ​properties.

### How​ ​would​ ​you​ ​thwart​ ​steganographic​ ​efforts​ ​if​ ​you​ ​could​ ​be​ ​in​ ​the​ ​middle​ ​of​ ​the transmission,​ ​i.e.​ ​you​ ​take​ ​the​ ​role​ ​of​ ​an​ ​active​ ​warden​ ​and​ ​modify​ ​traffic​ ​in​ ​transit?

The​ ​role​ ​of​ ​an​ ​active​ ​warden​ ​is​ ​to​ ​prevent​ ​the​ ​exploitation​ ​of​ ​the​ ​TCP/IP​ ​header​ ​fields​ ​by removing​ ​any​ ​information​ ​that​ ​could​ ​possibly​ ​be​ ​embedded​ ​into​ ​network​ ​traffic​ ​without breaking​ ​communications. One​ ​way​ ​to​ ​thwart​ ​the​ ​use​ ​of​ ​covert​ ​channels​ ​and​ ​steganography​ ​at​ ​the​ ​IP​ ​layer​ ​is​ ​to​ ​alter all​ ​data​ ​that​ ​passes​ ​across​ ​that​ ​network.​ ​​ ​The​ ​covert_tcp​ ​program​ ​exploits​ ​the​ ​fact​ ​that header​ ​fields​ ​can​ ​be​ ​assigned​ ​arbitrarily​ ​chosen​ ​numbers​ ​within​ ​the​ ​requirements​ ​of​ ​the standard.​ ​​ ​An​ ​active​ ​warden​ ​can​ ​use​ ​the​ ​same​ ​fact​ ​to​ ​rewrite​ ​network​ ​packets. As​ ​demonstrated​ ​by​ ​covert_tcp,​ ​the​ ​IP​ ​identification​ ​and​ ​TCP​ ​initial​ ​sequence​ ​number (ISN)​ ​fields​ ​can​ ​both​ ​be​ ​used​ ​as​ ​a​ ​covert​ ​channel.​ ​​ ​To​ ​prevent​ ​exploitation​ ​of​ ​the​ ​IP​ ​ID field,​ ​the​ ​active​ ​warden​ ​can​ ​assign​ ​a​ ​new​ ​IP​ ​identification​ ​to​ ​all​ ​packets.​ ​​ ​The​ ​warden​ ​can also​ ​renumber​ ​the​ ​packet​ ​ID’s​ ​to​ ​thwart​ ​covert​ ​channels. Similarly,​ ​to​ ​prevent​ ​exploitation​ ​of​ ​the​ ​TCP​ ​ISN​ ​field,​ ​the​ ​warden​ ​can​ ​assign​ ​a​ ​new​ ​ISN number​ ​at​ ​the​ ​beginning​ ​of​ ​a​ ​connection​ ​and​ ​compute​ ​the​ ​subsequent​ ​packets​ ​by incrementing​ ​the​ ​initial​ ​sequence​ ​number.


### References:
1. [Covert_TCP on GitHub]( https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c)
2. [Basic Tool Usage]( https://dunnesec.com/category/tools/covert_tcp/)
3. [Supporting Paper]()
