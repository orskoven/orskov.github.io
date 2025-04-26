# SIMON'S ✍️ CYBER SECURITY NOTES


___

## SOF-ELK ##

Elsatic Stack -> SOF ELK 


### The Stack ###

ELK stack 

Elasticsearch 

Logstash 
Kibana
Beats 
and others 

Centralized logs 

Helps centralize between example: 

Web servers - Admin servers - Redundant databases - Application Servers

Major outages avoid, since elastic stack is centralized logs. 

Kibana is visualisation of the logs.

Can search logs for it security issues. 

Not like Splunk. 

Core components opensource and free

end point security monitoring self host stack


### BEATS ###

Light weight way to ship logs into the stack
written in go:

Filebeat 
Packetbeat 
+ more

Logstash transform incoming data.
Beats single purpose tool. 

Logstash is more resource intensive.


Elasticsearch 

holds index of data 
holds all data itself

in production is deployed in a cluster 
with shards a b c 
redundant copies in clusters like kubernetes 


### KIBANA ### 

Web frontend, define preset dashboard for birdseye view. 


### Setup ###

VM 
Vagrant

___

## Arp Spoofing ##

Installing arpspoof for linux.
```bash
sudo apt-get update
```
```bash
sudo apt-get install dsniff
```
> Make linux act as a "router" (man in the middle).
Remove '#' commented line with the text: “net.ipv4.ip_forward = 1”.
/etc/sysctl.conf
```bash
sudo nano /etc/sysctl.conf
```
Reconfigure the kernel parameters at runtime to apply the change.
```bash
sudo sysctl -p
```

On victim ubuntu:
```bash
sudo apt install net-tools
```
Check arp table. 
```bash
sudo arp -a
```

🔻On both attacker and victim terminals.

🔺 Adjust ip addresses acordingly: 

> in my setup: Attacker IP: 172.16.196.132 | Victim IP: 172.16.196.133
> 
```bash
sudo arpspoof -i eth0 -t 172.16.196.133 172.16.196.132
```
```bash
sudo arpspoof -i eth0 -t 172.16.196.132 172.16.196.133
```

Check the ARP table again to verify that the victim ip address has been removed when arp spoofing.
```bash
sudo arp -a
```

> In my case it all i one terminal so i will use '&' to allow multiple commands running simulatniously:

```bash
sudo arpspoof -i eth0 -t 172.16.196.132 172.16.196.133 & sudo arpspoof -i eth0 -t 172.16.196.133 172.16.196.132 & sudo arp -a
```

___
## ARP Posoning with SCAPY ##

>research the arp possibilities in scapy
```python
ls(ARP)
```
> >>> ls(ARP)
hwtype     : XShortEnumField                     = ('1')
ptype      : XShortEnumField                     = ('2048')
hwlen      : FieldLenField                       = ('None')
plen       : FieldLenField                       = ('None')
op         : ShortEnumField                      = ('1')
hwsrc      : MultipleTypeField (SourceMACField, StrFixedLenField) = ('None')
psrc       : MultipleTypeField (SourceIPField, SourceIP6Field, StrFixedLenField) = ('None')
hwdst      : MultipleTypeField (MACField, StrFixedLenField) = ('None')
pdst       : MultipleTypeField (IPField, IP6Field, StrFixedLenField) = ('None')

Trying to build an ARP packet:
```python
from scapy.all import *

pkt = ARP(psrc="ff-ff-ff-ff-ff")
print(pkt.psrc)
```
> b'ff-ff-ff-ff-ff'
```python
ls(ARP)
```
https://github.com/KimiNewt/pyshark/
```python
ls(ARP)
```
```python
ls(ARP)
```

```python
ls(ARP)
```
```python
ls(ARP)
```

```python
ls(ARP)
```
```python
ls(ARP)
```

```python
ls(ARP)
```

___

# Ethical Hacking: Wireless Networks

## Wireless Testing

- ✅ Use Virtual Machines (VMs) for safer testing environments
- ✅ Kali Linux – preferred OS for penetration testing
- ✅ Understand computer and networking basics
- ✅ USB wireless adapters – monitor/injection capable
- ✅ WiFi Pineapple – specialized penetration device

**Tools & Considerations:**

- 🛠️ Use both commercial and open-source software
- 🔻 Testing sites can be targets for hackers
- ⚠️ Watch for conflicting software that disrupts testing
- 🔺 Powerful methods available – use responsibly
- 🔺 Practice due diligence when downloading any tools

---

## Wireless Setup

- 🌐 Router or Internet Gateway required
- 🔌 Wired ISP connection recommended for stability

---

## Wireless Speed

| Standard     | Frequency | Max Speed    |
|--------------|-----------|--------------|
| Cat 6 Cable  | Wired     | 10 Gbps      |
| 802.11ac     | 5 GHz     | Up to 2 Gbps |

### 2.4 GHz Channels

- Channel 1: 2412 MHz  
- Channel 2: 2417 MHz  
- ...  
- Channel 14: 2472 MHz

---

## Wireless Infrastructure

```
Public Internet <--> Access Point <--> Host
```

- **SSID** – Network name (should not be hidden)
- **BSSID** – MAC address of the access point

---

## Wireless Security

- 🔑 Network Key – Required for access
- 🔒 Internet Login – Authentication portal
- 🚫 MAC Filtering – Can be circumvented
- 🔐 Encryption Standards:
  - WEP (Weak)
  - WPA (Improved)
  - WPA2 (Strongest widely supported)
- 📶 WPS – Simplifies connection, but can be vulnerable

---

## MAC Filtering

**On Router Configuration:**

- ✅ Whitelist: Only allow specified MACs
- 🚫 Blacklist: Block specific MAC addresses

> ⚠️ Not a robust security method on its own

---

## Wireless Network Basics

- 📡 Uses antennas to send/receive packets
- 🔁 Cycles through channels for optimal performance
- ❌ Can cause disconnections
- 🖥️ Essential for virtualized networks
- 🔄 Converts electrical signals to radio waves
- 📈 Antenna performance rated by **dBi**
  - Positive: Strong signal
  - Negative: Weak signal (e.g., -90 dBi is poor)
- ⚡ Power measured in **dBm**

### Antenna Types

#### Yagi Antenna (Fishbone Style)

- 🎯 High unidirectional range
- 🔑 Performance depends on phase alignment of elements

#### Parabolic Antenna

- 📡 Large dish = higher gain
- 🏞️ Ideal for rural or long-distance communication

---

## Open Wireless Networks

- 🚨 Unauthorized bandwidth/data usage
- 🛡️ Launchpad for malicious internet attacks
- 🧑‍💻 Can be exploited for internal attacks (e.g., MitM)

---

## Wireless Security Protocols

### WEP – Wired Equivalent Privacy

- ❌ Not secure
- 🧩 Designed to prevent eavesdropping & ensure integrity
- ✅ Lightweight – low performance impact
- ❌ Weak encryption and key management
- ❌ Vulnerable to sniffing and RNG flaws

### WPA – Wi-Fi Protected Access

- 🔄 Uses TKIP – rotates key for each frame
- 🔐 Supports AES encryption
- ✅ Includes integrity checks and longer keys

#### WPA2 – Enhanced WPA

- 🔐 WPA2 Personal – Shared key (PSK)
- 🔐 WPA2 Enterprise – Uses RADIUS server for auth

> 🔒 WPA2 is the current standard for secure wireless networking

___

With TP-link module we can

use some commands 

WIFITE 
-mac
-aircrack

it run different attacks 

caffe latte attacks 
fake authenticatin 

and can crack IV (initial vector) 

Show cases way WEP is vulnerable 

___

WPS can also be tested

TG583 router is tested

setting wireless adapter to monitor mode 

lookig for BSSID for reaver

operating on channel 1 

running reaver to WPS attacks

generating keys and exract model manufacturer 
model number 

serial number 

m1 and m2 messags
m3 and m4 messages 

looking at rate limiting and wainting for lifting
and attempts again 
smart enough to resume session 

aftwer a while 
router will make a lock down.
WPA2 strong solution 
but WPS rate limiting is needed for more secure WPA2 level 
disable WPS to remove risk. 

___

How well is protection for WPA handshake 

WIFIT

```bash
airmon-ng start wlan0
```
SCAN 

DEVICES 
CLIENTS 
DEVICES associtated with acces point 

Press ctrl + c 
select targeet 

get into wpa attacks
checking for clients 
deauthentication 
found and 
saved as pcap file 

aircrack and dictionary "wifi.txt" 
to crack password

and can user pswd to connect to wifi. 

___

Pixiedust 

recover key
linksys nexus, 

Linksys n300 range extendor 
antenna into monitoring mode
bssid to AP 
run wash 
run reaver to specify pixiedust attack

try pin 
initate authentication handshake 
send m2 message 
verbose mode to dump hashes and nonces (set to zero) 

reaver gets pin
network key should be recoveredd 

not all ap vulnarable 

prevent with equipment is security tested 


___

# WPA3 #

2019 router on market 

essential for open networks 
WPA3 individualized encryption 
Dragonfly handshake 
use correct password to negotiate the connection encryption 

WPA2 vulnerability 

WPA3 comes with new krack preventing password almost 100 procent secure

simple connectivuty with qr code 

enhance AES-192 encryption 

## Dragonblood - on WPA3 ##

- timing leaks
- authentication bypasses
- downgrade attacks
- denial of service
- side channel attacks
- even after patched

Design issues 
- 1$ spended on amazon EC2 enough to brute force password
- History of side channel attacks
- most attack could be fixed with minor design changes

- research tools available

Wifi alliance have confirmed this WPA3 issues and vulnarbilities
some controvercy over dragonfly 
some is validated through the fixes. 

Long way to be trusted
___

## Evil Twin ##

Rogue Access Point 
been activated to attract on vary users to connect for MitM attack 
same SSID as legimate access points - stronger signal in zone 
deauth from legitimate access point 

SIGNIFICANT THREAT

Airbase-ng 

set wireless adapter into monitor mode

```bash
airmon-ng start wlan0 
```


```bash
airdump-ng wlan0mon
```
```bash
airbase-ng -a <MAC> --essid Telecom05 -c 1 wlan0mon
```

wireshark to monitor traffic 

wlan0mon

interface

see traffic 
stop capturing

rerouting traffic airbase-ng for evil twin

buy the wifi Pineapple from hack5.org

wifi testing 

Nano Tetra beeing popular 

MARK VII and ENTERPRISE 

802.11/ac addon unit 
3 antennas 
independntly 

USB-C port

172.16.42.1:1471 

access and download software 

after installing firmware

can begin setup

setup 

restrict for SSIDs
good for client facing roles 

devope and install third party 

___
Testing with WIFI pinapple 

activating as rogue access point

start harvesting client devices 

scan for access points 
default 30 seconds 

Reconnaisance 


Add MAC to filter 
PineAP tap 
HTTPeek start listening 
Man in the middle 

### Capture WPA handshakes ###

Handshakes panel
Capture WPA handshake 
and download for pcap analysis 

___
Fluxion 

runs on kali linux
get network hash 
setup 
rogues access point 

external wifi usb link 

will check missing dependencies

cd fluxion 
sudo ./fluxion.sh 

fluxion@kali: 1

scan all 2.4 ghz channels 

attack a network 
select it

select RA link wifi modem 

reset attack and configure again 
passive monitoring attack to wait for attack to be made
take recommended verfication 
and wait for 30 seconds

attacks taking place connect to network 
attack complete
valid hash added to database 

rogue AP first step complete 

obtained Hash to obtain 

select another attack 
captive portal attack inteface
create own custom user portal captive portal 
continue to attack comfast ap

select wlan0 as interface
select airreplay
cowpattty for hash verification

use handshake snooper
use cowpatty 

create new ssl certificate for portal 
use recoomenced for connectivity 

running main dashboard for captive portal 

dns service active 
ruuning as man in the middle 
___
## Bluetooth ##

vulnerabilities 
works in 2.4ghz and also zigbee
defined in IEEE 802.15.1 

master and slave 

48-biut address decive id 

OUI Organ unique identifie 

friendly names 

class one devices 1: 100m 2:10m 3: 10 cm or less

real time stream or files

slave master identify each other and pair 

send inquiry request and active address will reply 

automitic bonding with bluetooth system 

or 6-digit number displayed 

Bluetooth operating profiles 

SERIAL Port Profile (SPP)

human interface device profile (HID) 

handsfree profile (HFP)

advanced audio distribution profile (A2DP)

Audio/Video Remote control profile (AVRCP) 

Service discovery protocol offers direct support for specific ssid 
AUDIO
TCP IP HCI RFCOMM 
DATA 
L2CAP 
LINK MANAGET
DRIVER
HARDWARE [
BASEBAND
RADIO
]


___

USE bluetooth with kali 

usb configuration 
open a terminal
lsusb 
hciconfig command
hcitool scan --info --oui 

enumrate and tell what device it is 

first is iphone 
name chip set manufacture 
first 3 of addres oui 

wireless attacks 
bluetooth tools
bluelog -l command 

/tmp/live.log 

foun 3 devices 

BT scanner also tool

l2ping to check active devices  network ping 

can find hidden devics with bruteforce on hidden adresses

redfang:
fang -s -r 0CD..... < range command 

found hidden device 

hidden address close to wifi address 

run airodump 
combine wifi scanning and redfang 
detecting hidden devices straight forward

Bluesnarfer is overtaken by other tools 

go through:

lsusb 

hciconfig 

hcitool scan 

l2ping 00:11:43:...

c flag character based device 
which channelse communicationg on 

sdp tool 
phone connected on channel 11

doesnt work with new phones 


___

Wifi cracker

select monitoring interface to use 
monitor mode automatically 

FernWifi 

initialize and detect 
networks

if been cracked key will be stored 

2 options for attack 
wps pin attack 
tpg secured access point


fernwifi 
comes with its own 
finds associated names

wifi button to start attack 
found network password 

one entry in key database 

FernPro .> upgrade 

InSSIDer4 payed low cost share product
identify network strength for walk around 

Graph of signal strengths 
SSID and secure or not 
bssid mac address 
filters to limit display 
channel minimal signal strength 
extender not shown in logical display but 
indicates best channels for sender to best on 

ACRYLIC wifi 
pro version 
identifing strength network through walkaround or warrundown 
SSID vendor infomation 

right click 
add device to inventory 
keep track of home network small businesses 

WPS information 
manufacturer 
device name
model

dictionary attack against acces point 

select connectivity 
disconnect from network 

and right click to start 

network quailty

speed signal to noist 
spectrum operating 
networks requested 
device info 

associted devices can be expanded with plus sign
station view shows all bssids been identified active and inactive devices
wireless packets view / turn on packet viewing, full 
data control manage
expand packets to see the structure 
scripts tab assists with wpa and keys Seriuous companion testing >>!!!

heat map 
ekahau
free popular
HeatMapper 

commercial 

no multifloor

useful for home and business

walk saround site and click for points right click to terminate

calculate signal strength 
pentest can provide hearmapping


wireshark monitor mode 
wlan0mon 
start capturing 
connect mobile 

wireless lan summary 
wlan traffic 
summery
beacons and data 

collected traffic 
radio tap header 
beacon 
bssid
dest
source
vendor data
radio tap header 

qos control field
for delays
data sections ip 

can add keys to decrypt data 
enable decryption 
wireshark website calculate psk paste in the key 


Vistumbler

githun repository

list of minor releases 
versio6

google earth feurures 

tp link added 
scan aps 
acess points are listed
mac address and bssid
authentication

latitude and longitud
work with gps

chnnel encryption ssid


extra 2.4 ghz 
select left hand button 
graph in real time 

gps integration 
urban regin of access points 
settings gps settings 
speed and settings correct

wifi database online database 
contribute acces point data 

wifidb

5 million records 

open access points 

comm view nodes view 

protocols bar charts 

ssid singal tpe 

context window quickl
filter channel 

decryption 

commview 

can to acces points attack 

log viewer 

run attack aircrack ng

vemo switch for SOAP protocol

open network 

tcp ports 
udp

getbinary state

http xml netcat to send 
upmp services 
getbinarystate
control with netcat 
vulnerablityu 








USB UART


## 🕸️Virutal Private Networking (VPN)🕸️ ## 

Devices are typically protected on a local network, because of local ip address space not being defualt routable across the internet.

A Virtual Private Network (VPN) can be setup to securely connect and access resources on a reomte local ip address space and make resources securely availbale through network tunneling protocols, not requiring connected hosts to be on the same local ip network.

Encryption is vital to the security of the VPN when the VPN is accessed through insecure communication lines (the public internet).

Provider-provisioned VPN is isolating the provider's own network infrastruture in virtual segments. 
This allows for making segements private to other segements in the network. 
This can be implemented with weak or no security feautures 

[VPN](https://en.wikipedia.org/wiki/Virtual_private_network)
Sources for the following content origins from Scott Simpsons course on linkedin learning [Learning VPN](https://www.linkedin.com/learning/learning-vpn/how-vpn-works?resume=false&u=36836804)
___

### Routing ###

Routes determines how packets flow to different networks.
A **Layer 3 VPN** creates a new route for a virtual network adapter

### Bridging ###

**Layer 2** VPNs behave like devices that are on the same physical network.

### Encapsulation ###

Information is wrapped inside of packets that can travel between networks.
Local traffic is encapsulated to travel between client and server.

___

## Layer 2 (data link layer)💌 ##

Transmission of frames between devices
Bridged VPN 
Layer 2 virtual devices are called TAP (tap0,tap1) 


## Layer 3 (network layer)🛤️ ##

Transmission of packets (IP)
Routed VPN
Layer 3 virutal devices are called TUN (tun0, tun1)

## PPP (Point-to-Point Protocol) (Layer 2) ##

Sets up a connection between two hosts 
Creates a connection between two hosts with a virtual network adapter at each end
ISP used to crete a network link over media-like phones lines to carry ehternet frames between IP networks
Used in DSL Modems and most VPN protocols

## Key Exchange🗝️<->🗝️ ##

VPN peers exchange encryption information to establish a secure connection.

Some protocols rely on a PSK (pre-shared key) and others agree on what security keys to use when a connection is started. 

Negotiate back and forth to agress on a key exchange before setting up a secure channel.


## Forward Security🔐 ##

Also called "Perfect Forward Security".

New session keys are generated for each session used to encrypt and decrypt the data.

Prevents malicious reuse of keys for future sessions. (Go to the hybrid encryption section)

🔺 RISK : be sure to use secure and not broken protocols 🔺

## Ports🛳️ ##

Ports used by VPN protocls are the ports on the server.

Clients choose a local port to connect from.

Ports need to be opened on the server's firewall and on the any firewalls between it and the internet. 

___

## 🔺PPTP (Point-to-Point Tunneling Protocol🔺 ###

🔺 Considered obsolete because most of the ciphers it uses are easily broken🔺

🔺Top out on 128 bit encryption🔺

🔺Uses **TCP port 1723** to set up a **GRE tunnel**, through which a PPP connection **(Protocol 47)** transfers encrypted packets.🔺

🔺Most routers pass PPTP traffic without a problem. 🔺

___

## L2TP/IPsec ##

Layer 2 Tunneling Protocol over IPsec (IP security)

IPsec creates a secure channel through which an L2TP tunnel transfers data.

# [L2TP](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol) #
Encapsulates Layer 2 traffic to travel over Layer 3 (IP) (normally not possible)
Allows Ethernet Bridging over the internet
No security

# [IPsec](https://en.wikipedia.org/wiki/IPsec) #
Creates a secure connection
Only carries IP traffic

## Making an [L2TP](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol)/[IPsec](https://en.wikipedia.org/wiki/IPsec) Connection ##

IPsec uses IKE (Internet Key Exchange) via UDP port 500 to negotiate a Security Association (SA) 

UDP port 4500 for NAT traversal mode

SA sets up ESP (Encapsulating Security Payload; protocol 50) to encrypt packets.

L2TP tunnel is established through TCP port 1701, to pass traffic protected with ESP

PPP establishes virtual network interface with IP addresses at each end.

👱‍♀️
Uses user authentication and machine-level shared secret or certificate
may need group name based on system admin setup.

✔️ Good choice for security and is widely available

Useful if you need to transfer Layer 2 data instead of just Layer 3 data.

# IKEv2 #
Internet Key Exchange, version 2

IKEv2 manages the SA for an IPsec connection

Uses UDP port 500 and UDP port 4500 for NAT traversal (supports 256 bit encryption) 

IPsec provides Layer 3 connectivity (IP)

💲MOBIKE feature provides quick reconnection - great for mobile devices📴💲

Uses user authentication, shared secret or certificate and a remote ID

___

## [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN) ##

Open-source software and protocol.

Uses OpenSSL library to handle key exchange via **SSL/TLS** (offers 256 bit encryption) 

Creates a Layer 2 or Layer 3 connection. 

Via custom security protocol based on TLS. 

Uses TCP port 1194 by default, can be changed to other UDP/TCP ports. 

Works well through NAT and proxies.

✔️✔️ Widely recommended


___
### Other Protocols ###

## [Secure Socket Tunneling Protocol](https://en.wikipedia.org/wiki/Secure_Socket_Tunneling_Protocol) ##

Creates a secure channel using **SSL/TLS**

Uses **TCP port 443**

Fairly wide support 

Creates a client-network connection

## [WireGuard](https://www.wireguard.com) ##

Software and protocol (offers high security) 

Out-of-band key exchange (keys are assigned to peers in configuration)

Creates Layer 2 and Layer 3 connections over IP

Packets are encrypted with the public key of the destination host

Open source, with a goal of easy auditability

Not considered finalized (yet) [WireGuard.com](https://www.wireguard.com)

## [SoftEther](https://en.wikipedia.org/wiki/SoftEther_VPN) ##

Software Ethernet

Offers IPsec, SSTP, and other protocols, in addition to its own protocol

Sends traffic through HTTPS

Offers Layer 2 and Layer 3 connections

Creates virtualized Ethernet devices

Open source [softether.com](https://www.softether.org)


___

## [SSH](https://en.wikipedia.org/wiki/Secure_Shell) FORWARDING ##

Secure Shell 

Create a connection to an SSH server for port forwarding

Uses TCP port 22 but can use other ports 

Can forward a local port to a remote port (connect localhost:8080 to server:80)

Some implementations can open a local port and act as a SOCKS proxy sending traffic to the server


SSH doesnt create network interfaces 

Very useful for certain cases 

Widespored and difficult to block


___


🚦For practical implementation show casing🚦

Two Virtual Machines: 

One is publicly accesible and other is not.
A webpage that is not directly accesible from the public internet will be accessed through a VPN. 

___

The guide will be following:
[Algo VPN](https://github.com/trailofbits/algo)


Source of truth [Algo Cloud Deployment Guide](https://github.com/trailofbits/algo?tab=readme-ov-file#deploy-the-algo-server)
On cloudshell perform in the Command Line Interface:

download algo zip file
```bash
wget https://github.com/trailofbits/algo/archive/master.zip
```
unpack using 
```bash
unzip master.zip
```
move into directory
```bash
cd algo-master
```

```bash
sudo apt install -y --no-install-recommends python3-virtualenv file lookup
```

```bash
python3 -m virtualenv --python="$(command -v python3)" .env &&
  source .env/bin/activate &&
  python3 -m pip install -U pip virtualenv &&
  python3 -m pip install -r requirements.txt
```
open config.cfg file
```bash
nano config.cfg
```
cofigure the following usernames to be created:
```txt
users:umbers should be escaped in d>
  - phone
  - laptop
  - desktop
```
To match: 
```txt
users:umbers should be escaped in d>
  - ssorskov
```
save and exit (control + x)

run the last step with the algo command:

```bash
./algo
```
answer the question with pressing ```12``` for installing to existing ubuntu server:
```12```
Then press enter on the rest until:
```bash
Enter the public IP address or domain name of your server: (IMPORTANT! This is used to verify the certificate)
[localhost]:
```

enter the public address of your algo cloud server.


```cd```
```cd```




___

Algo allows different clients to connect. 

iOS devices.


___

Setup a connection that allows for connection acroos the internet.

___

## Windows Network Services ##

Source of truth : Network Security Assesment 

Services used for large internal networks for file sharing, printing and more:

Risk: 
Used to enumerate system details to cause complete network compromise.

| Keyword | Definition | Technical |
| --- | -- | -- |
Microsoft RPC |   | 
NetBios |  |
CIFS ||

___



| service | port | protocol | 
| --- | -- | --- | 
| loc-srv | 135 | tcp | 
| loc-srvi | 135 | udp | 
| netbios-ns | 137 | udp | 
| netbios-dgm | 138 | udp |
| netbios-ssn | 139 | tcp | 
| microsoft-ds | 445 | tcp | 
| microsoft-ds | 445 | udp | 



## 🚦TRANSFERING A FILE SECURELY WITH SCP AND SFTP🗃️🔐🚦 ##

Transferring files should be confidentially encrypted to secure zero tampering while in transit.
FTP <a href="https://en.wikipedia.org/wiki/File_Transfer_Protocol">[File Transfer Protoco]</a>  was not concieved with proper encryption, hence SFTP is prefered.

In this guide i propose two different commandline linux solutions for encrypted file transfer, SFTP (recommended) and SCP (outdated / not-recommended). 

We are using scp even if it is outdated, for learning purposes.
___
### TOOLS USED ###

| Command | Description | Link | OS |
|  ---    | ---      | --      | --   |
| (not-recommended)  ```scp``` | Uses SSH for secure copy (outdated)| <a href="https://en.wikipedia.org/wiki/Secure_copy_protocol">[Secure Copy Protocol]</a> | linux |
| ```fstp``` | Uses secure channel (like SSH) for file transfering | <a href="https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol">[SSH File Transfer Protocol]</a> | linux |
| ```cp``` | copy file protocol | <a href="https://en.wikipedia.org/wiki/Cp_(Unix)">[Copy Protocol]</a> | linux |
| (not safe)```ftp``` |file transfer protocol | <a href="https://en.wikipedia.org/wiki/File_Transfer_Protocol">[File Transfer Protoco]</a> | linux |
___

### Requirements ###

Two (linux) host machines either being local🏚️ or remote🌥️ (doesn't make a difference).

[i run two seperate hosts on vmware (community/free) locally]
 
**[IPv4](https://en.wikipedia.org/wiki/IPv4) addresses (IP addresses)** of the two machines🖥️ running linux (preferrable ubuntu servers).

You can find the ip address with ```ifconfig``` look at eth0 and inet.

or 

use ```ip a``` and look for inet.
Basic knowledge of bash command line scripting and perhaps (networking).
___
#### !NETWORK SETUP! ####

On both hosts add a user1 or use another user to send recieve files.

Create a user named "user1"
```bash
adduser user1
```
switch user to "user1"
```bash
su - user1
```
___
### CODE IMPLEMENTATION ###


#### FILE TRASNFER USING SCP(outdated) ####

ON SENDING HOST
```cd``` into the /home/user1 directory
create a file using ```nano``` 
```bash
cd /home/user1
 ```
create a file using ```nano``` 
```bash
nano file.txt
 ```
add some txt
```txt
hello world
```

(not-recommended) use scp to transfer the file.txt
```bash
scp file.txt user1@<ip address>:/home/user1
```
[in my local setup] i use ipv4 address: ```172.16.196.134``` for the recieving server
```bash
scp file.txt user1@$172.16.196.134:/home/user1
```

#### Verify the result on the recieving server ####

ON RECIEVING HOST

```bash
su - user1
```
```bash
cd /home/user1/
```
check if the file.txt appears
```bash
ls 
```
```bash
nano file.txt
```

If the text matches ```hello world```, congratulations you are done✔️.


___

## Kerboros (protocol) 🦮🦮🦮
[![](https://img.youtube.com/vi/npNXXRAvMpU/maxresdefault.jpg)](https://www.youtube.com/watch?v=npNXXRAvMpU&t=524s)
AUTHENTICATION SYSTEM | CENTRALIZED MANAGEMENT | SINGLE SIGN ON (SSO)

Preventing potential threat actors from sniffing any enterprise confidential information can be handle with Kerberos, while maintaining high availability to critical to employee resources.

**[Kerberos](https://web.mit.edu/kerberos/)**  a network authentication protocol [Free], offers usability through it's Ticket Granting System/Ticket based authentication. It uses [symmetric-key cryptography](https://en.wikipedia.org/wiki/Kerberos_(protocol)) and requires a trusted third party and optionally may use public-key cryptography during certain phases of communication.

Uses UDP port 88 as default.


### Kerberos from the inside

 Use Case: End user wishes to gain access to a service supporting Kerberos (Kerberized Service).

 1. End User🖥️ uses **Kerberos client** on their system with *username* & *password*
 2. **Kerberos client** creates *authentication request* in clear text to **authentication server**
 3. **Authentication server** looks up *user* in its *database* and retrieves user's *password*
 4. **Authentication server** sends two messages back to client:
    1. **TGS session key** randomly generated session key for **Kerberos Client** and **Ticket Granting Server** [Message is encrypted using the clients *password*].
    2. **Ticket Granting Ticket** includes information about the **Kerberos Client** and a copy of the client's **TGS session key**.
   Message is encrypted with a key only known to the **ticket-granting server**.
 5. **Kerberos Client** recieves the messages:
    1. Decrypts message using the user's *password*.
    2. This provides access to the **TGS session key** [without correct password, you wont get further].
 6

---

## 🚦IMPLEMENTING KERBEROS🚦 ##

#### KERBEROS SERVER / Key Distribution Center (KDC) 🏰 ####



Open the hosts file.
```bash
sudo nano /etc/hosts
```
add
```txt
127.0.0.1 kdc.example.com
```
to the following to the ip address list so it looks something like this:
```txt
127.0.0.1 localhost
127.0.1.1 ldap
127.0.0.1 kdc.example.com
```

save the file and start installing.
```bash
sudo apt get update
sudo apt install krb5-kdc krb5-admin-server
``` 
Default Kerberos version 5 realm (realm needs to be capital letters):
```txt
EXAMPLE.COM
``` 
Kerberos servers for your realm:
 ```txt
kdc.example.com
```
 Administrative server for your Kerberos realm:      
 ```txt
kdc.example.com
```
**🛑🔐!! PROCTECT THE MASTER KEY !!🔐🛑**
to create the example.com realm run the following command
and you will be prompted to enter a master key, which is very important to store in safe manner.
```bash
sudo krb5_newrealm
```
add a user to manage centrally
```bash
sudo kadmin.local 
```
add a principal, this is what user and services are called 
```bash
addprinc simon 
```
enter a password twice and write 'exit to exit
```bash
exit
```

  edit /etc/krb5.conf file & add the following lines in [domain_realm] section
```txt
.kdc.com = kdc.example.com
kdc.com = kdc.example.com
```

#### CLIENT 🖥️ ####

```bash
sudo apt get update
sudo apt install krb5-user krb5-config
```
create a file called etc krb5.conf
```bash
dpkg-reconfigure krb5-config
```
Default Kerberos version 5 realm:
```txt
EXAMPLE.COM
```
look at the krb5.conf file and configure (based on your setup perhaps automation tools)
```bash
cat /etc/krb5.confl
```
we will edit /etc/krb5.conf file & add the following lines in [domain_realm] section
```txt
.example.com = kdc.example.com
example.com = kdc.example.com
```

**check if we can communicate with the Kerberos server /KDC** 

```bash
kinit -p simon@EXAMPLE.COM
```
list the details of the ticket with
```bash
klist
```
**Client is ready to request Ticket Granting Server**

## Configuring the system access 
We need to configure access on the system that corresponds to the Kerberos Principle.
Add a user simon
```bash
adduser simon
```
in order to let someone log in, the system needs an account for them to use.
Kerberos should handle the authentication/password and the activation of the user's account on that machine. The kerberos user will map onto the local user when they log in.
[PAM](https://en.wikipedia.org/wiki/Linux_PAM) support is added for our Kerberized user:
```bash
sudo apt install libpam-krb5.
```
see and control the inclusion of Kerboros in the PAM files:
```bash
grep krb /etc/pam.d/*
```
**Log in as Kerberized user**

Sign in again to the host/virtual machine, switch to a new console.
After signing in use:
```bash
klist
```
verify you get information about the Kerberos Ticket:
```bash

```
#### PROTECTED SERVER 📭 ####

```bash
sudo apt install krb5 config
```

Edit ***/etc/ssh/sshd_config***

add ***yes*** to following lines:

```txt
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
```

```bash
restart!!!
```

### KERBEROS SERVER 🏰 ###

  add the ssh server to the kerberos management
  add principal 
  creat a key file
```bash
ktadd  k /tmp/sshserver.kea.dk.keytab
host/sshserver.kea.dk
```
  copy the keyfile to the ssh server /etc directory

```bash
```

### CLIENT 🖥️ ###

  get the ticket from the kerberos server
```bash
kinit root/admin
klist  A 
```


### SUMMARY OF SETUP ###

  install both kerberos server packages on kerboros server
  install kerberos client package
    add get a a ticket for the user that will login remotely
  on ssh server [protected server] 
    install krb5 


___
# CRYPTOGRAPHY #


## 📖 CRYPTOLOGY: HASHING WEAKNESS


Sources:
<p>  <a href="https://www.rfc editor.org/rfc/rfc8554.html">RFC 8554 </a> </p>

<p> <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function"> wikipedia. </a></p>

### 3 Weaknesses of Hashing ###



The hashing function must be deterministic in it's output given an input of arbritary size. 
This is the way hashing is used to encode data for more effcient memory utilization.

This is useful, but not the primer goal of hashing in cryptography.

While providing the effectiveness of hashing algorithm's ability to obfuscate information, like password storage in databases, many algorithms have proven to be weak to certain types of attacks.

Therefore, as always, we must carefully research and evalutate any security methodes, before bringing them to production environment.
According to <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function"> wikipedia <a> the following conditions are met in a secure hash function and it's corresponding output, such as SHA 3 and Argon2.

```
Pre image resistance
Given a hash value h, it should be difficult to find any message m such that h = hash(m). This concept is related to that of a one way function. Functions that lack this property are vulnerable to preimage attacks.
```
```
Second pre image resistance
Given an input m1, it should be difficult to find a different input m2 such that hash(m1) = hash(m2). This property is sometimes referred to as weak collision resistance. Functions that lack this property are vulnerable to second preimage attacks.
```
```
Collision resistance
It should be difficult to find two different messages m1 and m2 such that hash(m1) = hash(m2). Such a pair is called a cryptographic hash collision. This property is sometimes referred to as strong collision resistance. It requires a hash value at least twice as long as that required for pre image resistance; otherwise, collisions may be found by a birthday attack.
```

Attack vectors against hashes (output of the hash functions) count, birthday attacks, preimage attack, second preimage attack.

#### Security / Computational Speed Tradeoff ###

| HASH FUNCTION | SECURITY | SPEED 
| ------        | ------- |  ----- |
| SHA 1         | NOT SECURE | FAST |
| SHA 2         | HIGH    | FAST |
| SHA 3         |  HIGHEST | FAST |
| Argon2         | HIGEHST | SLOW | 
| SHA 256         | HIGH | FAST |
| SHA 512         | VERY HIGH | FAST | 

#### Tools used: ####


| Name | Description | OS |
| ---     | ---            | --   |
| hash identifier | Identifies hash function algorithm based on an output/digest | Linux | 
| <a href="https://gchq.github.io/CyberChef/#input=SGVsbG8gd29ybGQ">Cyber Chef </a> | Online tool for calculating outputs/digests with all major cryptology algorithms | webbrowser |
| John The Ripper | Password cracking tool | Linux |
| Hash Cat | | Linux |




#### Birthday attack ####

Relates to the property, collision resistance. Given the output value, it should be extremely hard to calculate another input value. 

In the case of SHA 256, the security from birthday attacks is given by the 50% of hashing the same output given two distinct hash inputs.

SHA 256 algorithm output birthday attack security level is 2^(256/2) = 2^128 different inputs needed to collide with an existing hash output.

The security level against brithday attacks withing the SHA 1 algorithm output of 160 bits (not secure) is 2^(160/2) = 2^80 different inputs needed to collide with an existing hash output hashed with the same algorithm (SHA 1 of 160 bits).

#### Use Key Derivative Functions for password storage ####

Attackers can download a database of hashed password and attempt to crack the password by comparing salts from already known passwords, and thereby obtain access to matching passwords accounts.

Salting can to some extend prevent attackers success by adding an extra entry/element together with the hashed password. 

***Best practice*** is to couple salting with a Key Derivative Function.

***KDF's, take a key, salt, iterations as inputs.***
The goal is to slow down the process of attempts to bruteforce or use dictionary attakcs to obtain the password or passphrase of a victim.

[![](https://img.youtube.com/vi/mUH5ffD5X5Q/maxresdefault.jpg)](https://www.youtube.com/watch?v=mUH5ffD5X5Q)








   

## 📖 SYMMETRIC ENCRYPTION WEAKNESSES

Sources:

Jon, Hacking The art of exploitation

### Block Ciphers

Hiding relationships between plaintext, ciphertext and the key, are methodes performed by the algorithm to ensure the highest level of security of block ciphers. 

[![](https://img.youtube.com/vi/BwKS_yTj08M/maxresdefault.jpg)](https://www.youtube.com/watch?v=BwKS_yTj08M)

## 📖 HYBRID ENCRYPTION : DIFFIE-HELLMANN (MERKLE)


[![](https://img.youtube.com/vi/9FyBmtdMRiE/maxresdefault.jpg)](https://www.youtube.com/watch?v=9FyBmtdMRiE&t=50s)


## 📖 HYBRID ENCRYPTION : TLS HANDSHAKE


[![](https://img.youtube.com/vi/9FyBmtdMRiE/maxresdefault.jpg)](https://www.youtube.com/watch?v=9FyBmtdMRiE?&t=266s)
