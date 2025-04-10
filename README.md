# SIMON'S ✍️ CYBER SECURITY NOTES





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

#### KERBEROS SERVER / Key Distribution Center (kdc) 🏰 ####

Open the hosts file.
```bash
nano /etc/hosts
```
add the following to the ip address list.
```txt
127.0.0.1      kdc.example.com
``` 
Then start installing.
```bash
sudo apt get update
sudo apt install krb5-admin-server krb5 kdc
``` 
Configure Package configuration using 

  [CRITICAL] 🔐!! PROCTECT THE PASSWORD !!🔐
```bash
sudo krb5_newrealm
```
  Default kerberos realm [upper case]:
```txt
KERBEROS.[YOUR COMPANY NAME].COM
```
  Kerberos server [lower case]:
```txt
kerberos.[your company name].com
```
  Administrative server [lower case]:
 ```txt
kerberos.[your company name].com
```

  edit /etc/krb5.conf file & add the following lines in [domain_realm] section
```txt
.kerberos.[your company name].com = KERBEROS.[your company name].com
kerberos.[your company name].com = KERBEROS.[your company name].com
```

#### CLIENT 🖥️ ####

```bash
sudo apt get update
sudo apt install krb5 user
```

**Try Pinging Servers**

```bash

```

**Client is ready to request Ticket Granting Server**


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
|      |             |    |
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
