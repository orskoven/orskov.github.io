___

## 📖 CRYPTOLOGY: HASHING WEAKNESS


Sources:
<p>  <a href="https://www.rfc-editor.org/rfc/rfc8554.html">RFC-8554 </a> </p>

<p> <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function"> wikipedia. </a></p>

### 3 Weaknesses of Hashing ###



The hashing function must be deterministic in it's output given an input of arbritary size. 
This is the way hashing is used to encode data for more effcient memory utilization.

This is useful, but not the primer goal of hashing in cryptography.

While providing the effectiveness of hashing algorithm's ability to obfuscate information, like password storage in databases, many algorithms have proven to be weak to certain types of attacks.

Therefore, as always, we must carefully research and evalutate any security methodes, before bringing them to production environment.
According to <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function"> wikipedia <a> the following conditions are met in a secure hash function and it's corresponding output, such as SHA-3 and Argon2.

```
Pre-image resistance
Given a hash value h, it should be difficult to find any message m such that h = hash(m). This concept is related to that of a one-way function. Functions that lack this property are vulnerable to preimage attacks.
```
```
Second pre-image resistance
Given an input m1, it should be difficult to find a different input m2 such that hash(m1) = hash(m2). This property is sometimes referred to as weak collision resistance. Functions that lack this property are vulnerable to second-preimage attacks.
```
```
Collision resistance
It should be difficult to find two different messages m1 and m2 such that hash(m1) = hash(m2). Such a pair is called a cryptographic hash collision. This property is sometimes referred to as strong collision resistance. It requires a hash value at least twice as long as that required for pre-image resistance; otherwise, collisions may be found by a birthday attack.
```

Attack vectors against hashes (output of the hash functions) count, birthday attacks, preimage-attack, second-preimage attack.

#### Security / Computational Speed Tradeoff ###
___
| HASH FUNCTION | SECURITY | SPEED | 
|-------------- | -------- | ----- |
| SHA-1         | NOT SECURE | FAST |
| SHA-2         | HIGH| FAST |
| SHA-3         |  HIGHEST | FAST |
| Argon2         | HIGEHST | SLOW | 
| SHA-256         | HIGH | FAST |
| SHA-512         | VERY HIGH | FAST | 

#### Tools used: ####


| Name | Description | OS |
| ---- | ----------- | -- |
| hash-identifier | Identifies hash function algorithm based on an output/digest | Linux | 
| <a href="https://gchq.github.io/CyberChef/#input=SGVsbG8gd29ybGQ">Cyber Chef </a> | Online tool for calculating outputs/digests with all major cryptology algorithms | webbrowser |
| John The Ripper | Password cracking tool | Linux |
| Hash Cat | | Linux |




#### Birthday attack ####

Relates to the property, collision resistance. Given the output value, it should be extremely hard to calculate another input value. 

In the case of SHA-256, the security from birthday attacks is given by the 50% of hashing the same output given two distinct hash inputs.

SHA-256 algorithm output birthday attack security level is 2^(256/2) = 2^128 different inputs needed to collide with an existing hash output.

The security level against brithday attacks withing the SHA-1 algorithm output of 160 bits (not secure) is 2^(160/2) = 2^80 different inputs needed to collide with an existing hash output hashed with the same algorithm (SHA-1 of 160 bits).

#### Use Key Derivative Functions ####

Attackers can download a database of hashed password and attempt to crack the password by comparing salts from already known passwords, and thereby obtain access to matching passwords accounts.

Salting can to some extend prevent attackers success by adding an extra entry/element together with the hashed password. 

***Best practice*** is to couple salting with a Key Derivative Function.

***KDF's, take a key, salt, iterations as inputs.***
The goal is to slow down the process of attempts to bruteforce or use dictionary attakcs to obtain the password or passphrase of a victim.










---

## 📖 SYMMETRIC ENCRYPTION WEAKNESSES

Sources:

Jon, Hacking The art of exploitation

### Block Ciphers

Hiding relationships between plaintext, ciphertext and the key, are methodes performed by the algorithm to ensure the highest level of security of block ciphers. 





### Key Derivative Function (KDF)

KDFs are applied to symmetric encryption 
