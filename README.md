# **30-Days SOC Challenge**

### **Day 1: Building a Network Architecture Diagram**

To kick off the challenge, I used **Draw.io** to design a logical network diagram for our SOC environment. This setup consists of six key servers:

- **Elastic & Kibana**: For centralized logging and visualization.
- **Windows Server**: With RDP enabled for remote desktop access.
- **Ubuntu Server**: With SSH enabled for secure management.
- **Fleet Server**: To manage agents across the network.
- **OS Ticket Server**: For ticketing and incident management.
- **C2 Server**: Running Mythic for command and control operations.

Our cloud infrastructure will be hosted on **VULTR**, with all servers residing within a **Virtual Private Cloud (VPC)** to maintain a secure, private network. 

I also added an **Internet Gateway** symbol to represent our connection to the broader internet via our Internet Service Provider (ISP).

The attacker's machine will run **Kali Linux**, serving as the platform for testing attacks on our SOC environment. The **C2 Server** will use **Mythic** to simulate adversarial command and control.

![Logical Diagram](https://github.com/user-attachments/assets/51a620c1-a44b-46d9-8705-c76211eb8fa4)

### **Day 2: Introduction to the Elastic Stack**

The **Elastic Stack**—commonly referred to as the **ELK Stack**—consists of three core components that work together to ingest, process, store, and visualize data:

- **Logstash**: Handles data ingestion. Acting as a pipeline, Logstash pulls data from various sources, processes it using filter plugins, and sends it to the desired destination, typically Elasticsearch. It transforms raw logs into structured data for more effective analysis.
  
- **Elasticsearch**: The heart of the stack. Elasticsearch is a highly scalable search and analytics engine that stores and indexes the processed data. It enables powerful querying, searching, and real-time analysis, making it ideal for managing large datasets.

- **Kibana**: The visualization tool for the stack. Kibana offers an intuitive web interface where users can interact with the data stored in Elasticsearch. You can build detailed dashboards, perform real-time analysis, and generate insightful reports.

When properly integrated, these components provide a comprehensive platform for managing, analyzing, and visualizing log data—a critical asset for cybersecurity operations.

#### **Comparing ELK Stack to Splunk**
- **Elasticsearch** is equivalent to **Splunk's Indexer/Search Head**.
- **Logstash** functions similarly to the **Heavy Forwarder** in Splunk.
- **Kibana** serves as the **Web GUI**.
- **Beats/Agents** can be likened to Splunk’s **Universal Forwarder**.

### **Day 3: Elasticsearch Setup**

Today, I set up Elasticsearch on a cloud instance to continue building my SOC lab.

1. **Vultr Configuration**  
   I started by creating a new account on **Vultr**. Under the *Products* section, I navigated to *Network* and selected **VPC 2.0**. For the IP range, I configured it to match the one from my logical diagram.  
   ![VPC Configuration](https://github.com/user-attachments/assets/7775f919-f691-4c03-a46b-37790deb9020)

2. **Deploying Elasticsearch Server**  
   I deployed a new server for **Elasticsearch**, choosing **Ubuntu 22.04** as the base image and allocating **80GB** of storage. After setting it up, I used my **Kali VM** to SSH into the server.  
   ![SSH Into Elasticsearch Server](https://github.com/user-attachments/assets/f5649bbd-778f-4586-87ec-0f56363854d8)

3. **Installing Elasticsearch**  
   In the terminal, I searched for the **Elasticsearch** package for the **debx86** platform and used the `wget` command to download it.  
   ![Wget Command for Elasticsearch](https://github.com/user-attachments/assets/0fc9299a-ffda-4376-9f58-c920891f5d51)

   To install it, I ran the command:  
   ```bash
   dpkg -i elasticsearch-8.15.0-amd64.deb
   ```

4. **Network Configuration**  
   I opened a **nano** file and stored the **Elasticsearch** password for future use. To configure the network, I typed `ip a` to get the server’s IP address and then modified the **elasticsearch.yml** file. I set the `network.host` to the server's IP and uncommented the `http.port` line to ensure proper configuration.  
   ![Network Configuration](https://github.com/user-attachments/assets/a04e1c99-fc54-4eb6-8f58-06c559c79592)

5. **Firewall Setup**  
   I added a **firewall rule** in Vultr to only allow my IP address to SSH into the Elasticsearch server, ensuring security for remote access.

6. **Issue and Resolution**  
While configuring **Elasticsearch**, I encountered the following error when trying to start the service:

```bash
java.net.UnknownHostException: 45.76.64.199/23: Name or service not known
```

This error occurred because **Elasticsearch** was trying to bind to the IP address `45.76.64.199/23`, which includes `/23` — a **CIDR (Classless Inter-Domain Routing)** notation that represents a subnet. 

**Elasticsearch** doesn't expect CIDR notation in the `network.host` setting because it's looking for a single IP address, not a range of addresses. The `/23` essentially tells Elasticsearch to interpret the IP as part of a larger network, which isn't appropriate for this setting.

To fix the issue, I removed the `/23` from the IP address, leaving just the single IP (`45.76.64.199`). This allowed Elasticsearch to bind to the correct network interface and start successfully.

**DAY 4: KIBANA SETUP**

1. **Downloading Kibana:**
   I visited the official Elastic website and copied the download link for the **Kibana** `Debx86_64` package, and pasted the link to the terminal to download it.
   ![image](https://github.com/user-attachments/assets/273becb8-b553-4faa-99f2-99bd9876ba15)

2. **Configuring Kibana:**
   After downloading, I opened the `kibana.yml` configuration file and made the following changes:
   - **Server Port**: Confirmed the default Kibana port (`5601`).
   - **Server Host**: Set this to the public IP address of the VULTR virtual machine to allow external access.

3. **Starting Kibana Service:**
   I started the Kibana service and verified its status to ensure it was running correctly.
   ![image](https://github.com/user-attachments/assets/a3ed1893-d928-46ac-8bad-96ae1b2a8add)

4. **Creating Enrollment Token:**
   To connect Kibana to **Elasticsearch**, I needed to create an enrollment token. I navigated to the **Elasticsearch bin directory** with:
   ```bash
   cd /usr/share/elasticsearch/bin
   ```
   Then, I generated the token using the following command:
   ```bash
   ./elasticsearch-create-enrollment-token --scope kibana
   ```

5. **Accessing Kibana in the Browser:**
   I tried to access the Kibana web interface by typing `http://<VM-Public-IP>:5601` in my browser. However, I couldn't connect because the firewall was configured to allow **SSH connections only**, and I was trying to access port 5601.

6. **Updating Firewall Rules:**
   To resolve the issue, I updated the firewall rules on **VULTR** to allow any **TCP connections (ports 1-65535)** from my SOC analyst workstation to the VM.  
   
   Additionally, I needed to allow port 5601 on the Ubuntu server itself. I ran the following command on my terminal:
   ```bash
   ufw allow 5601
   ```

7. **Logging in to Kibana:**
   After updating the firewall rules, I could access the Kibana web interface. I pasted the previously generated **enrollment token**, and Kibana prompted me for a verification code. To obtain it, I ran the following command:
   ```bash
   cd /usr/share/kibana/bin
   ./kibana-verification-code
   ```
   ![image](https://github.com/user-attachments/assets/8410f44c-248a-4572-9031-e45725172b1f)

8. **Logging In:**
   Kibana then asked for my username and password. I retrieved these credentials from the file where I had saved the **Elasticsearch security configuration** details. Once logged in, I navigated to **Security → Alerts**.
   ![image](https://github.com/user-attachments/assets/04585c90-5d4a-4409-a5d3-cee4cdb3940f)

9. **Generating Encryption Keys:**
   To enhance security, I generated encryption keys for Kibana using the following command: Here’s how you can include the command:
    ```bash
    ./kibana-encryption-keys generate
    ```

    This ensured that Kibana had the necessary encryption keys for secure communication.
    ![image](https://github.com/user-attachments/assets/e173e987-d683-4d98-8801-cfc4afa30b60)

10. **Restarting Kibana:**
    After adding the encryption keys to the configuration, I restarted the Kibana service. 
    ![image](https://github.com/user-attachments/assets/68d1f2dd-77ef-420b-972b-86068b2b2fdc)
    The **Security Alerts** section no longer displayed any warning messages. 
    ![image](https://github.com/user-attachments/assets/d55fbfcc-62b3-451b-ac5e-777679d883e1)


**DAY 5: WINDOWS SERVER 2022 INSTALLATION**

I began by deploying a new server, selecting "Cloud Compute - Shared CPU" for the deployment options. I chose the same city as my Elastic server and selected the "Windows Standard 2022" image.

To enhance security, I updated my logical diagram to ensure that the Windows server and the Ubuntu server are outside of the Virtual Private Cloud (VPC). This segregation was implemented to prevent attackers from accessing critical servers like the Fleet Server, Elastic & Kibana, or the OS Ticket system in case these servers were compromised.

![Updated Diagram](https://github.com/user-attachments/assets/088aec71-37be-49ea-a4b2-32a131ebb6bb)

I disabled IPv6 and opted out of Virtual Private Cloud 2.0 to ensure that the Windows server was not included in the VPC. By leaving the firewall group blank, I allowed unrestricted access to the server for this deployment.

![Windows Server Deployment](https://github.com/user-attachments/assets/c4bcb25d-b441-456a-97d5-374bb34f42a9)

**DAY 6: ELASTIC AGENT AND FLEET SERVER INTRODUCTION**

**Elastic Agent**: The Elastic Agent is a unified, lightweight software tool that can be installed on servers, VMs, or containers to collect and send data to the Elastic Stack. It merges the functionalities of multiple agents, such as Filebeat, Metricbeat, and Packetbeat, into a single agent. This consolidation simplifies deployment and management. Elastic Agent is used to collect logs, metrics, and security data, and it also performs endpoint security tasks, such as malware detection and threat analysis.

**Fleet Server**: Fleet Server is a component responsible for managing and coordinating communication between Elastic Agents and the Elastic Stack. It serves as a central hub for enrolling, configuring, and monitoring Elastic Agents in real time. Fleet Server facilitates large-scale deployments of Elastic Agents, ensuring proper management and monitoring. It simplifies scaling, configuration management, and agent activity monitoring.

**DAY 7: ELASTIC AGENT AND FLEET SERVER SETUP**
I clicked on deploy new server, and selected the same city again. For the image I selected Ubuntu 22.04. I selected VPC 2.0 and connected it to the VPC network I created earlier.
Went to the elastic website and selected fleet under management.
Clicked odn add Fleet Server and then clicked on Quick Start
FOr the host URL i put https://the public IP of the Fleet Server
<img width="1415" alt="image" src="https://github.com/user-attachments/assets/1d7c872e-7fd4-4927-b699-ca48a66601ed">
I then sshed into the fleet server. I updated my repositories with the command: 'apt-get update && apt-get upgrade -y'
I went back to the elastic webpage and copied the installation and pasted it to the Fleet server's terminal inoreder to install the agent.
<img width="1503" alt="image" src="https://github.com/user-attachments/assets/e0a71fcb-4884-44e0-b269-430ba2cf7c2c">
I modified the ELK server firewall to allow the Fleet server to communicate with the ELK server. I added the fleet server's public IP address to the firewall rules.
On the terminal for the ELK server I set the firewall to allow port 9200 because that's the port  elasticsearch listens on by default.
<img width="635" alt="image" src="https://github.com/user-attachments/assets/a8e3f679-b6a8-48a4-a308-2586f9c05fdf">

After succesful installation, I went back to the elastic website the fleet server was successfully connected. I clicked on continue enrolling elastic Agent. I created a policy named 'SOC-Windows-Policy" and selected and copied the Windows installation that I would install on the Windows server.
<img width="903" alt="image" src="https://github.com/user-attachments/assets/b0cd1e6b-6193-4553-955d-57edba91494b">
I opened powershell and pasted the installetion 
<img width="1053" alt="image" src="https://github.com/user-attachments/assets/e74cd772-d343-4fc2-8da5-0ac50bc6ba91">

The installation failed because of a firewall rule. i wen to my fleet server terminal and allowed port 8220: ufw allow 8220
I got an error agian and saw that my agent was trying to access port 443, so i added 443 to the firewall.

I got an errror againand after troubleshooting I went to the elastic server and realized that it was set to use port 443 instead of 8220. so I changed it to 8220 and waited to see.
<img width="1511" alt="image" src="https://github.com/user-attachments/assets/dab4cfaf-6a88-46fc-a19e-8155f947367e">

I reran the command again but I changed the port number to 8220 and put --insecure at the end because I didn't have a certificate authority. It worked and the agent successfully installed.
<img width="1359" alt="image" src="https://github.com/user-attachments/assets/a371ac1e-d5e4-4389-a66d-56b31c99044b">
I went back to the elastic web page and saw that the Windows server successfully enrolled into our fleet.
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/cfc518ac-0e8c-4958-b8dd-61c771d8a8d0">
I clicked on discover and saw that there were some logs
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/a9c00ba0-90f2-4982-89b9-ecf532476b4f">










