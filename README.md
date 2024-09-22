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

1. **Deploying the Fleet Server**  
   I clicked on "Deploy New Server" and selected the same city as my previous setup. For the image, I chose Ubuntu 22.04, and connected it to the VPC network I created earlier using VPC 2.0.

2. **Fleet Server Setup**  
   In the Elastic Management Console, I navigated to **Fleet** under **Management**. I clicked on **Add Fleet Server** and selected **Quick Start**.  
   For the **Host URL**, I used the public IP of the Fleet Server.  

   ![Fleet Server Setup](https://github.com/user-attachments/assets/1d7c872e-7fd4-4927-b699-ca48a66601ed)

3. **SSH into the Fleet Server**  
   I SSHed into the Fleet Server and updated the system by running:  
   ```bash
   apt-get update && apt-get upgrade -y
   ```  
   After updating, I went back to the Elastic webpage, copied the installation command for the Elastic Agent, and pasted it into the Fleet Server terminal to begin the installation.

   ![Elastic Agent Installation](https://github.com/user-attachments/assets/e0a71fcb-4884-44e0-b269-430ba2cf7c2c)

4. **Configuring Firewall Rules**  
   To allow the Fleet Server to communicate with the ELK server, I modified the ELK server firewall by adding the Fleet Server's public IP address. I also allowed port **9200**, as it’s the default port for Elasticsearch.
   ![Firewall Configuration](https://github.com/user-attachments/assets/a8e3f679-b6a8-48a4-a308-2586f9c05fdf)

5. **Fleet Server Connected**  
   After successfully installing, I returned to the Elastic webpage and confirmed that the Fleet Server was connected. I clicked **Continue** to begin enrolling the Elastic Agent. I then created a policy named **SOC-Windows-Policy** and copied the Windows installation command for later use on the Windows Server.

   ![Fleet Server Connected](https://github.com/user-attachments/assets/b0cd1e6b-6193-4553-955d-57edba91494b)

6. **Elastic Agent Installation on Windows Server**  
   I opened PowerShell on the Windows server and pasted the installation command, but the installation failed due to a firewall rule. To fix this, I allowed port **8220** on the Fleet Server:  

   ```bash
   ufw allow 8220
   ```

7. **Troubleshooting and Resolution**  
   I encountered another error related to port **443**. After inspecting the Fleet Server, I realized that it was set to use **port 443** instead of **8220**, so I corrected the configuration.

   I reran the command  on Powershell, this time changing the port to **8220** and adding the `--insecure` flag, as I didn't have a certificate authority. The agent was installed successfully.
   ![Elastic Agent Installation Successful](https://github.com/user-attachments/assets/a371ac1e-d5e4-4389-a66d-56b31c99044b)

8. **Final Verification**  
   After installation, I returned to the Elastic console and confirmed that the Windows Server was successfully enrolled into the fleet.

   ![Windows Server Enrolled](https://github.com/user-attachments/assets/cfc518ac-0e8c-4958-b8dd-61c771d8a8d0)

9. **Viewing Logs in Discover**  
   I clicked on **Discover** in the Elastic console and confirmed that logs were being successfully collected from the Windows Server.

   ![Logs in Discover](https://github.com/user-attachments/assets/a9c00ba0-90f2-4982-89b9-ecf532476b4f)

**DAY 8: WHAT IS SYSMON?**

On Windows endpoints, logging is enabled by default, but the built-in log settings often lack the depth required for effective monitoring in security operations. **Sysmon** (System Monitor) is a free, powerful tool from Microsoft that enhances the default logging capabilities and provides detailed information about various system activities.

### What Sysmon Monitors:
- **Process Creation (Event ID 1)**: Logs whenever a process is created. This includes information such as process name, process ID (PID), and the user account that executed the process.
- **Network Connections (Event ID 3)**: Captures network connection details, including source IP, destination IP, source port, destination port, and the process involved in making the connection. This is extremely useful for network forensics and tracing back malicious connections to a specific process.
- **File Creations**: Logs whenever new files are created on the system, helping to detect unauthorized file modifications or malware installations.
- **Hashes of Executables**: Sysmon can generate cryptographic hashes of executables, which can be valuable for OSINT (Open-Source Intelligence) and comparing files against known malicious software.
  
### Process GUID and Event Correlation:
Each process logged by Sysmon is assigned a **Process GUID** (Globally Unique Identifier), which remains consistent across multiple events related to the same process. This allows analysts to easily correlate different logs, even if the process ID changes (which happens when a process terminates and a new one starts).

### Additional Sysmon Events:
- **Event ID 6**: Captures driver loading, useful for identifying potentially malicious drivers loaded onto the system.
- **Event ID 7**: Logs image loading, providing insight into libraries and DLLs being loaded by processes.
- **Event ID 8**: Detects the creation of remote thread injections, which could indicate malicious code injection techniques used by attackers.
- **Event ID 10**: Identifies process access, which logs when one process gains access to another (often a sign of malicious activity such as privilege escalation).
- **Event ID 22**: Logs DNS queries, which can reveal suspicious domain lookups and potential command-and-control (C2) activity, crucial for threat detection involving malware or phishing attempts.


### **Day 9: Sysmon Setup**

 I set up **Sysmon** (v15.5) on my Windows server to improve system monitoring capabilities. Below are the steps I followed:

1. **Accessing the Server**:  
   I used **RDP** to connect to the Windows Server.

2. **Downloading Sysmon**:  
   Opened **Microsoft Edge**, searched for "Sysmon," and downloaded the latest version (**v15.5**) from the official Sysinternals page.
   ![Download Sysmon](https://github.com/user-attachments/assets/41a01ca4-c4c3-4cf1-84ea-e662ce737243)

3. **Extracting Sysmon**:  
   After downloading, I located the zip file, right-clicked on it, and selected **Extract All** to unpack the files.
   ![Extract Sysmon](https://github.com/user-attachments/assets/ae05211b-fadb-4c71-abe6-a3eac62ea5a7)

4. **Downloading the Sysmon Configuration File**:  
   I navigated to the **Sysmon Olaf Configuration File** repository on GitHub, saved the file as raw, and placed it in the Sysmon folder.

5. **Installing Sysmon**:  
   I opened **PowerShell as an Administrator**, navigated to the folder where the Sysmon configuration file was saved, and ran the following commands to install Sysmon and apply the configuration:
   ```powershell
   .\Sysmon64.exe
   .\Sysmon64.exe -i sysmonconfig.xml
   ```

6. **Verifying Sysmon Installation**:  
   I checked **Services** to confirm Sysmon was active and opened **Event Viewer** to verify that Sysmon logs were being generated.
   ![Sysmon Logs in Event Viewer](https://github.com/user-attachments/assets/764a3358-f39d-4814-884b-2d79c2985f06)


### **Day 10: Ingesting Data With Elasticsearch**

1. **Custom Windows Event Logs Integration:**
   - Navigated to the Elasticsearch homepage and clicked on 'Add integrations.'
   - Selected 'Custom Windows Event Logs' and added the integration.
   - For the channel name, I used `Microsoft-Windows-Sysmon/Operational`, which I identified by opening the Window's Server Event Viewer, navigating to Sysmon, right-clicking on 'Operational,' and selecting 'Properties.'
     ![Sysmon Channel](https://github.com/user-attachments/assets/866c4715-629c-4d51-9a06-2ee9b9fd3782)
   - Assigned this integration to the previously created Agent policy: `SOC-Windows-policy 1`
   - Clicked 'Save and Continue,' then `Save and Deploy`.

2. **Defender Logs Integration:**
   - Created another integration for Windows Defender Logs.
   - Found the channel name by going to the Event Viewer, selecting `Windows Defender,`. right-clicking `Operational,` and clicking on `Properties`.
     ![Defender Logs Channel](https://github.com/user-attachments/assets/4ca2f9ba-bab9-4699-8779-338fd306af31)
   - To limit the number of informational logs, I chose the following event IDs: 116, 117, 5001. In the advanced settings, I entered these event IDs and added the integration to the 'SOC-Windows-policy 1.'
   - Saved and deployed the changes.
     ![Event IDs Configuration](https://github.com/user-attachments/assets/4dc88d3c-809f-488b-bdb4-d75740499bae)

3. **Troubleshooting and Verification:**
   - Initially, I could not see any Sysmon logs under the 'Discover' tab in Elasticsearch.
   - I Restarted the Elastic Agent service on the Windows Server.
   - Adjusted the firewall settings to allow traffic on port 9200.
   - After making these adjustments, I was able to see Sysmon logs in Elasticsearch.
     ![Sysmon Logs](https://github.com/user-attachments/assets/6a18caeb-5be2-4428-a183-f3b35b2ee641)

### **Day 11: Brute Force Attack**
A **Brute Force Attack** is a trial-and-error method used by attackers to guess login credentials or encryption keys by systematically trying every possible combination until the correct one is found. This attack is commonly used when weak passwords or limited security measures are in place, exploiting the vast number of potential guesses. Although time-consuming and resource-intensive, brute force attacks can be successful against systems with inadequate protection, making strong passwords and account lockout mechanisms essential defense measures.

### **Day 12: Ubuntu Server 24.04 Installation**
I clicked on `Deploy New Server` and chose a `cloud compute-shared CPU` since I didn’t need a powerful server. I selected the same city as the other servers and chose Ubuntu 24.04 as the image. I left the server settings as default.

Once the server was running, I used a Linux VM to SSH into it. I updated the server from the terminal and checked the `auth.log` file to see if there were any failed logins, but since I had just opened the server, nothing was there. I ran the command `grep -i failed auth.log`, and nothing showed up.  
![image](https://github.com/user-attachments/assets/5c19fa18-57a9-4fe7-bef3-227b6b1df262)

After waiting 45 minutes, I ran the command again, and this time, there were several failed logins.  
![image](https://github.com/user-attachments/assets/006c1b27-b4a4-42f3-a489-fdaeb8d7d409)

I wanted to filter the output to only display the IP addresses of users attempting to use the root command. Since the IP address was the 9th delimiter, I used the command `grep -i failed auth.log | grep -i root | cut -d ' ' -f 9`to extract it.  
![image](https://github.com/user-attachments/assets/790964cb-ca35-48f4-8b83-6248b6066229)
All the attempts seemed to come from the same IP address. 


### **Day 13: Installing Elastic Agent on Ubuntu**
I navigated to the Fleet section of Elastic, created a new agent policy named `Ubuntu-SSH-Policy`, and selected it.

Next, I went back to Fleet, clicked on `Add Agent`, selected the `Ubuntu-SSH-Policy`, and clicked on `Enroll in Fleet`. I chose `Linux Tar` for installation and copied the command.  
![image](https://github.com/user-attachments/assets/739eb0f9-789f-4d19-978b-89362de600e0)

After running the command on the Ubuntu terminal, I encountered the following error:  
`Error: fail to enroll: fail to execute request to fleet-server: x509: certificate signed by unknown authority`.  
To resolve this, I added `--insecure` to the command, since I didn’t have a self-signed certificate.

After rerunning the command, the agent successfully enrolled.  
![image](https://github.com/user-attachments/assets/76ba3fc7-bf17-4743-96d4-8359feee7b73)

I then went to the `Discover` section in Elastic, and the Ubuntu server appeared under the list of agents.

Returning to the Ubuntu terminal, I checked the `auth.log` file again and noticed a new IP address with failed login attempts. I copied the IP address with the most failed attempts and pasted it into Elastic.  
![image](https://github.com/user-attachments/assets/390e0546-bb63-4ed4-bc48-47e1d662ac0b)  
There were 177 events showing authentication failures from this IP address.

### **Day 14: Creating Alerts and Dashboards in Kibana**
In Elastic, I clicked on `Discover`, filtered the results to show only the Ubuntu server agent, and added `system.auth.ssh.event`, `user.name`, and `source.ip` as columns. I filtered the results to display only failed attempts and saved it as `SSH failed activity`.  
![image](https://github.com/user-attachments/assets/2887306e-e551-42f8-8a0f-1c433fa730b5)

I created a new rule from this search query and named it `SSH Brute Force Activity`. I configured the rule to alert me if there were 5 failed login attempts within 5 minutes. Though not perfect, it served as a basic test for the lab.  
![image](https://github.com/user-attachments/assets/92abdf6e-e4b9-44ed-8f9f-8eea9ab9937c)

Next, I went to the `Maps` section and typed the following into the search:  
`system.auth.ssh.event:*` and `agent.name:"Ubuntu-SSH-Server"` and `system.auth.ssh.event:"Failed"`

I clicked `Add Layer`, selected `Choropleth`, chose `Administrative Boundaries`, and then under EMS, selected `World Countries`. For the data view, I used the query we had just defined.  
![image](https://github.com/user-attachments/assets/5dae236f-99cd-4c68-a49b-109fbf6b8e0b)

I saved this visualization as `SSH Failed Authentications Network Map` and added it to a new dashboard.  
![image](https://github.com/user-attachments/assets/110171e9-e254-4564-9eb6-3b878186fbd2)

I duplicated the map, modified the query to show both `failed` and  `accepted` attempts.
![image](https://github.com/user-attachments/assets/669422bd-237b-4f5e-ad63-ea4610e96294)

### **Day 15: Remote Desktop Protocol (RDP)**

**Overview:**
Remote Desktop Protocol (RDP) is a widely used tool that allows users to remotely connect to and control systems over a network. While it provides convenience for administrators and users working offsite, RDP can be a major security risk if not properly secured. If attackers gain access through RDP, they can exploit it to steal credentials (known as credential dumping) and move laterally across the network, compromising other systems. This makes RDP a significant attack vector, especially when it's exposed to the internet without adequate protection.

**Identifying Open RDP Ports:**
Tools like **Shodan** and **Censys** allow you to search for open RDP ports (3389) and identify exposed systems. If you find an open RDP port in your organization, evaluate if it's necessary. If not, **disable RDP**. If needed, ensure it's behind a firewall and accessible only via a **VPN**.

**Protecting Against Unauthorized RDP Access:**
To secure RDP, follow these best practices:
1. **Turn off RDP** when not in use.
2. **Use Multi-Factor Authentication (MFA)** for an added layer of security.
3. **Restrict access** by limiting RDP to specific IP addresses.
4. **Strengthen passwords** and use **Privileged Access Management (PAM)** to monitor sessions.
5. **Disable or rename default accounts** like Administrator to prevent easy exploitation.

These steps will help secure your network from RDP-based attacks.


### **Day 16: Creating Alerts and Dashboards in Kibana**

Today, I focused on setting up alerts and dashboards in Kibana to monitor failed login attempts, particularly through Remote Desktop Protocol (RDP) and Secure Shell (SSH) brute force attempts.

To start, I navigated to Elastic's "Discover" section, selected `agent.name`, and filtered for my Windows Server. I knew that failed login attempts are logged under Event ID 4625, so I entered `event.code:4625` in the query to narrow the results. From there, I added filters for the source IP and username to get a clearer picture of what was happening.

Once I had everything in place, I saved the query as **RDP failed activity**. To test the setup, I attempted an RDP login from a virtual machine, expecting it to fail. Sure enough, Kibana captured the failed attempt!
 
<img width="1265" alt="image" src="https://github.com/user-attachments/assets/f5117f21-ec96-47d6-8760-bb4ce6158302">


With the failed login attempt visible, I proceeded to create an alert. By selecting **Alerts** and clicking on **Create search threshold rule**, I named the rule **RDP Brute Force Activity** and set it to trigger when there were more than 5 failed attempts. I then went to **Management** > **Stack Management** > **Alerts** to confirm the alert was being generated.

However, I quickly noticed the alert lacked crucial information—it didn’t show the affected user or the source IP. To address this, I decided to recreate the rule under the **Security** section for more detailed results.

Under **Security** > **Rules** > **Detection rules (SIEM)**, I created a new threshold rule. For my custom query, I used:

```bash
system.auth.ssh.event: "Failed" AND agent.name: "Ubuntu-SSH-Server" AND user.name: "root"
```

I grouped the results by `user.name` and `source.ip`, naming this rule **SSH Brute Force Attempt**. The rule was set to run every 5 minutes with a 5-minute look-back period, ensuring that any new attempts would be detected quickly.

![SSH Brute Force Rule](https://github.com/user-attachments/assets/01bde113-1db2-4b89-8409-82c09a3fe066)

I replicated this process for my Windows server, using a similar query:

```bash
system.auth.ssh.event: "Failed" AND agent.name: "Windows-Server" AND user.name: "Administrator"
```

With both rules in place, I ensured continuous monitoring of potential brute force activities across both SSH and RDP connections.

### **Day 17: Creating Alerts and Dashboards in Kibana related to RDP**
Went to maps and typed in the following query: ' event.code: "4625" and agent.name: "Windows-Server" '.
I clicked on add layer then selected "Choropleth", and chose "World Countries" for the EMS Boundaries.
![image](https://github.com/user-attachments/assets/c6562806-02ed-468b-8387-df35698fef68)
I was surprised to see over 46,000 failed RDP events coming from Australia.
I named it "RDP Failed Authentication" and saved it to the dashboard that I created earlier.

I decided to create a new map with succesful RDP authentication focusing on RDP Logon type 10 abd type 7 using the following query: ' event.code: "4624" and (winlog.event_data.LogonType 7 or winlog.event_data.LogonType 10) and agent.name: "Windows-Server" '
![image](https://github.com/user-attachments/assets/0c563f01-8047-40a8-a83f-7b496aee8c93)

I went to discover and create a field that showerd the timestamp,country nae, source Ip , and username
![image](https://github.com/user-attachments/assets/e3168441-a29d-4969-972d-e1fd45f4d26f)

I clicked on create visualization and I pasted in the failed SSH query. I added the following values to be displayed: username, country name, source IP.
I sorted the count of records to descending. I saved it and named it "SSH Failed Authentications [Table]". I duplicated it and created a table to show successful SSH authentications.
<img width="1271" alt="image" src="https://github.com/user-attachments/assets/2e9868ff-3fa7-446d-930b-8f819e0f65af">
I did the same thing for the RDP Authentications
<img width="1505" alt="image" src="https://github.com/user-attachments/assets/d05fb258-dace-40b1-83bd-31d2623d0336">





























