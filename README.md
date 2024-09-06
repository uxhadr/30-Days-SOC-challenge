# 30-Days-SOC-challenge

**DAY 1: BUILDING A LOGICAL DIAGRAM**
Opened Draw.io to create a logical diagram 
We're going to have 6 servers: Elastic & Kibana, Windows Server with RDP enabled, Ubuntu Server with SSH enabled, FLeet Server, OS Ticket Server, and the C2 Server
Our cloud provider will be VULTR

We will also have a Virtual Private Cloud to put all our servers in the same private network
Added the internet gateway symbol which will represent our ISP

The attackers laptop will have Kali Linux installed and the C2 server will be Mythic.
![image](https://github.com/user-attachments/assets/51a620c1-a44b-46d9-8705-c76211eb8fa4)

**DAY 2: INTRO TO ELASTIC SEARCH**
The Elastic Stack is comprised of three key components:

Logstash: Responsible for data ingestion, Logstash acts as a pipeline that pulls data from various sources, processes it using filter plugins, and sends it to the desired destination. It efficiently handles data processing, transforming raw logs into structured data ready for analysis.

Elasticsearch: Serving as the core of the ELK Stack, Elasticsearch is a highly scalable search and analytics engine. It receives data from Logstash, allowing for powerful searching, querying, and real-time analysis of large datasets.

Kibana: Kibana is the visualization layer of the stack. It provides an intuitive web interface that enables users to interact with the data stored in Elasticsearch, creating dashboards and reports that offer deep insights into the data.

By configuring and integrating these components, the ELK Stack provides a robust platform for managing and analyzing log data, crucial for effective cybersecurity operations.

Similarities to Splunk
Elasticsearch = Indexer / Search Head
Logstash = Heavy Forwarder
Kibana = Web GUI
Beats/Agents = Universal Forwarder

**DAY 3: ELASTICSEARCH SETUP**
Went to Vultr and created a new account. clicked on products, then network, then selected VPC 2.0
I configured the IP range to the same one I had on the logical diagram
![image](https://github.com/user-attachments/assets/7775f919-f691-4c03-a46b-37790deb9020)

I deployed the Elasticsearch server and for the image I selected Ubuntu version 22.04 and added 80GB

After creating the  Elasticsearch server, I then sshed into the server using my Kali VM.
<img width="1045" alt="image" src="https://github.com/user-attachments/assets/f5649bbd-778f-4586-87ec-0f56363854d8">

On my web browser searched for download elasticsearch for the debx86 platform and I copied the link and pasted it to the terminal using the 'wget' command.
<img width="1127" alt="image" src="https://github.com/user-attachments/assets/0fc9299a-ffda-4376-9f58-c920891f5d51">

Typed the following command to install elasticsearch: 'dpkg -i elasticsearch-8.15.0-amd64.deb'
I opened a nano file and stored the elasticsearch password

I typed in the command "ip a" and copied the network host IP. I opened elasticsearch.yml and changed the network host to that IP. I also uncommented the http port.
<img width="1131" alt="image" src="https://github.com/user-attachments/assets/a04e1c99-fc54-4eb6-8f58-06c559c79592">

I went back to VULTR and created a firewall rule to only allow my IP to be able to SSH into the server.
I encountered issues when trying to start up my elasticsearch. I opened the log at: '/var/log/elasticsearch/elasticsearch.log' to find out what was causing the issue. 
I found the following error: java.net.UnknownHostException: 45.76.64.199/23: Name or service not known, suggests that Elasticsearch is attempting to bind to an invalid or misconfigured network address or hostname. Here's what might be happening and how to fix it:
I removed the /23 from my network houst and I was able to get elasticsearch running since Elasticsearch doesn't expect CIDR notation for a single network.host
<img width="874" alt="image" src="https://github.com/user-attachments/assets/2a7b98b1-7880-49c8-b5b6-10c8e8fb1de7">

**DAY 4: KIBANA SETUP**
I went to the elastic website and copied the link to download Kibana Debx86_64
<img width="938" alt="image" src="https://github.com/user-attachments/assets/273becb8-b553-4faa-99f2-99bd9876ba15">

Opened the kibana.yml file and made changes to the server port and the server host. For the server host I put the public IP address of our VULTR virtual machine.
I started the Kibalna service and checked the status to make sure it was running
<img width="973" alt="image" src="https://github.com/user-attachments/assets/a3ed1893-d928-46ac-8bad-96ae1b2a8add">

I needed to create an enrollment token. I navigated to the following: 'cd /usr/share/elasticsearch/bin' and then ran the following command: ' ./elasticsearch-create-enrollment-token --scope kibana'

I went to my web browser and typed in HTTP:my vm public ip/5601. I wasn't able to reach the website because I set the firewall rule to only allow ssh connections and I was now trying to access port 5601.
I changed the firewall rules to allow any TCP (port 1-65535) from my SOC analyst workstation to the VM.

I was still unable to connect so I added the firewall rule to accept 5601 on the ubuntu machine. On my terminal I typed in the following command: ufw allow 5601
I was now able to access the web interface and I pasted the enrollment tokn. after that it assked for the verification code. I navigated to '/usr/share/kibana/bin' and the ran the following command: './kibana-verification-code'
<img width="1330" alt="image" src="https://github.com/user-attachments/assets/8410f44c-248a-4572-9031-e45725172b1f">

It now asked for my username and password. I found it in the file i save earlier which had all the security configuratin information.
I logged in and navigated to alerts under security.
<img width="1508" alt="image" src="https://github.com/user-attachments/assets/04585c90-5d4a-4409-a5d3-cee4cdb3940f">

I went back to the terminal and generated the ecryption keys
<img width="1334" alt="image" src="https://github.com/user-attachments/assets/e173e987-d683-4d98-8801-cfc4afa30b60">

I added the encryption keys and restarted kibana:
<img width="1047" alt="image" src="https://github.com/user-attachments/assets/68d1f2dd-77ef-420b-972b-86068b2b2fdc">

I no longer so the message under security alerts 
<img width="1504" alt="image" src="https://github.com/user-attachments/assets/d55fbfcc-62b3-451b-ac5e-777679d883e1">









