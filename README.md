# Azure-SOC-Automation-Lab

I built a small home SOC on Azure to study real-world brute-force attacks in real time. The setup involved exposing a Windows VM to the internet (a deliberate honeypot), streaming Windows Security logs into Microsoft Sentinel. Using KQL, I analyzed failed RDP login attempts, enriched attacker IPs with geolocation data and created a live attack map to visualize adversary activity in real time. Here’s how I did it step by step.

## Objective

The goal was to gain hands-on experience in SIEM operations and threat detection by simulating real-world attack scenarios. The lab focused on collecting and analyzing Windows security logs, detecting failed RDP login attempts, enriching data with geolocation context and visualizing attack patterns through Sentinel workbooks.

### Skills Learned

- Practical deployment and configuration of Microsoft Sentinel in a cloud environment.

- Log ingestion, parsing and analysis using KQL (Kusto Query Language).

- Monitoring and detection of brute-force attack attempts against exposed endpoints.

- Building custom visualizations and workbooks to track attacker activity globally.

### What You Need

- Azure subscription (free for new signers)
- A small Windows VM (Windows 10 or Server 2022)
- Microsoft Sentinel + Log Analytics workspace
- A GeoIP CSV imported as a Sentinel watchlist

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

### 1. Create Resource Group and Virtual Network

A dedicated resource group and virtual network were created to host the SOC lab. Throughout the process, the Azure subscription, resource group and region must be consistent.

<img width="975" height="668" alt="image" src="https://github.com/user-attachments/assets/911e7030-a785-411b-a8c7-a81ce0029146" />

The VNet was configured with the address space 10.0.0.0/16 and a default subnet of 10.0.0.0/24.

<img width="975" height="769" alt="image" src="https://github.com/user-attachments/assets/2f3fd980-e1e4-42f5-8ed2-d8c1e9cdaf9d" />

### 2. Deploy Windows VM (Honeypot)

A Windows VM was deployed and deliberately exposed to the internet as a honeypot. The Windows firewall was disabled.

<img width="956" height="659" alt="image" src="https://github.com/user-attachments/assets/de40bfe7-fd9f-43f4-8490-7222d54f74f1" />

The Network Security Group (NSG) was configured with an inbound rule allowing RDP (port 3389) from any source. This setup was crucial to attract brute-force login attempts from external actors.

<img width="700" height="1169" alt="image" src="https://github.com/user-attachments/assets/8c3d553b-5862-40e3-9956-1b327f82e708" />

### 3. Connect Microsoft Sentinel

Enabled Microsoft Sentinel on a Log Analytics workspace and connected Windows Security events from the VM for ingestion.

<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/3ca837b1-b54f-4022-b104-05a631db7725" />

### 4. Query with KQL

Used KQL to filter failed RDP login attempts (Event ID 4625) and extract attacker IP addresses from logs.

<img width="975" height="353" alt="image" src="https://github.com/user-attachments/assets/eae1ab3c-1974-4410-864f-ea1ab36d6f62" />

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IPAddress
```

### 5. Enrich with Geolocation (Watchlist)

Uploaded a watchlist mapping IPs to geolocation data and joined it with failed login events for enrichment.

<img width="975" height="593" alt="image" src="https://github.com/user-attachments/assets/fd6d28cd-25b6-4512-b16e-a12adfe0d95a" />


```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

### 6. Build Attack Map Visualization

Finally, I created a Sentinel Workbook and used the geolocation data to display a world map of attacker IPs.

<img width="975" height="448" alt="image" src="https://github.com/user-attachments/assets/707caaf6-0d9e-4457-994c-40dbed7b5ed8" />

## Results

Within just 30 minutes, I saw multiple login attempts from across the globe. Leaving the VM up for 24 hours gave me thousands more hits! A live feed of brute-force attacks against my honeypot.

<div align="center">
  <img width="1100" height="583" alt="image" src="https://github.com/user-attachments/assets/a176a8e7-cbf9-4f92-afef-2ff22d6e1621" />
  <p><em>Fig 1: Attack Map after 30 minutes of capturing events</em></p>
</div>

<div align="center">
  <img width="1100" height="576" alt="image" src="https://github.com/user-attachments/assets/453328aa-1afb-486d-ab9d-dd2f21913be9" />
  <p><em>Fig 2: Dense global attack map after a day online</em></p>
</div>












