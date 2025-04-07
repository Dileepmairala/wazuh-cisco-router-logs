# Cisco Router Syslog Integration with Wazuh/OSSEC - Two-Tier Architecture

## Overview

This guide documents the integration between a Cisco router and a Wazuh/OSSEC monitoring system using a two-tier architecture:
1. **Tier 1**: Cisco router forwards logs to a Wazuh agent server
2. **Tier 2**: Wazuh agent forwards processed logs to the central Wazuh/OSSEC monitoring server

![Cisco Router Syslog Configuration](https://placeholder-image.com/cisco-syslog-config.png)

## Architecture Diagram

```
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│  Cisco Router │ ──→ │  Wazuh Agent  │ ──→ │ Wazuh/OSSEC   │
│   (IP:        │ UDP  │  (Log Server) │      │  Monitoring   │
│ 106.51.5.232) │ 514  │               │      │    Server     │
└───────────────┘      └───────────────┘      └───────────────┘
                      /var/log/cisco_router.log
                      /var/log/cisco/[hostname].log
```

## Configuration Components

The integration involves four main components:
1. Cisco Router Syslog Configuration
2. Wazuh Agent Server Configuration (Log Receiver)
3. Log Processing on the Agent
4. Central Wazuh/OSSEC Server with Custom Decoders and Rules

## 1. Cisco Router Configuration

### Web UI Configuration
As shown in the screenshot, the Cisco router is configured via the web interface:

- **Email Server** section is used for log notifications
- **Remote Syslog Servers** section has been configured with:
  - Syslog Server: Enabled ✓
  - Syslog Server 1: 10.10.5.42 (IP of the Wazuh agent server)
  - Transport: UDP
  - Port: 514 (standard syslog port)

## 2. Wazuh Agent Server Configuration (Log Receiver)

### Syslog Receiver Setup

The Wazuh agent server is configured to receive and process syslog messages from the Cisco router (IP: 106.51.5.232).

#### Main rsyslog Configuration (`/etc/rsyslog.conf`)

```
# rsyslog configuration file
# Global directives and modules
global(workDirectory="/var/lib/rsyslog")
module(load="builtin:omfile" Template="RSYSLOG_TraditionalFileFormat")

# Standard modules
module(load="imuxsock" SysSock.Use="off")
module(load="imjournal" UsePid="system" FileCreateMode="0644" StateFile="imjournal.state")

# Include all config files in /etc/rsyslog.d/
include(file="/etc/rsyslog.d/*.conf" mode="optional")

# Standard log rules
*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
mail.*                                                  -/var/log/maillog
cron.*                                                  /var/log/cron
*.emerg                                                 :omusrmsg:*
uucp,news.crit                                          /var/log/spooler
local7.*                                                /var/log/boot.log

# UDP module for receiving Cisco logs
module(load="imudp")
input(type="imudp" port="514")

# Specific rule for Cisco router
if $fromhost-ip startswith '106.51.5.232' then /var/log/cisco_router.log
& ~
```

#### Cisco-specific Configuration (`/etc/rsyslog.d/cisco.conf`)

```
# Load UDP module
$ModLoad imudp
# Listen on UDP port 514
$UDPServerRun 514
# Template for Cisco logs
$template CiscoLogs,"/var/log/cisco/%HOSTNAME%.log"
# Rule for Cisco router logs
if $fromhost-ip startswith '106.51.5.232' then ?CiscoLogs
& stop
```

This configuration:
1. Loads the UDP module to receive syslog messages on port 514
2. Creates a template to store logs in separate files based on hostname
3. Routes all logs from the Cisco router (IP: 106.51.5.232) to:
   - `/var/log/cisco_router.log` (from main config)
   - `/var/log/cisco/[hostname].log` (from cisco.conf)

### Preparing Log Directories

Create the necessary directories for Cisco logs:

```bash
sudo mkdir -p /var/log/cisco
sudo chmod 755 /var/log/cisco
sudo chown syslog:adm /var/log/cisco  # Adjust owner/group as needed
```

### Firewall Configuration

Ensure UDP port 514 is open on the Wazuh agent server:

```bash
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --reload
```

## 3. Log Processing on the Wazuh Agent

### Configure Wazuh Agent to Monitor Cisco Logs

1. Edit the Wazuh agent configuration:
```bash
sudo vi /var/ossec/etc/ossec.conf
```

2. Add the following configuration to monitor the Cisco log files:
```xml
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/cisco_router.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/cisco/*.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

 
</ossec_config>
```

3. Restart the Wazuh agent:
```bash
sudo systemctl restart wazuh-agent
```

## 4. Central Wazuh/OSSEC Server Configuration

### Custom Decoders

The custom decoders for Cisco router logs are configured in `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="Cisco_router">
  <prematch>FIREWALL: |dnsmasq-dhcp|log_sslvpnac|sslvpnd</prematch>
  <regex>^[^:]+:\s*User\s+([^\s]+)\s+authenticated successfully|tunnel established successfully</regex>
  <order>user, event</order>
</decoder>

<decoder name="Cisco_router1">
  <prematch>FIREWALL: |dnsmasq-dhcp|log_sslvpnac|sslvpnd</prematch>
</decoder>
```

### Custom Rules

The corresponding alert rules are defined in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="Cisco_router_custom">
  <!-- Rule for VPN Login Success with Username -->
  <rule id="130300" level="5">
    <decoded_as>Cisco_router</decoded_as>
    <match>authenticated successfully|tunnel established successfully</match>
    <description>Cisco VPN Login: User $(user) connected to VPN</description>
    <group>vpn,authentication_success,</group>
  </rule>
  
  <!-- Rule for VPN Authorization Success with AnyConnect -->
  <rule id="130301" level="5">
    <decoded_as>Cisco_router1</decoded_as>
    <match>anyconnect-vpn</match>
    <description>Cisco VPN Login: User authorized with AnyConnect VPN</description>
    <group>vpn,authentication_success,</group>
  </rule>
</group>
```

5. Restart the Wazuh manager to apply the changes:
```bash
sudo systemctl restart wazuh-manager
```

## Log Flow

1. Cisco router (IP: 106.51.5.232) generates logs and forwards them to the Wazuh agent server on UDP port 514
2. The rsyslog service on the agent server receives the logs and writes them to:
   - `/var/log/cisco_router.log`
   - `/var/log/cisco/[hostname].log`
3. The Wazuh agent monitors these log files and forwards relevant events to the central Wazuh/OSSEC server
4. The central server processes the events using custom decoders and rules
5. Alerts are generated based on the defined rules

## Testing the Integration

To verify the integration is working:

1. Trigger a VPN connection to the Cisco router

2. Check if logs are being received on the Wazuh agent server:
```bash
tail -f /var/log/cisco_router.log
tail -f /var/log/cisco/*.log
```

3. Verify the Wazuh agent is processing the logs:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

4. Check the Wazuh/OSSEC server for alerts:
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

## Troubleshooting

### Cisco Router to Wazuh Agent Communication
If logs are not reaching the Wazuh agent server:

1. Verify network connectivity:
```bash
tcpdump -i any host 106.51.5.232 and port 514
```

2. Check if rsyslog is listening on port 514:
```bash
netstat -tulpn | grep 514
```

3. Verify log files are being created:
```bash
ls -la /var/log/cisco/
ls -la /var/log/cisco_router.log
```

4. Check rsyslog service status:
```bash
systemctl status rsyslog
journalctl -u rsyslog
```

### Wazuh Agent to Central Server Communication
If logs are not reaching the central server:

1. Check the Wazuh agent connection status:
```bash
sudo /var/ossec/bin/agent_control -i
```

2. Review the agent logs:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

3. Verify the central server is receiving data:
```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

## Maintenance

1. Regularly review and update custom decoders and rules as needed
2. Implement log rotation for the Cisco log files:
```bash
sudo vi /etc/logrotate.d/cisco
```
```
/var/log/cisco_router.log /var/log/cisco/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

3. Monitor disk space regularly on the Wazuh agent server
4. Update all components when new versions are available
