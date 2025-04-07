# wazuh-cisco-router-logs# Cisco Router Syslog Integration with OSSEC

## Overview

This guide documents the integration between a Cisco router and an OSSEC monitoring server for log collection and analysis. The setup forwards syslog events from the Cisco device to OSSEC for security monitoring and alerting.

![Cisco Router Syslog Configuration](https://placeholder-image.com/cisco-syslog-config.png)

## Configuration Components

The integration involves three main components:
1. Cisco Router Syslog Configuration
2. OSSEC Syslog Collector Setup
3. OSSEC Custom Decoders and Rules

## 1. Cisco Router Configuration

### Web UI Configuration
As shown in the screenshot, the Cisco router is configured via the web interface:

- **Email Server** section is used for log notifications
- **Remote Syslog Servers** section has been configured with:
  - Syslog Server: Enabled ✓
  - Syslog Server 1: 10.10.5.42
  - Transport: UDP
  - Port: 514 (standard syslog port)

## 2. OSSEC Server Configuration

### Syslog Collector Setup

Ensure OSSEC is configured to listen for remote syslog messages on UDP port 514:

1. Edit the OSSEC configuration file:
```bash
sudo vi /var/ossec/etc/ossec.conf
```

2. Add or verify the syslog configuration section:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.10.5.0/24</allowed-ips>
</remote>
```

3. Restart OSSEC to apply changes:
```bash
sudo systemctl restart ossec
```

## 3. Custom Decoders and Rules

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

These decoders:
- Match Cisco router firewall and VPN log messages
- Extract username information when available
- Identify successful authentication events

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

These rules:
- Generate level 5 alerts for successful VPN connections
- Track both standard VPN and AnyConnect VPN logins
- Group alerts under vpn and authentication_success categories

## Log Storage

The Cisco router logs are stored in `/var/log/messages` on the OSSEC server.

## Testing the Integration

To verify the integration is working:

1. Trigger a VPN connection to the Cisco router
2. Check the logs in the OSSEC server:
```bash
tail -f /var/log/messages | grep -E "FIREWALL|sslvpn"
```

3. Verify OSSEC alerts are generated:
```bash
tail -f /var/ossec/logs/alerts/alerts.log
```

## Troubleshooting

If logs are not being received:

1. Verify connectivity between the Cisco router and OSSEC server:
```bash
tcpdump -i any port 514
```

2. Check OSSEC is listening on port 514:
```bash
netstat -tulpn | grep 514
```

3. Verify firewall rules allow UDP traffic on port 514:
```bash
sudo iptables -L -n | grep 514
```

## Maintenance

Regularly review and update custom decoders and rules as needed to adapt to changes in log formats or to capture additional security events.
