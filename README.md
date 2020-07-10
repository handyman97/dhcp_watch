# Summary

`dhcp_watch` is a small utility program in C that
receives DHCPREQUEST packets
and reports their senders over MQTT.  
Unlike those similar programs written in script languages, this one is quite resource-efficient.  
It works as a daemon process.


# Functionality

- `dhcp_watch` sniffs BOOTP/DHCPREQUEST broadcast packets at udp port 67.
- Each time a DHCPREQUEST packet is detected,  
  it publishes a MQTT message of the following form
  - topic: `dhcp_watch/<ip_addr>`  
    where `<ip_addr>` denotes the address of the machine where `dhcp_watch` is running
  - payload: formated in JSON as  
  `{mac_address:<mac_address>, network_address:<network_address>}`  
   where `<mac_address>` identifies the request sender.


# Installation

## Prerequisites (Debian/Ubuntu packages)
- libpcap-dev
- libmosquitto-dev

## Build

- `make && PREFIX=<wherever_you_like> make install`

# Usage

```
$ sudo dhcp_watch [-i <interface>] [-b <mqtt_broker>(:<port>)]
```

where

- `<interface>` specifies a network interface such as `eth0` and `wlan0`
- `<mqtt_broker>` and `port` specify a MQTT server (localhost by default) and its port (1883 by default)

Note it needs root permission for sniffing network packets.
