from __future__ import annotations

from enum import Enum


class Service(str, Enum):
    """
    Well-known services a network appliance plugin can claim ownership of.

    A plugin declares its services in plugin.py:

        services:
          - dns
          - dhcp

    Only one plugin may claim a given service at a time. The loader will
    refuse to load a second plugin that declares a service already owned
    by a loaded plugin.
    """

    FIREWALL = "firewall"
    DNS = "dns"
    DHCP = "dhcp"
    NTP = "ntp"
    PROXY = "proxy"
    VPN = "vpn"
    QOS = "qos"
    SNMP = "snmp"
    SYSLOG = "syslog"
    SECURITY_LOG = "security_log"
    RADIUS = "radius"
    LDAP = "ldap"
    SMTP = "smtp"
    TFTP = "tftp"
    PXE = "pxe"
    MDNS = "mdns"
    BGP = "bgp"
    OSPF = "ospf"
    NAT = "nat"
    DDNS = "ddns"
    VLAN = "vlan"
    LOAD_BALANCER = "load_balancer"
    HOST = "host"
    NETWORKING = "networking"
    PKG_MANAGEMENT = "pkg_management"
    PKG_CACHE = "pkg_cache"
    MONITORING = "monitoring"
    SYSCTL = "sysctl"
    CRON = "cron"
    USERS = "users"
    GROUPS = "groups"
    APP_PROXY = "app_proxy"
