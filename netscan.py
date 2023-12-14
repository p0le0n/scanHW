import socket
from typing import TypedDict

import requests
from scapy.all import IP, TCP, sr1


class HostInfo(TypedDict):
    country: str
    regionName: str
    city: str
    lat: float
    lon: float
    org: str


def scan_port(ip: str, port: int, timeout: float = .1) -> str | None:
    response = sr1(
        IP(dst=ip) / TCP(dport=port, flags='S'), timeout=timeout, verbose=False)

    return socket.getservbyport(port) if response and response.haslayer(TCP) and response[TCP].flags == 0x12 else None


def scan_host(ip: str) -> HostInfo:
    return requests.get(
        f'http://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,org').json()
