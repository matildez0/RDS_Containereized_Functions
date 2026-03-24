#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import yaml
from scapy.all import BOOTP, DHCP, Ether, IP, UDP, sendp, sniff

# DHCP PROTOCOL NOTES
# -------------------
# The DHCP exchange follows a four-step handshake:
#   1. Discover  — client broadcasts: "I need an IP" (client has no IP yet)
#   2. Offer     — server replies with an available IP
#   3. Request   — client broadcasts: "I accept that IP" (broadcast so other servers hear it)
#   4. Ack       — server confirms the assignment
#
# Broadcast vs unicast:
#   - Discover and Request are always sent by the client in broadcast (Ethernet + IP)
#     because the client has no IP address yet and cannot receive unicast IP packets.
#   - Offer and initial Ack are sent by the server in broadcast for the same reason.
#   - Renewal Ack (client already has an IP, sends Request with ciaddr set) can be
#     sent unicast directly to the client.
#   - NAK is always broadcast — the client's IP may be wrong or absent.
#
# Common pitfalls:
#   - Race condition: if two clients send Discover before any Ack is processed,
#     get_next_ip() returns the same IP to both. Reserve the IP at Offer time, not Ack time.
#   - INIT-REBOOT: dhclient caches leases and may skip Discover on restart, sending
#     a Request directly for a previously assigned IP. The server must handle this
#     gracefully — Ack if the IP is still available, NAK otherwise.
#   - Offer mismatch: the IP in the Request is chosen by the client, not the server.
#     A client could request an IP different from what was offered. Always validate
#     that the requested IP matches your offer before sending an Ack.
#   - Stale offers: if a client never sends a Request after receiving an Offer, the
#     offered IP is blocked forever unless offers have a timeout.


def load_config(path):
    with open(path) as f:
        config = yaml.safe_load(f)
    return config


def build_pool(config):
    """Build the IP pool for the full subnet.
    Each entry: {mac, reserved}
    TODO: generate all IPs in the subnet from config["subnet"] and config["subnet_mask"]
    TODO: mark as reserved: network address, broadcast, server_ip, gateway
    TODO: apply static reservations from config["reservations"] (ip locked to mac)
    """
    # TODO
    pass


def get_next_ip(pool, offered_pool):
    """Return the next available IP from the pool, or None if exhausted."""
    # TODO
    pass


def handle_dhcp(packet, interface, config, pool, offered_pool):
    # TODO: handle DHCP Discover and Request messages
    # hint: packet.haslayer(X) checks if a layer is present; packet[X].field reads a field
    # hint: build replies with Ether() / IP() / UDP() / BOOTP() / DHCP() and send with sendp()
    pass


def main():
    config       = load_config("dhcp_server.yaml")
    interface    = config["interface"]
    pool         = build_pool(config)
    offered_pool = {}  # {mac -> {ip, timestamp}} — pending offers not yet Acked

    print(f"DHCP server listening on {interface}")

    sniff(
        iface=interface,
        filter="udp and (port 67 or port 68)",
        prn=lambda pkt: handle_dhcp(pkt, interface, config, pool, offered_pool),
        store=False,
    )


if __name__ == "__main__":
    main()
