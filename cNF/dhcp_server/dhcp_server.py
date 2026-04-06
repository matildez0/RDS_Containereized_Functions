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
    Each entry: {mac, reserved}"""
    import ipaddress

    network = ipaddress.IPv4Network(
        f"{config['subnet']}/{config['subnet_mask']}", strict=True
    )

    always_reserved={
     str(network.network_address), #.0
     str(network.broadcast_address), #.255
     config["server_ip"], 
     config["gateway"], 
    }

    # Build reservation map: ip -> mac
    static_by_ip  = {}
    static_by_mac = {}
    for r in config.get("reservations", []):
        static_by_ip[r["ip"]]   = r["mac"]
        static_by_mac[r["mac"]] = r["ip"]
 
    pool = {}
    for addr in network.hosts():
        ip = str(addr)
        reserved = ip in always_reserved
        mac = static_by_ip.get(ip)  # None unless statically reserved
        pool[ip] = {"mac": mac, "reserved": reserved}
 
    return pool
    """
    TODO: generate all IPs in the subnet from config["subnet"] and config["subnet_mask"]
    TODO: mark as reserved: network address, broadcast, server_ip, gateway
    TODO: apply static reservations from config["reservations"] (ip locked to mac)
    """
    


def get_next_ip(pool, offered_pool):
    """Return the next available IP from the pool, or None if exhausted."""
    # TODO
    offered_ips = {v["ip"] for v in offered_pool.values()}
    for ip, entry in pool.items():
        if entry["reserved"]:
            continue
        if entry["mac"] is not None:
            # locked to a specific MAC — skip (handled separately)
            continue
        if ip in offered_ips:
            continue
        return ip
    return None
    


def handle_dhcp(packet, interface, config, pool, offered_pool):
    # TODO: handle DHCP Discover and Request messages
    # hint: packet.haslayer(X) checks if a layer is present; packet[X].field reads a field
    # hint: build replies with Ether() / IP() / UDP() / BOOTP() / DHCP() and send with sendp()
    if not packet.haslayer(BOOTP):
        return
 
    bootp = packet[BOOTP]
    client_mac = bootp.chaddr.hex()[:12]
    # normalise to colon-separated lowercase
    client_mac = ":".join(client_mac[i:i+2] for i in range(0, 12, 2))
 
    dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
    msg_type = dhcp_options.get("message-type")
 
    server_ip  = config["server_ip"]
    gateway    = config["gateway"]
    dns        = config["dns"]
    lease_time = config["lease_time"]
    subnet_mask = config["subnet_mask"]

    def find_ip_for_mac(mac):
        """Check pool for a statically reserved IP for this MAC, or a currently leased IP."""
        for ip, entry in pool.items():
            if entry["mac"] == mac and not entry["reserved"]:
                return ip
        return None
 
    def send_reply(msg_type_str, offered_ip, client_mac_raw):
        reply = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src=server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                xid=bootp.xid,
                yiaddr=offered_ip,
                siaddr=server_ip,
                chaddr=bootp.chaddr,
            ) /
            DHCP(options=[
                ("message-type", msg_type_str),
                ("server_id", server_ip),
                ("lease_time", lease_time),
                ("subnet_mask", subnet_mask),
                ("router", gateway),
                ("name_server", dns),
                "end",
            ])
        )
        sendp(reply, iface=interface, verbose=False)
 
    if msg_type == 1:  # DHCP Discover
        # Check for static reservation first
        offered_ip = find_ip_for_mac(client_mac)
        if offered_ip is None:
            offered_ip = get_next_ip(pool, offered_pool)
        if offered_ip is None:
            print(f"[DHCP] Pool exhausted — cannot offer to {client_mac}")
            return
 
        # Reserve at offer time (avoid race condition)
        offered_pool[client_mac] = {"ip": offered_ip}
        print(f"[DHCP] Offer {offered_ip} → {client_mac}")
        send_reply("offer", offered_ip, bootp.chaddr)
 
    elif msg_type == 3:  # DHCP Request
        requested_ip = dhcp_options.get("requested_addr")
 
        # INIT-REBOOT: client has no prior offer, uses ciaddr
        if requested_ip is None:
            requested_ip = bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else None
 
        if requested_ip is None:
            print(f"[DHCP] Request from {client_mac} with no requested IP — ignoring")
            return
 
        # Validate: must match our offer (if any), and must be available in pool
        our_offer = offered_pool.get(client_mac, {}).get("ip")
        pool_entry = pool.get(requested_ip)
 
        # Accept if: matches our offer OR static reservation for this MAC
        if pool_entry is None:
            # IP not in our subnet
            nak = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, xid=bootp.xid, chaddr=bootp.chaddr) /
                DHCP(options=[("message-type", "nak"), ("server_id", server_ip), "end"])
            )
            sendp(nak, iface=interface, verbose=False)
            return
 
        static_for_mac = find_ip_for_mac(client_mac)
        ip_ok = (
            requested_ip == our_offer or
            (static_for_mac and requested_ip == static_for_mac) or
            (pool_entry["mac"] is None and not pool_entry["reserved"])
        )
 
        if ip_ok:
            # Commit the lease
            pool[requested_ip]["mac"] = client_mac
            offered_pool.pop(client_mac, None)
            print(f"[DHCP] Ack {requested_ip} → {client_mac}")
            send_reply("ack", requested_ip, bootp.chaddr)
        else:
            print(f"[DHCP] Nak {requested_ip} → {client_mac} (not available)")
            nak = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, xid=bootp.xid, chaddr=bootp.chaddr) /
                DHCP(options=[("message-type", "nak"), ("server_id", server_ip), "end"])
            )
            sendp(nak, iface=interface, verbose=False)


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
