# -*- coding: utf-8 -*-
"""TwimStar 预研探测：从本机实测中国大陆可用 STUN 服务器 / IPv6 / iroh 中继可达性。
只发标准 STUN Binding Request，读回 XOR-MAPPED-ADDRESS（本机公网映射地址）。
"""
import socket, struct, os, time, sys

MAGIC = 0x2112A44E

def stun_binding(sock, timeout):
    tid = os.urandom(16)
    msg = struct.pack("!HHI", 0x0001, 0, MAGIC) + tid
    start = time.monotonic()
    sock.sendto(msg, dst)
    sock.settimeout(timeout)
    data, _ = sock.recvfrom(2048)
    rtt = (time.monotonic() - start) * 1000
    # 解析 XOR-MAPPED-ADDRESS (0x0020) / MAPPED-ADDRESS (0x0001)
    ip = port = None
    off = 20
    while off + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[off:off+4])
        aval = data[off+4:off+4+alen]
        if atype == 0x0020 and alen >= 8:
            xport = struct.unpack("!H", aval[2:4])[0] ^ (MAGIC >> 16)
            xip = bytes(b ^ m for b, m in zip(aval[4:8], struct.pack("!I", MAGIC)))
            port, ip = xport, socket.inet_ntoa(xip)
        elif atype == 0x0001 and alen >= 8:
            port, ip = struct.unpack("!HI", aval[2:8])[0], socket.inet_ntoa(aval[4:8])
        off += 4 + alen
    return ip, port, rtt

UDP_SERVERS = [
    ("stun.miwifi.com", 3478),        # 小米（北京）
    ("stun.chat.bilibili.com", 3478), # B站（百度云）
    ("stun.douyucdn.cn", 18000),      # 斗鱼
    ("stun.hitv.com", 3478),          # 芒果TV
    ("stun.qq.com", 3478),            # 腾讯（存疑，实测）
    ("stun.cdnbye.com", 3478),        # CDNBye
    ("stun1.l.google.com", 19302),    # Google（对照组，预期不通）
    ("stun.cloudflare.com", 3478),    # Cloudflare（对照组）
]
TCP_SERVERS = [("turn.cloud-rtc.com", 80)]  # 腾讯云 TURN（TCP，STUN 兼容）
IROH_RELAYS = ["use1-1.relay.iroh.network", "euw1-1.relay.iroh.network", "aps1-1.relay.iroh.network"]

print("=" * 72)
print("[1] UDP STUN 探测（中国大陆候选 + 海外对照组）")
print("=" * 72)
for host, port in UDP_SERVERS:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        srv_ip = infos[0][4][0]
    except Exception as e:
        print(f"  {host:<28} DNS 解析失败: {e}"); continue
    dst = (srv_ip, port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        ip, p, rtt = stun_binding(s, 5.0)
        print(f"  {host:<28} ({srv_ip:<15}) OK  {rtt:6.0f}ms  本机公网映射 = {ip}:{p}")
        s.close()
    except Exception as e:
        print(f"  {host:<28} ({srv_ip:<15}) 失败: {type(e).__name__}")

print()
print("=" * 72)
print("[2] TCP STUN 探测")
print("=" * 72)
for host, port in TCP_SERVERS:
    try:
        start = time.monotonic()
        s = socket.create_connection((host, port), timeout=5)
        rtt = (time.monotonic() - start) * 1000
        tid = os.urandom(16)
        s.sendall(struct.pack("!HHI", 0x0001, 0, MAGIC) + tid)
        s.settimeout(5)
        data = s.recv(2048)
        ok = "OK" if data[:2] == b"\x01\x01" else "异常响应"
        print(f"  {host:<28} TCP OK  {rtt:5.0f}ms  binding={ok}")
        s.close()
    except Exception as e:
        print(f"  {host:<28} 失败: {type(e).__name__}: {e}")

print()
print("=" * 72)
print("[3] IPv6 可用性")
print("=" * 72)
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect(("2400:3200::1", 53))  # 阿里 DNS-over-IPv6
    print(f"  本机 IPv6 出口地址 = {s.getsockname()[0]}")
    s.close()
except Exception as e:
    print(f"  IPv6 不可用: {type(e).__name__}: {e}")

print()
print("=" * 72)
print("[4] iroh 官方中继可达性（TCP 443）")
print("=" * 72)
for host in IROH_RELAYS:
    try:
        start = time.monotonic()
        s = socket.create_connection((host, 443), timeout=6)
        rtt = (time.monotonic() - start) * 1000
        print(f"  {host:<28} OK  {rtt:5.0f}ms  {s.getpeername()[0]}")
        s.close()
    except Exception as e:
        print(f"  {host:<28} 失败: {type(e).__name__}")
print()
print("探测完成。")
