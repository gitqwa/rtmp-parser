#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
step2 快速探针（标准库，无第三方依赖）
读 pcap -> 提取 TCP payload -> 按方向重组 -> 识别并跳过 RTMP 握手(C0/C1/C2 / S0/S1/S2)
与 C++ 版 rtmp_probe 逻辑镜像，用于在无编译器的机器上验证数据。

用法: python probe_pcap.py rtmp.pcap
"""
import struct
import sys
import collections

def load_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[0:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        e, ts_unit = '<', 1e-6
    elif magic == b'\xa1\xb2\xc3\xd4':
        e, ts_unit = '>', 1e-6
    elif magic == b'\x4d\x3c\xb2\xa1':
        e, ts_unit = '<', 1e-9
    elif magic == b'\xa1\xb2\x3c\x4d':
        e, ts_unit = '>', 1e-9
    else:
        raise ValueError('unknown pcap magic: %r' % magic)
    ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack(e + 'HHIIII', data[4:24])
    pkts = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, orig = struct.unpack(e + 'IIII', data[off:off + 16])
        off += 16
        pkts.append((ts_sec + ts_frac * ts_unit, data[off:off + incl]))
        off += incl
    return linktype, ver_major, ver_minor, pkts

def parse_linktype(linktype, body):
    """返回 (ip_bytes, 描述) 或 None"""
    if linktype == 0:  # DLT_NULL / BSD loopback
        fam = struct.unpack('<I', body[0:4])[0]
        return body[4:], 'DLT_NULL(family=%d)' % fam
    if linktype == 1:  # Ethernet
        ethertype = struct.unpack('>H', body[12:14])[0]
        if ethertype == 0x8100:  # VLAN
            ethertype = struct.unpack('>H', body[16:18])[0]
            return body[18:], 'Ethernet+VLAN'
        return body[14:], 'Ethernet'
    if linktype == 101:  # Raw IP
        return body, 'RawIP'
    if linktype == 113:  # Linux cooked v1
        proto = struct.unpack('>H', body[14:16])[0]
        return body[16:], 'LinuxSLL'
    return None, 'unsupported linktype=%d' % linktype

def parse_ip(pkt):
    """返回 (src_ip, dst_ip, proto, tcp_bytes) 或 None"""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    src = struct.unpack('>I', pkt[12:16])[0]
    dst = struct.unpack('>I', pkt[16:20])[0]
    return src, dst, proto, pkt[ihl:]

def parse_tcp(tcp):
    if len(tcp) < 20:
        return None
    sport = struct.unpack('>H', tcp[0:2])[0]
    dport = struct.unpack('>H', tcp[2:4])[0]
    seq = struct.unpack('>I', tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    return sport, dport, seq, flags, tcp[doff:]

def ip_str(ip):
    return '%d.%d.%d.%d' % (ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)

def reassemble(segs):
    """按 seq 排序后合并，处理重叠/重传，返回 (stream_bytes, 缺口数, 重传字节)"""
    segs.sort(key=lambda s: s[0])
    out = bytearray()
    next_seq = None
    gaps = 0
    rexmit = 0
    for seq, payload in segs:
        if next_seq is None:
            out += payload
            next_seq = seq + len(payload)
            continue
        if seq == next_seq:
            out += payload
            next_seq += len(payload)
        elif seq < next_seq:
            # 重叠：只取未覆盖部分
            skip = next_seq - seq
            if skip < len(payload):
                out += payload[skip:]
                next_seq += len(payload) - skip
            rexmit += 1
        else:
            gaps += 1
            out += payload
            next_seq = seq + len(payload)
    return bytes(out), gaps, rexmit

def main():
    if len(sys.argv) < 2:
        print('usage: probe_pcap.py <file.pcap>')
        sys.exit(1)
    linktype, vmaj, vmin, pkts = load_pcap(sys.argv[1])
    print('== pcap 概况 ==')
    print('linktype=%d  version=%d.%d  包总数=%d' % (linktype, vmaj, vmin, len(pkts)))

    streams = collections.defaultdict(list)  # (sip,sport,dip,dport) -> [(seq,payload)]
    conn_count = 0
    n_handled = 0
    for ts, body in pkts:
        ip_part, desc = parse_linktype(linktype, body)
        if ip_part is None:
            print('  跳过链路层: %s' % desc)
            continue
        r = parse_ip(ip_part)
        if r is None:
            continue
        src, dst, proto, tcp = r
        if proto != 6:  # TCP
            continue
        t = parse_tcp(tcp)
        if t is None:
            continue
        sport, dport, seq, flags, payload = t
        if not payload:
            continue
        n_handled += 1
        key = (src, sport, dst, dport)
        streams[key].append((seq, bytes(payload)))

    print('含 payload 的 TCP 包=%d  独立方向数=%d' % (n_handled, len(streams)))

    for key, segs in streams.items():
        src, sport, dst, dport = key
        stream, gaps, rexmit = reassemble(segs)
        if dport == 1935:
            d, tag = 'client->server', 'C'   # ffmpeg 发 C0/C1/C2
        elif sport == 1935:
            d, tag = 'server->client', 'S'   # SRS 发 S0/S1/S2
        else:
            d, tag = 'unknown', '?'
        print()
        print('== 方向 %s:%d -> %s:%d (%s)  %d 个段, 重组 %d 字节, 缺口=%d, 重传=%d' % (
            ip_str(src), sport, ip_str(dst), dport, d,
            len(segs), len(stream), gaps, rexmit))

        if len(stream) < 3073:
            print('  数据不足 3073 字节（可能不是完整握手）')
            continue
        head = stream[0]
        c1 = stream[1:1537]
        c2 = stream[1537:3073]
        rest = stream[3073:]
        print('  [0]=0x%02X (期望 0x03=%s)  %s1=%d字节  %s2=%d字节' % (
            head, 'OK' if head == 0x03 else 'NO!', tag, len(c1), tag, len(c2)))
        print('  %s1 前16字节: %s' % (tag, c1[:16].hex()))
        print('  %s2 前16字节: %s' % (tag, c2[:16].hex()))
        print('  握手已跳过，剩余 chunk 数据 %d 字节' % len(rest))
        if rest:
            print('  首个 chunk 前32字节: %s' % rest[:32].hex())
            # 简单判别：第1字节高2位是 fmt，低6位是 csid
            b0 = rest[0]
            print('  basic header[0]=0x%02X -> fmt=%d csid=%d' % (b0, (b0 >> 6) & 0x03, b0 & 0x3F))

    if len(streams) == 1:
        k = list(streams.keys())[0]
        if not (k[1] == 1935 or k[3] == 1935):
            pass
        elif k[1] != 1935 and k[3] == 1935:
            print()
            print('提示: 只抓到 client->server 方向。')
        else:
            print()
            print('提示: 只抓到 server->client 方向（SRS 在 WSL2/Docker + Windows loopback 抓包常见）。')
            print('      完整双向抓包建议在 WSL 内 tcpdump 或抓 vEthernet (WSL) 接口。')

if __name__ == '__main__':
    main()
