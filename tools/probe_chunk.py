#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_chunk.py — step3 探针：解析握手后的 chunk 流
验证 basic header 三种形式 + message header 字段 + 分片跳转逻辑，
与 C++ 实现交叉对照。用法: python probe_chunk.py <file.pcap>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe_pcap import load_pcap, parse_linktype, parse_ip, parse_tcp, ip_str, reassemble

RTMP_HS = 1 + 1536 + 1536  # 握手长度 C0/C1/C2 或 S0/S1/S2


def parse_basic(buf, pos):
    """basic header: 第 1 字节高 2 bit = fmt，低 6 bit = csid。
    csid==0 -> 2 字节头，真实 csid = 第 2 字节 + 64
    csid==1 -> 3 字节头，真实 csid = 第 2 字节 + 第 3 字节*256 + 64
    返回 (fmt, csid, header_len)
    """
    b0 = buf[pos]
    fmt = (b0 >> 6) & 0x03
    csid = b0 & 0x3F
    hdr = 1
    if csid == 0:
        csid = buf[pos + 1] + 64
        hdr = 2
    elif csid == 1:
        csid = buf[pos + 1] + (buf[pos + 2] << 8) + 64
        hdr = 3
    return fmt, csid, hdr


TYPE_NAMES = {
    1: 'SetChunkSize', 2: 'Abort', 3: 'Ack', 4: 'UserCtrl', 5: 'WinAckSize',
    6: 'SetPeerBW', 8: 'Audio', 9: 'Video', 15: 'AMF3Data', 18: 'Metadata',
    19: 'AMF3Cmd', 20: 'AMF0Cmd', 22: 'AMF0Data',
}


def dump_chunks(rest, max_chunks=30):
    pos = 0
    state = {}     # csid -> dict(length, typeid, streamid, ts_abs, remaining)
    chunk_size = 4096  # RTMP 默认 128，但 SRS/ffmpeg 通常协商成 4096
    n = 0
    while pos < len(rest) and n < max_chunks:
        start = pos
        fmt, csid, bh_len = parse_basic(rest, pos)
        pos += bh_len
        prev = state.get(csid)

        if fmt == 0:
            ts = (rest[pos] << 16) | (rest[pos + 1] << 8) | rest[pos + 2]
            length = (rest[pos + 3] << 16) | (rest[pos + 4] << 8) | rest[pos + 5]
            typeid = rest[pos + 6]
            streamid = (rest[pos + 7] | (rest[pos + 8] << 8) |
                        (rest[pos + 9] << 16) | (rest[pos + 10] << 24))
            mh = 11
            ts_abs = ts
            state[csid] = dict(length=length, typeid=typeid, streamid=streamid,
                               ts=ts, remaining=length)
        elif fmt == 1:
            dts = (rest[pos] << 16) | (rest[pos + 1] << 8) | rest[pos + 2]
            mh = 7
            if prev is None:
                print('  !! fmt=1 但 csid=%d 无前序状态' % csid); break
            ts_abs = prev['ts'] + dts
            state[csid] = dict(length=prev['length'], typeid=prev['typeid'],
                               streamid=prev['streamid'], ts=ts_abs,
                               remaining=prev['remaining'])
        elif fmt == 2:
            dts = (rest[pos] << 16) | (rest[pos + 1] << 8) | rest[pos + 2]
            mh = 3
            if prev is None:
                print('  !! fmt=2 但 csid=%d 无前序状态' % csid); break
            ts_abs = prev['ts'] + dts
        else:  # fmt == 3
            mh = 0
            if prev is None:
                print('  !! fmt=3 但 csid=%d 无前序状态' % csid); break
            ts_abs = prev['ts']

        pos += mh
        st = state[csid]
        length, typeid, streamid = st['length'], st['typeid'], st['streamid']

        # Set Chunk Size 控制消息（typeid=1, 4 字节 payload，高 31 位是 size）
        if fmt == 0 and typeid == 1 and length >= 4 and pos + 4 <= len(rest):
            chunk_size = (rest[pos] << 24 | rest[pos + 1] << 16 |
                          rest[pos + 2] << 8 | rest[pos + 3]) & 0x7FFFFFFF

        # 本 chunk 携带的 payload = min(message 剩余字节, chunk_size)
        payload = min(st['remaining'], chunk_size)
        st['remaining'] -= payload

        tname = TYPE_NAMES.get(typeid, '?')
        print('  chunk#%02d off=%7d basic[%d] fmt=%d csid=%-4d mh[%d] ts=%-8d '
              'len=%-6d type=0x%02X(%-11s) sid=%d payload=%d' %
              (n, start, bh_len, fmt, csid, mh, ts_abs, length, typeid,
               tname, streamid, payload))
        n += 1
        pos += payload
        if payload <= 0:
            print('  !! payload<=0，停在 off=%d' % pos)
            break
    print('  共解析 %d 个 chunk（数据耗尽或达上限）' % n)


def main(path):
    linktype, vmaj, vmin, pkts = load_pcap(path)
    streams = {}
    for ts, body in pkts:
        ip_part, desc = parse_linktype(linktype, body)
        if ip_part is None:
            continue
        r = parse_ip(ip_part)
        if r is None:
            continue
        src, dst, proto, tcp = r
        if proto != 6:
            continue
        t = parse_tcp(tcp)
        if t is None:
            continue
        sport, dport, seq, flags, payload = t
        if not payload:
            continue
        key = (src, sport, dst, dport)
        streams.setdefault(key, []).append((seq, payload))

    for key, segs in streams.items():
        src, sport, dst, dport = key
        stream, gaps, rexmit = reassemble(segs)
        rest = stream[RTMP_HS:]
        print('== 方向 %s:%d -> %s:%d  握手后 chunk 数据 %d 字节'
              % (ip_str(src), sport, ip_str(dst), dport, len(rest)))
        dump_chunks(rest)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'rtmp.pcap')
