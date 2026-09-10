// rtmp_probe — 动手任务 step2
// 读 pcap -> 提取 TCP payload（按方向重组）-> 识别并跳过 RTMP 握手
//   client -> server 方向：C0 + C1 + C2（各自 1/1536/1536 字节）
//   server -> client 方向：S0 + S1 + S2（同样 1/1536/1536 字节）
// 握手之后剩余的字节就是 RTMP chunk 流（step3 开始解析）。
//
// 编译：见 Makefile / CMakeLists.txt，C++11 即可。
// 运行：rtmp_probe <file.pcap>

#include "pcap_reader.h"
#include "tcp_stream.h"
#include "chunk_parser.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>  // SetConsoleOutputCP：修正 Windows 控制台中文乱码
#endif

namespace {

const size_t RTMP_HANDSHAKE_LEN = 1 + 1536 + 1536;  // C0/C1/C2 或 S0/S1/S2

// ---------- 链路层 ----------
// 把链路层帧解出 IP 报文（指针 + 长度）。返回 false 表示不支持/解析失败。
bool parseLinkLayer(uint32_t linktype, const std::vector<uint8_t>& frame,
                    const uint8_t** ip, size_t* ipLen) {
    switch (linktype) {
        case 0: {  // DLT_NULL（BSD loopback）：4 字节 family 头
            if (frame.size() < 4) return false;
            *ip = &frame[4];
            *ipLen = frame.size() - 4;
            return true;
        }
        case 1: {  // Ethernet II：14 字节头（含可选的 802.1Q VLAN 4 字节）
            size_t off = 14;
            if (frame.size() < off) return false;
            uint16_t ethertype = static_cast<uint16_t>((frame[12] << 8) | frame[13]);
            if (ethertype == 0x8100) {  // VLAN tag
                off += 4;
                if (frame.size() < off) return false;
            }
            *ip = &frame[off];
            *ipLen = frame.size() - off;
            return true;
        }
        case 101:  // Raw IP
            *ip = &frame[0];
            *ipLen = frame.size();
            return true;
        case 113: {  // Linux cooked v1 (SLL)：16 字节头
            if (frame.size() < 16) return false;
            *ip = &frame[16];
            *ipLen = frame.size() - 16;
            return true;
        }
        default:
            return false;
    }
}

// ---------- IPv4 ----------
struct IpInfo {
    uint32_t src;
    uint32_t dst;
    uint8_t proto;   // 6=TCP 17=UDP
    const uint8_t* payload;
    size_t payloadLen;
};

bool parseIp(const uint8_t* p, size_t len, IpInfo* out) {
    if (len < 20) return false;
    if ((p[0] >> 4) != 4) return false;  // 只处理 IPv4
    size_t ihl = static_cast<size_t>(p[0] & 0x0F) * 4;
    if (len < ihl + 4) return false;
    out->proto = p[9];
    out->src = (static_cast<uint32_t>(p[12]) << 24) | (static_cast<uint32_t>(p[13]) << 16) |
               (static_cast<uint32_t>(p[14]) << 8) | static_cast<uint32_t>(p[15]);
    out->dst = (static_cast<uint32_t>(p[16]) << 24) | (static_cast<uint32_t>(p[17]) << 16) |
               (static_cast<uint32_t>(p[18]) << 8) | static_cast<uint32_t>(p[19]);
    out->payload = p + ihl;
    out->payloadLen = len - ihl;
    return true;
}

// ---------- TCP ----------
struct TcpInfo {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint8_t flags;
    const uint8_t* payload;
    size_t payloadLen;
};

bool parseTcp(const uint8_t* p, size_t len, TcpInfo* out) {
    if (len < 20) return false;
    out->sport = static_cast<uint16_t>((p[0] << 8) | p[1]);
    out->dport = static_cast<uint16_t>((p[2] << 8) | p[3]);
    out->seq = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
               (static_cast<uint32_t>(p[6]) << 8) | static_cast<uint32_t>(p[7]);
    out->flags = p[13];
    size_t doff = static_cast<size_t>(p[12] >> 4) * 4;
    if (len < doff) return false;
    out->payload = p + doff;
    out->payloadLen = len - doff;
    return true;
}

// ---------- 工具 ----------
std::string ipStr(uint32_t ip) {
    char b[32];
    std::snprintf(b, sizeof(b), "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                  (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(b);
}

std::string hexDump(const uint8_t* p, size_t n) {
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += hx[p[i] >> 4];
        s += hx[p[i] & 0x0F];
    }
    return s;
}

// ---------- 握手分析（step2 核心） ----------
void analyzeHandshake(const TcpFlow& f) {
    printf("== 方向 %s:%u -> %s:%u\n", ipStr(f.srcIp).c_str(), f.srcPort,
           ipStr(f.dstIp).c_str(), f.dstPort);
    printf("   TCP 段数=%zu  重组字节=%zu  缺口=%zu  重叠/重传=%zu\n", f.segs.size(),
           f.stream.size(), f.gapCount, f.rexmitCount);

    // 1935 是 SRS 监听端口：源端口为 1935 说明是 SRS 在发 -> 握手段是 S0/S1/S2
    bool fromServer = (f.srcPort == 1935);
    const char* tag = fromServer ? "S" : "C";

    if (f.stream.size() < RTMP_HANDSHAKE_LEN) {
        printf("   警告: 数据不足 %u 字节（完整握手长度），无法验证握手。\n",
               static_cast<unsigned>(RTMP_HANDSHAKE_LEN));
        return;
    }

    const uint8_t* s = &f.stream[0];
    printf("   握手首字节[0]=0x%02X  (期望 0x03: %s)\n", s[0],
           s[0] == 0x03 ? "OK" : "FAIL");
    printf("   握手段: %s[0](1B) + %s[1](1536B) + %s[2](1536B)\n", tag, tag, tag);
    printf("   %s[1] 前16字节: %s\n", tag, hexDump(s + 1, 16).c_str());
    printf("   %s[2] 前16字节: %s\n", tag, hexDump(s + 1 + 1536, 16).c_str());
    printf("   握手(3073B)已跳过，剩余 chunk 数据 %zu 字节\n",
           f.stream.size() - RTMP_HANDSHAKE_LEN);

    const uint8_t* rest = s + RTMP_HANDSHAKE_LEN;
    size_t restLen = f.stream.size() - RTMP_HANDSHAKE_LEN;
    if (restLen > 0) {
        size_t show = restLen < 32 ? restLen : 32;
        printf("   首个 chunk 前32字节: %s\n", hexDump(rest, show).c_str());
        uint8_t b0 = rest[0];
        printf("   basic header[0]=0x%02X -> fmt=%u csid=%u  (step3 从这里继续)\n", b0,
               static_cast<unsigned>((b0 >> 6) & 0x03), static_cast<unsigned>(b0 & 0x3F));
    }
}

// ---------- step3：chunk 流解析 ----------
const char* typeName(uint8_t t) {
    switch (t) {
        case 1:  return "SetChunkSize";
        case 2:  return "Abort";
        case 3:  return "Ack";
        case 4:  return "UserCtrl";
        case 5:  return "WinAckSize";
        case 6:  return "SetPeerBW";
        case 8:  return "Audio";
        case 9:  return "Video";
        case 15: return "AMF3Data";
        case 18: return "Metadata";
        case 19: return "AMF3Cmd";
        case 20: return "AMF0Cmd";
        case 22: return "AMF0Data";
        default: return "?";
    }
}

void dumpChunks(const uint8_t* data, size_t len, size_t maxChunks) {
    rtmp::ChunkWalker walker;
    size_t pos = 0;
    size_t n = 0;
    printf("-- chunk 解析（前 %u 个：basic header + message header）--\n",
           static_cast<unsigned>(maxChunks));
    while (pos < len && n < maxChunks) {
        const size_t off = pos;
        rtmp::MsgHeader h;
        if (!walker.next(data, len, &pos, &h)) {
            printf("   !! 解析失败于 off=%zu（数据不足或 fmt=1/2/3 无前序状态）\n", off);
            break;
        }
        printf("  chunk#%02zu off=%7zu basic[%zu] fmt=%u csid=%-4u mh[%zu] "
               "ts=%-8u len=%-6u type=0x%02X(%-11s) sid=%u payload=%zu\n",
               n, off, h.basicLen, static_cast<unsigned>(h.fmt), h.csid, h.msgLen,
               h.timestamp, h.length, h.typeId, typeName(h.typeId), h.streamId,
               h.payload);
        ++n;
    }
    printf("  共解析 %u 个 chunk（当前 chunk size=%u）\n",
           static_cast<unsigned>(n), static_cast<unsigned>(walker.chunkSize()));
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    // 源码/字面量是 UTF-8，而 Windows 控制台默认按 GBK(936) 解码输出，
    // 不切代码页的话所有中文都会乱码。这里把输出代码页设为 UTF-8。
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2) {
        printf("用法: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    PcapReader reader;
    std::string err;
    if (!reader.open(argv[1], err)) {
        printf("打开失败: %s\n", err.c_str());
        return 1;
    }
    printf("== pcap 概况 ==\n");
    printf("linktype=%u  精度: %s\n", reader.linktype(),
           reader.nanosecond() ? "纳秒" : "微秒");

    TcpReassembler reasm;
    PcapPacket pkt;
    size_t totalPkts = 0, ipPkts = 0, tcpPayloadPkts = 0, other = 0;
    while (reader.next(pkt)) {
        ++totalPkts;
        const uint8_t* ip = nullptr;
        size_t ipLen = 0;
        if (!parseLinkLayer(reader.linktype(), pkt.data, &ip, &ipLen)) {
            ++other;
            continue;
        }
        IpInfo ii;
        if (!parseIp(ip, ipLen, &ii)) {
            ++other;
            continue;
        }
        ++ipPkts;
        if (ii.proto != 6) continue;  // 只关心 TCP
        TcpInfo ti;
        if (!parseTcp(ii.payload, ii.payloadLen, &ti)) continue;
        if (ti.payloadLen == 0) continue;
        ++tcpPayloadPkts;
        reasm.add(ii.src, ti.sport, ii.dst, ti.dport, ti.seq, ti.payload, ti.payloadLen);
    }

    printf("包总数=%zu  IPv4包=%zu  含payload的TCP包=%zu  其他(非IPv4/TCP)=%zu\n",
           totalPkts, ipPkts, tcpPayloadPkts, other);

    reasm.reassemble();
    printf("独立 TCP 方向数=%zu\n\n", reasm.flows().size());

    printf("basic header 自测: %s（1/2/3 字节 + 边界）\n\n",
           rtmp::selftestBasicHeader() ? "通过" : "失败!");

    if (reasm.flows().empty()) {
        printf("没有抓到任何 TCP 数据。\n");
        return 1;
    }
    for (size_t i = 0; i < reasm.flows().size(); ++i) {
        const TcpFlow& f = reasm.flows()[i];
        analyzeHandshake(f);
        if (f.stream.size() > RTMP_HANDSHAKE_LEN) {
            dumpChunks(&f.stream[RTMP_HANDSHAKE_LEN],
                       f.stream.size() - RTMP_HANDSHAKE_LEN, 30);
        }
        printf("\n");
    }

    printf("提示: 若样本只有 1935->客户端 单方向（SRS 在 WSL2/Docker 而抓包点在 Windows loopback），\n");
    printf("      是 localhost 转发路径导致反向数据未经过抓包点。双向抓包可在 WSL 内用 tcpdump 完成。\n");
    return 0;
}
