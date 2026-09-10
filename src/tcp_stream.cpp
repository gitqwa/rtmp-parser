#include "tcp_stream.h"

#include <algorithm>
#include <cstdio>

namespace {

std::string keyOf(uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp) {
    char k[40];
    std::snprintf(k, sizeof(k), "%08x:%04x:%08x:%04x", sip, sp, dip, dp);
    return std::string(k);
}

}  // namespace

void TcpReassembler::add(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp,
                         uint16_t dstPort, uint32_t seq, const uint8_t* data,
                         size_t len) {
    if (len == 0) return;
    std::string k = keyOf(srcIp, srcPort, dstIp, dstPort);
    std::map<std::string, size_t>::iterator it = index_.find(k);
    if (it == index_.end()) {
        TcpFlow f;
        f.srcIp = srcIp;
        f.srcPort = srcPort;
        f.dstIp = dstIp;
        f.dstPort = dstPort;
        f.gapCount = 0;
        f.rexmitCount = 0;
        flows_.push_back(f);
        index_[k] = flows_.size() - 1;
        it = index_.find(k);
    }
    TcpFlow& f = flows_[it->second];
    TcpSegment s;
    s.seq = seq;
    s.payload.assign(data, data + len);
    f.segs.push_back(s);
}

void TcpReassembler::reassemble() {
    for (size_t i = 0; i < flows_.size(); ++i) {
        TcpFlow& f = flows_[i];
        std::sort(f.segs.begin(), f.segs.end(),
                  [](const TcpSegment& a, const TcpSegment& b) { return a.seq < b.seq; });

        uint32_t nextSeq = 0;
        bool first = true;
        for (size_t j = 0; j < f.segs.size(); ++j) {
            const TcpSegment& s = f.segs[j];
            if (first) {
                f.stream.insert(f.stream.end(), s.payload.begin(), s.payload.end());
                nextSeq = s.seq + static_cast<uint32_t>(s.payload.size());
                first = false;
                continue;
            }
            if (s.seq == nextSeq) {
                f.stream.insert(f.stream.end(), s.payload.begin(), s.payload.end());
                nextSeq += static_cast<uint32_t>(s.payload.size());
            } else if (s.seq < nextSeq) {
                // 重叠/重传：跳过已覆盖部分
                uint32_t skip = nextSeq - s.seq;
                if (skip < s.payload.size()) {
                    f.stream.insert(f.stream.end(), s.payload.begin() + skip,
                                    s.payload.end());
                    nextSeq += static_cast<uint32_t>(s.payload.size() - skip);
                }
                ++f.rexmitCount;
            } else {
                // 缺口：记录并直接续上（简化处理，不做等待补包）
                ++f.gapCount;
                f.stream.insert(f.stream.end(), s.payload.begin(), s.payload.end());
                nextSeq = s.seq + static_cast<uint32_t>(s.payload.size());
            }
        }
    }
}
