#ifndef RTMP_PARSER_TCP_STREAM_H
#define RTMP_PARSER_TCP_STREAM_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// 单个 TCP 段（带序列号）
struct TcpSegment {
    uint32_t seq;
    std::vector<uint8_t> payload;
};

// 一个方向的 TCP 流（按 4 元组 + 方向区分）
struct TcpFlow {
    uint32_t srcIp;
    uint16_t srcPort;
    uint32_t dstIp;
    uint16_t dstPort;
    std::vector<TcpSegment> segs;
    std::vector<uint8_t> stream;   // 重组后的连续字节流
    size_t gapCount;               // 序列号缺口（丢包/乱序导致的空洞）
    size_t rexmitCount;            // 重叠/重传段数量
};

// 简化 TCP 流重组：按方向分组、按 seq 排序、重叠部分去重后拼接。
// 教学级实现，不处理 FIN 边界和 ACK 窗口，对本地无丢包抓包足够。
class TcpReassembler {
public:
    void add(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort,
             uint32_t seq, const uint8_t* data, size_t len);
    void reassemble();
    const std::vector<TcpFlow>& flows() const { return flows_; }

private:
    std::map<std::string, size_t> index_;
    std::vector<TcpFlow> flows_;
};

#endif  // RTMP_PARSER_TCP_STREAM_H
