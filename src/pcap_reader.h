#ifndef RTMP_PARSER_PCAP_READER_H
#define RTMP_PARSER_PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>

// 单个抓包记录（链路层数据 + 时间戳，时间戳统一换算为微秒）
struct PcapPacket {
    uint64_t ts_usec;
    std::vector<uint8_t> data;
};

// 极简 pcap 文件读取器：只解析"全局头 + 包记录头"，不做任何链路层解析。
// 支持微秒/纳秒两种 magic、大小端两种字节序。
class PcapReader {
public:
    bool open(const std::string& path, std::string& err);
    bool next(PcapPacket& pkt);   // 读到尾部返回 false（正常结束）
    uint32_t linktype() const { return linktype_; }
    size_t packetCount() const { return packetCount_; }
    bool nanosecond() const { return nanosecond_; }

private:
    uint16_t rd16(const uint8_t* p) const;
    uint32_t rd32(const uint8_t* p) const;

    std::vector<uint8_t> buf_;   // 整个文件读入内存（教学用途；大文件可改流式）
    size_t pos_ = 0;
    size_t packetCount_ = 0;
    uint32_t linktype_ = 0;
    bool swap_ = false;          // 文件字节序与主机相反时交换
    bool nanosecond_ = false;
};

#endif  // RTMP_PARSER_PCAP_READER_H
