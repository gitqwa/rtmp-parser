#include "pcap_reader.h"

#include <cstdio>
#include <cstring>

namespace {

uint16_t bswap16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }

uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

}  // namespace

bool PcapReader::open(const std::string& path, std::string& err) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) {
        err = "cannot open file: " + path;
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 24) {
        fclose(fp);
        err = "file too small: no pcap global header (24 bytes)";
        return false;
    }
    buf_.resize(static_cast<size_t>(sz));
    size_t rd = fread(&buf_[0], 1, buf_.size(), fp);
    fclose(fp);
    if (rd != buf_.size()) {
        err = "file read error";
        return false;
    }

    // 魔数判断：文件里存的 4 字节经 memcpy 读入后与主机字节序相关，
    // 通过比较判断文件字节序与精度（微秒/纳秒）。
    uint32_t magic = 0;
    std::memcpy(&magic, &buf_[0], 4);
    if (magic == 0xa1b2c3d4u) {
        swap_ = false; nanosecond_ = false;      // 小端 + 微秒
    } else if (magic == 0xd4c3b2a1u) {
        swap_ = true;  nanosecond_ = false;      // 大端 + 微秒
    } else if (magic == 0xa1b23c4du) {
        swap_ = false; nanosecond_ = true;       // 小端 + 纳秒
    } else if (magic == 0x4d3cb2a1u) {
        swap_ = true;  nanosecond_ = true;       // 大端 + 纳秒
    } else {
        err = "unknown pcap magic: not a pcap file?";
        return false;
    }

    linktype_ = rd32(&buf_[20]);   // 全局头 offset 20: network/linktype
    pos_ = 24;                     // 全局头固定 24 字节
    packetCount_ = 0;
    return true;
}

uint16_t PcapReader::rd16(const uint8_t* p) const {
    uint16_t v = 0;
    std::memcpy(&v, p, 2);
    return swap_ ? bswap16(v) : v;
}

uint32_t PcapReader::rd32(const uint8_t* p) const {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return swap_ ? bswap32(v) : v;
}

bool PcapReader::next(PcapPacket& pkt) {
    if (pos_ + 16 > buf_.size()) return false;   // 正常读完
    const uint8_t* h = &buf_[pos_];
    uint32_t ts_sec = rd32(h);
    uint32_t ts_frac = rd32(h + 4);
    uint32_t incl = rd32(h + 8);
    pos_ += 16;
    if (pos_ + incl > buf_.size()) return false; // 记录被截断（文件损坏）
    pkt.ts_usec = static_cast<uint64_t>(ts_sec) * 1000000ull +
                  (nanosecond_ ? ts_frac / 1000u : ts_frac);
    pkt.data.assign(&buf_[pos_], &buf_[pos_] + incl);
    pos_ += incl;
    ++packetCount_;
    return true;
}
