// chunk_parser.h — step3：RTMP chunk 流解析
//   basic header：第 1 字节高 2 bit = fmt，低 6 bit = csid（变长 1/2/3 字节）
//   message header：type0=11B / type1=7B / type2=3B / type3=0B（字段继承由 ChunkWalker 维护）
// 只解析"结构"，不解释消息内容（AMF0、音视频数据是 step4+ 的事）。
#ifndef RTMP_CHUNK_PARSER_H_
#define RTMP_CHUNK_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <map>

namespace rtmp {

// ---------- basic header 解析结果 ----------
struct BasicHeader {
    uint8_t  fmt;        // 0..3，决定 message header 的长度
    uint32_t csid;       // 解析后的真实 csid（0/1 形式已 +64）
    size_t   headerLen;  // 1 / 2 / 3
};

// ---------- 单个 chunk 的解析结果 ----------
struct MsgHeader {
    uint8_t  fmt;        // 0..3
    uint32_t csid;
    uint32_t timestamp;  // 绝对时间戳（type1/2 已把增量加上）
    uint32_t length;     // type0 读自流；type1/2/3 继承同 csid 的上一个消息
    uint8_t  typeId;
    uint32_t streamId;
    size_t   basicLen;   // basic header 长度（1/2/3）
    size_t   msgLen;     // message header 长度（0/3/7/11）
    size_t   payload;    // 本 chunk 携带的 payload 字节数（可能只是消息的一部分）
};

// 解析 basic header 的三种变长形式。
//   csid 2-63    -> 1 字节头
//   csid == 0    -> 2 字节头，真实 csid = 第 2 字节 + 64
//   csid == 1    -> 3 字节头，真实 csid = 第 2 字节 + 第 3 字节*256 + 64
// 返回 false 表示剩余字节不足。
bool parseBasicHeader(const uint8_t* p, size_t remain, BasicHeader* out);

// ---------- chunk 流遍历器 ----------
// 维护每个 csid 的上一个消息状态（length/typeid/streamid/timestamp 继承）、
// 当前 chunk size（解析 Set Chunk Size 控制消息后更新）、分片剩余字节。
class ChunkWalker {
public:
    explicit ChunkWalker(size_t defaultChunkSize = 4096);

    // 在流中解析下一个 chunk。pos 是输入/输出游标（从 0 开始，不断前进）。
    // 返回 false 表示数据不足或结构非法（如 fmt=1/2/3 但同 csid 无前序消息）。
    bool next(const uint8_t* stream, size_t streamLen, size_t* pos, MsgHeader* out);

    size_t chunkSize() const { return chunkSize_; }
    size_t chunksParsed() const { return parsed_; }

private:
    struct StreamState {
        uint32_t length;
        uint8_t  typeId;
        uint32_t streamId;
        uint32_t tsAbs;      // 基准绝对时间戳
        uint32_t remaining;  // 当前消息尚未分片发送的字节数
    };

    std::map<uint32_t, StreamState> state_;
    size_t chunkSize_;
    size_t parsed_;
};

// 自测：用构造的字节序列验证 basic header 三种形式 + 边界情况。
// 返回 false 表示自测失败（本样本没有 csid 0/1 实例，靠它补覆盖）。
bool selftestBasicHeader();

}  // namespace rtmp

#endif  // RTMP_CHUNK_PARSER_H_
