// chunk_parser.cpp — step3 实现，见 chunk_parser.h 说明
#include "chunk_parser.h"

namespace rtmp {

// ---------- basic header ----------
bool parseBasicHeader(const uint8_t* p, size_t remain, BasicHeader* out) {
    if (remain < 1) return false;
    const uint8_t b0 = p[0];
    out->fmt = static_cast<uint8_t>((b0 >> 6) & 0x03);
    uint32_t csid = b0 & 0x3F;
    size_t hlen = 1;
    if (csid == 0) {  // 2 字节头：真实 csid = 第 2 字节 + 64（64..319）
        if (remain < 2) return false;
        csid = static_cast<uint32_t>(p[1]) + 64;
        hlen = 2;
    } else if (csid == 1) {  // 3 字节头：真实 csid = 第 2 字节 + 第3字节*256 + 64
        if (remain < 3) return false;
        csid = static_cast<uint32_t>(p[1]) + (static_cast<uint32_t>(p[2]) << 8) + 64;
        hlen = 3;
    }
    out->csid = csid;
    out->headerLen = hlen;
    return true;
}

// ---------- 内部工具 ----------
static uint32_t be24(const uint8_t* p) {  // 3 字节大端（timestamp / length）
    return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

static uint32_t le32(const uint8_t* p) {  // 4 字节小端（stream id）
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// ---------- ChunkWalker ----------
ChunkWalker::ChunkWalker(size_t defaultChunkSize)
    : chunkSize_(defaultChunkSize), parsed_(0) {}

bool ChunkWalker::next(const uint8_t* s, size_t slen, size_t* pos, MsgHeader* out) {
    if (pos == NULL || out == NULL || *pos >= slen) return false;
    const size_t start = *pos;

    // 1) basic header（变长）
    BasicHeader bh;
    if (!parseBasicHeader(s + start, slen - start, &bh)) return false;

    // 2) message header（长度由 fmt 决定）
    const size_t q = start + bh.headerLen;  // message header 起点
    const size_t remain = slen - q;

    MsgHeader h;
    h.fmt = bh.fmt;
    h.csid = bh.csid;
    h.basicLen = bh.headerLen;
    h.msgLen = 0;
    h.payload = 0;

    std::map<uint32_t, StreamState>::iterator it = state_.find(bh.csid);
    StreamState* st = (it != state_.end()) ? &it->second : NULL;

    switch (bh.fmt) {
        case 0: {  // type0 = 11B 全量：timestamp + length + typeid + streamid
            if (remain < 11) return false;
            h.timestamp = be24(s + q);
            h.length = be24(s + q + 3);
            h.typeId = s[q + 6];
            h.streamId = le32(s + q + 7);
            h.msgLen = 11;
            StreamState ns;
            ns.length = h.length;
            ns.typeId = h.typeId;
            ns.streamId = h.streamId;
            ns.tsAbs = h.timestamp;
            ns.remaining = h.length;
            state_[bh.csid] = ns;
            st = &state_[bh.csid];
            break;
        }
        case 1: {  // type1 = 7B：增量时间戳，length/typeid/streamid 继承
            if (remain < 7) return false;
            if (st == NULL) return false;  // 无前序消息，无法继承
            const uint32_t dts = be24(s + q);
            h.msgLen = 7;
            h.length = st->length;
            h.typeId = st->typeId;
            h.streamId = st->streamId;
            h.timestamp = st->tsAbs + dts;
            st->tsAbs = h.timestamp;  // type1 更新基准
            break;
        }
        case 2: {  // type2 = 3B：增量时间戳，其余继承
            if (remain < 3) return false;
            if (st == NULL) return false;
            const uint32_t dts = be24(s + q);
            h.msgLen = 3;
            h.length = st->length;
            h.typeId = st->typeId;
            h.streamId = st->streamId;
            h.timestamp = st->tsAbs + dts;
            break;
        }
        default: {  // fmt == 3：0B 头，全部继承（通常是分片续片）
            if (st == NULL) return false;
            h.length = st->length;
            h.typeId = st->typeId;
            h.streamId = st->streamId;
            h.timestamp = st->tsAbs;
            break;
        }
    }

    // 3) payload 起点
    const size_t payloadBegin = q + h.msgLen;
    if (payloadBegin > slen) return false;

    // 4) Set Chunk Size 控制消息（typeid=1，4B payload，31 位大端）
    //    注意：必须在跳转前读，因为下一个 chunk 的尺寸由它决定
    if (h.fmt == 0 && h.typeId == 1 && h.length >= 4 && payloadBegin + 4 <= slen) {
        chunkSize_ = (static_cast<size_t>(s[payloadBegin]) << 24) |
                     (static_cast<size_t>(s[payloadBegin + 1]) << 16) |
                     (static_cast<size_t>(s[payloadBegin + 2]) << 8) |
                     static_cast<size_t>(s[payloadBegin + 3]);
        chunkSize_ &= 0x7FFFFFFF;
    }

    // 5) 本 chunk 携带的 payload = min(消息剩余字节, chunk size)；消费并前进
    const uint32_t payload =
        (st->remaining < chunkSize_) ? st->remaining
                                     : static_cast<uint32_t>(chunkSize_);
    h.payload = static_cast<size_t>(payload);
    st->remaining -= payload;

    *pos = payloadBegin + payload;
    *out = h;
    ++parsed_;
    return true;
}

// ---------- basic header 自测 ----------
bool selftestBasicHeader() {
    BasicHeader bh;
    bool ok = true;

    // 1 字节：0x42 = 0b01_000010 -> fmt=1, csid=2
    {
        const uint8_t buf[1] = {0x42};
        if (!parseBasicHeader(buf, 1, &bh) || bh.fmt != 1 || bh.csid != 2 ||
            bh.headerLen != 1) {
            ok = false;
        }
    }
    // 2 字节：0x00, 100 -> csid==0 形式，真实 csid = 100+64 = 164
    {
        const uint8_t buf[2] = {0x00, 100};
        if (!parseBasicHeader(buf, 2, &bh) || bh.fmt != 0 || bh.csid != 164 ||
            bh.headerLen != 2) {
            ok = false;
        }
    }
    // 3 字节：0x01, 0xE8, 0x01 -> csid = 232 + 1*256 + 64 = 552
    {
        const uint8_t buf[3] = {0x01, 0xE8, 0x01};
        if (!parseBasicHeader(buf, 3, &bh) || bh.fmt != 0 || bh.csid != 552 ||
            bh.headerLen != 3) {
            ok = false;
        }
    }
    // 边界：csid==0 但只剩 1 字节 -> 必须失败
    {
        const uint8_t buf[1] = {0x00};
        if (parseBasicHeader(buf, 1, &bh)) ok = false;
    }
    // 边界：csid==1 但只剩 2 字节 -> 必须失败
    {
        const uint8_t buf[2] = {0x01, 0x00};
        if (parseBasicHeader(buf, 2, &bh)) ok = false;
    }
    return ok;
}

}  // namespace rtmp
