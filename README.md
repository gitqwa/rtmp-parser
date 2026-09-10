# rtmp-parser — RTMP 协议抓包解析器（握手 + chunk 流）

从 pcap 文件提取 TCP payload，识别并跳过 RTMP 握手（`C0/C1/C2` / `S0/S1/S2`），
再解析握手之后的 chunk 流：basic header（1/2/3 字节变长）+ message header（type0/1/2/3）。

## 目录结构

```
rtmp-parser/
├── rtmp.pcap            # Wireshark 抓包样本（SRS 5.0.213, 推流/拉流会话）
├── src/
│   ├── pcap_reader.{h,cpp}   # pcap 文件格式解析（全局头 + 包记录，支持大小端/微秒纳秒）
│   ├── tcp_stream.{h,cpp}    # TCP 流重组（按方向分组、seq 排序、重叠去重）
│   ├── chunk_parser.{h,cpp}  # step3：basic header 三种形式 + chunk 流遍历器
│   └── main.cpp              # 链路层/IP/TCP 解包 + 握手跳过 + chunk 解析入口
├── tools/probe_pcap.py       # Python 标准库对照探针（step2 握手验证）
├── tools/probe_chunk.py      # Python 标准库对照探针（step3 chunk 验证）
├── Makefile                  # Linux / WSL / macOS 编译
├── CMakeLists.txt
└── build_msvc.bat            # Windows MSVC 编译
```

## 编译与运行

**Windows（MSVC，已装 VS 2026）**
```
build_msvc.bat
rtmp_probe.exe rtmp.pcap
```

**Linux / WSL**
```
make
./rtmp_probe rtmp.pcap
```
