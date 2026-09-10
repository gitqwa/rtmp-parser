# 用于 Linux / WSL / macOS（Windows 上用 VS 工程或 CMake 见下）
CXX      ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wextra
SRCS      = src/pcap_reader.cpp src/tcp_stream.cpp src/chunk_parser.cpp src/main.cpp
TARGET    = rtmp_probe

$(TARGET): $(SRCS) src/pcap_reader.h src/tcp_stream.h src/chunk_parser.h
	$(CXX) $(CXXFLAGS) -I src $(SRCS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET) rtmp.pcap

clean:
	rm -f $(TARGET)

.PHONY: run clean
