@echo off
rem Build rtmp_probe with MSVC (Visual Studio 2026 / 18)
rem Usage: build_msvc.bat  (run in project root)
rem NOTE: /utf-8 是必须的 —— 源文件是 UTF-8，不加会被按 GBK 误读导致诡异编译错误
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo [ERROR] vcvars64.bat not found, check Visual Studio install path
  exit /b 1
)
cl /nologo /utf-8 /std:c++14 /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /I src src\pcap_reader.cpp src\tcp_stream.cpp src\chunk_parser.cpp src\main.cpp /Fe:rtmp_probe.exe
