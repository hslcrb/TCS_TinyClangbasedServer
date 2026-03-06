# TCS_TinyClangbasedServer

**Tiny Clang-based Server (TCS)** is a lightweight, general-purpose mini HTTP server written in C for Windows. It is designed for simplicity, serving static web assets and supporting Single Page Application (SPA) routing.

**Tiny Clang-based Server (TCS)**는 Windows용 C 언어로 작성된 가볍고 범용적인 미니 HTTP 서버입니다. 단순함을 위해 설계되었으며, 정적 웹 에셋을 제공하고 SPA(Single Page Application) 라우팅을 지원합니다.

---

## Features / 기능

- **Lightweight**: Minimal dependencies, using native Winsock.
- **가벼움**: 최소한의 의존성으로 네이티브 Winsock을 사용합니다.
- **Multi-Protocol**: Supports HTTP/1.1 and HTTPS (via native SChannel).
- **다중 프로토콜**: HTTP/1.1 및 HTTPS(네이티브 SChannel 사용)를 지원합니다.
- **HTTP/3 Ready**: Initial foundation for HTTP/3 (QUIC) over UDP.
- **HTTP/3 준비**: UDP를 통한 HTTP/3(QUIC)의 초기 기반이 마련되었습니다.
- **SPA Friendly**: Automatically serves `index.html` for unknown paths without extensions.
- **SPA 최적화**: 확장자가 없는 알 수 없는 경로에 대해 자동으로 `index.html`을 제공합니다.
- **MIME Support**: Extensive support for modern web formats (WASM, SVG, Fonts, etc.).
- **MIME 지원**: 최신 웹 형식(WASM, SVG, 글꼴 등)을 다양하게 지원합니다.
- **Security**: Built-in protection against directory traversal attacks.
- **보안**: 디렉토리 탐색(traversal) 공격에 대한 보호 기능이 내장되어 있습니다.

## Getting Started / 시작하기

### Prerequisites / 요구 사항
- Windows OS
- A C compiler (Clang, GCC, or MSVC) / C 컴파일러 (Clang, GCC 또는 MSVC)

### Compilation / 컴파일

#### Using Clang:
```bash
clang -I./src -o tcs.exe src/main.c -lws2_32 -lsecur32
```

#### Using GCC:
```bash
gcc -I./src -o tcs.exe src/main.c -lws2_32 -lsecur32
```

### Usage / 사용법

1. Place your web files in a folder named `www` in the same directory as the executable, or just use the current directory.
2. Run `tcs.exe`.
3. Open your browser and navigate to `http://localhost:8080`.

1. 실행 파일과 동일한 디렉토리에 `www` 폴더를 만들고 웹 파일을 넣거나, 단순히 현재 디렉토리를 사용하세요.
2. `tcs.exe`를 실행합니다.
3. 브라우저를 열고 `http://localhost:8080`으로 접속하세요.

---

## License / 라이선스
Licensed under the Apache License, Version 2.0.
Apache License 2.0 라이선스에 따라 라이선스가 부여됩니다.

Rheehose (Rhee Creative) 2008-2026