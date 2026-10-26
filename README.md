# OFFSET. 🔬⚡
> **Client-Side Memory Segment Analysis & Binary Forensic Engine**  
> *Zero-Trust. Zero Server-Side Egress. 100% In-Browser Execution.*

[![License: MIT](https://img.shields.io/badge/License-MIT-00f2a9.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=black)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Deployment-GitHub%20Pages-00d4ff?style=for-the-badge&logo=github&logoColor=white)](https://pranav-aitha.github.io/offset/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Local%20Sandbox-00f2a9?style=for-the-badge&logo=shield&logoColor=black)](#zero-trust-privacy-guarantee)

---

## 🌐 Live Interactive Demo
Explore the live forensic sandbox on GitHub Pages:  
👉 **[https://pranav-aitha.github.io/offset/](https://pranav-aitha.github.io/offset/)**

---

## 📌 Architectural Overview

```
                      +-----------------------------+
                      |   Target Binary Ingestion   |
                      |     (JPEG, JFIF, PDF)       |
                      +--------------+--------------+
                                     |
                         [HTML5 File API Sandbox]
                                     |
              +----------------------+----------------------+
              |                                             |
              v                                             v
    +-------------------+                         +-------------------+
    |  Binary Splicer   |                         | Telemetry Ledger  |
    |  - Hex Stream     |                         |  - SHA-256 Digest |
    |  - Byte Alignment |                         |  - Shannon Entropy|
    |  - ASCII Mirror   |                         |  - Marker Parser  |
    +-------------------+                         +-------------------+
              |                                             |
              +----------------------+----------------------+
                                     |
                         [Zero-Egress Diagnostics]
```

**OFFSET** is a serverless, single-page client-side binary segment parser and forensic engine. Designed with strict zero-trust principles, files ingested into OFFSET are parsed purely within the browser's JavaScript V8 runtime memory space using HTML5 `ArrayBuffer` and `DataView` primitives. No bytes, hashes, or metadata ever leave your client environment.

---

## 🚀 Key Features

- **🛡️ 100% Local Sandbox Privacy**: No backends, no tracking, and no external telemetry transmissions. Full zero-trust data sovereignty.
- **⚡ Volatile Vector Background**: Responsive canvas mesh rendering dynamic connection nodes and vector lines.
- **🧬 [0x00] Binary Header Splicer**:
  - Real-time 16-byte aligned hexadecimal dump with byte offset markers.
  - Interactive ASCII character preview alongside raw hexadecimal columns.
  - One-click raw stream clipboard export.
- **📊 [0x01] Extracted Telemetry Registers**:
  - **Cryptographic Verification**: WebCrypto-powered local SHA-256 hash digest.
  - **Information Entropy**: Shannon Entropy calculation ($0.0 - 8.0\text{ bits/byte}$) to identify encryption or compression density.
  - **JPEG Segment Parsing**: Dissects `SOI`, `APP0` (JFIF versions), `APP1` (EXIF/XMP headers), `DQT` (Quantization matrices), `SOF0/SOF2` (Frame dimensions & channels), `DHT` (Huffman tables), and `SOS` (Scan stream).
  - **PDF Object Model Inspection**: Identifies PDF spec version, indirect object count, stream containers, linearized cross-reference indices, and catalog structures.

---

## 📁 Repository Structure

```
offset/
├── index.html        # Structural shell with canvas backdrop & forensic viewport
├── style.css         # Dark obsidian cyberpunk-minimalist theme & styling
├── app.js            # In-browser binary parser, vector canvas & telemetry engine
├── LICENSE           # MIT License (2026 Pranav Aitha)
└── README.md         # Documentation, architecture & author references
```

---

## 🛠️ Local Development & Quickstart

OFFSET is completely zero-dependency and runs on any modern web browser.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pranav-aitha/offset.git
   cd offset
   ```

2. **Launch directly in your browser:**
   - Double-click `index.html`, or
   - Serve using any lightweight static server:
     ```bash
     npx serve .
     # or
     python -m http.server 8000
     ```

---

## 🔒 Zero-Trust Privacy Guarantee

In sensitive cyber defense, forensic analysis, and data compliance operations, uploading proprietary binaries or evidentiary documents to remote SaaS servers introduces unacceptable legal and operational risks. 

OFFSET guarantees:
1. No `fetch()`, `XMLHttpRequest`, or `WebSocket` transmissions with your payload.
2. Direct execution via standard browser `FileReader.readAsArrayBuffer()` APIs.
3. Memory segments are released and garbage-collected once your tab is closed.

---

## 👨‍💻 Author & Connect

Crafted with dedication by **Pranav Aitha**. Connect with me across platforms:

- **X // Twitter:** [@PRANAV_AITHA](https://x.com/PRANAV_AITHA)
- **GitHub:** [@pranav-aitha](https://github.com/pranav-aitha)
- **Instagram:** [@pranav_aitha](https://instagram.com/pranav_aitha)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details.
