/**
 * OFFSET // Client-Side Memory Segment Analysis & Binary Forensic Engine
 * Enforces zero-trust data privacy: 100% in-browser processing via HTML5 File APIs.
 * Author: Pranav Aitha
 */

(() => {
  'use strict';

  // DOM Elements
  const canvas = document.getElementById('vanta-canvas');
  const dropNode = document.getElementById('drop-node');
  const fileInput = document.getElementById('file-ingest');
  const analysisViewport = document.getElementById('analysis-viewport');
  const hexStream = document.getElementById('hex-stream');
  const metadataLedger = document.getElementById('metadata-ledger');
  const hexRangeTag = document.getElementById('hex-range-tag');
  const entropyTag = document.getElementById('entropy-tag');
  const copyHexBtn = document.getElementById('copy-hex-btn');
  const sampleJpgBtn = document.getElementById('sample-jpg-btn');
  const samplePdfBtn = document.getElementById('sample-pdf-btn');

  let currentRawHex = '';

  /* ==========================================================================
     Volatile Vector Background Canvas (Smooth & Elegant Particles)
     ========================================================================== */
  function initVectorCanvas() {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const count = Math.min(Math.floor((width * height) / 22000), 55);
    const maxDist = 130;

    let mouse = { x: -1000, y: -1000 };

    window.addEventListener('resize', () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });

    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
        radius: Math.random() * 1.2 + 0.8,
        alpha: Math.random() * 0.3 + 0.15
      });
    }

    function render() {
      ctx.clearRect(0, 0, width, height);

      // Render subtle nodes & links
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = width;
        else if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        else if (p.y > height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 242, 169, ${p.alpha})`;
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.hypot(dx, dy);

          if (dist < maxDist) {
            const alpha = (1 - dist / maxDist) * 0.12;
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
            ctx.lineWidth = 0.6;
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }

        const mdx = p.x - mouse.x;
        const mdy = p.y - mouse.y;
        const mDist = Math.hypot(mdx, mdy);
        if (mDist < 140) {
          const mAlpha = (1 - mDist / 140) * 0.25;
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0, 242, 169, ${mAlpha})`;
          ctx.lineWidth = 0.8;
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.stroke();
        }
      }

      requestAnimationFrame(render);
    }

    render();
  }

  /* ==========================================================================
     Drag-and-Drop & Workspace Interactions
     ========================================================================== */
  function initDropWorkspace() {
    if (!dropNode || !fileInput) return;

    dropNode.addEventListener('click', () => fileInput.click());
    dropNode.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });

    ['dragenter', 'dragover'].forEach((eventName) => {
      dropNode.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropNode.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach((eventName) => {
      dropNode.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropNode.classList.remove('dragover');
      });
    });

    dropNode.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        processTargetFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        processTargetFile(e.target.files[0]);
      }
    });

    if (copyHexBtn) {
      copyHexBtn.addEventListener('click', () => {
        if (!currentRawHex) return;
        navigator.clipboard.writeText(currentRawHex).then(() => {
          const original = copyHexBtn.textContent;
          copyHexBtn.textContent = 'COPIED!';
          setTimeout(() => (copyHexBtn.textContent = original), 1600);
        });
      });
    }

    if (sampleJpgBtn) {
      sampleJpgBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        loadSampleJpeg();
      });
    }

    if (samplePdfBtn) {
      samplePdfBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        loadSamplePdf();
      });
    }
  }

  /* ==========================================================================
     Sample Generators (For Instant In-Browser Exploration)
     ========================================================================== */
  function loadSampleJpeg() {
    // Construct a standard minimal valid JPEG binary (JFIF APP0 + DQT + SOF0 + DHT + SOS + EOI)
    const jpegBytes = new Uint8Array([
      0xFF, 0xD8, // SOI
      0xFF, 0xE0, 0x00, 0x10, // APP0 (JFIF)
      0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
      0xFF, 0xDB, 0x00, 0x43, 0x00, // DQT (Luminance)
      ...Array(64).fill(16),
      0xFF, 0xC0, 0x00, 0x11, 0x08, 0x01, 0x80, 0x02, 0x00, 0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // SOF0: 512x384 3 channels
      0xFF, 0xC4, 0x00, 0x1F, 0x00, // DHT
      0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, // SOS
      0x7B, 0x4F, 0xA2, 0x39, 0x18, 0x90, 0xEE, 0x5D, 0x42, 0x8C, 0x33, 0x91,
      0xFF, 0xD9 // EOI
    ]);

    const blob = new Blob([jpegBytes], { type: 'image/jpeg' });
    const sampleFile = new File([blob], 'forensic_target_demo.jpg', { type: 'image/jpeg' });
    processTargetFile(sampleFile);
  }

  function loadSamplePdf() {
    const pdfContent = `%PDF-1.4
%âãÏÓ
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
>>
endobj
2 0 obj
<<
  /Type /Pages
  /Kids [3 0 R]
  /Count 1
>>
endobj
3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 612 792]
  /Contents 4 0 R
>>
endobj
4 0 obj
<<
  /Length 44
>>
stream
BT
/F1 24 Tf
100 700 Td
(OFFSET ZERO TRUST ENGINE) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000015 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000210 00000 n 
trailer
<<
  /Size 5
  /Root 1 0 R
>>
startxref
306
%%EOF`;

    const blob = new Blob([pdfContent], { type: 'application/pdf' });
    const sampleFile = new File([blob], 'intelligence_report_demo.pdf', { type: 'application/pdf' });
    processTargetFile(sampleFile);
  }

  /* ==========================================================================
     Forensic Telemetry Calculators
     ========================================================================== */
  async function computeSHA256(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function calculateShannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) {
      freq[bytes[i]]++;
    }
    const len = bytes.length;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }

  /* ==========================================================================
     Hex Dump Formatter
     ========================================================================== */
  function generateHexDump(uint8Array, maxBytes = 1024) {
    const limit = Math.min(uint8Array.length, maxBytes);
    const lines = [];
    let plainAccumulator = '';

    for (let i = 0; i < limit; i += 16) {
      const offset = i.toString(16).padStart(8, '0').toUpperCase();
      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (i + j < limit) {
          const byte = uint8Array[i + j];
          const hex = byte.toString(16).padStart(2, '0').toUpperCase();
          hexPart += hex + ' ';
          asciiPart += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
        } else {
          hexPart += '   ';
          asciiPart += ' ';
        }
        if (j === 7) hexPart += ' ';
      }

      plainAccumulator += `${offset}  ${hexPart} |${asciiPart}|\n`;

      lines.push(
        `<span class="hex-offset">${offset}</span>  ` +
        `<span class="hex-bytes">${escapeHTML(hexPart)}</span> ` +
        `<span class="hex-ascii">${escapeHTML(asciiPart)}</span>`
      );
    }

    currentRawHex = plainAccumulator;
    return lines.join('\n');
  }

  function escapeHTML(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ==========================================================================
     JPEG & PDF Forensic Analyzers
     ========================================================================== */
  function parseJpegSegments(bytes) {
    const segments = [];
    let isJpeg = false;

    if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      isJpeg = true;
      segments.push({
        marker: '0xFFD8',
        name: 'SOI (Start of Image)',
        info: 'JPEG Magic Signature Verified'
      });
    }

    if (!isJpeg) return { isJpeg: false, segments: [], meta: {} };

    let i = 2;
    const meta = {
      jfifVersion: null,
      exifPresent: false,
      quantizationTables: 0,
      huffmanTables: 0,
      dimensions: null,
      colorComponents: null,
      encoding: 'Standard / Baseline'
    };

    while (i < bytes.length - 1) {
      if (bytes[i] === 0xff) {
        const marker = bytes[i + 1];

        if (marker === 0xd9) {
          segments.push({
            marker: '0xFFD9',
            name: 'EOI (End of Image)',
            info: 'Terminating Segment'
          });
          break;
        }

        if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
          i += 1;
          continue;
        }

        if (i + 3 < bytes.length) {
          const segLength = (bytes[i + 2] << 8) | bytes[i + 3];
          const hexMarker = '0x' + ((0xff00 | marker).toString(16).toUpperCase());
          let segName = 'Segment Payload';
          let segInfo = `${segLength} bytes`;

          switch (marker) {
            case 0xe0:
              segName = 'APP0 (JFIF Application)';
              if (i + 9 < bytes.length) {
                const jfifId = String.fromCharCode(...bytes.slice(i + 4, i + 9));
                if (jfifId.startsWith('JFIF')) {
                  const major = bytes[i + 9];
                  const minor = bytes[i + 10];
                  meta.jfifVersion = `v${major}.${minor.toString().padStart(2, '0')}`;
                  segInfo = `JFIF Standard ${meta.jfifVersion}`;
                }
              }
              break;
            case 0xe1:
              segName = 'APP1 (EXIF / XMP Metadata)';
              meta.exifPresent = true;
              segInfo = 'Camera Hardware & Geospatial Segment';
              break;
            case 0xe2:
              segName = 'APP2 (ICC Color Profile)';
              segInfo = 'Embedded Color Space Profile';
              break;
            case 0xdb:
              segName = 'DQT (Quantization Table)';
              meta.quantizationTables++;
              segInfo = `Quantization Matrix #${meta.quantizationTables}`;
              break;
            case 0xc0:
            case 0xc1:
            case 0xc2:
              segName = marker === 0xc2 ? 'SOF2 (Progressive DCT)' : 'SOF0 (Baseline DCT)';
              if (marker === 0xc2) meta.encoding = 'Progressive DCT';
              if (i + 8 < bytes.length) {
                const precision = bytes[i + 4];
                const height = (bytes[i + 5] << 8) | bytes[i + 6];
                const width = (bytes[i + 7] << 8) | bytes[i + 8];
                const components = bytes[i + 9];
                meta.dimensions = `${width} × ${height} px (${precision}-bit)`;
                meta.colorComponents = `${components} Channel(s)`;
                segInfo = `${meta.dimensions}, Channels: ${components}`;
              }
              break;
            case 0xc4:
              segName = 'DHT (Huffman Table)';
              meta.huffmanTables++;
              segInfo = `Huffman Entropy Table #${meta.huffmanTables}`;
              break;
            case 0xda:
              segName = 'SOS (Start of Scan)';
              segInfo = 'Compressed Bitstream Payload';
              break;
            case 0xdd:
              segName = 'DRI (Restart Interval)';
              segInfo = 'Define Restart Marker Interval';
              break;
            case 0xfe:
              segName = 'COM (Embedded Comment)';
              segInfo = 'Plaintext Annotation';
              break;
          }

          segments.push({
            marker: hexMarker,
            name: segName,
            info: segInfo
          });

          if (marker === 0xda) break;
          i += 2 + segLength;
          continue;
        }
      }
      i++;
    }

    return { isJpeg: true, segments, meta };
  }

  function parsePdfStructure(bytes) {
    const textDecoder = new TextDecoder('latin1');
    const fullText = textDecoder.decode(bytes);

    const isPdf = fullText.startsWith('%PDF-');
    if (!isPdf) return { isPdf: false, segments: [], meta: {} };

    const versionMatch = fullText.match(/^%PDF-([0-9.]+)/);
    const pdfVersion = versionMatch ? `PDF v${versionMatch[1]}` : 'PDF Format';

    const objMatches = fullText.match(/\b\d+\s+\d+\s+obj\b/g);
    const objCount = objMatches ? objMatches.length : 0;

    const countMatch = fullText.match(/\/Count\s+(\d+)/);
    const pageCount = countMatch ? countMatch[1] : '1';

    const streamMatches = fullText.match(/\bstream\b/g);
    const streamCount = streamMatches ? streamMatches.length : 0;

    const isEncrypted = fullText.includes('/Encrypt');
    const hasXref = fullText.includes('xref');

    const meta = {
      version: pdfVersion,
      objectCount: objCount,
      pageCount: pageCount,
      streamCount: streamCount,
      encrypted: isEncrypted ? 'YES (Protected)' : 'NO (Cleartext)',
      xrefTable: hasXref ? 'Standard Linearized Xref' : 'Cross-Reference Stream'
    };

    const segments = [
      {
        marker: '0x2550',
        name: '%PDF-Header',
        info: `${pdfVersion} Document Signature`
      },
      {
        marker: 'OBJ_POOL',
        name: 'Indirect Reference Objects',
        info: `${objCount} Body Objects Indexed`
      },
      {
        marker: 'STREAM_REG',
        name: 'FlateDecode / Data Streams',
        info: `${streamCount} Content Streams Spliced`
      }
    ];

    if (fullText.includes('%%EOF')) {
      segments.push({
        marker: '0x2525',
        name: '%%EOF (PDF Trailer)',
        info: 'Document Terminus Marker'
      });
    }

    return { isPdf: true, segments, meta };
  }

  /* ==========================================================================
     Execution Pipeline
     ========================================================================== */
  async function processTargetFile(file) {
    if (!file) return;

    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);

    const sha256 = await computeSHA256(arrayBuffer);
    const entropy = calculateShannonEntropy(bytes);

    const hexOutput = generateHexDump(bytes, 1024);
    hexStream.innerHTML = hexOutput;
    hexRangeTag.textContent = `0x0000 - 0x${Math.min(bytes.length, 1024).toString(16).toUpperCase()}`;
    entropyTag.textContent = `ENTROPY: ${entropy.toFixed(3)} bits/B`;

    const jpegData = parseJpegSegments(bytes);
    const pdfData = parsePdfStructure(bytes);

    renderTelemetryRegisters({
      file,
      bytesLength: bytes.length,
      sha256,
      entropy,
      jpegData,
      pdfData
    });

    analysisViewport.classList.remove('is-hidden');
    analysisViewport.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderTelemetryRegisters(data) {
    const { file, bytesLength, sha256, entropy, jpegData, pdfData } = data;

    let detectedFormat = 'UNKNOWN RAW BINARY';
    let segments = [];
    let customRegisterHTML = '';

    if (jpegData.isJpeg) {
      detectedFormat = 'JPEG (ISO/IEC 10918-1 JFIF / EXIF)';
      segments = jpegData.segments;

      customRegisterHTML = `
        <div class="telemetry-section">
          <div class="telemetry-section-title">// FORMAT REGISTERS</div>
          <div class="telemetry-field-grid">
            <div class="telemetry-field-card">
              <span class="field-key">Resolution</span>
              <span class="field-value">${jpegData.meta.dimensions || 'N/A'}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Color Channels</span>
              <span class="field-value">${jpegData.meta.colorComponents || 'N/A'}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Quantization Tables</span>
              <span class="field-value">${jpegData.meta.quantizationTables}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Huffman Tables</span>
              <span class="field-value">${jpegData.meta.huffmanTables}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Encoding Mode</span>
              <span class="field-value">${jpegData.meta.encoding}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">EXIF Segment</span>
              <span class="field-value">${jpegData.meta.exifPresent ? 'PRESENT' : 'NONE'}</span>
            </div>
          </div>
        </div>
      `;
    } else if (pdfData.isPdf) {
      detectedFormat = `ADOBE PDF (${pdfData.meta.version})`;
      segments = pdfData.segments;

      customRegisterHTML = `
        <div class="telemetry-section">
          <div class="telemetry-section-title">// FORMAT REGISTERS</div>
          <div class="telemetry-field-grid">
            <div class="telemetry-field-card">
              <span class="field-key">Specification</span>
              <span class="field-value">${pdfData.meta.version}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Indexed Objects</span>
              <span class="field-value">${pdfData.meta.objectCount} objects</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Content Streams</span>
              <span class="field-value">${pdfData.meta.streamCount} streams</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Page Count</span>
              <span class="field-value">${pdfData.meta.pageCount}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Encrypted</span>
              <span class="field-value">${pdfData.meta.encrypted}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Catalog Index</span>
              <span class="field-value">${pdfData.meta.xrefTable}</span>
            </div>
          </div>
        </div>
      `;
    }

    const entropyPercent = Math.min(100, (entropy / 8) * 100).toFixed(1);
    let entropyDescription = 'Low density (Structured text / sparse data)';
    if (entropy > 7.5) {
      entropyDescription = 'High density (Compressed / Encrypted payload)';
    } else if (entropy > 5.0) {
      entropyDescription = 'Medium density (Formatted structured binary)';
    }

    const segmentsHTML = segments.map((seg) => `
      <div class="segment-item">
        <span class="segment-badge">${seg.marker}</span>
        <span class="segment-name">${seg.name}</span>
        <span class="segment-range">${seg.info}</span>
      </div>
    `).join('');

    metadataLedger.innerHTML = `
      <!-- Core Telemetry -->
      <div class="telemetry-section">
        <div class="telemetry-section-title">// FILE TELEMETRY</div>
        <div class="telemetry-field-grid">
          <div class="telemetry-field-card">
            <span class="field-key">File Name</span>
            <span class="field-value">${escapeHTML(file.name)}</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">File Size</span>
            <span class="field-value">${formatBytes(bytesLength)} (${bytesLength.toLocaleString()} B)</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">Format</span>
            <span class="field-value field-value-mono">${detectedFormat}</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">Sandbox Privacy</span>
            <span class="field-value" style="color: var(--accent-emerald);">100% LOCAL (NO EGRESS)</span>
          </div>
        </div>
      </div>

      <!-- Hash & Entropy Analysis -->
      <div class="telemetry-section">
        <div class="telemetry-section-title">// CRYPTOGRAPHIC DIGEST &amp; ENTROPY</div>
        <div class="telemetry-field-grid">
          <div class="telemetry-field-card" style="grid-column: 1 / -1;">
            <span class="field-key">SHA-256 Checksum</span>
            <span class="field-value field-value-mono">${sha256}</span>
          </div>
        </div>
        <div class="entropy-meter">
          <div class="entropy-meter-head">
            <span class="field-key">Shannon Entropy: ${entropy.toFixed(4)} / 8.0000 bits/B</span>
            <span class="field-key" style="color: var(--accent-amber);">${entropyPercent}%</span>
          </div>
          <div class="entropy-track">
            <div class="entropy-fill" style="width: ${entropyPercent}%;"></div>
          </div>
          <span style="font-size: 0.68rem; color: var(--text-muted);">${entropyDescription}</span>
        </div>
      </div>

      <!-- Dynamic Custom Model Registers -->
      ${customRegisterHTML}

      <!-- Parsed Segment Table -->
      <div class="telemetry-section">
        <div class="telemetry-section-title">// PARSED BINARY SEGMENTS</div>
        <div class="segment-list">
          ${segments.length > 0 ? segmentsHTML : '<div class="segment-item"><span class="segment-name">No structured marker table available.</span></div>'}
        </div>
      </div>
    `;
  }

  // Initialize on load
  document.addEventListener('DOMContentLoaded', () => {
    initVectorCanvas();
    initDropWorkspace();
  });
})();
