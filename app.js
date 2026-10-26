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

  let currentRawHex = '';

  /* ==========================================================================
     Volatile Vector Background Canvas (Native Canvas Engine)
     ========================================================================== */
  function initVectorCanvas() {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const particleCount = Math.min(Math.floor((width * height) / 18000), 75);
    const maxDistance = 140;

    let mouse = { x: -1000, y: -1000 };

    window.addEventListener('resize', () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        radius: Math.random() * 1.5 + 1,
        baseAlpha: Math.random() * 0.4 + 0.2
      });
    }

    function render() {
      ctx.clearRect(0, 0, width, height);

      // Render subtle forensic grid
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.015)';
      ctx.lineWidth = 1;
      const gridSize = 60;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Render nodes & dynamic vectors
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = width;
        else if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        else if (p.y > height) p.y = 0;

        // Draw particle
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 242, 169, ${p.baseAlpha})`;
        ctx.fill();

        // Connect nearby nodes
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.hypot(dx, dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.16;
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }

        // Mouse interaction
        const mdx = p.x - mouse.x;
        const mdy = p.y - mouse.y;
        const mDist = Math.hypot(mdx, mdy);
        if (mDist < 160) {
          const mAlpha = (1 - mDist / 160) * 0.35;
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0, 242, 169, ${mAlpha})`;
          ctx.lineWidth = 1;
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
     File Drag-and-Drop Workspace Handlers
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
          setTimeout(() => (copyHexBtn.textContent = original), 1800);
        });
      });
    }
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
     Binary Header Splicer & Hex Formatter
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

      // Highlighted line for UI
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
     Format Analyzers (JPEG & PDF Binary Structure)
     ========================================================================== */
  function parseJpegSegments(bytes) {
    const segments = [];
    let isJpeg = false;

    if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      isJpeg = true;
      segments.push({
        marker: '0xFFD8',
        name: 'SOI (Start of Image)',
        offset: '0x0000',
        length: 2,
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

        // Standalone markers
        if (marker === 0xd9) {
          segments.push({
            marker: '0xFFD9',
            name: 'EOI (End of Image)',
            offset: '0x' + i.toString(16).toUpperCase(),
            length: 2,
            info: 'Terminating Segment'
          });
          break;
        }

        if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
          i += 1;
          continue;
        }

        // Variable length markers
        if (i + 3 < bytes.length) {
          const segLength = (bytes[i + 2] << 8) | bytes[i + 3];
          const hexMarker = '0x' + ((0xff00 | marker).toString(16).toUpperCase());
          let segName = 'UNKNOWN';
          let segInfo = `Segment payload: ${segLength} bytes`;

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
              segInfo = 'Camera Hardware & Geospatial Segment Header';
              break;
            case 0xe2:
              segName = 'APP2 (ICC Color Profile)';
              segInfo = 'Embedded Color Space Profile Descriptor';
              break;
            case 0xdb:
              segName = 'DQT (Quantization Table)';
              meta.quantizationTables++;
              segInfo = `Luminance/Chrominance Quantization Matrix #${meta.quantizationTables}`;
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
                meta.colorComponents = `${components} Component(s)`;
                segInfo = `${meta.dimensions}, Channels: ${components}`;
              }
              break;
            case 0xc4:
              segName = 'DHT (Huffman Table)';
              meta.huffmanTables++;
              segInfo = `Entropy Huffman Encoding Specification #${meta.huffmanTables}`;
              break;
            case 0xda:
              segName = 'SOS (Start of Scan)';
              segInfo = 'Primary Compressed Entropy-Coded Bitstream';
              break;
            case 0xdd:
              segName = 'DRI (Restart Interval)';
              segInfo = 'Define Restart Marker Interval';
              break;
            case 0xfe:
              segName = 'COM (Embedded Comment)';
              segInfo = 'User / Compiler Plaintext Annotation';
              break;
          }

          segments.push({
            marker: hexMarker,
            name: segName,
            offset: '0x' + i.toString(16).toUpperCase(),
            length: segLength + 2,
            info: segInfo
          });

          // SOS marker starts entropy data; rest is binary scan stream
          if (marker === 0xda) {
            break;
          }

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

    // Object count approximation
    const objMatches = fullText.match(/\b\d+\s+\d+\s+obj\b/g);
    const objCount = objMatches ? objMatches.length : 0;

    // Page count extraction
    const countMatch = fullText.match(/\/Count\s+(\d+)/);
    const pageCount = countMatch ? countMatch[1] : 'Undetermined';

    // Stream count
    const streamMatches = fullText.match(/\bstream\b/g);
    const streamCount = streamMatches ? streamMatches.length : 0;

    // Encryption check
    const isEncrypted = fullText.includes('/Encrypt');

    // Cross-reference table check
    const hasXref = fullText.includes('xref');

    // Extract Info dictionary metadata
    const meta = {
      version: pdfVersion,
      objectCount: objCount,
      pageCount: pageCount,
      streamCount: streamCount,
      encrypted: isEncrypted ? 'YES (Protected Payload)' : 'NO (Cleartext DOM)',
      xrefTable: hasXref ? 'Standard Linearized Xref' : 'Cross-Reference Stream'
    };

    const segments = [
      {
        marker: '0x2550',
        name: '%PDF-Header',
        offset: '0x0000',
        length: versionMatch ? versionMatch[0].length : 8,
        info: `${pdfVersion} Standard File Header`
      },
      {
        marker: 'OBJ_POOL',
        name: 'Cross-Reference Body Nodes',
        offset: '0x0020',
        length: bytes.length > 1024 ? 1024 : bytes.length,
        info: `${objCount} Indirect Reference Objects Indexed`
      },
      {
        marker: 'STREAM_REG',
        name: 'FlateDecode / Stream Buffers',
        offset: 'DYNAMIC',
        length: streamCount,
        info: `${streamCount} Compressed Content Streams Spliced`
      }
    ];

    if (fullText.includes('%%EOF')) {
      segments.push({
        marker: '0x2525',
        name: '%%EOF (PDF Trailer Suffix)',
        offset: 'TAIL_OFFSET',
        length: 5,
        info: 'Document Structure Terminus'
      });
    }

    return { isPdf: true, segments, meta };
  }

  /* ==========================================================================
     Orchestration: Ingest & Render Telemetry
     ========================================================================== */
  async function processTargetFile(file) {
    if (!file) return;

    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);

    // Compute cryptographic hash & shannon entropy
    const sha256 = await computeSHA256(arrayBuffer);
    const entropy = calculateShannonEntropy(bytes);

    // Generate formatted hex output
    const hexOutput = generateHexDump(bytes, 1024);
    hexStream.innerHTML = hexOutput;
    hexRangeTag.textContent = `0x0000 - 0x${Math.min(bytes.length, 1024).toString(16).toUpperCase()}`;

    // Update entropy tag
    entropyTag.textContent = `ENTROPY: ${entropy.toFixed(3)} bits/B`;

    // Parse structure
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

    // Reveal diagnostic viewport
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
          <div class="telemetry-section-title">// JPEG COMPRESSION REGISTERS</div>
          <div class="telemetry-field-grid">
            <div class="telemetry-field-card">
              <span class="field-key">Resolution</span>
              <span class="field-value">${jpegData.meta.dimensions || 'N/A'}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Color Space</span>
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
              <span class="field-key">EXIF Metadata</span>
              <span class="field-value">${jpegData.meta.exifPresent ? 'PRESENT (Segment APP1)' : 'NONE'}</span>
            </div>
          </div>
        </div>
      `;
    } else if (pdfData.isPdf) {
      detectedFormat = `ADOBE PORTABLE DOCUMENT (${pdfData.meta.version})`;
      segments = pdfData.segments;

      customRegisterHTML = `
        <div class="telemetry-section">
          <div class="telemetry-section-title">// PDF OBJECT MODEL REGISTERS</div>
          <div class="telemetry-field-grid">
            <div class="telemetry-field-card">
              <span class="field-key">Specification</span>
              <span class="field-value">${pdfData.meta.version}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Indirect Objects</span>
              <span class="field-value">${pdfData.meta.objectCount} indexed</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Document Streams</span>
              <span class="field-value">${pdfData.meta.streamCount} streams</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Reported Pages</span>
              <span class="field-value">${pdfData.meta.pageCount}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Cryptographic Security</span>
              <span class="field-value">${pdfData.meta.encrypted}</span>
            </div>
            <div class="telemetry-field-card">
              <span class="field-key">Catalog Indexing</span>
              <span class="field-value">${pdfData.meta.xrefTable}</span>
            </div>
          </div>
        </div>
      `;
    }

    // Build Entropy Bar calculation
    const entropyPercent = Math.min(100, (entropy / 8) * 100).toFixed(1);
    let entropyDescription = 'Low density (Structured text / sparse data)';
    if (entropy > 7.5) {
      entropyDescription = 'High density (Encrypted, compressed, or high entropy)';
    } else if (entropy > 5.0) {
      entropyDescription = 'Medium density (Mixed formatted structures)';
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
        <div class="telemetry-section-title">// HARDWARE TELEMETRY &amp; DIGEST REGISTERS</div>
        <div class="telemetry-field-grid">
          <div class="telemetry-field-card">
            <span class="field-key">Target Name</span>
            <span class="field-value">${escapeHTML(file.name)}</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">File Size</span>
            <span class="field-value">${formatBytes(bytesLength)} (${bytesLength.toLocaleString()} B)</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">Detected Container</span>
            <span class="field-value field-value-mono">${detectedFormat}</span>
          </div>
          <div class="telemetry-field-card">
            <span class="field-key">Browser Sandbox Privacy</span>
            <span class="field-value" style="color: var(--accent-green);">100% LOCAL (NO EGRESS)</span>
          </div>
        </div>
      </div>

      <!-- Hash & Entropy Analysis -->
      <div class="telemetry-section">
        <div class="telemetry-section-title">// CRYPTOGRAPHIC VERIFICATION &amp; ENTROPY</div>
        <div class="telemetry-field-grid">
          <div class="telemetry-field-card" style="grid-column: 1 / -1;">
            <span class="field-key">SHA-256 Checksum</span>
            <span class="field-value field-value-mono">${sha256}</span>
          </div>
        </div>
        <div class="entropy-meter">
          <div class="entropy-meter-head">
            <span class="field-key">Shannon Entropy: ${entropy.toFixed(4)} / 8.0000 bits/byte</span>
            <span class="field-key" style="color: var(--accent-amber);">${entropyPercent}%</span>
          </div>
          <div class="entropy-track">
            <div class="entropy-fill" style="width: ${entropyPercent}%;"></div>
          </div>
          <span style="font-size: 0.68rem; color: var(--text-dim);">${entropyDescription}</span>
        </div>
      </div>

      <!-- Dynamic Custom Model Registers -->
      ${customRegisterHTML}

      <!-- Segment Splicer Table -->
      <div class="telemetry-section">
        <div class="telemetry-section-title">// PARSED BINARY SEGMENT TABLE</div>
        <div class="segment-list">
          ${segments.length > 0 ? segmentsHTML : '<div class="segment-item"><span class="segment-name">No structured marker table available for this binary.</span></div>'}
        </div>
      </div>
    `;
  }

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', () => {
    initVectorCanvas();
    initDropWorkspace();
  });
})();
