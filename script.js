/* ============================================================
   StegoSafe — LSB Steganography + AES-256-GCM (Web Crypto API)
   Pure vanilla JavaScript · No dependencies · Runs entirely
   in the browser.
   ============================================================ */

(() => {
  "use strict";

  /* ============================================================
     SECTION 1 — DOM references
     ============================================================ */
  const $ = (id) => document.getElementById(id);

  // Header
  const yearEl = $("year");

  // Encode panel
  const encodeFile          = $("encodeFile");
  const encodeDrop          = $("encodeDrop");
  const encodePreviewWrap   = $("encodePreviewWrap");
  const encodePreview       = $("encodePreview");
  const encodeMeta          = $("encodeMeta");
  const secretMessage       = $("secretMessage");
  const charCount           = $("charCount");
  const useEncryption       = $("useEncryption");
  const passwordArea        = $("passwordArea");
  const encPassword         = $("encPassword");
  const encPasswordConfirm  = $("encPasswordConfirm");
  const passwordHint        = $("passwordHint");
  const encodeBtn           = $("encodeBtn");
  const encodeSpinner       = $("encodeSpinner");
  const encodeBtnLabel      = $("encodeBtnLabel");
  const encodeStatus        = $("encodeStatus");
  const encodePlaceholder   = $("encodePlaceholder");
  const encodeResultWrap    = $("encodeResultWrap");
  const encodeResult        = $("encodeResult");
  const encodeResultMeta    = $("encodeResultMeta");
  const downloadLink        = $("downloadLink");

  // Decode panel
  const decodeFile          = $("decodeFile");
  const decodeDrop          = $("decodeDrop");
  const decodePreviewWrap   = $("decodePreviewWrap");
  const decodePreview       = $("decodePreview");
  const decodeMeta          = $("decodeMeta");
  const useDecryption       = $("useDecryption");
  const decryptArea         = $("decryptArea");
  const decPassword         = $("decPassword");
  const decodeBtn           = $("decodeBtn");
  const decodeSpinner       = $("decodeSpinner");
  const decodeBtnLabel      = $("decodeBtnLabel");
  const decodeStatus        = $("decodeStatus");
  const clearDecodeBtn      = $("clearDecodeBtn");
  const recoveredMessage    = $("recoveredMessage");
  const copyMsg             = $("copyMsg");

  /* ============================================================
     SECTION 2 — Constants
     ============================================================ */

  // Payload layout:
  // [magic(4)] [version(1)] [flag(1)] [length(4)] [crc32(4)] [data(length)]
  const MAGIC          = new Uint8Array([0x53, 0x54, 0x45, 0x47]); // "STEG"
  const VERSION        = 1;
  const FLAG_PLAIN     = 0;
  const FLAG_ENCRYPTED = 1;
  const HEADER_LEN     = 4 + 1 + 1 + 4 + 4; // = 14 bytes

  const PBKDF2_ITERATIONS = 100000;
  const SALT_LEN          = 16;
  const IV_LEN            = 12;

  const MAX_IMAGE_DIM = 4096; // safety limit for memory

  /* ============================================================
     SECTION 3 — State
     ============================================================ */
  let encodeImageData = null;   // ImageData of the cover image
  let decodeImageData = null;   // ImageData of the stego image
  let lastObjectURL   = null;   // track for cleanup

  /* ============================================================
     SECTION 4 — Small utilities
     ============================================================ */

  const setStatus = (el, msg, type = "info") => {
    el.textContent = msg;
    el.className = "status " + type;
  };

  const setLoading = (spinner, labelEl, btn, loading, defaultLabel) => {
    if (loading) {
      spinner.classList.remove("hidden");
      btn.disabled = true;
    } else {
      spinner.classList.add("hidden");
      if (labelEl) labelEl.textContent = defaultLabel;
    }
  };

  const formatBytes = (n) => {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  };

  /* ============================================================
     SECTION 5 — CRC-32 (for payload integrity detection)
     ============================================================ */

  const crc32Table = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  const crc32 = (bytes) => {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      crc = crc32Table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
  };

  /* ============================================================
     SECTION 6 — Byte helpers
     ============================================================ */

  const u32ToBytes = (n) => [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8)  & 0xff,
    n & 0xff
  ];

  const bytesToU32 = (b, o) =>
    (((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0);

  /* ============================================================
     SECTION 7 — Crypto: PBKDF2 + AES-256-GCM
     ============================================================ */

  const deriveKey = async (password, salt) => {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  };

  /**
   * Encrypts plaintext with AES-256-GCM.
   * Output layout: salt(16) | iv(12) | ciphertext+authTag
   */
  const encryptPayload = async (plaintext, password) => {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key  = await deriveKey(password, salt);
    const enc  = new TextEncoder();
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        enc.encode(plaintext)
      )
    );
    const out = new Uint8Array(SALT_LEN + IV_LEN + cipher.length);
    out.set(salt, 0);
    out.set(iv, SALT_LEN);
    out.set(cipher, SALT_LEN + IV_LEN);
    return out;
  };

  /**
   * Decrypts a packed payload from encryptPayload().
   * Throws if the password is wrong or the data is corrupted.
   */
  const decryptPayload = async (packed, password) => {
    if (packed.length < SALT_LEN + IV_LEN + 16) {
      throw new Error("Encrypted payload is too short or corrupted.");
    }
    const salt   = packed.slice(0, SALT_LEN);
    const iv     = packed.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const cipher = packed.slice(SALT_LEN + IV_LEN);
    const key    = await deriveKey(password, salt);
    const plain  = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );
    return new TextDecoder().decode(plain);
  };

  /* ============================================================
     SECTION 8 — LSB Embed / Extract
     ============================================================ */

  const lsbCapacity = (imageData) =>
    Math.floor((imageData.width * imageData.height * 3) / 8);

  const buildPayload = (dataBytes, encryptedFlag) => {
    const checksum = crc32(dataBytes);
    const payload  = new Uint8Array(HEADER_LEN + dataBytes.length);
    let o = 0;
    for (const b of MAGIC) payload[o++] = b;
    payload[o++] = VERSION;
    payload[o++] = encryptedFlag;
    const lenBytes = u32ToBytes(dataBytes.length);
    for (const b of lenBytes) payload[o++] = b;
    const crcBytes = u32ToBytes(checksum);
    for (const b of crcBytes) payload[o++] = b;
    payload.set(dataBytes, o);
    return payload;
  };

  const embedLSB = (imageData, payload) => {
    const capacity = lsbCapacity(imageData);
    if (payload.length > capacity) {
      throw new Error(
        `Payload too large: needs ${payload.length} bytes, image capacity is ` +
        `${capacity} bytes (${formatBytes(capacity)}). Use a larger image or shorter message.`
      );
    }
    const data      = imageData.data;
    const totalBits = payload.length * 8;
    let bitIndex    = 0;

    for (let i = 0; i < data.length && bitIndex < totalBits; i += 4) {
      for (let c = 0; c < 3 && bitIndex < totalBits; c++) {
        const byteIdx = bitIndex >> 3;
        const bit     = (payload[byteIdx] >> (7 - (bitIndex & 7))) & 1;
        data[i + c]   = (data[i + c] & 0xfe) | bit;
        bitIndex++;
      }
      // Alpha channel (i + 3) is left untouched
    }
    return imageData;
  };

  const extractLSB = (imageData) => {
    const data     = imageData.data;
    const capacity = lsbCapacity(imageData);

    if (capacity < HEADER_LEN) {
      throw new Error("Image is too small to contain a StegoSafe payload.");
    }

    // Reads `count` bytes worth of bits starting at `startBit`, in the same
    // RGB order used during embedding.
    const readBits = (startBit, count) => {
      const bytes = new Uint8Array(count);
      let bitIndex = startBit;
      for (let b = 0; b < count; b++) {
        let val = 0;
        for (let k = 0; k < 8; k++) {
          const pixelIdx = Math.floor(bitIndex / 3);
          const channel  = bitIndex % 3;
          const dataIdx  = pixelIdx * 4 + channel;
          val = (val << 1) | (data[dataIdx] & 1);
          bitIndex++;
        }
        bytes[b] = val;
      }
      return bytes;
    };

    const header = readBits(0, HEADER_LEN);

    for (let i = 0; i < MAGIC.length; i++) {
      if (header[i] !== MAGIC[i]) {
        throw new Error(
          "No StegoSafe payload detected in this image. " +
          "Make sure you uploaded the stego PNG produced by StegoSafe."
        );
      }
    }

    const version = header[4];
    const flag    = header[5];
    const length  = bytesToU32(header, 6);
    const expectedCrc = bytesToU32(header, 10);

    if (version !== VERSION) {
      throw new Error(`Unsupported payload version: ${version}`);
    }
    if (length < 0 || HEADER_LEN + length > capacity) {
      throw new Error(
        "The embedded payload length exceeds the image capacity — " +
        "the image may be corrupted or was resized/recompressed."
      );
    }

    const body      = readBits(HEADER_LEN * 8, length);
    const actualCrc = crc32(body);

    if (actualCrc !== expectedCrc) {
      throw new Error(
        "Checksum mismatch — the image has been modified, resized, " +
        "or recompressed. LSB data is destroyed by such operations."
      );
    }

    return { body, encrypted: flag === FLAG_ENCRYPTED };
  };

  /* ============================================================
     SECTION 9 — Image loading helpers
     ============================================================ */

  const loadImageFile = (file) =>
    new Promise((resolve, reject) => {
      if (!file || !file.type.startsWith("image/")) {
        return reject(new Error("Please select a valid image file."));
      }
      if (file.type === "image/jpeg" || file.type === "image/jpg") {
        return reject(
          new Error(
            "JPEG is not supported — lossy compression destroys hidden data. " +
            "Please use PNG, BMP, or WEBP."
          )
        );
      }
      if (lastObjectURL) URL.revokeObjectURL(lastObjectURL);
      lastObjectURL = URL.createObjectURL(file);

      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(lastObjectURL);
        lastObjectURL = null;
        resolve(img);
      };
      img.onerror = () => {
        URL.revokeObjectURL(lastObjectURL);
        lastObjectURL = null;
        reject(new Error("Failed to load image. The file may be corrupted."));
      };
      img.src = lastObjectURL;
    });

  const imageToImageData = (img) => {
    let width  = img.naturalWidth  || img.width;
    let height = img.naturalHeight || img.height;

    if (width > MAX_IMAGE_DIM || height > MAX_IMAGE_DIM) {
      const scale = MAX_IMAGE_DIM / Math.max(width, height);
      width  = Math.max(1, Math.floor(width  * scale));
      height = Math.max(1, Math.floor(height * scale));
    }

    const canvas = document.createElement("canvas");
    canvas.width  = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, width, height);
    return ctx.getImageData(0, 0, width, height);
  };

  const drawPreview = (canvas, imageData) => {
    canvas.width  = imageData.width;
    canvas.height = imageData.height;
    const ctx = canvas.getContext("2d");
    ctx.putImageData(imageData, 0, 0);
  };

  /* ============================================================
     SECTION 10 — Dropzone wiring
     ============================================================ */

  const wireDropzone = (dropEl, inputEl, onFile) => {
    dropEl.addEventListener("click", () => inputEl.click());

    dropEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        inputEl.click();
      }
    });

    inputEl.addEventListener("change", () => {
      if (inputEl.files && inputEl.files[0]) onFile(inputEl.files[0]);
    });

    ["dragenter", "dragover"].forEach((evt) =>
      dropEl.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropEl.classList.add("dragover");
      })
    );

    ["dragleave", "drop"].forEach((evt) =>
      dropEl.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropEl.classList.remove("dragover");
      })
    );

    dropEl.addEventListener("drop", (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) onFile(f);
    });
  };

  /* ============================================================
     SECTION 11 — ENCODE flow
     ============================================================ */

  const updateEncodeButton = () => {
    let ok = !!encodeImageData && secretMessage.value.trim().length > 0;
    if (useEncryption.checked) {
      const match = encPassword.value.length >= 6 &&
                    encPassword.value === encPasswordConfirm.value;
      ok = ok && match;
      passwordHint.textContent = !encPassword.value
        ? "Password must be at least 6 characters."
        : encPassword.value.length < 6
          ? "Password is too short (min 6 characters)."
          : encPassword.value !== encPasswordConfirm.value
            ? "Passwords do not match."
            : "✓ Passwords match.";
    } else {
      passwordHint.textContent = "";
    }
    encodeBtn.disabled = !ok;
  };

  wireDropzone(encodeDrop, encodeFile, async (file) => {
    try {
      setStatus(encodeStatus, "Loading image…", "info");
      const img = await loadImageFile(file);
      encodeImageData = imageToImageData(img);
      drawPreview(encodePreview, encodeImageData);

      const capacity = lsbCapacity(encodeImageData);
      encodeMeta.innerHTML =
        `<strong>${file.name}</strong><br>` +
        `📐 ${encodeImageData.width} × ${encodeImageData.height} px · ` +
        `🔋 Capacity ≈ ${formatBytes(capacity)} (${capacity} bytes)`;

      encodePreviewWrap.classList.remove("hidden");
      updateEncodeButton();
      setStatus(encodeStatus, "Cover image loaded. Ready to embed.", "ok");
    } catch (err) {
      encodeImageData = null;
      encodePreviewWrap.classList.add("hidden");
      setStatus(encodeStatus, err.message, "err");
      updateEncodeButton();
    }
  });

  secretMessage.addEventListener("input", () => {
    charCount.textContent = secretMessage.value.length;
    updateEncodeButton();
  });

  useEncryption.addEventListener("change", () => {
    passwordArea.classList.toggle("hidden", !useEncryption.checked);
    updateEncodeButton();
  });

  [encPassword, encPasswordConfirm].forEach((el) =>
    el.addEventListener("input", updateEncodeButton)
  );

  encodeBtn.addEventListener("click", async () => {
    if (!encodeImageData) return;

    setLoading(encodeSpinner, null, encodeBtn, true);
    encodeBtnLabel.textContent = "Processing…";
    encodeResultWrap.classList.add("hidden");
    encodePlaceholder.classList.remove("hidden");
    encodePlaceholder.innerHTML =
      '<div class="placeholder-icon">⏳</div><p>Processing…</p>';
    setStatus(encodeStatus, "Preparing payload…", "info");

    try {
      const message = secretMessage.value;
      let dataBytes, flag;

      if (useEncryption.checked) {
        setStatus(encodeStatus, "Encrypting with AES‑256‑GCM…", "info");
        dataBytes = await encryptPayload(message, encPassword.value);
        flag = FLAG_ENCRYPTED;
      } else {
        dataBytes = new TextEncoder().encode(message);
        flag = FLAG_PLAIN;
      }

      setStatus(encodeStatus, "Building payload…", "info");
      const payload  = buildPayload(dataBytes, flag);
      const capacity = lsbCapacity(encodeImageData);

      if (payload.length > capacity) {
        throw new Error(
          `Message too large for this image. Payload needs ${payload.length} bytes ` +
          `but image capacity is ${capacity} bytes (${formatBytes(capacity)}). ` +
          `Use a larger image or a shorter message.`
        );
      }

      setStatus(encodeStatus, "Embedding into pixels…", "info");

      // Clone so the preview source is untouched
      const work = new ImageData(
        new Uint8ClampedArray(encodeImageData.data),
        encodeImageData.width,
        encodeImageData.height
      );
      embedLSB(work, payload);

      drawPreview(encodeResult, work);

      const pct = ((payload.length / capacity) * 100).toFixed(1);
      encodeResultMeta.innerHTML =
        `✅ Embedded ${payload.length} bytes · ` +
        `${flag === FLAG_ENCRYPTED ? "🔒 AES‑256 encrypted" : "📝 Plaintext"} · ` +
        `${pct}% of capacity used`;

      const dataUrl = encodeResult.toDataURL("image/png");
      downloadLink.href = dataUrl;
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      downloadLink.download = `stegosafe-${stamp}.png`;

      encodeResultWrap.classList.remove("hidden");
      encodePlaceholder.classList.add("hidden");

      setStatus(
        encodeStatus,
        flag === FLAG_ENCRYPTED
          ? "✓ Stego image created with AES‑256 encryption. Download it and keep your password safe."
          : "✓ Stego image created. Download it now.",
        "ok"
      );
    } catch (err) {
      console.error("Encode error:", err.message);
      setStatus(encodeStatus, err.message || "Embedding failed.", "err");
      encodePlaceholder.innerHTML =
        '<div class="placeholder-icon">⚠️</div><p>Embedding failed — see status above.</p>';
      encodePlaceholder.classList.remove("hidden");
      encodeResultWrap.classList.add("hidden");
    } finally {
      setLoading(encodeSpinner, encodeBtnLabel, encodeBtn, false, "🔒 Embed Message");
      updateEncodeButton();
    }
  });

  /* ============================================================
     SECTION 12 — DECODE flow
     ============================================================ */

  const updateDecodeButton = () => {
    let ok = !!decodeImageData;
    if (useDecryption.checked) {
      ok = ok && decPassword.value.length > 0;
    }
    decodeBtn.disabled = !ok;
  };

  wireDropzone(decodeDrop, decodeFile, async (file) => {
    try {
      setStatus(decodeStatus, "Loading image…", "info");
      const img = await loadImageFile(file);
      decodeImageData = imageToImageData(img);
      drawPreview(decodePreview, decodeImageData);

      decodeMeta.innerHTML =
        `<strong>${file.name}</strong><br>` +
        `📐 ${decodeImageData.width} × ${decodeImageData.height} px · ` +
        `${formatBytes(file.size)}`;

      decodePreviewWrap.classList.remove("hidden");
      recoveredMessage.value = "";
      copyMsg.disabled = true;
      updateDecodeButton();
      setStatus(decodeStatus, "Stego image loaded. Ready to extract.", "ok");
    } catch (err) {
      decodeImageData = null;
      decodePreviewWrap.classList.add("hidden");
      setStatus(decodeStatus, err.message, "err");
      updateDecodeButton();
    }
  });

  useDecryption.addEventListener("change", () => {
    decryptArea.classList.toggle("hidden", !useDecryption.checked);
    updateDecodeButton();
  });

  decPassword.addEventListener("input", updateDecodeButton);

  decodeBtn.addEventListener("click", async () => {
    if (!decodeImageData) return;

    setLoading(decodeSpinner, null, decodeBtn, true);
    decodeBtnLabel.textContent = "Extracting…";
    recoveredMessage.value = "";
    copyMsg.disabled = true;
    setStatus(decodeStatus, "Reading LSB data…", "info");

    try {
      const { body, encrypted } = extractLSB(decodeImageData);

      // Warn if the checkbox doesn't match the payload flag
      if (encrypted && !useDecryption.checked) {
        throw new Error(
          "This payload is AES‑256 encrypted. Enable “Message is encrypted” " +
          "and enter the password."
        );
      }
      if (!encrypted && useDecryption.checked) {
        setStatus(
          decodeStatus,
          "Note: the payload is plaintext (not encrypted) — ignoring password.",
          "warn"
        );
      }

      let text;
      if (encrypted) {
        setStatus(decodeStatus, "Decrypting with AES‑256‑GCM…", "info");
        try {
          text = await decryptPayload(body, decPassword.value);
        } catch (cryptoErr) {
          throw new Error(
            "Decryption failed — incorrect password or corrupted payload."
          );
        }
      } else {
        text = new TextDecoder().decode(body);
      }

      recoveredMessage.value = text;
      copyMsg.disabled = false;
      setStatus(
        decodeStatus,
        encrypted
          ? "✓ Message decrypted and recovered successfully."
          : "✓ Message recovered successfully.",
        "ok"
      );
    } catch (err) {
      console.error("Decode error:", err.message);
      setStatus(decodeStatus, err.message || "Extraction failed.", "err");
    } finally {
      setLoading(decodeSpinner, decodeBtnLabel, decodeBtn, false, "🔓 Extract Message");
      updateDecodeButton();
    }
  });

  clearDecodeBtn.addEventListener("click", () => {
    decodeFile.value = "";
    decodeImageData = null;
    decPassword.value = "";
    useDecryption.checked = false;
    decryptArea.classList.add("hidden");
    decodePreviewWrap.classList.add("hidden");
    recoveredMessage.value = "";
    copyMsg.disabled = true;
    decodeMeta.textContent = "";
    setStatus(decodeStatus, "", "info");
    updateDecodeButton();
    // Reset preview canvas
    decodePreview.width = 0;
    decodePreview.height = 0;
  });

  copyMsg.addEventListener("click", async () => {
    if (!recoveredMessage.value) return;
    try {
      await navigator.clipboard.writeText(recoveredMessage.value);
      const old = copyMsg.textContent;
      copyMsg.textContent = "✓ Copied!";
      setTimeout(() => { copyMsg.textContent = old; }, 1500);
    } catch {
      // Fallback for older browsers / non-HTTPS
      recoveredMessage.select();
      document.execCommand("copy");
    }
  });

  /* ============================================================
     SECTION 13 — Tab navigation
     ============================================================ */

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      const panel = document.getElementById("panel-" + tab.dataset.tab);
      if (panel) panel.classList.add("active");
    });
  });

  /* ============================================================
     SECTION 14 — Init
     ============================================================ */

  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Initial state
  updateEncodeButton();
  updateDecodeButton();
})();