// Sunbird's crypto (protocol.md §2–§7). Defines the global SunbirdCrypto.
//
// A plain script, not a module, so web/test/crypto.html works from file://.
// Needs hash-wasm's argon2 (global `hashwasm`) loaded first.
//
// Errors callers need to tell apart carry a `code`. All header offsets live
// here; callers use parseHeader rather than computing them.
(function (global) {
  'use strict';

  const VERSION = 0x01;
  const FLAG_PASSPHRASE = 0x01;

  const FRAGMENT_SECRET_LEN = 16;
  const FRAGMENT_CHARS = 22;
  const SALT_LEN = 16;
  const FILE_KEY_LEN = 32;
  const IV_LEN = 12;
  const TAG_LEN = 16;

  // §3.1
  const HEADER_PREFIX_LEN = 30;
  const METADATA_CT_LEN = 528;
  const HEADER_CORE_LEN = HEADER_PREFIX_LEN + METADATA_CT_LEN; // 558
  const MAX_HEADER_LEN = 8192;
  const MAX_SLOT_ENTRIES = 64;
  const SALT_OFFSET = 2;
  const EXPIRES_AT_OFFSET = 18;
  const MAX_DOWNLOADS_OFFSET = 26;

  // §7
  const METADATA_PLAINTEXT_LEN = 512;
  const MAX_METADATA_JSON_LEN = METADATA_PLAINTEXT_LEN - 2; // 510

  // §4.1: fixed for version 0x01, never read from the header. hash-wasm only
  // implements Argon2 v1.3; the known-answer test in crypto.html pins it.
  const ARGON2ID = {
    iterations: 3,      // t
    memorySize: 65536,  // m, in KiB (64 MiB)
    parallelism: 1,     // p
    hashLength: 32,
  };

  const INFO_WRAP = 'sunbird/v1/wrap';
  const INFO_CONTENT = 'sunbird/v1/content';
  const INFO_CONTENT_NONCE = 'sunbird/v1/content-nonce';
  const INFO_METADATA = 'sunbird/v1/metadata';
  const INFO_METADATA_NONCE = 'sunbird/v1/metadata-nonce';

  // §5, type 0x01: type u8 ‖ length u16 ‖ iv 12 ‖ wrapped_key 32 ‖ tag 16
  const ENTRY_FRAGMENT = 0x01;
  const ENTRY_FRAGMENT_BODY_LEN = IV_LEN + FILE_KEY_LEN + TAG_LEN; // 60
  const ENTRY_FRAGMENT_LEN = 1 + 2 + ENTRY_FRAGMENT_BODY_LEN;       // 63

  // §6.1, §6.4
  const RECORD_LEN = 65536;                       // rs: ciphertext bytes per record
  const RECORD_DATA_LEN = RECORD_LEN - TAG_LEN - 1; // 65519
  const MIN_RECORD_LEN = 1 + TAG_LEN;             // 17: delimiter only
  const MAX_PLAINTEXT = 104857600;                // 100 MiB
  const MAX_RECORDS = 1601;
  const DELIMITER_MORE = 0x01;
  const DELIMITER_FINAL = 0x02;

  function requireBytes(value, length, name) {
    if (!(value instanceof Uint8Array) || value.length !== length) {
      throw new Error(`${name} must be a Uint8Array of ${length} bytes`);
    }
  }

  function failure(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
  }

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // ---- §2 Fragment ----------------------------------------------------------

  function generateFragmentSecret() {
    return randomBytes(FRAGMENT_SECRET_LEN);
  }

  function generateSalt() {
    return randomBytes(SALT_LEN);
  }

  function generateFileKey() {
    return randomBytes(FILE_KEY_LEN);
  }

  // base64url, no padding: 16 bytes → 22 characters, trailing 4 bits zero.
  function encodeFragment(secret) {
    requireBytes(secret, FRAGMENT_SECRET_LEN, 'fragment secret');
    return btoa(String.fromCharCode(...secret))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // §2: exactly 22 base64url characters with the last 4 bits zero. Re-encoding
  // and comparing checks those bits.
  function decodeFragment(fragment) {
    if (typeof fragment !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(fragment)) {
      throw failure('malformed', 'Link secret is malformed: expected 22 base64url characters');
    }
    const binary = atob(fragment.replace(/-/g, '+').replace(/_/g, '/') + '==');
    const secret = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    if (secret.length !== FRAGMENT_SECRET_LEN || encodeFragment(secret) !== fragment) {
      throw failure('malformed', 'Link secret is malformed: trailing bits are not zero');
    }
    return secret;
  }

  // ---- §4.1 Passphrase ------------------------------------------------------

  async function passphraseKey(passphrase, salt) {
    if (typeof passphrase !== 'string') throw new Error('passphrase must be a string');
    requireBytes(salt, SALT_LEN, 'salt');
    // NFC-normalize, do not trim.
    const passphraseBytes = new TextEncoder().encode(passphrase.normalize('NFC'));
    if (passphraseBytes.length === 0) throw failure('empty-passphrase', 'Passphrase must not be empty');
    if (!global.hashwasm || typeof global.hashwasm.argon2id !== 'function') {
      throw new Error('hash-wasm argon2 is not loaded');
    }
    return global.hashwasm.argon2id({
      password: passphraseBytes,
      salt,
      ...ARGON2ID,
      outputType: 'binary',
    });
  }

  // ---- §4.2 Keying material -------------------------------------------------

  // One code path for both modes (D4). A passphrase is required only when the
  // flag is set.
  async function deriveIkm(flags, fragmentSecret, salt, passphrase) {
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xff) {
      throw new Error('flags must be a byte');
    }
    if (flags & ~FLAG_PASSPHRASE) throw new Error('Reserved flag bits are set');
    requireBytes(fragmentSecret, FRAGMENT_SECRET_LEN, 'fragment secret');
    requireBytes(salt, SALT_LEN, 'salt');

    if (flags & FLAG_PASSPHRASE) {
      return concat(fragmentSecret, await passphraseKey(passphrase, salt)); // 48 bytes
    }
    if (passphrase !== undefined && passphrase !== null) {
      throw new Error('A passphrase was given but the passphrase flag is not set');
    }
    return fragmentSecret.slice(); // 16 bytes
  }

  // ---- §4.3 HKDF ------------------------------------------------------------

  // HKDF-SHA256 with the header salt as HKDF salt. Returns raw bytes.
  async function hkdf(ikm, salt, info, length) {
    requireBytes(salt, SALT_LEN, 'salt');
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
      baseKey,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  // wrapping_key = HKDF(ikm, "sunbird/v1/wrap", 32), as a non-extractable AES-GCM key.
  async function deriveWrappingKey(ikm, salt) {
    const raw = await hkdf(ikm, salt, INFO_WRAP, 32);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  // content_key = HKDF(file_key, "sunbird/v1/content", 32)
  // nonce_base  = HKDF(file_key, "sunbird/v1/content-nonce", 12)
  async function deriveRecordKeys(fileKey, salt) {
    requireBytes(fileKey, FILE_KEY_LEN, 'file_key');
    const raw = await hkdf(fileKey, salt, INFO_CONTENT, 32);
    return {
      contentKey: await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
      nonceBase: await hkdf(fileKey, salt, INFO_CONTENT_NONCE, 12),
    };
  }

  // ---- §5 Key-wrapping slot -------------------------------------------------

  const ENTRY_AAD = new Uint8Array([VERSION, ENTRY_FRAGMENT]);

  // Returns the complete 63-byte entry: type ‖ length ‖ iv ‖ wrapped_key ‖ tag.
  async function wrapFileKey(wrappingKey, fileKey) {
    requireBytes(fileKey, FILE_KEY_LEN, 'file_key');
    const iv = randomBytes(IV_LEN);
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: ENTRY_AAD, tagLength: TAG_LEN * 8 },
      wrappingKey,
      fileKey,
    ));
    const entry = new Uint8Array(ENTRY_FRAGMENT_LEN);
    entry[0] = ENTRY_FRAGMENT;
    entry[1] = ENTRY_FRAGMENT_BODY_LEN >> 8;
    entry[2] = ENTRY_FRAGMENT_BODY_LEN & 0xff;
    entry.set(iv, 3);
    entry.set(sealed, 3 + IV_LEN);
    return entry;
  }

  // Unwrap one type-0x01 entry. Private, so callers always go through
  // unwrapSlot and try every entry.
  async function unwrapFileKey(wrappingKey, entry) {
    if (entry.length !== ENTRY_FRAGMENT_LEN ||
        ((entry[1] << 8) | entry[2]) !== ENTRY_FRAGMENT_BODY_LEN) {
      throw new Error('Not a well-formed type 0x01 slot entry');
    }
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: entry.subarray(3, 3 + IV_LEN), additionalData: ENTRY_AAD, tagLength: TAG_LEN * 8 },
      wrappingKey,
      entry.subarray(3 + IV_LEN),
    ));
  }

  // The only place slot entries are framed (§3.1, §5). Throws 'malformed' on
  // any bound.
  function frameSlot(bytes) {
    const pastEnd = (end) => failure('malformed', HEADER_CORE_LEN + end > MAX_HEADER_LEN
      ? 'Header is larger than 8 KiB'
      : 'Slot entry runs past the end of the bytes held');
    const count = bytes.length > 0 ? bytes[0] : 0;
    if (count === 0 || count > MAX_SLOT_ENTRIES) {
      throw failure('malformed', `Slot has ${count} entries; 1 to ${MAX_SLOT_ENTRIES} are allowed`);
    }
    const entries = [];
    let offset = 1;
    for (let k = 0; k < count; k++) {
      if (offset + 3 > bytes.length) throw pastEnd(offset + 3);
      const end = offset + 3 + ((bytes[offset + 1] << 8) | bytes[offset + 2]);
      if (end > bytes.length) throw pastEnd(end);
      entries.push(bytes.subarray(offset, end));
      offset = end;
    }
    return { entries, length: offset };
  }

  // Returns file_key from the first entry that unwraps.
  async function unwrapSlot(wrappingKey, slot) {
    if (!(slot instanceof Uint8Array)) throw new Error('slot must be a Uint8Array');
    if (slot.length > MAX_HEADER_LEN - HEADER_CORE_LEN) {
      throw failure('malformed', 'Header is larger than 8 KiB');
    }

    // Frame every entry before trying any: a malformed slot is rejected whole.
    const { entries, length } = frameSlot(slot);
    if (length !== slot.length) throw failure('malformed', 'Bytes follow the last slot entry');

    // Try every known entry in order; skip unknown types by their length.
    let triedKnown = false;
    for (const entry of entries) {
      if (entry[0] !== ENTRY_FRAGMENT) continue;
      triedKnown = true;
      try {
        return await unwrapFileKey(wrappingKey, entry);
      } catch (_) {
        // Keep going. Rejecting the whole slot gains nothing (§5).
      }
    }
    if (triedKnown) throw failure('wrong-passphrase', 'Wrong passphrase or damaged link.');
    throw failure('needs-newer-version', 'This link needs a newer version of Sunbird.');
  }

  // ---- §3.1 Header ----------------------------------------------------------

  const UNKNOWN_VERSION = 'This link was created by a newer version of Sunbird. Update your client.';

  // Parses the preview (from /api/meta) or a whole blob, checking the bounds
  // in §3.1. Nothing here is verified yet: flags and limits are just what the
  // server sent until decryptMetadata succeeds. expiresAt is a BigInt so a
  // u64 isn't silently rounded.
  function parseHeader(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('header bytes must be a Uint8Array');
    if (bytes.length === 0) throw failure('malformed', 'Header is empty');
    // Version first: another version's header may have another shape.
    if (bytes[0] !== VERSION) throw failure('unknown-version', UNKNOWN_VERSION);
    if (bytes.length < HEADER_CORE_LEN + 1) throw failure('malformed', 'Header is truncated');
    const flags = bytes[1];
    if (flags & ~FLAG_PASSPHRASE) throw failure('malformed', 'Reserved flag bits are set');

    const { length: slotLength } = frameSlot(
      bytes.subarray(HEADER_CORE_LEN, Math.min(bytes.length, MAX_HEADER_LEN)));
    const headerLength = HEADER_CORE_LEN + slotLength;
    const view = new DataView(bytes.buffer, bytes.byteOffset, HEADER_CORE_LEN);

    return Object.freeze({
      version: bytes[0],
      flags,
      salt: bytes.slice(SALT_OFFSET, SALT_OFFSET + SALT_LEN),
      expiresAt: view.getBigUint64(EXPIRES_AT_OFFSET),
      maxDownloads: view.getUint32(MAX_DOWNLOADS_OFFSET),
      metadataCt: bytes.slice(HEADER_PREFIX_LEN, HEADER_CORE_LEN),
      headerCore: bytes.slice(0, HEADER_CORE_LEN),
      slot: bytes.slice(HEADER_CORE_LEN, headerLength),
      headerLength,
    });
  }

  function requireHeaderCore(headerCore) {
    requireBytes(headerCore, HEADER_CORE_LEN, 'header_core');
    if (headerCore[0] !== VERSION) throw failure('unknown-version', UNKNOWN_VERSION);
  }

  // ---- §7 Metadata ----------------------------------------------------------

  // metadata_key = HKDF(file_key, "sunbird/v1/metadata", 32)
  // metadata_iv  = HKDF(file_key, "sunbird/v1/metadata-nonce", 12)
  // From file_key only. Each file_key encrypts exactly one metadata message.
  async function deriveMetadataKeys(fileKey, salt) {
    requireBytes(fileKey, FILE_KEY_LEN, 'file_key');
    const raw = await hkdf(fileKey, salt, INFO_METADATA, 32);
    return {
      metadataKey: await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
      metadataIv: await hkdf(fileKey, salt, INFO_METADATA_NONCE, 12),
    };
  }

  // len(json) as 2 bytes ‖ json ‖ zeros to 512. Too long is refused, never cut.
  function encodeMetadata({ name, type, size }) {
    if (typeof name !== 'string' || typeof type !== 'string') throw new Error('name and type must be strings');
    if (!Number.isSafeInteger(size) || size < 0) throw new Error('size must be a non-negative integer');

    // The bound is on encoded bytes after JSON escaping, not on characters.
    const json = new TextEncoder().encode(JSON.stringify({ name, type, size }));
    if (json.length > MAX_METADATA_JSON_LEN) {
      throw failure('name-too-long',
        `The file name is too long: with its type and size it takes ${json.length} bytes, ` +
        `and at most ${MAX_METADATA_JSON_LEN} are allowed. Shorten the name and try again.`);
    }
    const plaintext = new Uint8Array(METADATA_PLAINTEXT_LEN); // zero fill
    plaintext[0] = json.length >> 8;
    plaintext[1] = json.length & 0xff;
    plaintext.set(json, 2);
    return plaintext;
  }

  // header_prefix is the AAD, so the limits are sealed with the metadata.
  async function encryptMetadata(fileKey, headerPrefix, fields) {
    requireBytes(headerPrefix, HEADER_PREFIX_LEN, 'header_prefix');
    if (headerPrefix[0] !== VERSION) throw new Error('header_prefix is not version 0x01');
    const plaintext = encodeMetadata(fields);
    const salt = headerPrefix.slice(SALT_OFFSET, SALT_OFFSET + SALT_LEN);
    const { metadataKey, metadataIv } = await deriveMetadataKeys(fileKey, salt);
    return new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metadataIv, additionalData: headerPrefix, tagLength: TAG_LEN * 8 },
      metadataKey,
      plaintext,
    ));
  }

  // Decrypting also proves the flags and limits are what the uploader set
  // (§7, §8). Returns { name, type, size } only.
  //
  // name and type are HOSTILE: anyone can upload a file and send the link.
  // Show them with textContent only, and never let `type` decide anything.
  // Otherwise it's stored XSS on the page that holds the keys (D7).
  async function decryptMetadata(fileKey, headerCore) {
    requireHeaderCore(headerCore);
    const headerPrefix = headerCore.subarray(0, HEADER_PREFIX_LEN);
    const salt = headerCore.slice(SALT_OFFSET, SALT_OFFSET + SALT_LEN);
    const { metadataKey, metadataIv } = await deriveMetadataKeys(fileKey, salt);
    let plaintext;
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: metadataIv, additionalData: headerPrefix, tagLength: TAG_LEN * 8 },
        metadataKey,
        headerCore.subarray(HEADER_PREFIX_LEN),
      ));
    } catch (_) {
      throw failure('corrupt', 'File details failed to authenticate: the header was altered');
    }

    const jsonLen = (plaintext[0] << 8) | plaintext[1];
    if (jsonLen > MAX_METADATA_JSON_LEN) throw failure('malformed', 'File details are malformed: length over 510');
    // No legitimate encoder writes a non-zero fill byte; it would be a covert channel.
    for (let i = 2 + jsonLen; i < METADATA_PLAINTEXT_LEN; i++) {
      if (plaintext[i] !== 0) throw failure('malformed', 'File details are malformed: padding is not zero');
    }
    let fields;
    try {
      // ignoreBOM keeps a byte-order mark as U+FEFF, which JSON.parse rejects;
      // by default TextDecoder would strip it silently (§7: no BOM).
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext.subarray(2, 2 + jsonLen));
      fields = JSON.parse(text);
    } catch (_) {
      throw failure('malformed', 'File details are malformed: not UTF-8 JSON');
    }
    if (fields === null || typeof fields !== 'object' || Array.isArray(fields) ||
        typeof fields.name !== 'string' || typeof fields.type !== 'string' ||
        !Number.isSafeInteger(fields.size) || fields.size < 0) {
      throw failure('malformed', 'File details are malformed: name, type or size missing or of the wrong kind');
    }
    return Object.freeze({ name: fields.name, type: fields.type, size: fields.size });
  }

  // ---- §6 Records -----------------------------------------------------------

  // nonce_i = nonce_base XOR I2OSP(i, 12). i < 1601, so only the low bytes are non-zero.
  function recordNonce(nonceBase, i) {
    const nonce = nonceBase.slice();
    nonce[8] ^= i >>> 24;
    nonce[9] ^= (i >>> 16) & 0xff;
    nonce[10] ^= (i >>> 8) & 0xff;
    nonce[11] ^= i & 0xff;
    return nonce;
  }

  // AAD_i = version ‖ SHA-256(header_core) ‖ I2OSP(i, 8)   (41 bytes)
  function recordAad(headerHash, i) {
    const aad = new Uint8Array(1 + 32 + 8);
    aad[0] = VERSION;
    aad.set(headerHash, 1);
    new DataView(aad.buffer).setUint32(37, i);
    return aad;
  }

  async function recordContext(fileKey, headerCore) {
    requireHeaderCore(headerCore);
    const salt = headerCore.slice(SALT_OFFSET, SALT_OFFSET + SALT_LEN);
    const { contentKey, nonceBase } = await deriveRecordKeys(fileKey, salt);
    const headerHash = new Uint8Array(await crypto.subtle.digest('SHA-256', headerCore));
    return { contentKey, nonceBase, headerHash };
  }

  // Salt and AAD both come from header_core, so they can't come from different
  // headers. onProgress gets { stage, done, total } after each record.
  async function encryptRecords(fileKey, headerCore, plaintext, onProgress) {
    if (!(plaintext instanceof Uint8Array)) throw new Error('plaintext must be a Uint8Array');
    if (plaintext.length > MAX_PLAINTEXT) throw failure('too-large', 'File is larger than 100 MiB');
    const { contentKey, nonceBase, headerHash } = await recordContext(fileKey, headerCore);

    // Full records hold 65519 bytes; an empty file is one record with just
    // the final delimiter.
    const n = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / RECORD_DATA_LEN);
    const finalDataLen = plaintext.length - (n - 1) * RECORD_DATA_LEN;
    const out = new Uint8Array((n - 1) * RECORD_LEN + finalDataLen + MIN_RECORD_LEN);
    const buffer = new Uint8Array(RECORD_DATA_LEN + 1);

    for (let i = 0; i < n; i++) {
      const start = i * RECORD_DATA_LEN;
      const dataLen = i === n - 1 ? finalDataLen : RECORD_DATA_LEN;
      const recordPlaintext = buffer.subarray(0, dataLen + 1);
      recordPlaintext.set(plaintext.subarray(start, start + dataLen));
      recordPlaintext[dataLen] = i === n - 1 ? DELIMITER_FINAL : DELIMITER_MORE;
      const sealed = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: recordNonce(nonceBase, i), additionalData: recordAad(headerHash, i), tagLength: TAG_LEN * 8 },
        contentKey,
        recordPlaintext,
      ));
      out.set(sealed, i * RECORD_LEN);
      if (onProgress) onProgress({ stage: 'records', done: i + 1, total: n });
    }
    return out;
  }

  // §6.5. Returns the plaintext only when every record authenticates, the
  // final delimiter is present and the size matches.
  //
  // `expectedSize` MUST come from decryptMetadata, never from the server
  // (Content-Length, JSON, anything). Otherwise the server could pass the check.
  async function decryptRecords(fileKey, headerCore, body, expectedSize, onProgress) {
    if (!(body instanceof Uint8Array)) throw new Error('body must be a Uint8Array');
    if (!Number.isSafeInteger(expectedSize) || expectedSize < 0) {
      throw new Error('expectedSize must be a non-negative integer');
    }
    requireHeaderCore(headerCore);

    // Steps 1–3, before decrypting anything.
    if (body.length === 0) throw failure('malformed', 'File has no records');
    const n = Math.ceil(body.length / RECORD_LEN);
    if (n > MAX_RECORDS) {
      throw failure('too-many-records', `File claims ${n} records; at most ${MAX_RECORDS} are allowed`);
    }
    const finalLen = body.length - (n - 1) * RECORD_LEN;
    if (finalLen < MIN_RECORD_LEN) throw failure('malformed', 'Final record is too short');

    const { contentKey, nonceBase, headerHash } = await recordContext(fileKey, headerCore);
    const out = new Uint8Array((n - 1) * RECORD_DATA_LEN + finalLen - MIN_RECORD_LEN);

    // Steps 4–5.
    for (let i = 0; i < n; i++) {
      const isFinal = i === n - 1;
      const start = i * RECORD_LEN;
      let recordPlaintext;
      try {
        recordPlaintext = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: recordNonce(nonceBase, i), additionalData: recordAad(headerHash, i), tagLength: TAG_LEN * 8 },
          contentKey,
          body.subarray(start, isFinal ? body.length : start + RECORD_LEN),
        ));
      } catch (_) {
        throw failure('corrupt', `Record ${i} of ${n} failed to authenticate: the file is damaged or was altered`);
      }
      const delimiter = recordPlaintext[recordPlaintext.length - 1];
      if (isFinal && delimiter === DELIMITER_MORE) {
        throw failure('truncated', 'The file is truncated: its final record is missing');
      }
      if (delimiter !== (isFinal ? DELIMITER_FINAL : DELIMITER_MORE)) {
        throw failure('corrupt', `Record ${i} of ${n} has an invalid delimiter`);
      }
      out.set(recordPlaintext.subarray(0, recordPlaintext.length - 1), i * RECORD_DATA_LEN);
      if (onProgress) onProgress({ stage: 'records', done: i + 1, total: n });
    }

    // Step 6.
    if (out.length !== expectedSize) {
      throw failure('size-mismatch', `Decrypted ${out.length} bytes but the file declares ${expectedSize}`);
    }
    return out;
  }

  // ---- §10 Procedures -------------------------------------------------------

  // header_prefix = version ‖ flags ‖ salt ‖ expires_at u64 ‖ max_downloads u32
  function buildHeaderPrefix(flags, salt, expiresAt, maxDownloads) {
    const prefix = new Uint8Array(HEADER_PREFIX_LEN);
    prefix[0] = VERSION;
    prefix[1] = flags;
    prefix.set(salt, SALT_OFFSET);
    const view = new DataView(prefix.buffer);
    view.setBigUint64(EXPIRES_AT_OFFSET, expiresAt);
    view.setUint32(MAX_DOWNLOADS_OFFSET, maxDownloads);
    return prefix;
  }

  // Upload, §10 steps 1–7. No passphrase means a public link. maxDownloads 0
  // means no limit. Returns { fragment, blob }. onProgress hears
  // { stage: 'passphrase' } before Argon2id, then record counts.
  async function encryptFile(plaintext, { name, type, passphrase, expiresAt, maxDownloads, onProgress }) {
    if (!(plaintext instanceof Uint8Array)) throw new Error('plaintext must be a Uint8Array');
    // Refuse bad input before spending seconds on Argon2id.
    if (plaintext.length > MAX_PLAINTEXT) throw failure('too-large', 'File is larger than 100 MiB');
    const restricted = passphrase !== undefined;
    if (restricted && (typeof passphrase !== 'string' || passphrase === '')) {
      throw failure('empty-passphrase', 'Passphrase must not be empty');
    }
    const expires = typeof expiresAt === 'bigint' ? expiresAt
      : Number.isSafeInteger(expiresAt) ? BigInt(expiresAt) : -1n;
    if (expires < 0n || expires > 0xffffffffffffffffn) throw new Error('expiresAt must be a u64');
    if (!Number.isInteger(maxDownloads) || maxDownloads < 0 || maxDownloads > 0xffffffff) {
      throw new Error('maxDownloads must be a u32');
    }
    const fields = { name, type, size: plaintext.length };
    encodeMetadata(fields);

    // 1–2
    const secret = generateFragmentSecret();
    const salt = generateSalt();
    const fileKey = generateFileKey();
    const flags = restricted ? FLAG_PASSPHRASE : 0;
    const prefix = buildHeaderPrefix(flags, salt, expires, maxDownloads);
    // 3
    if (restricted && onProgress) onProgress({ stage: 'passphrase' });
    const ikm = await deriveIkm(flags, secret, salt, passphrase);
    const wrappingKey = await deriveWrappingKey(ikm, salt);
    // 4
    const metadataCt = await encryptMetadata(fileKey, prefix, fields);
    // 5
    const slot = concat(new Uint8Array([1]), await wrapFileKey(wrappingKey, fileKey));
    // 6
    const headerCore = concat(prefix, metadataCt);
    // 7
    const body = await encryptRecords(fileKey, headerCore, plaintext, onProgress);
    return {
      fragment: encodeFragment(secret),
      blob: new Blob([headerCore, slot, body], { type: 'application/octet-stream' }),
    };
  }

  // Download, §10 steps 3–4. Returns file_key.
  async function unlockFile(header, fragmentSecret, passphrase) {
    const restricted = (header.flags & FLAG_PASSPHRASE) !== 0;
    if (restricted && (typeof passphrase !== 'string' || passphrase === '')) {
      throw failure('empty-passphrase', 'Passphrase must not be empty');
    }
    const ikm = await deriveIkm(header.flags, fragmentSecret, header.salt, restricted ? passphrase : undefined);
    return unwrapSlot(await deriveWrappingKey(ikm, header.salt), header.slot);
  }

  // Download, §10 step 6. Returns { metadata, plaintext } only after every
  // check in §6.5 and §7 passes. The expected size is decrypted here, so no
  // caller (and never the server) supplies it.
  async function decryptFile(fileKey, preview, blob, onProgress) {
    if (!(blob instanceof Uint8Array)) throw new Error('blob must be a Uint8Array');
    requireBytes(preview.headerCore, HEADER_CORE_LEN, 'preview header_core');
    const downloaded = parseHeader(blob);
    for (let i = 0; i < HEADER_CORE_LEN; i++) {
      if (downloaded.headerCore[i] !== preview.headerCore[i]) {
        throw failure('corrupt', 'The downloaded file does not match its preview: the server changed its header between the two requests');
      }
    }
    const metadata = await decryptMetadata(fileKey, downloaded.headerCore);
    // Records begin after the DOWNLOADED slot, which may have grown since the preview (§5).
    const plaintext = await decryptRecords(fileKey, downloaded.headerCore,
      blob.subarray(downloaded.headerLength), metadata.size, onProgress);
    return { metadata, plaintext };
  }

  global.SunbirdCrypto = Object.freeze({
    VERSION,
    FLAG_PASSPHRASE,
    generateFragmentSecret,
    generateSalt,
    generateFileKey,
    encodeFragment,
    decodeFragment,
    passphraseKey,
    deriveIkm,
    hkdf,
    deriveWrappingKey,
    wrapFileKey,
    unwrapSlot,
    parseHeader,
    encryptMetadata,
    decryptMetadata,
    encryptRecords,
    decryptRecords,
    encryptFile,
    unlockFile,
    decryptFile,
  });
})(typeof globalThis !== 'undefined' ? globalThis : self);
