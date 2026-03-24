// ============================================================
//  PGP-Like Encryption System — Custom RSA Implementation
//  Pure JavaScript / BigInt — No external crypto libraries
// ============================================================

// ── 1. RANDOM BIGINT GENERATOR ──────────────────────────────
function bigRand(bits) {
    let n = 0n;
    for (let i = 0; i < bits; i++) {
      n = (n << 1n) | BigInt(Math.random() < 0.5 ? 0 : 1);
    }// ============================================================
//  PGP-Like Encryption System -- Custom RSA Implementation
//  Pure JavaScript / BigInt -- No external crypto libraries
// ============================================================

// --- 1. RANDOM BIGINT GENERATOR ------------------------------
// Generates a random BigInt of exactly `bits` bits.
// The lowest bit is forced to 1 (all primes > 2 are odd).
function bigRand(bits) {
    var n = 0n;
    for (var i = 0; i < bits; i++) {
      n = (n << 1n) | BigInt(Math.random() < 0.5 ? 0 : 1);
    }
    return n | 1n;
  }
  
  // --- 2. MODULAR EXPONENTIATION (Square-and-Multiply) ---------
  // Computes base^exp mod in O(log exp) multiplications.
  // Used by encrypt, decrypt, sign, and verify.
  function modpow(base, exp, mod) {
    var result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = result * base % mod;
      }
      exp = exp >> 1n;
      base = base * base % mod;
    }
    return result;
  }
  
  // --- 3. GREATEST COMMON DIVISOR (Euclidean Algorithm) --------
  // Used to verify gcd(e, phi) === 1 before key derivation.
  function gcd(a, b) {
    while (b) {
      var t = b;
      b = a % b;
      a = t;
    }
    return a;
  }
  
  // --- 4. MODULAR INVERSE (Extended Euclidean Algorithm) -------
  // Returns d such that: e * d === 1 (mod phi).
  // This is the private exponent derived from the public one.
  function modInverse(e, phi) {
    var old_r = e,  r = phi;
    var old_s = 1n, s = 0n;
    while (r !== 0n) {
      var q = old_r / r;
      var tmp_r = r;
      r = old_r - q * r;
      old_r = tmp_r;
      var tmp_s = s;
      s = old_s - q * s;
      old_s = tmp_s;
    }
    return ((old_s % phi) + phi) % phi;
  }
  
  // --- 5. MILLER-RABIN PRIMALITY TEST --------------------------
  // Returns true if n is probably prime.
  // k = witness rounds; false-positive rate <= 4^(-k).
  function millerRabin(n, k) {
    k = k || 10;
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;
  
    // Write n-1 as 2^r * d
    var r = 0n;
    var d = n - 1n;
    while (d % 2n === 0n) {
      d = d >> 1n;
      r++;
    }
  
    for (var i = 0; i < k; i++) {
      var a = (bigRand(64) % (n - 4n)) + 2n;
      var x = modpow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      var composite = true;
      for (var j = 0n; j < r - 1n; j++) {
        x = modpow(x, 2n, n);
        if (x === n - 1n) { composite = false; break; }
      }
      if (composite) return false;
    }
    return true;
  }
  
  // --- 6. PRIME NUMBER GENERATOR -------------------------------
  // Finds a random prime of exactly `bits` bits.
  function randPrime(bits) {
    for (var attempts = 0; attempts < 10000; attempts++) {
      var n = bigRand(bits);
      n = n | (1n << BigInt(bits - 1));
      n = n | 1n;
      if (millerRabin(n, 10)) return n;
    }
    throw new Error("Prime generation failed after 10000 attempts");
  }
  
  // --- 7. RSA KEY PAIR GENERATION ------------------------------
  // Returns: { owner, bits, p, q, n, phi, e, d }
  // p, q, phi, d are secret; n and e are public.
  function generateKeyPair(bits, owner) {
    owner = owner || "User";
    var half = bits / 2;
    var p = randPrime(half);
    var q;
    do { q = randPrime(half); } while (q === p);
    var n   = p * q;
    var phi = (p - 1n) * (q - 1n);
    var e   = 65537n;
    if (gcd(e, phi) !== 1n) throw new Error("gcd(e, phi) != 1");
    var d = modInverse(e, phi);
    return { owner: owner, bits: bits, p: p, q: q, n: n, phi: phi, e: e, d: d };
  }
  
  // --- 8. STRING -> BIGINT BLOCKS ------------------------------
  // Packs UTF-8 bytes into BigInt values sized to fit below n.
  // blockBytes = (keyBits/2 - 4) ensures every block < n.
  function strToBlocks(msg, keyBits) {
    var bytes = new TextEncoder().encode(msg);
    var blockBytes = Math.max(1, Math.floor(keyBits / 2 / 8) - 1);
    var blocks = [];
    for (var i = 0; i < bytes.length; i += blockBytes) {
      var val = 0n;
      var count = 0;
      for (var j = 0; j < blockBytes && (i + j) < bytes.length; j++) {
        val = (val << 8n) | BigInt(bytes[i + j]);
        count++;
      }
      // Store actual byte count alongside value so decoding is exact
      blocks.push({ val: val, len: count });
    }
    return blocks;
  }
  
  // --- 9. BIGINT BLOCKS -> STRING ------------------------------
  // Reverses strToBlocks using the stored byte counts.
  function blocksToStr(blocks) {
    var allBytes = [];
    for (var i = 0; i < blocks.length; i++) {
      var v = blocks[i].val;
      var len = blocks[i].len;
      var chunk = [];
      for (var j = 0; j < len; j++) {
        chunk.unshift(Number(v & 0xffn));
        v = v >> 8n;
      }
      allBytes = allBytes.concat(chunk);
    }
    return new TextDecoder().decode(new Uint8Array(allBytes));
  }
  
  // --- 10. ENCRYPT ---------------------------------------------
  // c = m^e mod n for each plaintext block.
  // Returns colon-separated pairs: "hexCipher/blockLen:..."
  function encrypt(publicKey, message) {
    var blocks = strToBlocks(message, publicKey.bits);
    var hexWidth = publicKey.bits / 4;
    var result = [];
    for (var i = 0; i < blocks.length; i++) {
      var m = blocks[i].val;
      if (m >= publicKey.n) throw new Error("Block >= n: use larger key");
      var c = modpow(m, publicKey.e, publicKey.n);
      var hex = c.toString(16);
      while (hex.length < hexWidth) { hex = "0" + hex; }
      result.push(hex + "/" + blocks[i].len);
    }
    return result.join(":");
  }
  
  // --- 11. DECRYPT ---------------------------------------------
  // m = c^d mod n for each ciphertext block.
  function decrypt(privateKey, ciphertext) {
    var parts = ciphertext.split(":");
    var blocks = [];
    for (var i = 0; i < parts.length; i++) {
      var pair = parts[i].split("/");
      var c   = BigInt("0x" + pair[0]);
      var len = parseInt(pair[1], 10);
      var m   = modpow(c, privateKey.d, privateKey.n);
      blocks.push({ val: m, len: len });
    }
    return blocksToStr(blocks);
  }
  
  // --- 12. FNV-1a HASH -----------------------------------------
  // 32-bit non-cryptographic hash used as message digest.
  // NOTE: replace with SHA-256 (SubtleCrypto) for production use.
  function fnv1aHash(msg) {
    var h = 0x811c9dc5n;
    var bytes = new TextEncoder().encode(msg);
    for (var i = 0; i < bytes.length; i++) {
      h = h ^ BigInt(bytes[i]);
      h = (h * 0x01000193n) & 0xFFFFFFFFn;
    }
    return h;
  }
  
  // --- 13. SIGN ------------------------------------------------
  // sig = H(m)^d mod n  -- sign hash with private key.
  function sign(privateKey, message) {
    var h = fnv1aHash(message);
    if (h >= privateKey.n) throw new Error("Hash >= n: use larger key");
    return modpow(h, privateKey.d, privateKey.n).toString(16);
  }
  
  // --- 14. VERIFY ----------------------------------------------
  // recovered = sig^e mod n; compare to H(message).
  function verify(publicKey, message, signatureHex) {
    var sig = BigInt("0x" + signatureHex);
    var recovered = modpow(sig, publicKey.e, publicKey.n);
    return recovered === fnv1aHash(message);
  }
  
  // ============================================================
  //  DEMO
  // ============================================================
  function demo() {
    console.log("==============================================");
    console.log("  PGP-Like RSA System -- Demo");
    console.log("==============================================\n");
  
    console.log("[1] Generating 128-bit key pair for Alice...");
    var alice = generateKeyPair(128, "Alice");
    console.log("    n   = " + alice.n.toString(16));
    console.log("    e   = " + alice.e.toString(16));
    console.log("    d   = " + alice.d.toString(16));
    console.log("    e*d mod phi(n) = " +
      ((alice.e * alice.d) % alice.phi).toString() + " (must be 1)");
  
    var message = "Hello, RSA World!";
    console.log("\n[2] Encrypting: \"" + message + "\"");
    var ciphertext = encrypt(alice, message);
    console.log("    Ciphertext: " + ciphertext);
  
    console.log("\n[3] Decrypting...");
    var plaintext = decrypt(alice, ciphertext);
    console.log("    Decrypted: \"" + plaintext + "\"");
    console.log("    Match: " + (plaintext === message ? "YES -- correct!" : "NO -- error!"));
  
    console.log("\n[4] Signing...");
    var signature = sign(alice, message);
    console.log("    Signature: " + signature);
  
    console.log("\n[5] Verifying (original message)...");
    console.log("    Result: " + (verify(alice, message, signature) ? "VALID" : "INVALID"));
  
    console.log("\n[6] Verifying (tampered message)...");
    var tampered = "Hello, RSA World? TAMPERED";
    console.log("    Result: " + (verify(alice, tampered, signature)
      ? "VALID" : "INVALID -- tamper detected! (correct)"));
  
    console.log("\n[7] Two-party: Alice encrypts for Bob...");
    var bob = generateKeyPair(128, "Bob");
    var secret = "Meet at noon.";
    var ct = encrypt(bob, secret);
    var pt = decrypt(bob, ct);
    console.log("    Original : \"" + secret + "\"");
    console.log("    Decrypted: \"" + pt + "\"");
    console.log("    Match: " + (pt === secret ? "YES -- correct!" : "NO -- error!"));
  
    console.log("\n==============================================");
    console.log("  All tests complete.");
    console.log("==============================================");
  }
  
  if (typeof module !== "undefined" && require.main === module) {
    demo();
  }
    return n | 1n; // Force odd
  }
  
  // ── 2. MODULAR EXPONENTIATION (Square-and-Multiply) ─────────
  function modpow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = result * base % mod;
      exp = exp >> 1n;
      base = base * base % mod;
    }
    return result;
  }
  
  // ── 3. GREATEST COMMON DIVISOR ──────────────────────────────
  function gcd(a, b) {
    while (b) { [a, b] = [b, a % b]; }
    return a;
  }
  
  // ── 4. MODULAR INVERSE (Extended Euclidean Algorithm) ────────
  // Computes d = e^(-1) mod phi  =>  e * d ≡ 1 (mod phi)
  function modInverse(e, phi) {
    let [old_r, r] = [e, phi];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % phi) + phi) % phi; // Ensure positive
  }
  
  // ── 5. MILLER-RABIN PRIMALITY TEST ──────────────────────────
  // Returns true if n is probably prime (k = number of rounds)
  // False-positive probability: <= 4^(-k)
  function millerRabin(n, k = 10) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;
  
    // Write n-1 as 2^r * d
    let r = 0n, d = n - 1n;
    while (d % 2n === 0n) { d >>= 1n; r++; }
  
    for (let i = 0; i < k; i++) {
      const a = bigRand(Number(n.toString(2).length) - 2) % (n - 4n) + 2n;
      let x = modpow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let composite = true;
      for (let j = 0n; j < r - 1n; j++) {
        x = modpow(x, 2n, n);
        if (x === n - 1n) { composite = false; break; }
      }
      if (composite) return false;
    }
    return true; // Probably prime
  }
  
  // ── 6. PRIME NUMBER GENERATOR ────────────────────────────────
  function randPrime(bits) {
    let attempts = 0;
    while (attempts++ < 10000) {
      let n = bigRand(bits);
      n |= (1n << BigInt(bits - 1)); // Set top bit (ensures bit length)
      n |= 1n;                        // Set bottom bit (ensures odd)
      if (millerRabin(n, 10)) return n;
    }
    throw new Error('Prime generation failed after 10000 attempts');
  }
  
  // ── 7. RSA KEY PAIR GENERATION ───────────────────────────────
  // bits: total key size (e.g. 128 => two 64-bit primes)
  function generateKeyPair(bits, owner = 'User') {
    const halfBits = bits / 2;
  
    // Step 1: Generate two distinct primes
    let p = randPrime(halfBits);
    let q;
    do { q = randPrime(halfBits); } while (q === p);
  
    // Step 2: Compute RSA parameters
    const n   = p * q;                    // Modulus
    const phi = (p - 1n) * (q - 1n);    // Euler's totient φ(n)
    const e   = 65537n;                  // Public exponent (standard)
  
    // Step 3: Validate
    if (gcd(e, phi) !== 1n) throw new Error('gcd(e, phi) != 1 — retry');
  
    // Step 4: Compute private exponent
    const d = modInverse(e, phi);        // d = e^(-1) mod φ(n)
  
    return { owner, bits, p, q, n, phi, e, d, id: Date.now() };
  }
  
  // ── 8. MESSAGE ENCODING: String → BigInt Blocks ──────────────
  // Splits UTF-8 bytes into chunks that fit below modulus n
  function strToBlocks(msg, blockBits) {
    const bytes = new TextEncoder().encode(msg);
    const blockBytes = Math.max(1, Math.floor((blockBits - 8) / 8));
    const blocks = [];
    for (let i = 0; i < bytes.length; i += blockBytes) {
      let val = 0n;
      for (let j = 0; j < blockBytes && i + j < bytes.length; j++) {
        val = (val << 8n) | BigInt(bytes[i + j]);
      }
      blocks.push(val);
    }
    return blocks;
  }
  
  // ── 9. MESSAGE DECODING: BigInt Blocks → String ──────────────
  function blocksToStr(blocks, blockBits) {
    const blockBytes = Math.max(1, Math.floor((blockBits - 8) / 8));
    const allBytes = [];
    for (const block of blocks) {
      const bytes = [];
      let v = block;
      for (let i = 0; i < blockBytes; i++) {
        bytes.unshift(Number(v & 0xffn));
        v >>= 8n;
      }
      allBytes.push(...bytes);
    }
    while (allBytes.length && allBytes[allBytes.length - 1] === 0) allBytes.pop();
    return new TextDecoder().decode(new Uint8Array(allBytes));
  }
  
  // ── 10. ENCRYPT ──────────────────────────────────────────────
  // c = m^e mod n  (encrypt each block with recipient's public key)
  function encrypt(publicKey, message) {
    const blocks = strToBlocks(message, publicKey.bits);
    const encrypted = blocks.map(b => {
      if (b >= publicKey.n) throw new Error('Block too large for key size');
      return modpow(b, publicKey.e, publicKey.n)
             .toString(16)
             .padStart(publicKey.bits / 4, '0');
    });
    return encrypted.join(':'); // Colon-separated hex blocks
  }
  
  // ── 11. DECRYPT ──────────────────────────────────────────────
  // m = c^d mod n  (decrypt each block with your private key)
  function decrypt(privateKey, ciphertext) {
    const hexBlocks = ciphertext.split(':');
    const decrypted = hexBlocks.map(h =>
      modpow(BigInt('0x' + h), privateKey.d, privateKey.n)
    );
    return blocksToStr(decrypted, privateKey.bits);
  }
  
  // ── 12. FNV-1a HASH FUNCTION ─────────────────────────────────
  // Simple 32-bit non-cryptographic hash for signing demos.
  // In production: replace with SHA-256 via SubtleCrypto API.
  function fnv1aHash(msg) {
    let h = 0x811c9dc5n;          // FNV offset basis
    const bytes = new TextEncoder().encode(msg);
    for (const b of bytes) {
      h ^= BigInt(b);             // XOR with byte
      h = (h * 0x01000193n)      // Multiply by FNV prime
          & 0xFFFFFFFFn;          // Keep 32-bit
    }
    return h;
  }
  
  // ── 13. SIGN ─────────────────────────────────────────────────
  // sig = H(m)^d mod n  (sign hash of message with private key)
  function sign(privateKey, message) {
    const h = fnv1aHash(message);
    if (h >= privateKey.n) throw new Error('Hash too large for key size');
    const signature = modpow(h, privateKey.d, privateKey.n);
    return signature.toString(16);
  }
  
  // ── 14. VERIFY ───────────────────────────────────────────────
  // Verify: H(m) =? sig^e mod n  (recover hash using public key)
  function verify(publicKey, message, signatureHex) {
    const sig = BigInt('0x' + signatureHex);
    const recovered = modpow(sig, publicKey.e, publicKey.n);
    const expected  = fnv1aHash(message);
    return recovered === expected;
  }
  
  // ── 15. DEMO / USAGE EXAMPLE ─────────────────────────────────
  function demo() {
    console.log('=== PGP-Like RSA System Demo ===\n');
  
    // Generate key pair for Alice
    console.log('[1] Generating 128-bit key pair for Alice...');
    const alice = generateKeyPair(128, 'Alice');
    console.log('    n (modulus) =', alice.n.toString(16));
    console.log('    e (public)  =', alice.e.toString(16));
    console.log('    d (private) =', alice.d.toString(16));
  
    // Encrypt a message using Alice's public key
    const message = 'Hello, RSA!';
    console.log('\n[2] Encrypting message:', message);
    const ciphertext = encrypt(alice, message);
    console.log('    Ciphertext:', ciphertext);
  
    // Decrypt with Alice's private key
    console.log('\n[3] Decrypting...');
    const plaintext = decrypt(alice, ciphertext);
    console.log('    Decrypted:', plaintext);
    console.log('    Match:', plaintext === message ? 'YES' : 'NO');
  
    // Sign the message
    console.log('\n[4] Signing message with Alice\'s private key...');
    const signature = sign(alice, message);
    console.log('    Signature:', signature);
  
    // Verify the signature
    console.log('\n[5] Verifying signature...');
    const valid = verify(alice, message, signature);
    console.log('    Valid:', valid ? 'YES - Authentic!' : 'NO - Tampered!');
  
    // Tampered message test
    const tampered = 'Hello, RSA? TAMPERED';
    const tamperedValid = verify(alice, tampered, signature);
    console.log('\n[6] Verifying against tampered message...');
    console.log('    Valid:', tamperedValid ? 'YES' : 'NO - Correctly rejected!');
  }
  
  // Run demo (Node.js / browser console)
  if (typeof module !== 'undefined') demo();
