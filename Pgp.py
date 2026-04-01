import myRSA
import hashlib
import json
import os

# folder ที่ pgp.py อยู่ — ใช้เป็น base สำหรับทุก path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _path(filename):
    return os.path.join(BASE_DIR, filename)


# ─────────────────────────────────────────────
# Key Management
# ─────────────────────────────────────────────

def generate_keypair(bits=128):
    """Generate a fresh RSA keypair. Returns (PR, PU) each as (exponent, modulus)."""
    PR, PU = myRSA.rsaKeyGen(bits)
    return PR, PU


def save_keypair(name, PR, PU, priv_dir=".", pub_dir="."):
    """Save keys to text files (same format as rsa-keygen.py)."""
    priv_dir = _path(priv_dir)
    pub_dir  = _path(pub_dir)
    os.makedirs(priv_dir, exist_ok=True)
    os.makedirs(pub_dir, exist_ok=True)

    pr_path = os.path.join(priv_dir, f"PR_{name}.txt")
    pu_path = os.path.join(pub_dir,  f"PU_{name}.txt")

    with open(pr_path, "w") as f:
        f.write(f"{PR[0]}\n{PR[1]}")
    with open(pu_path, "w") as f:
        f.write(f"{PU[0]}\n{PU[1]}")

    print(f"[keygen] Saved {pr_path} and {pu_path}")
    return pr_path, pu_path


def load_key(path):
    """Load a key from a .txt file. Returns (exponent, modulus) as ints."""
    with open(_path(path)) as f:
        lines = f.read().strip().splitlines()
    return (int(lines[0]), int(lines[1]))


# ─────────────────────────────────────────────
# Hashing (for signatures)
# ─────────────────────────────────────────────

def hash_message(message: str) -> int:
    """
    SHA-256 hash of the message, truncated to an integer small enough to
    sign with any of the demo key sizes (we take the first 15 decimal digits).
    For production use full-length hashes with appropriate key sizes.
    """
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    # Convert hex digest to a large integer, then reduce to fit within n
    return int(digest, 16)


# ─────────────────────────────────────────────
# Digital Signature
# ─────────────────────────────────────────────

def sign(message: str, PR) -> int:
    """
    Sign a message with the sender's private key.
    Returns an integer signature: sig = hash(msg)^d mod n
    """
    h = hash_message(message)
    d, n = PR
    # Reduce hash modulo n so it fits in the key space
    h_mod = h % n
    sig = myRSA.moduloExp(h_mod, d, n)
    return sig


def verify(message: str, signature: int, PU) -> bool:
    """
    Verify a signature using the sender's public key.
    Checks: sig^e mod n == hash(msg) mod n
    """
    e, n = PU
    recovered_hash = myRSA.moduloExp(signature, e, n)
    expected_hash  = hash_message(message) % n
    return recovered_hash == expected_hash


# ─────────────────────────────────────────────
# PGP-like Encrypt + Sign
# ─────────────────────────────────────────────

def pgp_encrypt(plaintext: str, sender_PR, recipient_PU) -> dict:
    """
    PGP-like send operation:
      1. Sign plaintext with sender's private key  → signature
      2. Encrypt plaintext with recipient's public key → ciphertext

    Returns a dict (the 'envelope') containing:
      - ciphertext : encrypted message (bit string)
      - signature  : integer signature of the plaintext
    """
    print("\n[PGP SEND]")
    print(f"  Plaintext : {plaintext!r}")

    # Step 1 — Sign
    sig = sign(plaintext, sender_PR)
    print(f"  Signature : {sig}  (hash^d mod n)")

    # Step 2 — Encrypt
    ciphertext = myRSA.encryptText(plaintext, recipient_PU)
    print(f"  Ciphertext: {ciphertext[:60]}{'...' if len(ciphertext) > 60 else ''}")

    envelope = {
        "ciphertext": ciphertext,
        "signature":  sig,
    }
    return envelope


def pgp_decrypt(envelope: dict, recipient_PR, sender_PU) -> str:
    """
    PGP-like receive operation:
      1. Decrypt ciphertext with recipient's private key → plaintext
      2. Verify signature using sender's public key

    Returns the recovered plaintext, or raises ValueError on bad signature.
    """
    print("\n[PGP RECEIVE]")

    ciphertext = envelope["ciphertext"]
    sig        = envelope["signature"]

    # Step 1 — Decrypt
    plaintext = myRSA.descryptText(ciphertext, recipient_PR)
    print(f"  Decrypted : {plaintext!r}")

    # Step 2 — Verify signature
    valid = verify(plaintext, sig, sender_PU)
    if valid:
        print("  Signature : VALID ✓ — message is authentic and unmodified")
    else:
        print("  Signature : INVALID ✗ — message may have been tampered with!")
        raise ValueError("Signature verification failed — message integrity compromised.")

    return plaintext


# ─────────────────────────────────────────────
# Envelope serialization (save / load messages)
# ─────────────────────────────────────────────

def save_envelope(envelope: dict, path: str):
    """Save an envelope to a JSON file for transmission."""
    with open(_path(path), "w") as f:
        json.dump({"ciphertext": envelope["ciphertext"],
                   "signature":  str(envelope["signature"])}, f, indent=2)
    print(f"  Envelope saved → {_path(path)}")


def load_envelope(path: str) -> dict:
    """Load an envelope from a JSON file."""
    with open(_path(path)) as f:
        data = json.load(f)
    return {"ciphertext": data["ciphertext"],
            "signature":  int(data["signature"])}


# ─────────────────────────────────────────────
# Demo
# ─────────────────────────────────────────────

def demo_from_files():
    """
    Full demo using the pre-generated key files:
      PU_A.txt / PR_A.txt  — Alice's key pair
      PU_B.txt / PR_B.txt  — Bob's key pair
    """
    print("=" * 60)
    print("PGP-like Demo — loading existing keys")
    print("=" * 60)

    PU_A = load_key("PU_A.txt")
    PR_A = load_key("PR_A.txt")
    PU_B = load_key("PU_B.txt")
    PR_B = load_key("PR_B.txt")

    print(f"\nAlice PU: e={str(PU_A[0])[:20]}... n={str(PU_A[1])[:20]}...")
    print(f"Bob   PU: e={str(PU_B[0])[:20]}... n={str(PU_B[1])[:20]}...")

    # ── Alice → Bob ──────────────────────────────────────────
    print("\n" + "─" * 40)
    print("Alice sends a message to Bob")
    print("─" * 40)

    msg = "Hello Bob! This is Alice. Meet me at the library at 5pm."
    envelope = pgp_encrypt(msg, sender_PR=PR_A, recipient_PU=PU_B)
    save_envelope(envelope, "msg_alice_to_bob.json")

    # Bob receives and verifies
    received = load_envelope("msg_alice_to_bob.json")
    recovered = pgp_decrypt(received, recipient_PR=PR_B, sender_PU=PU_A)
    assert recovered == msg, "Plaintext mismatch!"
    print(f"\n  Bob reads: {recovered!r}")

    # ── Bob → Alice ──────────────────────────────────────────
    print("\n" + "─" * 40)
    print("Bob replies to Alice")
    print("─" * 40)

    reply = "Hi Alice! Confirmed. See you at 5pm."
    envelope2 = pgp_encrypt(reply, sender_PR=PR_B, recipient_PU=PU_A)
    save_envelope(envelope2, "msg_bob_to_alice.json")

    received2 = load_envelope("msg_bob_to_alice.json")
    recovered2 = pgp_decrypt(received2, recipient_PR=PR_A, sender_PU=PU_B)
    assert recovered2 == reply, "Plaintext mismatch!"
    print(f"\n  Alice reads: {recovered2!r}")

    # ── Tamper attack demo ───────────────────────────────────
    print("\n" + "─" * 40)
    print("Tamper attack — Eve modifies the message")
    print("─" * 40)

    tampered = dict(received)
    tampered["signature"] = 12345678  # attacker's fake signature

    print("  Eve changes the signature to a random value...")
    try:
        pgp_decrypt(tampered, recipient_PR=PR_B, sender_PU=PU_A)
    except ValueError as e:
        print(f"  Attack caught: {e}")

    print("\n" + "=" * 60)
    print("Demo complete — all assertions passed.")
    print("=" * 60)


def demo_generate_new_keys():
    """Generate brand-new keys, run the same PGP flow with them."""
    print("=" * 60)
    print("PGP-like Demo — generating fresh 128-bit key pairs")
    print("=" * 60)

    print("\nGenerating Alice's key pair...")
    PR_A, PU_A = generate_keypair(128)
    print("Generating Bob's key pair...")
    PR_B, PU_B = generate_keypair(128)

    save_keypair("A_new", PR_A, PU_A)
    save_keypair("B_new", PR_B, PU_B)

    msg = "Fresh-key test: The quick brown fox jumps over the lazy dog."
    print("\n" + "─" * 40)
    envelope = pgp_encrypt(msg, sender_PR=PR_A, recipient_PU=PU_B)
    recovered = pgp_decrypt(envelope, recipient_PR=PR_B, sender_PU=PU_A)
    assert recovered == msg
    print(f"\n  Recovered: {recovered!r}")
    print("\nAll good with freshly generated keys!")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Copy key files from upload dir if running standalone
    for fname in ["PU_A.txt", "PR_A.txt", "PU_B.txt", "PR_B.txt"]:
        src = f"/mnt/user-data/uploads/{fname}"
        if os.path.exists(src) and not os.path.exists(fname):
            import shutil; shutil.copy(src, fname)

    mode = sys.argv[1] if len(sys.argv) > 1 else "files"

    if mode == "newkeys":
        demo_generate_new_keys()
    else:
        demo_from_files()
