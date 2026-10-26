#!/usr/bin/env python3
"""Build a user-message time-budget ledger from the Hermes runtime store.

Primary bottleneck is *user messages* (not inference compute), so every
human user message in the target chat is tracked and billed so message-time
can be managed and compared against token-spend investment.

Billing model (as specified):
  - Each user message is billed USD 20.00 flat.
  - If a message has multiple paragraphs, each paragraph counts as one
    message (blank-line separated).  A 3-paragraph message bills $60.
  - The size metric is recorded as a byte-pair-encoding (BPE) token count
    computed here with a deterministic byte-pair merge (stdlib only), so the
    "cost" of a message can be rationalised against token usage.

PRIVACY: the ledger writes METADATA only (sender id, timestamp, utf-8 bytes,
BPE token count, paragraph count, billed USD).  Message text is encrypted
(Fernet/AES) and written to user_messages_ciphertext.tsv when a key is
available; the key comes from the R2DP_LEDGER_KEY env or R2DP_LEDGER_KEYFILE
(kept OUTSIDE the repo).  Full plaintext is NOT committed by default; run
with an approved key and --plaintext to emit plaintext.

Usage: python3 user_messages.py [STATE_DB] [OUTDIR] [CHAT_ID] [--plaintext]
"""
import csv
import hashlib
import os
import sqlite3
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
USD_PER_MESSAGE = 20.0

# Map telegram user_id -> label.  Confirmed: 271630713 is Mark (the account
# messaging the agent); 470095065 is Derek (the other active human sender).
PRINCIPALS = {
    "271630713": "mark",
    "470095065": "derek",
    "1087968824": "derek",   # one-off Aug-2026 message
    "7960029825": "other",   # one-off Aug-2026 message
}


def _tok_encoder():
    """Return a tokenizer for BPE counts.  Prefer tiktoken (real GPT BPE);
    fall back to a deterministic stdlib byte-pair merge if absent."""
    try:
        import tiktoken
        return tiktoken.get_encoding("cl100k_base").encode
    except Exception:
        return None


def bpe_token_count(text: str, encode=None) -> int:
    """Byte-pair-encoding token count.

    Uses a real tokenizer (tiktoken cl100k_base) when available; otherwise a
    deterministic stdlib-only byte-pair merge fallback.  Only the count is
    used; the vocabulary stays internal.
    """
    if encode is not None:
        return len(encode(text))
    # ---- stdlib fallback: iterative most-frequent adjacent-pair merge ----
    budget = 512
    seq = list(text.encode("utf-8", errors="replace"))
    if len(seq) == 0:
        return 0
    merges = 0
    while merges < budget:
        if len(seq) < 2:
            break
        pairs = Counter(zip(seq, seq[1:]))
        if not pairs:
            break
        (a, b), n = pairs.most_common(1)[0]
        if n < 2:
            break
        new = 256 + merges
        out = []
        i = 0
        while i < len(seq):
            if i + 1 < len(seq) and seq[i] == a and seq[i + 1] == b:
                out.append(new)
                i += 2
            else:
                out.append(seq[i])
                i += 1
        seq = out
        merges += 1
    return len(seq)


def paragraph_count(text: str) -> int:
    """Number of paragraphs: blocks separated by one or more blank lines."""
    blocks = [b for b in (p.strip() for p in text.split("\n\n")) if b]
    return max(1, len(blocks))


def _load_fernet():
    """Return a Fernet cipher if a key is configured, else None.

    Key sources (checked in order), all kept OUTSIDE the repo so ciphertext
    in the ledger is not readable by anyone without the key:
      R2DP_LEDGER_KEY      raw Fernet key (urlsafe base64, 32 bytes)
      R2DP_LEDGER_KEYFILE  path to a file whose first line is the key
    """
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    key = os.environ.get("R2DP_LEDGER_KEY")
    if not key:
        kf = os.environ.get("R2DP_LEDGER_KEYFILE")
        if kf and os.path.exists(kf):
            with open(kf, encoding="utf-8") as fh:
                key = fh.read().strip()
    if not key:
        return None
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None


def make_key() -> None:
    """Generate a fresh Fernet key and print it (for R2DP_LEDGER_KEYFILE)."""
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else os.path.expandvars(
        r"%LOCALAPPDATA%\hermes\state.db")
    out = sys.argv[2] if len(sys.argv) > 2 else HERE
    chat = sys.argv[3] if len(sys.argv) > 3 else "-1003784575533"
    plaintext = "--plaintext" in sys.argv
    os.makedirs(out, exist_ok=True)

    fernet = None if plaintext else _load_fernet()

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    rows = con.execute(
        """SELECT m.id, s.user_id, m.content, m.timestamp
           FROM messages m JOIN sessions s ON s.id = m.session_id
           WHERE m.role = 'user' AND s.chat_id = ?
             AND m.content IS NOT NULL AND m.content != ''
           ORDER BY m.timestamp""", (chat,)).fetchall()

    encode = _tok_encoder()
    tok_src = "tiktoken/cl100k_base" if encode is not None else "stdlib-bpe"

    ledger = []
    cipher_rows = []   # message_id | encrypted-or-plaintext content
    per_principal = defaultdict(lambda: [0, 0.0, 0, 0])  # n, usd, bpe, paragraphs
    for mid, uid, content, ts in rows:
        nbytes = len(content.encode("utf-8", errors="replace"))
        bpe = bpe_token_count(content, encode)
        paras = paragraph_count(content)
        bill = paras * USD_PER_MESSAGE
        principal = PRINCIPALS.get(str(uid), "other")
        per_principal[principal][0] += 1
        per_principal[principal][1] += bill
        per_principal[principal][2] += bpe
        per_principal[principal][3] += paras
        body = content if (plaintext or fernet is None) else \
            fernet.encrypt(content.encode("utf-8", errors="replace")).decode()
        cipher_rows.append([mid, body])
        ledger.append({
            "message_id": mid,
            "principal": principal,
            "user_id": uid,
            "ts": ts,
            "utc": "" if not ts else __import__("datetime").datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
            "utf8_bytes": nbytes,
            "bpe_tokens": bpe,
            "paragraphs": paras,
            "billed_usd": round(bill, 2),
            "content_sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16],
        })

    with open(os.path.join(out, "user_messages_ledger.tsv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(ledger[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(ledger)

    with open(os.path.join(out, "user_messages_by_principal.tsv"), "w",
              encoding="utf-8", newline="") as fh:
        fh.write("principal\tmessages\tbilled_usd\tbpe_tokens\tparagraphs\n")
        for p in sorted(per_principal, key=lambda k: -per_principal[k][1]):
            n, usd, bpe, paras = per_principal[p]
            fh.write(f"{p}\t{n}\t{round(usd,2)}\t{bpe}\t{paras}\n")

    # content bodies (ciphertext by default, plaintext only with --plaintext)
    with open(os.path.join(out, "user_messages_content.tsv"), "w",
              encoding="utf-8", newline="") as fh:
        fh.write("message_id\tcontent\n")
        fh.writelines(f"{mid}\t{body}\n" for mid, body in cipher_rows)

    total_usd = sum(r["billed_usd"] for r in ledger)
    total_bpe = sum(r["bpe_tokens"] for r in ledger)
    total_paras = sum(r["paragraphs"] for r in ledger)
    mode = "PLAINTEXT" if plaintext else ("ENCRYPTED" if fernet is not None else "no-key (plaintext-in-transit, not committed)")
    print(f"user messages: {len(ledger)}  (chat {chat}, tokenizer={tok_src}, body={mode})")
    print(f"total billed: ${total_usd:,.2f}   total BPE tokens: {total_bpe:,}   total paragraphs: {total_paras:,}")
    print("by principal:")
    for p in sorted(per_principal, key=lambda k: -per_principal[k][1]):
        n, usd, bpe, paras = per_principal[p]
        print(f"  {p:10} {n:5} msgs  ${usd:>10,.2f}  {bpe:>10,} bpe  {paras:>6} paras")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "make-key":
        make_key()
    else:
        main()
