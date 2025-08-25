import os
import json
import pandas as pd
import re
import chardet

import json, re, gzip, chardet

def _strip_json_comments(s: str) -> str:
    # 删除 // 和 /* */ 注释，保留字符串里的内容
    out = []
    i, n = 0, len(s)
    in_str = False
    esc = False
    while i < n:
        ch = s[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch); i += 1; continue
        if ch == '/' and i + 1 < n:
            nxt = s[i+1]
            if nxt == '/':        # 行注释
                i += 2
                while i < n and s[i] != '\n':
                    i += 1
                continue
            if nxt == '*':        # 块注释
                i += 2
                while i + 1 < n and not (s[i] == '*' and s[i+1] == '/'):
                    i += 1
                i += 2
                continue
        out.append(ch); i += 1
    return ''.join(out)

def _try_json_lines(text: str):
    objs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return objs if objs else None

def read_json_with_encoding_fallback(file_path):
    # 读原始字节 & 解 gzip（有些 .json 实际被压缩了）
    with open(file_path, 'rb') as fb:
        raw = fb.read()
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass

    # 先试常见编码
    for enc in ('utf-8', 'utf-8-sig', None):
        try:
            if enc:
                text = raw.decode(enc)
            else:
                enc_detected = (chardet.detect(raw)['encoding'] or 'utf-8')
                text = raw.decode(enc_detected, errors='replace')
            break
        except Exception:
            continue

    # 统一清理
    text = text.replace('\ufeff', '').replace('\x00', '')

    # 1) 严格 JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2) JSON Lines（NDJSON）
    jl = _try_json_lines(text)
    if jl is not None:
        return jl

    # 3) json5（可选）
    try:
        import json5
        return json5.loads(text)
    except Exception:
        pass

    # 4) 去注释/去尾逗号再试
    cleaned = _strip_json_comments(text)
    cleaned = re.sub(r',\s*([}\]])', r'\1', cleaned)  # 去尾逗号
    try:
        return json.loads(cleaned)
    except Exception:
        return None

# Encryption-related keywords
ENCRYPTION_KEYWORDS = [
    "encrypt", "encryption", "decrypt", "decryption", "cipher", "md5", "crypto", "private_key", "public_key",
    "key_iv", "hashlib.md5", "md5.new", "md5.sum", "md5.create", "digest::md5", "cc_md5",
    "md5", "md5::compute", "md5::new", "md5::digest", "cryptojs.md5", "crypto.createhash('md5')",
    "sparkmd5", "crypto.createhash(\"md5\")", "hashlib.sha1", "sha1.new", "sha1.sum", "sha1.computehash",
    "digest::sha1", "sha1", "sha1::sha1", "sha1::digest", "sha1::new", "cc_sha1", "cryptojs.sha1", "cryptojs",
    "crypto.createhash('sha1')", "require('sha1')", "messagedigest.getinstance", "crypto.createhash(\"sha1\")",
    "des", "rsa", "aes", "decrypt", "openssl", "hashlib"
]

STRICT_MATCH_KEYWORDS = {"des", "rsa", "aes"}

IMPORTANT_FIELDS = {"api", "function", "arguments", "args", "params", "method", "call", "operation"}
LOW_CONFIDENCE_FIELDS = {"trace", "location", "line", "file", "_trace", "produced_as"}

# False positives (prefix match)
FALSE_POSITIVE_API_PREFIXES = [
    "uuid.newsha1", "uuid.sha1", "uuid.v5", "uuid.v3"
]

# False positive field contexts (e.g. commit sha, version sha)
FALSE_POSITIVE_FIELD_CONTEXTS = [
    "commit.sha", "commitinfo.sha", "version.sha", "git.sha", "metadata.sha"
]

def is_false_positive_api(api_str: str) -> bool:
    api = api_str.lower()
    return any(api.startswith(p) for p in FALSE_POSITIVE_API_PREFIXES)

def is_false_positive_field(text: str) -> bool:
    text = text.lower()
    return any(text.startswith(p) for p in FALSE_POSITIVE_FIELD_CONTEXTS)

def is_weak_sha_reference(token: str, field: str, full_text: str) -> bool:
    return (
        token == "sha" and (
            is_false_positive_api(full_text) or
            is_false_positive_field(full_text) or
            "uuid" in full_text or
            "commit" in full_text or
            "version" in full_text
        )
    )

def find_encryption_in_json(json_data):
    hits = {
        "keywords": set(),
        "fields": set(),
        "has_api_crypto": False,
        "has_argument_key": False,
    }

    def search(obj, parent_key=None):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_lower = str(k).lower()
                if key_lower in LOW_CONFIDENCE_FIELDS:
                    continue
                if key_lower in IMPORTANT_FIELDS or parent_key in IMPORTANT_FIELDS:
                    scan(k, key_lower, is_key=True)
                    scan(v, key_lower)
                else:
                    if isinstance(v, (dict, list)):
                        search(v, key_lower)
        elif isinstance(obj, list):
            for item in obj:
                search(item, parent_key)
        elif isinstance(obj, str):
            if parent_key in IMPORTANT_FIELDS:
                scan(obj, parent_key)

    def scan(text, field, is_key=False):
        if not isinstance(text, str):
            return
        text = text.lower()
        field = field.lower()

        if field == "api" and is_false_positive_api(text):
            return
        if is_false_positive_field(text):
            return

        tokens = re.split(r"[._\-:/\\]+", text)

        if field == "api":
            if any(kw in text for kw in [
                "encrypt", "decrypt", "cipher", "sign", "crypto", "hash", "md5",
                "hmac", "digest", "sha1", "sha256", "sha512", "pbkdf2", "sha384", "sha3", "keccak", "hashlib",
                "encrypt", "encryption", "decrypt", "decryption", "cipher", "md5", "crypto", "private_key",
                "public_key","key_iv", "hashlib.md5", "md5.new", "md5.sum", "md5.create", "digest::md5", "cc_md5",
                "md5", "md5::compute", "md5::new", "md5::digest", "cryptojs.md5", "crypto.createhash('md5')",
                "sparkmd5", "crypto.createhash(\"md5\")", "hashlib.sha1", "sha1.new", "sha1.sum", "sha1.computehash",
                "digest::sha1", "sha1", "sha1::sha1", "sha1::digest", "sha1::new", "cc_sha1", "cryptojs.sha1",
                "cryptojs","crypto.createhash('sha1')", "require('sha1')", "messagedigest.getinstance",
                "crypto.createhash(\"sha1\")", "des", "rsa", "aes", "decrypt", "openssl", "hashlib"
            ]):
                hits["has_api_crypto"] = True

        if field in {"arguments", "args", "params"} and any(k in text for k in ["key", "secret", "signature", "hmac"]):
            hits["has_argument_key"] = True

        for word in ENCRYPTION_KEYWORDS:
            for token in tokens:
                if word in STRICT_MATCH_KEYWORDS:
                    if token == word and not is_weak_sha_reference(token, field, text):
                        hits["keywords"].add(word)
                        hits["fields"].add(field)
                else:
                    if word in token:
                        hits["keywords"].add(word)
                        hits["fields"].add(field)

    search(json_data)

    signal_count = sum([
        hits["has_api_crypto"],
        hits["has_argument_key"],
        len(hits["keywords"]) >= 1
    ])

    is_encryption = signal_count >= 2
    return is_encryption, list(hits["keywords"])

def process_directory(root_dir):
    records = []
    json_files = []

    for language in os.listdir(root_dir):
        lang_path = os.path.join(root_dir, language)
        if not os.path.isdir(lang_path):
            continue

        for market in os.listdir(lang_path):
            market_path = os.path.join(lang_path, market)
            if not os.path.isdir(market_path):
                continue

            for file in os.listdir(market_path):
                if file.endswith(".json"):
                    file_path = os.path.join(market_path, file)
                    json_files.append((file_path, file, language, market))

    total_files = len(json_files)

    for idx, (file_path, file, language, market) in enumerate(json_files, 1):
        print(f"🔍 Processing file {idx}/{total_files}: {file_path}")
        try:
            data = read_json_with_encoding_fallback(file_path)
            if data is None:
                raise ValueError("not valid JSON/JSONL/JSON5 after fallbacks")
            has_encryption, reasons = find_encryption_in_json(data)
            encryption_status = "Yes" if has_encryption else "No"
            reason_str = ", ".join(reasons) if has_encryption else ""

            print(f"[{idx}/{total_files}] → {encryption_status} | Reason: {reason_str}" if reason_str else "")

            records.append({
                "Project Name": file,
                "Encryption Involved": encryption_status,
                "Detection Basis": reason_str,
                "Language": language,
                "Market": market
            })

        except Exception as e:
            print(f"[{idx}/{total_files}] Failed to process {file_path}: {e}")
            continue

    return pd.DataFrame(records)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Root directory of the projects, e.g., D:\\mcp_detection_results")
    parser.add_argument("--output", default="encryption_check_result.xlsx", help="Output Excel file name")
    args = parser.parse_args()

    df = process_directory(args.input_dir)
    df.to_excel(args.output, index=False)
    print(f"\n✅ Processing complete. Results saved to: {args.output}")

if __name__ == "__main__":
    main()
