# MCP Cryptographic Misuse Detection

A cross-language **cryptographic misuse detection tool** designed for [Model Context Protocol (MCP)] servers.  
This tool supports AST analysis for **C#, Go, Java, JavaScript, PHP, Python, Ruby, Rust, and Swift**, and performs cryptographic misuse detection on a unified IR (Intermediate Representation).

---

## ✨ Features

- **Unified IR Representation**  
  Each language is parsed into a unified JSON format via its AST analyzer, enabling cross-language analysis.

- **Crypto Detection (crypto_identification.py)**  
  Quickly scans JSON results to check whether encryption/hash/secret-related calls are involved.

- **Cryptographic Misuse Detection (crypto_misuse_detection.py)**  
  The core detection engine, based on **taint analysis + data-flow graphs (NetworkX)**, supporting **8 rules**:
  
  - Rule 1: Fixed Key / API Key  
  - Rule 2: Fixed IV / Salt
  - Rule 3: Weak Hash Functions
  - Rule 4: Insecure Key Derivation Configuration  
  - Rule 5: Static Seed in PRNG
  - Rule 6: ECB Mode Usage
  - Rule 7: Missing Integrity Protection  
  - Rule 8: Deprecated Alg/APIs

- **Result Output**  
  Generates Excel reports, including:
  
  - Whether encryption is involved  
  - Misuse rules triggered  
  - Evidence keywords / matched strings  
  - Potential risky dependency paths  

---

## ⚠️ Prerequisites

Before running this tool, you **must install the runtime environments** for each supported language, otherwise the AST analyzers cannot execute:

- **C#** → [.NET SDK](https://dotnet.microsoft.com/download)  
- **Go** → [Go](https://go.dev/dl/)  
- **Java** → [JDK + Maven](https://maven.apache.org/install.html)  
- **JavaScript** → [Node.js](https://nodejs.org/)  
- **PHP** → [PHP + XAMPP](https://www.apachefriends.org/)  
- **Python** → [Python 3.9+](https://www.python.org/)  
- **Ruby** → [Ruby](https://www.ruby-lang.org/)  
- **Rust** → [Rust + Cargo](https://www.rust-lang.org/tools/install)  
- **Swift** → [Swift toolchain](https://www.swift.org/download/)  

Ensure each runtime is added to your system **PATH**, so analyzers can be executed from the command line.

---

## 📂 Directory Structure

```
mcp_crypto_misuse_detection/
├── csharp_ast_analyzer/       # C# AST analyzer (dotnet)
├── go_ast_analyzer/           # Go AST analyzer (go run)
├── java_ast_analyzer/         # Java AST analyzer (maven)
├── js_ast_analyzer/           # JavaScript AST analyzer (Node.js)
├── php_ast_analyzer/          # PHP AST analyzer (php/xampp)
├── python_ast_analyzer/       # Python AST analyzer
├── ruby_ast_analyzer/         # Ruby AST analyzer
├── rust_ast_analyzer/         # Rust AST analyzer (cargo)
├── swift_ast_analyzer/        # Swift AST analyzer (swift build)
├── crypto_identification/     # Initial crypto detection
└── crypto_misuse_detection.py # Misuse detection engine
```

---

## 🚀 Usage Workflow

### 1. Run AST Analyzers

Run each analyzer inside its directory. Take JavaScript as an example:

- **JavaScript**
  
  ```bash
  cd js_ast_analyzer
  node JS_IR_php.js "../mcp_source_code/mcpmarket/JavaScript" "../mcp_detection_results/Javascript/mcpmarket"
  ```

---

### 2. Crypto Identification

```bash
python crypto_identification.py ./mcp_detection_results --output ./results/crypto_check_result.xlsx
```

---

### 3. Cryptographic Misuse Detection

```bash
python crypto_misuse_detection.py ./mcp_detection_results --excel ./results/crypto_check_result.xlsx --output ./results/crypto_misuse_result.xlsx
```

---

## 🔄 Workflow (Diagram)

```
+----------------------------+
|    Multi-language source   |
|    code (C#/Go/Java/...)   |
+----------------------------+
             |
             v
+----------------------------+
|       AST Analyzers        |
|       (per language)       |
+----------------------------+
             |
             v
+----------------------------+
|       Unified JSON IR      |
+----------------------------+
             |
             v
+----------------------------+
| crypto_identification.py   |       
+----------------------------+
             |
             v
+----------------------------+
| Excel: crypto_check_result |
| .xlsx                      |
+----------------------------+
             |
             v
+----------------------------+
| crypto_misuse_detection.py |                     
+----------------------------+
             |
             v
+---------------------------+
|   Excel: crypto_misuse_   |
|   result.xlsx             |
+---------------------------+
```

---

## 📜 License

MIT License

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a PR to improve rules and extend language support.
