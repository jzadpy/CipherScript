# CipherScript

CipherScript is a cryptography-focused scripting language designed for simple, readable, and powerful cryptographic automation. It provides an easy way to write scripts for generating keys, encrypting/decrypting messages, and performing other cryptographic operations. CipherScript transpiles `.cycl` files (CipherScript code) to Python, leveraging Python's extensive cryptographic libraries.

Inspired by [PyML](https://github.com/jzadpy/pyml)'s clean architecture, CipherScript aims to keep cryptography scripting accessible and maintainable, while supporting modern algorithms.

---

## Features

- **Transpiles CipherScript (.cycl) files to Python**
- **Supports key generation** for AES, ChaCha20, RSA, ECDSA and more
- **Encryption/Decryption** using AES (CBC mode), ChaCha20, etc.
- **Hashing** with SHA256, SHA512, SHA1, MD5
- **HMAC and MAC support**
- **Signature and verification** (RSA/ECDSA, planned/partial)
- **File operations**: save/load encrypted data
- **Simple variable assignment and usage**
- **CLI interface** for compiling and running scripts

---

## Quick Start

### 1. Write a CipherScript file

Create a file called `example.cycl`:

```cipher
# AES encryption example
generate rkey 256b aes
set key to rkey
encrypt 256b "Hello CipherScript!" with key
set citext to result
decrypt citext with key 256b aes
display ptext
set hash to sha256 "Hello CipherScript!"
display hash
```

### 2. Compile and run your script

Make sure you have Python 3 and the `cryptography` library installed:

```bash
pip install cryptography
```

Run using the CLI:

```bash
python cycl.py example.cycl         # Compiles and runs the CipherScript file
python cycl.py example.cycl -c      # Compiles only (to .py)
python cycl.py example.cycl -o out.py   # Compiles to a specific Python file
python cycl.py --examples           # Creates example CipherScript files in ./examples
```

---

## Example Scripts

CipherScript ships with example programs. Generate them via:

```bash
python cycl.py --examples
```

- **Basic Example**: AES encryption/decryption, hashing
- **Advanced Example**: Multiple encryption algorithms, key generation, signatures

---

## Syntax Overview

CipherScript syntax is designed to be simple and intuitive:

- `generate <var> <size> <algorithm>`: Generate a key or keypair
- `set <var> to <value>`: Assign value to variable
- `encrypt <size> <message> with <key>`: Encrypt message
- `decrypt <var> with <key> <size> <algorithm>`: Decrypt ciphertext
- `display <var>`: Print variable
- `set <var> to sha256 <message>`: Hash message

Supported keywords: `generate`, `set`, `encrypt`, `decrypt`, `display`, `save`, `load`, `verify`, `sign`, and more.

---

## Architecture

- **Lexer/Parser/Transpiler**: Parses CipherScript code into AST, then transpiles to Python.
- **Main CLI**: Handles file compilation, execution, and example generation.
- **Clean code structure**: Inspired by PyML for maintainability and extensibility.

---

## Requirements

- Python 3.7+
- cryptography (`pip install cryptography`)

---

## License

[MIT](LICENSE)

---

## Author

[jzadpy](https://github.com/jzadpy)

---

## Contributing

Pull requests, issues, and ideas welcome!
