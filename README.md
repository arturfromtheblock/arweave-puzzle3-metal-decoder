# 🔐 Arweave Puzzle #3 — Metal Decoder

A high-performance, GPU-accelerated brute-force solver for the **Arweave Puzzle #3**
encrypted wallet challenge, written in Rust with Apple **Metal** compute shaders.

Built for Apple Silicon, this tool searches the passphrase of an encrypted
Arweave JSON keyfile using an 8-panel wordlist, leveraging the GPU to achieve
**~8,000+ passphrase attempts per second** (M1 Max).

**Default Mode**
<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/img/1.png?token=GHSAT0AAAAAADYEPC4PLPDC5PR25RXDDTKE2UMDMUA">
<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/img/2.png?token=GHSAT0AAAAAADYEPC4OS4QFLT4TKQ6LN5DO2UMDNAA">

**Debug Mode**
<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/img/3.png?token=GHSAT0AAAAAADYEPC4OQR3S4RJJD62MQCWG2UMDNOQ">
<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/img/4.png?token=GHSAT0AAAAAADYEPC4OPN6DSNIKZ766FOHO2UMDNVQ">

---

## 🧩 Puzzle #3

Price: 1000 AR - around $2000

Link: [Arweave Puzzle #3](https://kszeqgxezf5quhzld4nhpasyilhxphclq2peqi5mrn7utxmqhwga.arweave.net/VLJIGuTJewofKx8ad4JYQs93nEuGnkgjrIt_Sd2QPYw)

<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/puzzle3.png?token=GHSAT0AAAAAADYEPC4OGM76LJYNC6EVNYCU2UMDO4Q">

---

## 📖 Overview

Arweave Puzzle #3 protects an RSA private key (JSON keyfile) with a passphrase
composed of **8 words of exactly 4 characters each** (32 characters total).
The encryption is a non-standard OpenSSL-style scheme:

1. **SHA-512 chain** – the passphrase is hashed once, then re-hashed **11,512** more times.
2. **EvpKDF (MD5, 10,000 iterations)** – derives a 144-byte blob
   (128-byte key + 16-byte IV) from the hex-encoded SHA-512 result and the
   `Salted__` salt embedded in the ciphertext.
3. **Rijndael-1024 (CBC)** – AES-style decryption with the 1024-bit key.
4. **Marker detection** – a valid plaintext must contain the JSON marker `"kty"`.

Each stage runs as a dedicated Metal compute kernel, processing batches of
32,768 passphrases fully in parallel on the GPU.

---

## ✨ Features

- 🚀 **Metal GPU acceleration** – ~8,000+ passphrases/sec on M1 Max
- 🖥️ **Modern TUI** – live speed/progress/ETA, rotating passphrase ticker, scrolling log, auto-resize
- ⏸️ **Pause / Resume** – finishes the current GPU batch, paused time is excluded from stats
- ✅ **Wordlist validation** – every word must be exactly 4 characters; detailed error log on failure
- 🔒 **Embedded shader** – `shaders.metallib` is compiled by `build.rs` and embedded into the binary
- 🐛 **Debug mode** – full kernel inspection via `GPU_DEBUG=1`
- 🧪 **Reference test tool** – `test.html`, a browser-based verifier for crypto correctness
- 📦 **Standalone binary** – no runtime dependencies

---

## 🛠️ Requirements

- **macOS** (Apple Silicon)
- **Xcode Command Line Tools** (`xcode-select --install`)
- **Rust toolchain** (<https://rustup.rs>)

---

## 🏗️ Build

The Metal shader is compiled and embedded automatically – no manual steps:

```bash
git clone https://github.com/arturfromtheblock/arweave-puzzle3-metal-decoder.git
cd arweave-puzzle3-metal-decoder
chmod +x build.sh
./build.sh
```

The resulting binary (`gpusolver`) contains the compiled shader
library and can be copied anywhere. The `message.txt` and `words.txt` files
must be in the same folder as the binary.

---

## 📝 Input Files

### `message.txt`

The Base64-encoded ciphertext (OpenSSL `Salted__` format) from the puzzle.

### `words.txt`

Exactly **8 lines** (panels), each containing comma-separated candidate words.
**Every word must be exactly 4 characters** (spaces count as characters,
e.g. `a b ` is valid, `abc` is not).

```text
curl,weve,look,eyes,face,wave,anno,seal,logo,icon,name,tags,noah,a16z
md12,code,road,path,snow,hill,bash,head,date,2018,zero,mine
a256,sha2,-256
cash,swap,coin,rate,sell,ar.$,loki,silo,fees
node,e4d5,scan,1984,.erl,port,nord,loki,maps
root,asmt,node,fork,beam,hash,leaf,32ar,peer
pull,pool,vest,upll,load,west,fork
base,bs58
```

Invalid words are reported line-by-line in the log before the search starts.

---

## 🚀 Usage

### Normal mode (TUI)

```bash
./gpusolver
```

The TUI shows:

| Panel       | Content                                                |
| ----------- | ------------------------------------------------------ |
| ⚡ Speed    | live passphrases/sec (smoothed)                        |
| 🔎 Tested   | combinations checked so far                            |
| 🔨 Progress | percentage + gauge                                     |
| 🕞 Time     | elapsed time                                           |
| 🏁 ETA      | estimated time remaining                               |
| Batch       | panel sizes + rotating "actual" passphrase ticker      |
| Log         | startup checks, pause/resume, GPU errors, final result |

**Controls:**

| Key         | Action                                               |
| ----------- | ---------------------------------------------------- |
| `p`         | pause / resume (current GPU batch is finished first) |
| `q` / `ESC` | quit                                                 |
| `Enter`     | close the final result popup                         |

On a hit, the decrypted keyfile is written to `decrypted.json` and the
passphrase is shown in the log/popup.

### Debug mode (stdout)

```bash
GPU_DEBUG=1 ./gpusolver
```

Disables the TUI and prints deep diagnostics to stdout:

- batch headers with the first passphrases
- buffer read-backs (passphrases, offsets, salt, batch size)
- `derived[0..144]` hex dump after the KDF pass (compare against a reference implementation!)
- write-verification via `0xEE` sentinel prefill
- decrypted plaintext slots (hex + UTF-8 preview) when PKCS#7 padding validates
- `results[]` / `output_len[]` after the marker pass
- `Ctrl + C` to exit

Perfect for verifying correctness with a minimal `words.txt` containing only a
known test passphrase. Use this to check that the kernel is working properly if you change any parameters.

> **Note:** only `GPU_DEBUG=1` / `true` enables debug mode – `GPU_DEBUG=0` runs the normal TUI.

---

## 🧪 Crypto Test Tool (`test.html`)

The repository ships with a standalone HTML tool that runs **exactly the same
cryptographic pipeline** as the Rust decoder, executed locally in your browser
via [CryptoJS](https://github.com/brix/crypto-js). Open `test.html` in any
modern browser — no installation, no server, no data leaves your machine.

### What it is for

This tool is the **reference implementation** used during development to verify
that the Metal kernels produce bit-identical results to CryptoJS/OpenSSL.
Use it whenever you need to:

- ✅ **Verify the algorithm** — see exactly what the 11,513× SHA-512 chain produces for a given passphrase
- ✅ **Cross-check the decoder** — encrypt a known message, copy the ciphertext into `message.txt`, and confirm the Rust tool finds it
- ✅ **Generate test vectors** — produce known passphrase → ciphertext → plaintext triples to validate custom implementations
- ✅ **Debug padding issues** — check whether PKCS#7 failures come from the KDF or from AES-CBC
- ✅ **Experiment safely** — play with passphrases and messages without modifying the wordlist

### Three modes

| Mode              | Purpose                                                                                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 🔒 **Encrypt**    | Passphrase + plaintext → Base64 ciphertext. Shows the intermediate 11,513× SHA-512 hex hash so you can compare it directly against `derived[0..144]` from `GPU_DEBUG=1`. |
| 🔓 **Decrypt**    | Passphrase + Base64 ciphertext → plaintext. Flags whether the result contains `"kty":"RSA"` (the Arweave marker).                                                        |
| ⚡ **Rapid Test** | One-click roundtrip with a built-in test passphrase. Outputs a copy-paste-ready block of values to feed directly into the Rust decoder.                                  |

### Quick workflow

1. Open `test.html` in your browser
2. Click **⚡ Run quick test** — this generates a known-good ciphertext
3. Copy the ciphertext into your `message.txt`
4. Build a `words.txt` where the 8 words of the test passphrase form one valid combination
5. Run the decoder — it should find the hit immediately

If the decoder fails where the HTML tool succeeds, the bug is in the Metal
kernels (compare the `GPU_DEBUG=1` output against the hex hash shown in the
HTML tool).

### Privacy

Everything runs client-side. **No network requests are made with your data** —
CryptoJS is loaded from a CDN, but your passphrases and messages never leave
your browser. Safe to use with real puzzle data.

<img src="https://raw.githubusercontent.com/arturfromtheblock/arweave-puzzle3-metal-decoder/refs/heads/main/img/testtool.png?token=GHSAT0AAAAAADYEPC4OGPQKFKA5WLGRLDRI2UMDOLA">

---

## 📊 Performance (reference)

| Device | Speed    | 5M combinations |
| ------ | -------- | --------------- |
| M1 Max | ~8,200/s | ~10 min         |

---

## 📂 Project Structure

```text
├── build.rs            # Compiles metal shaders
├── build.sh            # Auto build setup
├── Cargo.toml
├── img /
├── LICENSE.txt
├── message.txt         # Base64 ciphertext
├── puzzle3.png         # Puzzle Image
├── README.md           # Readme file
├── src/
│   ├── main.rs         # CLI, wordlist validation, worker thread
│   ├── ui.rs           # Ratatui TUI
│   └── gpu_decoder.rs  # Metal pipeline + 3-pass batch dispatch
├── test-tool/
│   ├── test.html       # Browser-based crypto reference tool
└── words.txt           # Your 8-panel wordlist
```

---

## 🐛 Troubleshooting

| Symptom                                | Cause                                     | Fix                                                                    |
| -------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| `Word list validation failed`          | A word does not have exactly 4 characters | Fix the word in `words.txt` — spaces count as characters               |
| `GPU-Init failed`                      | No Metal device / Xcode tools missing     | Run `xcode-select --install`                                           |
| `Pass 1 failed: Error`                 | GPU timeout (batch too large)             | Already tuned for 32,768 — should not occur on M1+                     |
| `All combinations tested — no matches` | Correct passphrase not in wordlist        | Expand your wordlist                                                   |
| Decrypted JSON is empty                | Salt extraction / KDF mismatch            | Run `GPU_DEBUG=1` and compare `derived[0..64]` with `test.html` output |
| `Could not save decrypted.json`        | Permission issue / read-only folder       | Run from a writable directory                                          |

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 🙏 Credits

- [ratatui](https://github.com/ratatui/ratatui) — beautiful terminal UI
- [crossterm](https://github.com/crossterm-rs/crossterm) — cross-platform terminal manipulation
- [metal-rs](https://github.com/gfx-rs/metal-rs) — Rust bindings for Apple Metal
- [CryptoJS](https://github.com/brix/crypto-js) — JavaScript crypto library (used in `test.html`)
- Tiamat — for the puzzle

---

## ⚠️ Disclaimer

This tool is for educational purposes and for solving the public Arweave puzzle.
Use responsibly. The decrypted JSON keyfile contains a private RSA key — treat
`decrypted.json` as highly sensitive data and delete it after use.

---

## Donate

```text
bc1qlpdkr5djv0mpz948wh2dutq48qnaazaauxxlh0
```

**Happy hunting! 🔑**
