# ROP Hunter

![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ROP Hunter** is a modular Return-Oriented Programming (ROP) gadget finder written in Rust. It analyzes ELF and PE binaries to extract gadgets ending in `ret`, optimized for x86_64 architecture. Built with a focus on exploit development, it combines a flashy CLI with practical features like gadget filtering, JSON export, and parallel processing.

## Features

- **Multi-Format Support**: Processes ELF (Linux) and PE (Windows) binaries seamlessly.
- **x86_64 Gadget Hunting**: Identifies gadgets ending in `ret` (opcode `0xC3`) using an 8-byte lookback window for preceding instructions.
- **Flashy UI**: Displays color-coded output (green for gadgets, cyan for sections, yellow for warnings) and organizes results in tables with `prettytable`.
- **Filtering**: Filters gadgets by instruction keywords (e.g., `--filter "pop,mov"`) with comma-separated patterns.

## Installation

### Prerequisites

- Rust 1.70 or later (install via [rustup](https://rustup.rs/))
- For PE support on Linux/WSL: `gcc-mingw-w64-x86-64` (cross-compiler for Windows PE binaries)

On Ubuntu/WSL:

```bash
sudo apt update
sudo apt install gcc-mingw-w64-x86-64
```

### Example binaries

```bash
gcc -m64 -o test_binary test.c # For Linux
x86_64-w64-mingw32-gcc -o test_binary.exe test.c # For Windows
```

### Building from source

```bash
# Build in release mode
cargo build --release

# The binary will be available at target/release/rop-hunter
```

## Usage

Basic usage:

```bash
# Scan a Linux binary
rop-hunter /bin/ls

# Scan a Windows PE file
rop-hunter program.exe

# Filter for specific instructions
rop-hunter /bin/ls --filter "pop,mov,ret"
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `--filter <PATTERN>` | Filter gadgets containing specific instructions (comma-separated) |

**Note:** Additional options like `--output`, `--verbose`, `--no-color`, etc. are planned for future releases.

## Example Output

```bash
Scanning: /bin/ls
Read 149080 bytes
Detected ELF file
[+] Scanning /bin/ls (ELF x86_64)...
[+] Found 3 executable sections

Section: .text (0x4000 bytes at 0x00401000)
|----------------------------------------------------|
| Address    | Bytes             | Disassembly       |
|----------------------------------------------------|
| 0x00401123 | 5b c3             | pop rbx; ret      |
| 0x00401245 | 58 5f c3          | pop rax; pop rdi; ret |
| 0x0040137a | 48 89 c7 c3       | mov rdi, rax; ret |
|----------------------------------------------------|

[+] Found 127 unique gadgets in 0.42 seconds
```

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Make your changes and commit: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

Please make sure your code follows the project's coding style and includes appropriate tests.

## Troubleshooting

### Common Issues

- **Error loading PE files**: Make sure you have the necessary cross-compiler installed
- **Missing gadgets**: Check if the binary is stripped or obfuscated
- **Performance issues**: For large binaries, consider using filtering to reduce output

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Capstone Engine](https://www.capstone-engine.org/) for disassembly
- [Goblin](https://docs.rs/goblin) for binary parsing
- Inspired by other ROP gadget finders like ROPgadget and ropper
