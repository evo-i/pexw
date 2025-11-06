# pexw - Cross-Platform PE String Extractor

A cross-platform tool for extracting and decrypting strings from PE files (DLL/EXE) with multi-threaded processing.

## Features

- **Cross-platform**: Windows, Linux, macOS, *BSD
- **Multi-threaded**: Parallel processing with configurable thread count
- **Native PE parsing**: Manual PE structure parsing without external dependencies
- **XOR decryption**: Automatic decryption with key 0x5
- **High-performance**: Atomic operations and lock-based synchronization

## Architecture

The tool uses a sophisticated multi-threaded approach:
- **RData scanner threads**: Search for data markers in parallel
- **Marker function finder**: Identifies functions containing only marker references
- **String extraction threads**: Extract and decrypt strings in parallel
- **Atomic synchronization**: Lock-free coordination between threads

## Requirements

- C17 compiler (GCC, Clang, MSVC)
- POSIX threads (pthread on Unix-like systems, native threads on Windows)
- Standard C library

No external dependencies required - all PE parsing and disassembly is done natively.

## Building

### Using Meson (recommended)

```bash
# Setup build directory
meson setup builddir

# Compile
meson compile -C builddir

# Install (optional)
meson install -C builddir
```

### Manual compilation

#### Windows (MSYS2/MinGW)
```bash
gcc -std=c17 -O2 -Wall -Wextra pexw.c -o pexw.exe
```

#### Linux/macOS/*BSD
```bash
gcc -std=c17 -O2 -Wall -Wextra -pthread pexw.c -o pexw
```

## Usage

```bash
# Basic usage with auto-detected CPU count
./pexw sample.dll

# Specify custom thread count
./pexw sample.dll 8

# Windows
pexw.exe sample.dll 4
```

### Parameters
- `<PEfile>`: Path to the PE file (DLL or EXE)
- `[threads]`: Optional thread count (defaults to CPU core count)

## Output Format

The tool outputs decrypted strings in the format:
```
data01: Decrypted string content
data02: Another decrypted string
...
```

Performance information is written to stderr:
```
Elapsed: 0.1234 s (threads=8)
```

## Algorithm Overview

1. **PE File Loading**: Memory-mapped file loading for efficiency
2. **Header Parsing**: DOS, NT, and Optional Headers validation
3. **Section Discovery**: Locate .text (code) and .rdata (data) sections
4. **Parallel Marker Search**: Multi-threaded scanning for `dataXX` patterns in .rdata
5. **Marker Function Discovery**: Find function containing only marker references using atomic coordination
6. **String Extraction**: Multi-threaded extraction and XOR decryption (key: 0x5)
7. **Output**: Display marker-string pairs sorted by RVA

## Technical Details

### PE Structure Analysis
```
DOS Header (MZ)
  └─> e_lfanew → NT Headers (PE)
                   ├─> File Header
                   └─> Optional Header64
                         └─> Sections
                               ├─> .text (executable code)
                               └─> .rdata (read-only data)
```

### Function Pattern Recognition

**Function Prologue Pattern:**
```asm
sub rsp, 0x38     ; 48 83 EC 38 - Stack allocation
```

**LEA Instruction Pattern:**
```asm
lea rdx, [rip + disp]  ; 48 8D 15 [disp] - RIP-relative addressing
```

**Marker Function Criteria:**
- Contains ≥15 LEA instructions
- All references point to dataXX markers
- No references to other strings
- Uses atomic synchronization for thread-safe discovery

**String Function Criteria:**
- Contains ≥15 LEA instructions  
- All references point to non-marker strings
- Found after processing all marker functions

### XOR Decryption
```c
void xor_decrypt_inplace(char *s, char byte) {
    for (size_t i = 0; s[i]; ++i) {
        s[i] = (char)(s[i] ^ byte);
    }
}
```

### Threading Architecture

The application uses a sophisticated threading model:

- **Thread-safe data structures**: Mutex-protected dynamic arrays
- **Atomic coordination**: Lock-free marker function discovery
- **Work distribution**: Even workload distribution across CPU cores
- **Platform abstraction**: Windows threads vs POSIX threads

## Platform Support

| Platform | Status | Threading | Timer |
|----------|--------|-----------|-------|
| Windows | ✅ | Native Windows threads | QueryPerformanceCounter |
| Linux | ✅ | POSIX threads | clock_gettime |
| macOS | ✅ | POSIX threads | clock_gettime |
| FreeBSD | ✅ | POSIX threads | clock_gettime |
| OpenBSD | ✅ | POSIX threads | clock_gettime |
| NetBSD | ✅ | POSIX threads | clock_gettime |

## Error Handling

The tool validates all PE structures and provides clear error messages:

- **"file too small"**: File smaller than DOS header
- **"invalid DOS"**: Missing MZ signature
- **"invalid PE"**: Missing PE signature  
- **"only x64 supported"**: Not an AMD64 executable
- **".text or .rdata not found"**: Required sections missing

## Example Usage

### Basic Analysis
```bash
./pexw sample.dll
```

Output:
```
data01: C:\Program Files\Application\config.ini
data02: SELECT * FROM users WHERE id = ?
data03: Error: Invalid configuration file
...
Elapsed: 0.0156 s (threads=8)
```

### Performance Tuning
```bash
# Use 16 threads for large files
./pexw large_file.dll 16

# Use single thread for debugging
./pexw sample.dll 1
```

## Troubleshooting

### Common Issues

**"Invalid DOS signature"**
- Verify the file is a valid PE executable
- Check if the file is packed or protected

**"Required sections not found"**
- PE file must contain both .text and .rdata sections
- Some packed executables may have renamed sections

**"No markers found"**
- The executable might use a different string obfuscation method
- Try different XOR keys (modify `XOR_KEY` constant)

### Performance Tips

- **Optimal thread count**: Usually matches CPU core count
- **Large files**: Consider increasing `SCAN_DEPTH` for complex executables
- **Memory usage**: Tool loads entire PE file into memory

## License

MIT License

## Technical References

- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Intel x86-64 Instruction Set](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [POSIX Threads Programming](https://computing.llnl.gov/tutorials/pthreads/)
