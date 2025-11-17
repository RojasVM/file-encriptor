# file-encryptor

A small C++17 project that builds a `file_encryptor` command-line tool using **libsodium** for cryptographic primitives.
The project uses **CMake** and supports **GNU/Linux** and **Windows**.

## Requirements
- CMake ≥ 3.14
- C++17 compiler
- libsodium development libraries
- pkg-config (optional)

## Installing Dependencies

### GNU/Linux
Debian/Ubuntu:
```bash
sudo apt update
sudo apt install libsodium-dev pkg-config cmake g++
```

Fedora:
```bash
sudo dnf install libsodium-devel pkgconf-pkg-config cmake gcc-c++
```

Arch/Manjaro:
```bash
sudo pacman -S --needed libsodium pkgconf cmake gcc
```

### Windows

#### MSYS2 MinGW (recommended)
```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-pkgconf mingw-w64-x86_64-libsodium
```

#### MSVC + vcpkg
```powershell
vcpkg install libsodium:x64-windows
```

## Build Instructions

### GNU/Linux
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/file_encryptor
```
./
### Windows (MSVC + vcpkg)
```powershell
cmake -S . -B build -A x64 -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
.Build\ReleaseFile_encryptor.exe
```

### Windows (MSYS2 MinGW)
```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/file_encryptor.exe
```

## Running
Linux:
```bash
./build/file_encryptor
```

Windows:
```powershell
.Build\ReleaseFile_encryptor.exe
```

## Static Linking (Optional Linux)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build build -j
```

## Troubleshooting
- Ensure libsodium development files are installed.
- Verify pkg-config is available on Linux.
- If using a non-standard libsodium installation prefix:
```bash
export PKG_CONFIG_PATH=/prefix/lib/pkgconfig:$PKG_CONFIG_PATH
```
