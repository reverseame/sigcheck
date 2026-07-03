# Sigcheck - Volatility Plugin

> **`master` is the Volatility 3 / Python 3 version.** The legacy Volatility 2.6 (Python 2.7) version lives on the [`volatility2-latest`](../../tree/volatility2-latest) branch.

`sigcheck` aims to verify digital signatures of executable files (namely, .exe, .dll, and .sys files) in memory dumps. It is named after the [Microsoft's tool](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) that verifies digital signatures on binary files.

Microsoft Authenticode is the code-signing standard used by Windows to digitally sign files that adopt the Windows portable executable (PE) format (you can find more details in [documentation](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx)). These executables are signed either with embedded signature or catalog-signed; in order to verfiy the last, you **must** provide all catalog files (.cat) corresponding to your Windows version, located in `system32/catroot` (you can download catalog files extracted from [Win7SP1x86](https://drive.google.com/file/d/1l01L6A2YO9F9a9weo55PA_A_YeTZ-qBo/view?usp=sharing), [Win7SP1x64](https://drive.google.com/file/d/1CRMcOEDwN8P732EyQlNaY34ZUDuIWsyL/view?usp=sharing)).

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

### Sigvalidator

As a side product, we have also developed an independent Python module to verify signatures of PE files:

```python
import pefile
import sigvalidator

sigv = sigvalidator.SigValidator()

for path in ['Firefox Setup 77.0.exe', 'procexp.exe', 'invoice.exe.mlwr', 'CFF Explorer.exe']:
    pe = pefile.PE(path, fast_load=True)
    result = sigv.verify_pe(pe)
    print('{0}: {1}'.format(path, result))
```

```
Firefox Setup 77.0.exe: Verification successful
procexp.exe: Certificate has expired
invoice.exe.mlwr: Self signed certificate in certificate chain
CFF Explorer.exe: Not signed file
```

## Installation

- System: `openssl` (the plugin shells out to it for PKCS#7 verification)
- Python 3 with [Volatility 3](https://github.com/volatilityfoundation/volatility3) installed, plus `pefile>=2019.4.18` and `cryptography`

```
pip install volatility3 pefile cryptography
```

## Usage

```
Aims to validate Authenticode-signed processes, either with embedded signature or catalog-signed

Options:
    --catalog DIR  directory containing catalog files (.cat) to look signatures into
    --dll          verify library modules (.dll) as well
    --sys          verify driver modules (.sys)
```
You need to provide this project path as a [plugin directory to Volatility 3](https://volatility3.readthedocs.io/en/latest/getting-started.html) with `-p`:

```
$ vol -q -p /path/to/sigcheck --catalog /path/to/catroot -f /path/to/memory.dump sigcheck
Volatility 3 Framework 2.28.1

Module                  Pid     Result
smss.exe                268     Unable to rebuild PE file
csrss.exe               348     Partial file content. Not signed file (maybe catalog-signed?)
services.exe            476     Partial file content. Not signed file (maybe catalog-signed?)
taskhost.exe            1864    Not signed file
VBoxTray.exe            316     Partial file content. Unable to compare file hash and signature hash. Signature verification: Malformed certificate
ALINA_CJLXYJ.exe        1828    PE OptionalHeader.CheckSum mismatch

[... redacted ...]
```

> To obtain `Verification successful (catalog-signed)` for Windows system binaries you **must** supply the matching `.cat` catalog files via `--catalog` (see the links above). Without them, catalog-signed files are reported as *"maybe catalog-signed?"*.

## License

Licensed under the [GNU GPLv3](LICENSE) license.
