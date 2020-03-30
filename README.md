# Sigcheck - Volatility Plugin

`sigcheck` for Volatility 2.6 aims to verify digital signatures of executable files (namely, .exe, .dll, and .sys files) in memory dumps. It is named after the [Microsoft's tool](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) that verifies digital signatures on binary files.

Microsoft Authenticode is the code-signing standard used by Windows to digitally sign files that adopt the Windows portable executable (PE) format (you can find more details in [documentation](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx)). These executables are signed either with embedded signature or catalog-signed; in order to verfiy the last, you **must** provide all catalog files (.cat) corresponding to your Windows version (located in `system32/catroot`).

### Sigvalidator

`sigvalidator` module allows you to directly verify executable files:

```python
import pefile
import sigvalidator

sigv = sigvalidator.SigValidator()

for path in ['Firefox Setup 69.0.2.exe', 'procexp.exe', 'invoice.exe.mlwr', 'CFF Explorer.exe']:
    pe = pefile.PE(path, fast_load=True)
    result = sigv.verify_pe(pe)
    print '{0}: {1}'.format(path, result)
```

```
Firefox Setup 69.0.2.exe: Verification successful
procexp.exe: Certificate has expired
invoice.exe.mlwr: Self signed certificate in certificate chain
CFF Explorer.exe: Not signed file
```

## Instalation

You can install all dependencies with [setup.sh](setup.sh):

- System: `openssl`
- Python 2.7: `pefile>=2019.4.18`, `pycrypto`, `enum34`

## Usage

```
---------------------------------
Module SigCheck
---------------------------------

Aims to validate Authenticode-signed processes, either with embedded signature or catalog-signed

Options:
   --catalog [dir]: directory containing catalog files (.cat), default to '$PWD/catroot/$VOL_PROFILE'
    --dll: verify library modules (.dll)
    --sys: verify driver modules (.sys)
```
You need to provide this project path as [first parameter to Volatility](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#specifying-additional-plugin-directories):

```
$ vol.py --plugins /path/to/sigcheck --profile WinProfile --catalog /path/to/catroot -f /path/to/memory.dump sigcheck --sys
Volatility Foundation Volatility Framework 2.6.1

INFO    : volatility.debug    : sigcheck        : Retrieving all file objects, this may take a while...

Module                       Pid Result                                                                                                                  
------------------------- ------ -----------------------------------------------------------------------------------------------------------------------------------
ACPI.sys                       0 Partial file content. Unable to compare file hash and signature hash. Signatue verification: Unable to get local issuer certificate
usbuhci.sys                    0 Verification successful (catalog-signed)
monitor.sys                    0 Verification successful (catalog-signed)
ndistapi.sys                   0 Verification successful (catalog-signed)
spldr.sys                      0 Unable to read FileObject
volsnap.sys                    0 Unable to read FileObject
ntoskrnl.exe                   0 Unable to read FileObject
peauth.sys                     0 Verification successful (catalog-signed)
srvnet.sys                     0 Verification successful (catalog-signed)
srv.sys                        0 Partial file content. Not signed file
vmhgfs.sys                     0 Unable to rebuilt PE file
asyncmac.sys                   0 Verification successful (catalog-signed)
luafv.sys                      0 Verification successful (catalog-signed)
lltdio.sys                     0 Verification successful (catalog-signed)
rspndr.sys                     0 Verification successful (catalog-signed)

[... redacted ...]
```

## License

Licensed under the [GNU GPLv3](LICENSE.txt) license.
