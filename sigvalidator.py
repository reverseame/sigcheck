'''
This file is part of sigcheck.

sigcheck is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sigcheck is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sigcheck.  If not, see <https://www.gnu.org/licenses/>.
'''

import os
import re
import pefile
import struct
import hashlib
import binascii
import tempfile
import subprocess

from enum import Enum

CERTIFICATE_REGEX = re.compile(b'\x30.\x30.\x06.(?P<oid_algorithm>.{5,9})\x05\x00\x04(?P<hash_size>.)')
OPENSSL_REGEX = re.compile(r' *(?P<offset>[0-9]+):d=[0-9]+ +hl=(?P<header_length>[0-9]+) +l= *(?P<length>[0-9]+)')

class ReturnCode(Enum):
    CERT_EXPIRED = (1, 'Certificate expired')
    CERT_UNTRUSTED = (2, 'Certificate untrusted')
    CERT_FORMAT_ERROR = (3, 'Malformed certificate')
    CERT_VERIFICATION_SUCCESS = (4, 'Certificate verification successful')
    CERT_REVOKED = (5, 'Certificate revoked')
    AUTHENTICODE_SIGNATURE_MISMATCH_OR_INCORRECT_IMAGEBASE = (6, 'Certificate\'s hash mismatch calculated hash, or incorrect ImageBase during reconstruction')
    AUTHENTICODE_SIGNATURE_MISMATCH = (7, 'Certificate\'s hash mismatch calculated hash')
    CATALOG_SIGNED = (8, 'Verification successful (catalog-signed)')
    NOT_SIGNED_OR_INCORRECT_IMAGEBASE = (9, 'Not signed file, or incorrect ImageBase during reconstruction')
    NOT_SIGNED = (10, 'Not signed file')
    VERIFICATION_ERROR = (11, 'An error raised during verification process')

    def __int__(self):
        return self.value[0]

    def __str__(self):
        return self.value[1]

class SigValidator:
    def __init__(self, catalog=None):
        self.catalog = catalog

        _, self.file_signature = tempfile.mkstemp()
        _, self.file_signed_data = tempfile.mkstemp()

    def __del__(self):
        self.clean_workin_dir()

    def verify_pe(self, pe, rebuilt=False):
        cert = self.extract_cert(pe)

        if cert:
            algorithm, hash_file = self.get_digest_from_signature(cert)
            digest = self.calculate_pe_digest(algorithm, pe.__data__)

            if hash_file == digest:
                return self.verify_signature(cert)
            else:
                if rebuilt:
                    return ReturnCode.AUTHENTICODE_SIGNATURE_MISMATCH_OR_INCORRECT_IMAGEBASE
                else:
                    return ReturnCode.AUTHENTICODE_SIGNATURE_MISMATCH
        else:
            if self.catalog:
                for algorithm in ['md5', 'sha1', 'sha256']:
                    digest = self.calculate_pe_digest(algorithm, pe.__data__)

                    if self.is_in_catalog(digest):
                        return ReturnCode.CATALOG_SIGNED

            if rebuilt:
                return ReturnCode.NOT_SIGNED_OR_INCORRECT_IMAGEBASE
            else:
                return ReturnCode.NOT_SIGNED

    def clean_workin_dir(self):
        '''
        Deletes temporary files
        '''

        self.delete_file(self.file_signature)
        self.delete_file(self.file_signed_data)

    def delete_file(self, path):
        if os.path.exists(path):
            os.remove(path)

    def verify_signature(self, cert):
        SPC_PE_IMAGE_DATA_OBJID = '1.3.6.1.4.1.311.2.1.15'

        '''
        We need to skip _WIN_CERTIFICATE attributes and work only on bCertificate (PKCS #7 signed data)

        typedef struct _WIN_CERTIFICATE
        {
            DWORD       dwLength;
            WORD        wRevision;
            WORD        wCertificateType;   
            BYTE        bCertificate[ANYSIZE_ARRAY];
        } WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
        '''

        signature = cert[0x4+0x2+0x2:]

        self.save_data(self.file_signature, signature)

        # openssl asn1parse -inform DER -in /tmp/tmp0UGO2s
        process = subprocess.Popen(['openssl', 'asn1parse', '-inform', 'DER', '-in', self.file_signature], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = process.communicate()[0].decode("utf-8").split('\n')

        where = [i for i, item in enumerate(output) if SPC_PE_IMAGE_DATA_OBJID in item]

        if where:
            match = OPENSSL_REGEX.search(output[where[0]-2])

            offset = int(match.group('offset'))
            header_length = int(match.group('header_length'))
            length = int(match.group('length'))

            content = signature[offset+header_length:offset+header_length+length]
            self.save_data(self.file_signed_data, content)

            # openssl smime -verify -inform DER -in /tmp/tmpt8qzo4d6 -binary -content /tmp/tmpjoakp92x -purpose any -CApath /etc/ssl/certs/ -out /tmp/dummy.txt
            process = subprocess.Popen(['openssl', 'smime', '-verify', '-inform', 'DER', '-in', self.file_signature,
                                        '-binary', '-content', self.file_signed_data, '-purpose', 'any', '-CApath',
                                        '/etc/ssl/certs/', '-out', '/tmp/dummy.txt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            output = process.communicate()[1].decode("utf-8")
            result = output.split(':')[-1].replace('\n', '')

            if result:
                # Capitalize first letter
                return result.capitalize()
            else:
                return ReturnCode.VERIFICATION_ERROR
        else:
            return ReturnCode.CERT_FORMAT_ERROR

    def extract_cert(self, pe):
        '''
        Extracts _WIN_CERTIFICATE structure specified in Security directory entry

        @param pe: pefile.PE object

        @return _WIN_CERTIFICATE
        '''

        if self.has_cert(pe):
            security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]

            return pe.__data__[security_directory.VirtualAddress:security_directory.VirtualAddress+security_directory.Size]

    def has_cert(self, pe):
        security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]

        return (security_directory.Size and security_directory.VirtualAddress) != 0x0

    def get_digest_from_signature(self, signature):
        # $ openssl asn1parse -inform DER -in signature.der
        # https://github.com/torvalds/linux/blob/450313c5d1313e79059031e6185174616f7ea329/lib/oid_registry_data.c

        # OID_signed_data = binascii.unhexlify('2a864886f70d010702') # pkcs7-signedData

        OID_md5 = binascii.unhexlify('2a864886f70d0205')            # md5
        OID_sha1 = binascii.unhexlify('2b0e03021a')                 # sha1
        OID_sha256 = binascii.unhexlify('608648016503040201')       # sha256

        match = CERTIFICATE_REGEX.search(signature)

        if match:
            oid_algorithm = match.group('oid_algorithm')
            hash_size = ord(match.group('hash_size'))
            where = match.end()

            digest = signature[where:where+hash_size]

            if oid_algorithm == OID_md5:
                return 'md5', digest
            elif oid_algorithm == OID_sha1:
                return 'sha1', digest
            elif oid_algorithm == OID_sha256:
                return 'sha256', digest
        else:
            return None, 0x00

    def calculate_pe_digest(self, algorithm, raw_data):
        '''
        Calculate Authenticode hash given an algorithm

        @param algoritm: md5, sha1, sha256, or other function contained in hashlib
        @param raw_data: PE raw data

        @return calculated hash string
        '''

        # Skip parts omitted by Authenticode hash algorithm
        # http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx

        nt_headers_addr = self.get_nt_header_addr(raw_data)
        checksum_addr = nt_headers_addr + 0x58

        certificate_table_addr, certificate_virtual_addr, certificate_size = self.get_pe_certificate_attibutes(raw_data)

        # PE header except OptionalHeader.CheckSum and OptionalHeader.SecurityDirectoryEntry, because those fields are modified
        # due to the sign process itself
        data = raw_data[:checksum_addr] + raw_data[checksum_addr+0x04:certificate_table_addr]

        # Skip only embedded signature, there can be data after it
        if (certificate_virtual_addr and certificate_size) != 0x0:
            data += raw_data[certificate_table_addr+0x08:certificate_virtual_addr] + raw_data[certificate_virtual_addr+certificate_size:]
        # Or don't skip anything if signature is not present
        else:
            data += raw_data[certificate_table_addr+0x08:]

        return getattr(hashlib, algorithm)(data).digest()

    def get_nt_header_addr(self, pe_data):
        '''
        Gets NtHeader offset

        @param pe_data: PE raw data

        @return NtHeader offset
        '''
        if pe_data[:2] == b'\x4D\x5A':              # MZ
            nt_headers_addr = self.unpack_dword(pe_data[0x3c:0x3c+0x04])
            nt_headers = pe_data[nt_headers_addr:nt_headers_addr+0x04]
            if nt_headers == b'\x50\x45\x00\x00':   # PE
                return nt_headers_addr

    def get_pe_certificate_attibutes(self, pe_data):
        '''
        Gets SecurityDirectoryEntry offset and its attributes

        @param pe_data: PE raw data

        @return tuple with SecurityDirectoryEntry offset, SecurityDirectoryEntry.VirtualAddress, SecurityDirectoryEntry.Size
        '''
        nt_headers = self.get_nt_header_addr(pe_data)

        if self.is_32bits(pe_data):
            certificate_table_addr = nt_headers + 0x98
        elif self.is_64bits(pe_data):
            certificate_table_addr = nt_headers + 0xa8

        certificate_virtual_addr = self.unpack_dword(pe_data[certificate_table_addr:certificate_table_addr+0x04])
        certificate_size = self.unpack_dword(pe_data[certificate_table_addr+0x04:certificate_table_addr+0x08])

        return certificate_table_addr, certificate_virtual_addr, certificate_size

    def is_32bits(self, content):
        nt_headers_addr = self.get_nt_header_addr(content)
            
        magic = content[nt_headers_addr+0x18:nt_headers_addr+0x18+0x2]

        return magic == b'\x0B\x01'

    def is_64bits(self, content):
        nt_headers_addr = self.get_nt_header_addr(content)
            
        magic = content[nt_headers_addr+0x18:nt_headers_addr+0x18+0x2]

        return magic == b'\x0B\x02'

    def unpack_dword(self, bytes_):
        return struct.unpack('<I', bytes_)[0]

    def is_in_catalog(self, digest):
        files = self.get_files_by_extension(self.catalog, '.cat')

        for f in files:
            data = self.read_data(f)
            for match in CERTIFICATE_REGEX.finditer(data):
                oid_algorithm = match.group('oid_algorithm')
                hash_size = ord(match.group('hash_size'))
                where = match.end()

                hash_digest = data[where:where+hash_size]

                if digest == hash_digest:
                    return True

        return False

    def get_files_by_extension(self, path, extension):
        ret = []

        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    _, ext = os.path.splitext(f)
                    if ext == extension:
                        ret += [os.path.join(root, f)]

        return ret

    def read_data(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def save_data(self, filename, file_content):
        with open(filename, 'wb') as f:
            f.write(file_content)
