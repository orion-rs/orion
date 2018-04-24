import os
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# This file is used for generating test vectors for PBKDF2 with SHA2

pbkdf_1_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 32,
    salt = b"salt",
    iterations = 1,
    backend = backend
)

pbkdf_2_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 32,
    salt = b"salt",
    iterations = 2,
    backend = backend
)

pbkdf_3_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 32,
    salt = b"salt",
    iterations = 4096,
    backend = backend
)

pbkdf_4_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 32,
    salt = b"salt",
    iterations = 16777216,
    backend = backend
)

pbkdf_5_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 40,
    salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
    iterations = 4096,
    backend = backend
)

pbkdf_6_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 16,
    salt = b"sa\0lt",
    iterations = 4096,
    backend = backend
)

print("TC1:", binascii.hexlify(pbkdf_1_256.derive(b"password")))
print("TC2:", binascii.hexlify(pbkdf_2_256.derive(b"password")))
print("TC3:", binascii.hexlify(pbkdf_3_256.derive(b"password")))
print("TC4:", binascii.hexlify(pbkdf_4_256.derive(b"password")))
print("TC5:", binascii.hexlify(pbkdf_5_256.derive(b"passwordPASSWORDpassword")))
print("TC6:", binascii.hexlify(pbkdf_6_256.derive(b"pass\0word")))
