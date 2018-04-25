import os
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# This file is used for generating test vectors for PBKDF2 with SHA2
# Parameters are taken from the [RFC 6070](https://datatracker.ietf.org/doc/rfc6070/)
# that uses PBKDF2-HMAC-SHA1
###############################################################################
test_vector_1_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 20,
    salt = b"salt",
    iterations = 1,
    backend = backend
)

test_vector_2_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 20,
    salt = b"salt",
    iterations = 2,
    backend = backend
)

test_vector_3_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 20,
    salt = b"salt",
    iterations = 4096,
    backend = backend
)

test_vector_4_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 20,
    salt = b"salt",
    iterations = 16777216,
    backend = backend
)

test_vector_5_256 = PBKDF2HMAC (
    algorithm = hashes.SHA256(),
    length = 25,
    salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
    iterations = 4096,
    backend = backend
)

test_vector_6_256 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 16,
    salt = b"sa\0lt",
    iterations = 4096,
    backend = backend
)
###############################################################################
test_vector_1_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 20,
    salt = b"salt",
    iterations = 1,
    backend = backend
)

test_vector_2_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 20,
    salt = b"salt",
    iterations = 2,
    backend = backend
)

test_vector_3_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 20,
    salt = b"salt",
    iterations = 4096,
    backend = backend
)

test_vector_4_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 20,
    salt = b"salt",
    iterations = 16777216,
    backend = backend
)

test_vector_5_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 25,
    salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
    iterations = 4096,
    backend = backend
)

test_vector_6_384 = PBKDF2HMAC (
    algorithm = hashes.SHA384(),
    length = 16,
    salt = b"sa\0lt",
    iterations = 4096,
    backend = backend
)
###############################################################################
test_vector_1_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 20,
    salt = b"salt",
    iterations = 1,
    backend = backend
)

test_vector_2_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 20,
    salt = b"salt",
    iterations = 2,
    backend = backend
)

test_vector_3_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 20,
    salt = b"salt",
    iterations = 4096,
    backend = backend
)

test_vector_4_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 20,
    salt = b"salt",
    iterations = 16777216,
    backend = backend
)

test_vector_5_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 25,
    salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
    iterations = 4096,
    backend = backend
)

test_vector_6_512 = PBKDF2HMAC (
    algorithm = hashes.SHA512(),
    length = 16,
    salt = b"sa\0lt",
    iterations = 4096,
    backend = backend
)
###############################################################################
print("SHA256 TC1:", binascii.hexlify(test_vector_1_256.derive(b"password")))
print("SHA256 TC2:", binascii.hexlify(test_vector_2_256.derive(b"password")))
print("SHA256 TC3:", binascii.hexlify(test_vector_3_256.derive(b"password")))
print("SHA256 TC4:", binascii.hexlify(test_vector_4_256.derive(b"password")))
print("SHA256 TC5:", binascii.hexlify(test_vector_5_256.derive(b"passwordPASSWORDpassword")))
print("SHA256 TC6:", binascii.hexlify(test_vector_6_256.derive(b"pass\0word")))
###############################################################################
print("SHA384 TC1:", binascii.hexlify(test_vector_1_384.derive(b"password")))
print("SHA384 TC2:", binascii.hexlify(test_vector_2_384.derive(b"password")))
print("SHA384 TC3:", binascii.hexlify(test_vector_3_384.derive(b"password")))
print("SHA384 TC4:", binascii.hexlify(test_vector_4_384.derive(b"password")))
print("SHA384 TC5:", binascii.hexlify(test_vector_5_384.derive(b"passwordPASSWORDpassword")))
print("SHA384 TC6:", binascii.hexlify(test_vector_6_384.derive(b"pass\0word")))
###############################################################################
print("SHA512 TC1:", binascii.hexlify(test_vector_1_512.derive(b"password")))
print("SHA512 TC2:", binascii.hexlify(test_vector_2_512.derive(b"password")))
print("SHA512 TC3:", binascii.hexlify(test_vector_3_512.derive(b"password")))
print("SHA512 TC4:", binascii.hexlify(test_vector_4_512.derive(b"password")))
print("SHA512 TC5:", binascii.hexlify(test_vector_5_512.derive(b"passwordPASSWORDpassword")))
print("SHA512 TC6:", binascii.hexlify(test_vector_6_512.derive(b"pass\0word")))
