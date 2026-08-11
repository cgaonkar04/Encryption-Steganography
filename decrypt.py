import os
import struct
import getpass

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000

MAGIC = b"STEGv1"


# Key derivation

def derive_key(password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(password.encode("utf-8"))


# Convert bits → bytes

def bits_to_bytes(bits):

    if len(bits) % 8 != 0:
        raise ValueError("Invalid bit sequence.")

    result = bytearray()

    for i in range(0, len(bits), 8):

        byte = 0

        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit

        result.append(byte)

    return bytes(result)


# Extract hidden data

def extract_data(image_path):

    image = Image.open(image_path).convert("RGB")

    pixels = list(image.getdata())

    bits = []

    for pixel in pixels:

        for channel in pixel:

            bits.append(channel & 1)

    # First 32 bits = payload length
    length_bits = bits[:32]

    length_data = bits_to_bytes(length_bits)

    payload_length = struct.unpack(
        ">I",
        length_data
    )[0]

    total_bits = 32 + payload_length * 8

    if total_bits > len(bits):

        raise ValueError(
            "Invalid image or corrupted steganographic data."
        )

    payload_bits = bits[32:total_bits]

    payload = bits_to_bytes(payload_bits)

    return payload


# Decrypt payload

def decrypt_payload(payload, password):

    offset = 0

    # Check magic
    magic = payload[
        offset:offset + len(MAGIC)
    ]

    offset += len(MAGIC)

    if magic != MAGIC:
        raise ValueError(
            "No valid encrypted payload found."
        )

    # Salt
    salt = payload[
        offset:offset + SALT_SIZE
    ]

    offset += SALT_SIZE

    # Nonce
    nonce = payload[
        offset:offset + NONCE_SIZE
    ]

    offset += NONCE_SIZE

    # Filename length
    filename_length = struct.unpack(
        ">I",
        payload[offset:offset + 4]
    )[0]

    offset += 4

    # Filename
    filename = payload[
        offset:offset + filename_length
    ].decode("utf-8")

    offset += filename_length

    # Remaining bytes = ciphertext
    ciphertext = payload[offset:]

    # Derive key
    key = derive_key(
        password,
        salt
    )

    aes = AESGCM(key)

    # Wrong password OR modified data
    # causes this to fail
    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return filename, plaintext


# Main

def main():

    print("=== Secure File Steganography ===")

    image_path = input(
        "Steganographic PNG: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    try:

        print("\nExtracting hidden data...")

        payload = extract_data(
            image_path
        )

        print("Decrypting...")

        filename, file_data = decrypt_payload(
            payload,
            password
        )

        with open(filename, "wb") as f:
            f.write(file_data)

        print("\nSuccess!")
        print(f"Recovered file: {filename}")

    except Exception as e:

        print("\nDecryption failed.")
        print(
            "Possible causes: wrong password, "
            "corrupted image, or no valid payload."
        )


if __name__ == "__main__":
    main()