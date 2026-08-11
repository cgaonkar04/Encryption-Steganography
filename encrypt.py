import os
import struct
import getpass
from pathlib import Path

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


# Encrypt file

def encrypt_file(file_path, password):
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        file_data = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    aes = AESGCM(key)

    # AES-GCM produces ciphertext + authentication tag
    ciphertext = aes.encrypt(
        nonce,
        file_data,
        None
    )

    # Store original filename
    filename = file_path.name.encode("utf-8")

    # Payload format:
    #
    # MAGIC
    # salt
    # nonce
    # filename length
    # filename
    # ciphertext
    #
    payload = (
        MAGIC
        + salt
        + nonce
        + struct.pack(">I", len(filename))
        + filename
        + ciphertext
    )

    return payload


# Convert bytes → bits

def bytes_to_bits(data):
    bits = []

    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    return bits


# Hide data inside image

def hide_data(image_path, payload, output_path):

    image = Image.open(image_path).convert("RGB")

    width, height = image.size
    pixels = list(image.getdata())

    bits = bytes_to_bits(payload)

    capacity = len(pixels) * 3

    # Need 32 bits to store payload length
    required_bits = 32 + len(bits)

    if required_bits > capacity:
        max_bytes = (capacity - 32) // 8

        raise ValueError(
            f"File is too large for this image.\n"
            f"Maximum payload: approximately {max_bytes / 1024:.1f} KB"
        )

    # First store payload length
    length_bits = bytes_to_bits(struct.pack(">I", len(payload)))

    all_bits = length_bits + bits

    new_pixels = []

    bit_index = 0

    for pixel in pixels:

        new_pixel = list(pixel)

        for channel in range(3):

            if bit_index < len(all_bits):

                bit = all_bits[bit_index]

                # Replace least significant bit
                new_pixel[channel] = (
                    new_pixel[channel] & 0b11111110
                ) | bit

                bit_index += 1

        new_pixels.append(tuple(new_pixel))

    encoded_image = Image.new(
        "RGB",
        (width, height)
    )

    encoded_image.putdata(new_pixels)

    encoded_image.save(
        output_path,
        format="PNG"
    )


# Main

def main():

    print("=== Secure File Steganography ===")

    carrier = input("Carrier PNG image: ").strip()
    secret = input("File to hide: ").strip()
    output = input("Output PNG: ").strip()

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    try:

        print("\nEncrypting file...")

        payload = encrypt_file(
            secret,
            password
        )

        print("Hiding encrypted data inside image...")

        hide_data(
            carrier,
            payload,
            output
        )

        print("\nSuccess!")
        print(f"Output image: {output}")

    except Exception as e:

        print(f"\nError: {e}")


if __name__ == "__main__":
    main()