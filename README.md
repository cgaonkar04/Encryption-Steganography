# Secure File Steganography

A Python-based security utility that combines **AES-256-GCM encryption** and **LSB image steganography** to hide encrypted files inside PNG images.

The project provides two layers of protection:

- **Encryption:** Protects the contents of the file.
- **Steganography:** Conceals the existence of the encrypted data.

---

## Architecture

```text
                    Input File
                        │
                        ▼
                Read file as bytes
                        │
                        ▼
          Password ──► PBKDF2
                        │
                   AES-256 Key
                        │
                        ▼
                   AES-GCM
                        │
                        ▼
              Encrypted Payload
                        │
                        ▼
                 Convert to bits
                        │
                        ▼
              LSB Image Embedding
                        │
                        ▼
                   hidden.png
```

The reverse process is used for extraction and decryption.

---

## Encryption Flow

### 1. Read the input file

The selected file is opened in binary mode and read as raw bytes. This allows the system to work with different file types such as PDFs, images, and documents.

### 2. Derive the encryption key

The user's password is not used directly as an AES key.

A random **16-byte salt** is generated and used with:

```text
PBKDF2-HMAC-SHA256
```

to derive a **32-byte (256-bit) AES key**.

```text
Password + Salt
       │
       ▼
     PBKDF2
       │
       ▼
  256-bit AES Key
```

PBKDF2 uses repeated hashing to make password-guessing attacks more computationally expensive.

### 3. Encrypt using AES-GCM

The file is encrypted using **AES-256-GCM**.

A random **12-byte nonce** is generated for each encryption.

```text
File Bytes + AES Key + Nonce
             │
             ▼
          AES-GCM
             │
             ▼
     Ciphertext + Auth Tag
```

GCM provides both **confidentiality** and **integrity**. If the wrong password is supplied or the encrypted data has been modified, authentication fails during decryption.

The nonce and salt do not need to be secret and are stored with the encrypted payload.

---

## Payload Structure

Before hiding the data inside the image, the project constructs a binary payload:

```text
┌────────┬──────┬───────┬───────────────┬──────────┬────────────┐
│ MAGIC  │ SALT │ NONCE │ Filename Size │ Filename │ Ciphertext │
└────────┴──────┴───────┴───────────────┴──────────┴────────────┘
```

This allows the decoder to reconstruct the required information.

The original filename is also stored so that the recovered file can retain its original name.

---

## LSB Steganography

The encrypted payload is converted from bytes into individual bits:

```text
Byte: 10110110

        ↓

Bits: 1 0 1 1 0 1 1 0
```

These bits are hidden in the **Least Significant Bit (LSB)** of the RGB channels of the carrier image.

For example:

```text
Original pixel:

R = 10110110
G = 01011110
B = 11100111
```

If the secret bits are:

```text
1 0 1
```

the pixel becomes:

```text
R = 10110111
G = 01011110
B = 11100111
```

Only the least significant bit is changed, so the visual difference is negligible.

The output is saved as **PNG** because PNG uses lossless compression. Lossy formats such as JPEG can modify pixel values and destroy the hidden data.

---

## Decryption Flow

```text
hidden.png
    │
    ▼
Extract LSBs
    │
    ▼
Reconstruct Payload
    │
    ├── Salt
    ├── Nonce
    ├── Filename
    └── Ciphertext
            │
            ▼
    PBKDF2(password, salt)
            │
            ▼
       AES-256 Key
            │
            ▼
       AES-GCM Decrypt
            │
            ▼
      Original File Bytes
```

The password is used with the stored salt to derive the same AES key. AES-GCM then authenticates and decrypts the ciphertext, after which the original file is reconstructed.

---

## Capacity

The amount of data that can be hidden depends on the carrier image dimensions.

Since one bit is stored per RGB channel:

```text
Capacity = Width × Height × 3 bits
```

For example, a `1079 × 1317` RGB image provides approximately:

```text
1079 × 1317 × 3 ≈ 4.26 million bits
```

or roughly **532 KB of raw capacity**, before accounting for metadata.

---

## Security Model

The project combines two different security mechanisms:

```text
             File
              │
              ▼
          AES-GCM
              │
              ▼
      Encrypted Data
              │
              ▼
      LSB Steganography
              │
              ▼
         Carrier PNG
```

**AES-GCM** protects the contents even if the hidden data is discovered.

**Steganography** makes the encrypted data less obvious by hiding it inside an ordinary-looking image.

---



### Files

```text
encrypt.py   → Encrypts and hides the file
decode.py    → Extracts and decrypts the file
```

The original input file is not modified during encryption; the encrypted copy is stored inside the generated PNG.
