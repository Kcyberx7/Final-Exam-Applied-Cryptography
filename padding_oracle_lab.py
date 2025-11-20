from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)


def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if padding is valid."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()

        return True

    except Exception:
        return False


# -------------------------
# Task 2: Block Splitting
# -------------------------
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


# -------------------------
# Task 3: Decrypt One Block
# -------------------------
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    plaintext = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    fake_block = bytearray(BLOCK_SIZE)

    for pad in range(1, BLOCK_SIZE + 1):  # padding = 1 to 16
        # fix already discovered bytes
        for j in range(1, pad):
            fake_block[-j] = intermediate[-j] ^ pad

        # try all 256 guesses
        for guess in range(256):
            fake_block[-pad] = guess
            forged = bytes(fake_block + target_block)

            if padding_oracle(forged):
                intermediate_value = guess ^ pad
                intermediate[-pad] = intermediate_value
                plaintext[-pad] = intermediate_value ^ prev_block[-pad]
                break

    return bytes(plaintext)


# -------------------------
# Task 4: Full Attack
# -------------------------
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext)
    iv = blocks[0]
    ct_blocks = blocks[1:]

    plaintext = b""
    prev = iv

    for block in ct_blocks:
        decrypted = decrypt_block(prev, block)
        plaintext += decrypted
        prev = block

    return plaintext


# -------------------------
# Task 5: Unpad and Decode
# -------------------------
def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode(errors="ignore")
    except Exception:
        return "<Error decoding plaintext>"


# -------------------------
# Main Program
# -------------------------
if __name__ == "__main__":
    ciphertext = unhexlify(CIPHERTEXT_HEX)
    print("[*] Ciphertext length:", len(ciphertext))
    print("[*] IV:", ciphertext[:BLOCK_SIZE].hex())

    recovered = padding_oracle_attack(ciphertext)

    print("\n[+] Decryption complete!")
    print("Recovered plaintext (raw bytes):", recovered)
    print("Hex:", recovered.hex())

    decoded = unpad_and_decode(recovered)
    print("\nFinal plaintext:")
    print(decoded)
