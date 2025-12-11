from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import random
import os

'''
Experimental Cryptanalysis, Avalanche Effect in AES

Steps:
1. Take a fixed 128-bit AES key
2. Encrypt 2 plaintexts that differ in exactly 1 bit
3. Compare the two ciphertexts and count how many output bits are different
4. repeat 1-3 steps 5 times with different random plaintext
5. Display result and note how many output bits were changed when a signal bit is flipped
'''

def run_aes(plaintext : bytes, key : bytes) -> bytes:
    '''
    Encrypts plaintext using AES-128 in ECB mode with PKCS7 padding.
    
    :param plaintext: The data to be encrypted (bytes).
    :type plaintext: bytes
    :param key: The 16-byte AES key (bytes).
    :type key: bytes
    :return: The resulting ciphertext (bytes).
    :rtype: bytes
    '''
    # AES block size is 128 bits (16 bytes)
    block_size_bits = 128
    
    # Pad plaintext 
    # Use 128 for PKCS7 padder block size parameter (since AES block size is 128 bits)
    padder = padding.PKCS7(block_size_bits).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
        
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def create_random_plaintext(length: int = 16) -> bytes:
    '''
    Creates a random bytes object for plaintext. 
    :param length: The desired length of the plaintext in bytes. Defaults to 16.
    :type length: int
    :return: A random bytes object.
    :rtype: bytes
    '''
    # Generate random bytes directly, ensuring it's at least 16 bytes for padding
    # or just use 16 bytes (1 block) for simplicity in analysis.
    return os.urandom(length)

def flip_single_bit(data: bytes, byte_index: int, bit_index: int) -> bytes:
    '''
    Flips a single bit in a bytes object at a specified position.

    :param data: The input bytes.
    :type data: bytes
    :param byte_index: The index of the byte to modify.
    :type byte_index: int
    :param bit_index: The position of the bit (0-7, where 0 is LSB, 7 is MSB).
    :type bit_index: int
    :return: A new bytes object with one bit flipped.
    :rtype: bytes
    '''
    # Convert bytes to a mutable list/array of integers for modification
    data_list = list(data)
    
    # Calculate the mask: 1 shifted left by bit_index (e.g., 1<<7 is 0x80)
    mask = 1 << bit_index
    
    # Apply XOR to flip the bit
    data_list[byte_index] ^= mask
    
    # Convert back to bytes
    return bytes(data_list)

def count_set_bits(data: bytes) -> int:
    '''
    Counts the number of set bits (ones) in a bytes object.
    
    :param data: The bytes object (e.g., the XOR result of two ciphertexts).
    :type data: bytes
    :return: The total count of set bits.
    :rtype: int
    '''
    ones_counter = 0
    for byte in data:
        # Count the number of 1 bits in data
        ones_counter += bin(byte).count('1')
        
    return ones_counter


def main():
    try:
        # Generate a fixed 128-bit key (16 bytes)
        encryption_key = os.urandom(16)
        print(f"--- FIXED AES Key for all runs: {encryption_key.hex()} ---\n")
        
        # Repeat 5 times
        for i in range(5):
            # Generate a new random plaintext for each run
            plaintext1 = create_random_plaintext(length=16) 
            
            # Choose a random byte and bit to flip
            byte_to_flip = random.randrange(len(plaintext1)) # Random index from 0 to 15
            bit_to_flip = random.randrange(8) # Random bit position from 0 to 7
            
            # Create plaintext2 by flipping exactly 1 bit in plaintext1
            plaintext2 = flip_single_bit(plaintext1, byte_to_flip, bit_to_flip)

            # Create ciphers
            ciphertext1 = run_aes(plaintext1, encryption_key)
            ciphertext2 = run_aes(plaintext2, encryption_key)
            
            # Find the bits difference using XOR
            xor_result = bytes(a ^ b for a,b in zip(ciphertext1, ciphertext2)) 
            
            # Count number of ones in the xor result (this is the bit difference)
            bits_difference = count_set_bits(xor_result)
            
            # Total possible bits for comparison (16 bytes * 8 bits/byte)
            total_bits = len(ciphertext1) * 8

            # Prints
            print(f"--- Run No. {i + 1} ---")
            print(f"Key: {encryption_key.hex()}")
            print(f"Plaintext 1 (bytes): {plaintext1.hex()}")
            print(f"Plaintext 2 (1-bit flip at byte {byte_to_flip}, bit {bit_to_flip}): {plaintext2.hex()}")
            print(f"Ciphertext 1: {ciphertext1.hex()}")
            print(f"Ciphertext 2: {ciphertext2.hex()}")
            print(f"Bit Difference: **{bits_difference}** out of {total_bits} bits ({bits_difference/total_bits*100:.2f}%)")
            print("-" * 30)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()