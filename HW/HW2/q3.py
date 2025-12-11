from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import time
import matplotlib.pyplot as plt

'''
Brute-Force on a Reduced Key

We'll need to reduce the size of the key space while still using the real AES-128 algorithm
Use k = 20, 22, 24 bits and fill the remaining bits by repeating the short bitstring
'''

def get_random_bitstring(k: int) -> int:
    """
    Generates a random integer whose binary representation uses exactly k bits,
    falling in the range [0, 2^k - 1].
    """
    if k <= 0:
        return 0

    num_bytes = (k + 7) // 8    
    random_bytes = os.urandom(num_bytes)
    random_int_full = int.from_bytes(random_bytes, byteorder='big')

    # Truncate and Isolate the first k bits using a bitmask
    bitmask = (1 << k) - 1

    # Keep only the k least significant bits (0 to k-1)
    random_bitstring = random_int_full & bitmask

    return random_bitstring


def expand_key(x: int, bits: int) -> bytes:
    """
    Converts the k-bit integer 'x' into a 128-bit AES key by repeating its bitstring.
    """
    bin_key = format(x, f'0{bits}b') 
    repeated = (bin_key * 7)[:128] 

    # Convert the final 128-bit string back to an integer, and then to a 16-byte key
    return int(repeated, 2).to_bytes(16, 'big')


def create_random_plaintext(length: int = 16) -> bytes:
    '''
    Creates a random bytes object for plaintext.
    '''
    return os.urandom(length)


def run_aes(plaintext : bytes, key : bytes) -> bytes:
    '''
    Encrypts plaintext using AES-128 in ECB mode with PKCS7 padding.
    '''
    block_size_bits = 128
    
    # Pad plaintext 
    padder = padding.PKCS7(block_size_bits).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
        
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def brute_force_aes(plaintext : bytes, ciphertext : bytes, key_length : int) -> tuple:
    key_found = None
    
    start_time = time.perf_counter()
    brute_force_counter = 0
    
    max_range = 2**key_length 
    
    for possible_key in range(max_range):
        brute_force_counter += 1
        
        # Expand the k-bit key guess (possible_key) to a 128-bit key
        encryption_key = expand_key(possible_key, key_length)
        possible_cipher = run_aes(plaintext, encryption_key)
        
        if (possible_cipher == ciphertext):
            key_found = possible_key
            break
        
    end_time = time.perf_counter()
    time_elapsed = end_time - start_time                
    
    
    return key_found, brute_force_counter, time_elapsed


def plot_bruteforce_times(results):
    '''
    Plots the time taken vs. key size using a bar chart.
    '''
    key_sizes = [k for (k, t) in results]
    times = [t for (k, t) in results]
    
    plt.figure(figsize=(8, 6))
    
    plt.bar(key_sizes, times, width=1.5, color='skyblue', edgecolor='black') 
    
    plt.xlabel('Reduced Key Size (bits)')
    plt.ylabel('Brute-Force Time (seconds)')
    plt.title('Time vs. Reduced Key Size for AES Brute-Force')
    
    # Ensure all key sizes are visible on the x-axis
    plt.xticks(key_sizes) 
    
    plt.grid(axis='y', linestyle='--')
    plt.tight_layout()
    plt.show()


def main():
    try:
        keys_length_array = [20, 22, 24]
        results = []
        
        for key_length in keys_length_array:
            # Setup the key and ciphertext for the current key_length
            x = get_random_bitstring(key_length)
            encryption_key = expand_key(x, bits=key_length)
            plaintext = create_random_plaintext()
            ciphertext = run_aes(plaintext, encryption_key)

            # Perform the brute-force attack
            brute_force_results = brute_force_aes(plaintext, ciphertext, key_length)

            key_found = brute_force_results[0]
            attempts_counter = brute_force_results[1]
            time_elapsed = brute_force_results[2]

            # Print results summary
            print(
                f"--------------------------------------------\n"
                f"        Brute Force Results Summary         \n"
                f"--------------------------------------------\n"
                f"Original Plaintext:        {plaintext.hex()}\n"  
                f"Original Ciphertext:       {ciphertext.hex()}\n"
                f"Key Length Used:           {key_length} bits\n"
                f"Attempts Until Key Found:  {attempts_counter:,}\n"  
                f"Key Found (Reduced Int):   {key_found}\n"
                f"Time Elapsed (s):          {time_elapsed:.4f}\n"
                f"--------------------------------------------"
            )

            # Save result for plotting
            results.append((key_length, time_elapsed))

        # Plot results after finishing all key lengths (Moved outside the loop)
        plot_bruteforce_times(results)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()