def rc4(key, data):
    """
    RC4 stream cipher implementation with 16-bit block size.
    
    Args:
        key (bytes): The encryption/decryption key
        data (bytes): The data to be encrypted/decrypted
        
    Returns:
        bytes: The encrypted/decrypted data
    """
    # Key-scheduling algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-random generation algorithm (PRGA) with 16-bit blocks
    i = j = 0
    result = bytearray()
    
    # Ensure data length is even (for 16-bit blocks)
    if len(data) % 2 == 1:
        data = data + b'\x00'  # Padding with zero byte if needed
        
    # Process 16-bit blocks (2 bytes at a time)
    for idx in range(0, len(data), 2):
        # Generate two keystream bytes for the 16-bit block
        keystream_bytes = []
        for _ in range(2):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream_bytes.append(S[(S[i] + S[j]) % 256])
        
        # XOR the 16-bit block with the keystream
        if idx + 1 < len(data):
            # Full 16-bit block
            result.append(data[idx] ^ keystream_bytes[0])
            result.append(data[idx + 1] ^ keystream_bytes[1])
        else:
            # Handle partial block at the end if necessary
            result.append(data[idx] ^ keystream_bytes[0])
    
    return bytes(result)