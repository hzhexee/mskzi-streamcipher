import struct

def rotate_left(v, c):
    """Rotate left operation (ROL)"""
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def g_function(x, c):
    """G function in Rabbit"""
    # Square calculation
    temp = (x + c) & 0xFFFFFFFF
    square = (temp * temp) & 0xFFFFFFFFFFFFFFFF
    h = (square >> 32) ^ (square & 0xFFFFFFFF)
    return h

def counter_update(X, C, A):
    """Update counter variables in Rabbit"""
    # Calculate new counter values
    for i in range(8):
        temp = (C[i] + A[i] + (1 if i == 0 else 0)) & 0xFFFFFFFF
        C[i] = temp
    
    # Calculate new state variables
    g = [0] * 8
    for i in range(8):
        g[i] = g_function(X[i], C[i])
    
    # State update function
    X[0] = (g[0] + rotate_left(g[7], 16) + rotate_left(g[6], 16)) & 0xFFFFFFFF
    X[1] = (g[1] + rotate_left(g[0], 8) + g[7]) & 0xFFFFFFFF
    X[2] = (g[2] + rotate_left(g[1], 16) + rotate_left(g[0], 16)) & 0xFFFFFFFF
    X[3] = (g[3] + rotate_left(g[2], 8) + g[1]) & 0xFFFFFFFF
    X[4] = (g[4] + rotate_left(g[3], 16) + rotate_left(g[2], 16)) & 0xFFFFFFFF
    X[5] = (g[5] + rotate_left(g[4], 8) + g[3]) & 0xFFFFFFFF
    X[6] = (g[6] + rotate_left(g[5], 16) + rotate_left(g[4], 16)) & 0xFFFFFFFF
    X[7] = (g[7] + rotate_left(g[6], 8) + g[5]) & 0xFFFFFFFF

def derive_keystream(X):
    """Derive keystream from state variables"""
    S = [0] * 4
    S[0] = X[0] ^ (X[5] >> 16) ^ (X[3] << 16)
    S[1] = X[2] ^ (X[7] >> 16) ^ (X[5] << 16)
    S[2] = X[4] ^ (X[1] >> 16) ^ (X[7] << 16)
    S[3] = X[6] ^ (X[3] >> 16) ^ (X[1] << 16)
    return S

def rabbit(key, iv, data):
    """
    Rabbit stream cipher implementation.
    
    Args:
        key (bytes): 16-byte encryption key
        iv (bytes): 8-byte initialization vector (IV)
        data (bytes): Data to be encrypted/decrypted
        
    Returns:
        bytes: Encrypted/decrypted data
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if iv is not None and len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
    
    # Constants
    A = [
        0x4D34D34D, 0xD34D34D3, 
        0x34D34D34, 0x4D34D34D, 
        0xD34D34D3, 0x34D34D34, 
        0x4D34D34D, 0xD34D34D3
    ]
    
    # Initialize state variables
    X = [0] * 8  # State variables
    C = [0] * 8  # Counter variables
    
    # Key setup scheme (KSS)
    k = struct.unpack('<4I', key)
    for i in range(8):
        if i % 2 == 0:
            X[i] = (k[i//2] & 0xFFFF)
            C[i] = (k[i//2] >> 16) & 0xFFFF
        else:
            X[i] = (k[i//2] >> 16) & 0xFFFF
            C[i] = (k[i//2] & 0xFFFF)
    
    # Counter system setup
    for _ in range(4):
        counter_update(X, C, A)
    
    # Apply IV if provided
    if iv is not None:
        iv_words = struct.unpack('<2I', iv)
        C[0] ^= iv_words[0] & 0xFFFFFFFF
        C[1] ^= ((iv_words[0] >> 16) | (iv_words[1] << 16)) & 0xFFFFFFFF
        C[2] ^= iv_words[1] & 0xFFFFFFFF
        C[3] ^= ((iv_words[1] >> 16) | (iv_words[0] << 16)) & 0xFFFFFFFF
        C[4] ^= iv_words[0] & 0xFFFFFFFF
        C[5] ^= ((iv_words[0] >> 16) | (iv_words[1] << 16)) & 0xFFFFFFFF
        C[6] ^= iv_words[1] & 0xFFFFFFFF
        C[7] ^= ((iv_words[1] >> 16) | (iv_words[0] << 16)) & 0xFFFFFFFF
        
        # Run the cipher 4 times to diffuse IV
        for _ in range(4):
            counter_update(X, C, A)
    
    # Encrypt/decrypt
    result = bytearray()
    
    for i in range(0, len(data), 16):
        # Generate keystream block
        counter_update(X, C, A)
        S = derive_keystream(X)
        
        # XOR with data
        chunk = data[i:i+16]
        keystream = struct.pack('<4I', S[0], S[1], S[2], S[3])
        
        for j in range(len(chunk)):
            result.append(chunk[j] ^ keystream[j])
    
    return bytes(result)