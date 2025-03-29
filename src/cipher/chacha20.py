import struct

def rotate_left(v, c):
    """Rotate left operation (ROL)"""
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(a, b, c, d):
    """Quarter round function for ChaCha20"""
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left(d, 16)
    
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left(b, 12)
    
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left(d, 8)
    
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left(b, 7)
    
    return a, b, c, d

def chacha20_block(state):
    """Process a ChaCha20 block"""
    x = state.copy()
    
    # 10 iterations of 8 quarter-rounds = 20 rounds
    for _ in range(10):
        # Column round
        x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = quarter_round(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = quarter_round(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = quarter_round(x[3], x[7], x[11], x[15])
        
        # Diagonal round
        x[0], x[5], x[10], x[15] = quarter_round(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = quarter_round(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = quarter_round(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = quarter_round(x[3], x[4], x[9], x[14])
    
    # Add the original state
    for i in range(16):
        x[i] = (x[i] + state[i]) & 0xffffffff
    
    return x

def chacha20(key, nonce, counter, data):
    """
    ChaCha20 stream cipher implementation.
    
    Args:
        key (bytes): 32-byte encryption key
        nonce (bytes): 12-byte nonce
        counter (int): Initial counter value
        data (bytes): Data to be encrypted/decrypted
        
    Returns:
        bytes: Encrypted/decrypted data
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    
    # Initialize state
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
    
    state = constants.copy()
    state.extend(struct.unpack('<8I', key))
    state.append(counter)
    state.extend(struct.unpack('<3I', nonce))
    
    result = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(state)
        keystream = bytearray()
        for j in range(16):
            keystream.extend(struct.pack('<I', block[j]))
        
        chunk = data[i:i+64]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ keystream[j])
        
        state[12] = (state[12] + 1) & 0xffffffff  # Increment counter
    
    return bytes(result)