import struct

def rotate_left(v, c):
    """Rotate left operation (ROL)"""
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def salsa20_block(state):
    """Process a Salsa20 block"""
    x = state.copy()
    
    # 10 iterations of double round = 20 rounds
    for _ in range(10):
        # Column round
        x[4] ^= rotate_left((x[0] + x[12]) & 0xffffffff, 7)
        x[8] ^= rotate_left((x[4] + x[0]) & 0xffffffff, 9)
        x[12] ^= rotate_left((x[8] + x[4]) & 0xffffffff, 13)
        x[0] ^= rotate_left((x[12] + x[8]) & 0xffffffff, 18)
        
        x[9] ^= rotate_left((x[5] + x[1]) & 0xffffffff, 7)
        x[13] ^= rotate_left((x[9] + x[5]) & 0xffffffff, 9)
        x[1] ^= rotate_left((x[13] + x[9]) & 0xffffffff, 13)
        x[5] ^= rotate_left((x[1] + x[13]) & 0xffffffff, 18)
        
        x[14] ^= rotate_left((x[10] + x[6]) & 0xffffffff, 7)
        x[2] ^= rotate_left((x[14] + x[10]) & 0xffffffff, 9)
        x[6] ^= rotate_left((x[2] + x[14]) & 0xffffffff, 13)
        x[10] ^= rotate_left((x[6] + x[2]) & 0xffffffff, 18)
        
        x[3] ^= rotate_left((x[15] + x[11]) & 0xffffffff, 7)
        x[7] ^= rotate_left((x[3] + x[15]) & 0xffffffff, 9)
        x[11] ^= rotate_left((x[7] + x[3]) & 0xffffffff, 13)
        x[15] ^= rotate_left((x[11] + x[7]) & 0xffffffff, 18)
        
        # Row round
        x[1] ^= rotate_left((x[0] + x[3]) & 0xffffffff, 7)
        x[2] ^= rotate_left((x[1] + x[0]) & 0xffffffff, 9)
        x[3] ^= rotate_left((x[2] + x[1]) & 0xffffffff, 13)
        x[0] ^= rotate_left((x[3] + x[2]) & 0xffffffff, 18)
        
        x[6] ^= rotate_left((x[5] + x[4]) & 0xffffffff, 7)
        x[7] ^= rotate_left((x[6] + x[5]) & 0xffffffff, 9)
        x[4] ^= rotate_left((x[7] + x[6]) & 0xffffffff, 13)
        x[5] ^= rotate_left((x[4] + x[7]) & 0xffffffff, 18)
        
        x[11] ^= rotate_left((x[10] + x[9]) & 0xffffffff, 7)
        x[8] ^= rotate_left((x[11] + x[10]) & 0xffffffff, 9)
        x[9] ^= rotate_left((x[8] + x[11]) & 0xffffffff, 13)
        x[10] ^= rotate_left((x[9] + x[8]) & 0xffffffff, 18)
        
        x[12] ^= rotate_left((x[15] + x[14]) & 0xffffffff, 7)
        x[13] ^= rotate_left((x[12] + x[15]) & 0xffffffff, 9)
        x[14] ^= rotate_left((x[13] + x[12]) & 0xffffffff, 13)
        x[15] ^= rotate_left((x[14] + x[13]) & 0xffffffff, 18)
    
    # Add the original state
    for i in range(16):
        x[i] = (x[i] + state[i]) & 0xffffffff
    
    return x

def salsa20(key, nonce, counter, data):
    """
    Salsa20 stream cipher implementation.
    
    Args:
        key (bytes): 32-byte encryption key
        nonce (bytes): 8-byte nonce
        counter (int): Initial counter value
        data (bytes): Data to be encrypted/decrypted
        
    Returns:
        bytes: Encrypted/decrypted data
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 8:
        raise ValueError("Nonce must be 8 bytes")
    
    # Initialize state
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
    
    key_words = struct.unpack('<8I', key)
    nonce_words = struct.unpack('<2I', nonce)
    
    # Salsa20 state: [c,k,k,k,k,c,n,n,ctr,ctr,c,k,k,k,k,c]
    state = [
        constants[0], 
        key_words[0], key_words[1], key_words[2], key_words[3],
        constants[1],
        nonce_words[0], nonce_words[1],
        counter & 0xffffffff, (counter >> 32) & 0xffffffff,
        constants[2],
        key_words[4], key_words[5], key_words[6], key_words[7],
        constants[3]
    ]
    
    result = bytearray()
    for i in range(0, len(data), 64):
        block = salsa20_block(state)
        keystream = bytearray()
        for j in range(16):
            keystream.extend(struct.pack('<I', block[j]))
        
        chunk = data[i:i+64]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ keystream[j])
        
        # Increment counter
        state[8] = (state[8] + 1) & 0xffffffff
        if state[8] == 0:  # Handle overflow
            state[9] = (state[9] + 1) & 0xffffffff
    
    return bytes(result)