def bytesToGFVector(b):
    """
    Converts a 128-bit python byte-string into a vector of 128 values in GF(2)
    PAS BESOIN DE COMPRENDRE COMMENT FONCTIONNE CETTE FONCTION
    @type b: bytes
    @param b: A 128-bit byte-string
    @rtype: Sage vector over GF(2) 
    @returns: The corresponding vector of size 128
    """
    l =  [int(c) for c in "".join([format(i,"08b") for i in b])]
    V = VectorSpace(GF(2), 128)
    return V(l)


def GFVectorToBytes(vector):
    """
    Converts a vector of 128 values in GF(2) into a 128-bit python byte-string
    PAS BESOIN DE COMPRENDRE COMMENT FONTIONNE CETTE FONCTION
    @type vector: Sage Vector over GF(2)
    @param vector: A vector of size 128 in GF(2).
    @rtype: bytes
    @returns: The corresponding bytes
    """
    return bytes([int(x,2) for x in list(map(str,[''.join(map(str,vector))[i:i+8] for i in range(0, len(vector), 8)]))])


def keyGen():
    """
    Generates the key used in the cipher
    @rtype: 128x128 Matrix over GF(2)
    @returns:a random invertible matrix over GF(2)^(128x128)
    """
    M = MatrixSpace(GF(2), 128, 128)
    A = M.zero()
    while not A.is_invertible():
        A = M.random_element()
    V = VectorSpace(GF(2), 128)
    return A

def encrypt(message, A):
    """
    Encrypts a plaintext into a ciphertext using an invertible matrix as key
    The plaintext needs to have a size multiple of 128 bits
    The CBC mode of operation (with IV = 0) is used.
    
    @type message: bytes
    @param message: The message to encrypt. Its size needs to be a multiple of 128 bits
    @type A: matrix
    @param A: The invertible matrix over GF(2)^(128x128) to use as key
    @rtype: bytes
    @returns: a 128-bit ciphertext encrypted with CBC with underlying block cipher being A*m
    
    """
    if len(message) % 16 != 0:
        print("The length of the message has to be a multiple of 128 bits")
        return
    message_blocks = [message[16*i:16*(i+1)] for i in range(len(message)//16)]
    IV = bytesToGFVector(b"\x00"*16)
    ct = b""
    for m in message_blocks:
        m = bytesToGFVector(m)
        IV = A*(m+IV)
        ct += GFVectorToBytes(IV)
    return ct



