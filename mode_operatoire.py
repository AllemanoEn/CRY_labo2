import base64

import Crypto
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto import Random


def encrypt(key, clearMessage):
    ra = Random.new()
    IV = ra.read(16)

    t_i = b'\x00' * 16

    cipherKey = AES.new(key, AES.MODE_ECB)
    cipherIV = AES.new(IV, AES.MODE_ECB)

    # split the message in blocks of 16 bytes and convert to bytes
    clearMessage = clearMessage.encode()
    splitedClearMessage = [clearMessage[i:i + 16] for i in range(0, len(clearMessage), 16)]

    cipherMessage = [b'\x01' * 16] * len(splitedClearMessage)

    for i in range(len(splitedClearMessage)):
        t_i = cipherKey.encrypt(t_i)
        tmpCipherMessage = strxor(t_i, splitedClearMessage[i])
        cipherMessage[i] = strxor(tmpCipherMessage, cipherIV.encrypt(i.to_bytes(16, byteorder='big')))

    # concatenate the cipherMessage
    return b''.join(cipherMessage), IV


def decrypt(key, IV, cipherMessage):
    t_i = b'\x00' * 16

    cipherKey = AES.new(key, AES.MODE_ECB)
    cipherIV = AES.new(IV, AES.MODE_ECB)

    # split the message in blocks of 16 bytes
    splitedCipherMessage = [cipherMessage[i:i + 16] for i in range(0, len(cipherMessage), 16)]

    clearMessage = [b'\x01' * 16] * len(splitedCipherMessage)

    for i in range(len(splitedCipherMessage)):
        tmpCipherMessage = strxor(splitedCipherMessage[i], cipherIV.encrypt(i.to_bytes(16, byteorder='big')))
        t_i = cipherKey.encrypt(t_i)
        clearMessage[i] = strxor(t_i, tmpCipherMessage)

    # concatenate the clearMessage
    return b''.join(clearMessage)


def breakCipher(m3, c3, IV3, IV3chall, c3chall):
    cipherIV3 = AES.new(IV3, AES.MODE_ECB)
    cipherIV3chall = AES.new(IV3chall, AES.MODE_ECB)

    # split the m3 in blocks of 16 bytes and convert to bytes
    m3 = m3.encode()
    splitedM3 = [m3[i:i + 16] for i in range(0, len(m3), 16)]

    # split c3 in blocks of 16 bytes and convert to bytes
    splitedC3 = [c3[i:i + 16] for i in range(0, len(c3), 16)]

    # Get all t_i from m3 and c3
    t_i = [b'\x00' * 16] * len(splitedM3)
    for i in range(len(splitedM3)):
        unXORedToByte = strxor(splitedC3[i], cipherIV3.encrypt(i.to_bytes(16, byteorder='big')))
        t_i[i] = strxor(unXORedToByte, splitedM3[i])

    # split c3chall in blocks of 16 bytes
    splitedC3chall = [c3chall[i:i + 16] for i in range(0, len(c3chall), 16)]

    clearMessage = [b'\x01' * 16] * len(splitedC3chall)

    # decode c3chall

    for i in range(len(splitedC3chall)):
        tmpDecodedC3chall = strxor(splitedC3chall[i], cipherIV3chall.encrypt(i.to_bytes(16, byteorder='big')))
        clearMessage[i] = strxor(t_i[i], tmpDecodedC3chall)

    # concatenate the clearMessage
    return b''.join(clearMessage)


m3 = "Voici le test initial. Est-ce que tout fonctionne correctement ?"

IV3 = "i8ha85lNnD8iHbRi/eKmtQ=="
IV3 = base64.b64decode(IV3.encode('ascii'))

c3 = "1OVBFmGMKkd5eoUhv9+iWFYosLiRcAVU8pr1XM9vMr5081pzPuu3unIoLdWuYQ83pxyOmY4siHDCF3CLNaMgOQ=="
c3 = base64.b64decode(c3.encode('ascii'))

key = "VOICILACLESECRETEDE256BITSXXXXXX"
# Convert the key to bytes
key = key.encode('utf-8')

IV3chall= "RqawCDqOq1UNEPMfa+bCSQ=="
IV3chall = base64.b64decode(IV3chall.encode('ascii'))

c3chall= "PoHSZQwQlLE/PtZLyC3S+JbG/lx7PSo2RHabG+h9653lsGRaLLuF372Dh1I82PW5"
c3chall = base64.b64decode(c3chall.encode('ascii'))

print("Message to encrypt: " + m3)

cipherMessage, IV = encrypt(key, m3)
print("Message encrypted : " + str(cipherMessage))

print("Message decrypted : " + str(decrypt(key, IV, cipherMessage)))

print("Challenge 3 : " + str(breakCipher(m3, c3, IV3, IV3chall, c3chall)))