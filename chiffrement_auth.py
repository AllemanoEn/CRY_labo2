import Crypto.Util.strxor
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
from Crypto.Util.Padding import pad, unpad


def encrypt(message, key_enc, key_mac):
    cipher = AES.new(key_enc, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, 16))
    mac = HMAC.new(key_mac, digestmod=SHA256)
    tag = mac.update(ciphertext).digest()
    return (cipher.IV, ciphertext, tag)


def decrypt(IV, ciphertext, tag, key_enc, key_mac):
    mac = HMAC.new(key_mac, digestmod=SHA256)
    mac.update(ciphertext)
    try:
        mac.verify(tag)
        return unpad(AES.new(key_enc, AES.MODE_CBC, IV=IV).decrypt(ciphertext), 16)
    except ValueError:
        print("Wrong tag")


# example
message = b"00125CHF to send to the account 125-12-23 of Alexandre Duc"
ra = Random.new()
key_enc = ra.read(16)
key_mac = ra.read(16)
(iv, ciphertext, tag) = encrypt(message, key_enc, key_mac)
print(iv)
iv = Crypto.Util.strxor.strxor(iv, b'\x02\x09' + b'\x00' * 14)
print(iv)
print(decrypt(iv, ciphertext, tag, key_enc, key_mac))

