import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_private(path):
    return serialization.load_pem_private_key(open(path,"rb").read(), None)

def load_public(path):
    return serialization.load_pem_public_key(open(path,"rb").read())

def aes_encrypt(data):
    key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    return key, nonce, cipher.encrypt(nonce, data, None)

def aes_decrypt(key, nonce, data):
    return AESGCM(key).decrypt(nonce, data, None)

def sign(data, priv):
    return priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify(data, sig, pub):
    pub.verify(
        sig,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
