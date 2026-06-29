from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("keys", exist_ok=True)

def gen(name):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    open(f"keys/{name}_private.pem","wb").write(priv)
    open(f"keys/{name}_public.pem","wb").write(pub)

gen("sender")
gen("receiver")

print("Keys generated")
