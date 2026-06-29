import socket, ssl, pickle, sys, hashlib
from crypto_utils import *

if len(sys.argv) != 2:
    print("Usage: python sender.py file")
    exit()

file = sys.argv[1]

data = open(file,"rb").read()

sender_private = load_private("keys/sender_private.pem")

aes_key, nonce, cipher = aes_encrypt(data)

sig = sign(cipher, sender_private)

packet = {
    "name": file.split("/")[-1],
    "aes_key": aes_key,
    "nonce": nonce,
    "cipher": cipher,
    "sig": sig,
    "hash": hashlib.sha256(data).hexdigest()
}

raw = pickle.dumps(packet)

context = ssl.create_default_context(
    cafile="certs/server.crt"
)

context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED

sock = socket.socket()
tls = context.wrap_socket(
    sock,
    server_hostname="SecureTLSServer"
)

print("\n========================================")
print(" Secure TLS File Sender")
print("========================================")
print("[+] Starting TLS handshake...")

try:
    tls.connect(("192.168.1.25", 5000))     # Change IP if required

    print("[+] Server certificate verified successfully.")
    print("[+] TLS Handshake Successful")
    print(f"[+] TLS Version : {tls.version()}")

    cipher = tls.cipher()

    print(f"[+] Cipher Suite : {cipher[0]}")
    print(f"[+] Encryption Key Length : {cipher[2]} bits")
    print("[+] Secure channel established.\n")

except ssl.SSLCertVerificationError as e:

    print("\n========================================")
    print(" AUTHENTICATION FAILED")
    print("========================================")
    print("[!] Server certificate verification failed.")
    print(f"[!] Reason : {e.verify_message}")
    print("[!] File transfer aborted.")
    sys.exit(1)

except ssl.SSLError as e:

    print("\n========================================")
    print(" TLS ERROR")
    print("========================================")
    print(f"[!] {e}")
    sys.exit(1)

tls.sendall(len(raw).to_bytes(8,"big"))
tls.sendall(raw)

print("[+] Encrypted file transmitted successfully.")
print("[+] Secure connection closed.")
tls.close()
