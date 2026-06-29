import socket, ssl, sys, pickle, os
from crypto_utils import *

os.makedirs("received", exist_ok=True)

receiver_private = load_private("keys/receiver_private.pem")
sender_public = load_public("keys/sender_public.pem")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("certs/server.crt","certs/server.key")

sock = socket.socket()
sock.bind(("0.0.0.0", 5000))
sock.listen(5)

print("\n========================================")
print(" Secure TLS File Receiver")
print("========================================")
print("[+] Waiting for incoming connection...")

client, addr = sock.accept()

try:

    tls = context.wrap_socket(client, server_side=True)

    print("\n[+] Client connected.")
    print("[+] TLS Handshake Successful")
    print(f"[+] TLS Version : {tls.version()}")

    cipher = tls.cipher()

    print(f"[+] Cipher Suite : {cipher[0]}")
    print(f"[+] Encryption Key Length : {cipher[2]} bits")
    print("[+] Secure communication channel established.\n")

except ssl.SSLError as e:

    print("\n========================================")
    print(" TLS HANDSHAKE FAILED")
    print("========================================")
    print(f"[!] {e}")

    client.close()
    sock.close()
    sys.exit(1)

# length-prefixed receive (NO BUGS)
size = int.from_bytes(tls.recv(8), "big")
data = b""

while len(data) < size:
    data += tls.recv(4096)

packet = pickle.loads(data)

print("[+] Verifying sender's digital signature...")

try:

    verify(packet["cipher"], packet["sig"], sender_public)
    print("[+] Signature verification successful.")
    print("[+] Sender authenticated.\n")

except Exception:

    print("\n========================================")
    print(" SIGNATURE VERIFICATION FAILED")
    print("========================================")
    print("[!] Invalid digital signature detected.")
    print("[!] Possible reasons:")
    print("    - Wrong sender public key")
    print("    - File modified during transmission")
    print("    - Data integrity compromised")

    tls.close()
    sock.close()
    sys.exit(1)

print("[+] Decrypting received file...")

try:

    plaintext = aes_decrypt(packet["aes_key"], packet["nonce"], packet["cipher"])

    print("[+] File decrypted successfully.\n")

except Exception:

    print("\n========================================")
    print(" DECRYPTION FAILED")
    print("========================================")
    print("[!] AES-GCM authentication failed.")
    print("[!] Incorrect key or encrypted data was modified.")

    tls.close()
    sock.close()
    sys.exit(1)

path = "received/" + packet["name"]
open(path,"wb").write(plaintext)

print("========================================")
print(" FILE TRANSFER SUCCESSFUL")
print("========================================")
print(f"[+] File Name : {packet['name']}")
print(f"[+] Saved To  : {path}")
print("[+] Secure transfer completed.")
print("========================================")

tls.close()
sock.close()
