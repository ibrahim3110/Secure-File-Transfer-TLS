# TLS Certificates

This folder stores the TLS server certificate and private key.

These files are intentionally excluded from the repository for security reasons.

Generate them using OpenSSL before running the project.

Example:

openssl genrsa -out server.key 2048

openssl req -new -x509 -key server.key -out server.crt -days 365
