# Secure TLS File Transfer

A Python application that securely transfers files using TLS 1.3, AES-256-GCM, RSA digital signatures, and SHA-256 integrity verification.

## Features

- TLS 1.3 encrypted communication
- RSA digital signatures
- AES-256-GCM encryption
- SHA-256 integrity verification
- Certificate authentication

## Requirements

Python 3.13

cryptography

OpenSSL

## Installation

pip install -r requirements.txt

## Run Receiver

python receiver.py

## Run Sender

python sender.py files/test.jpeg
