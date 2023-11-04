import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

public_key = None
private_key = None
signature = None


def rsa_generate_key_pair():
    global public_key, private_key

    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize and store the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("../private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_pem)

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Serialize and store the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("../public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_pem)

    print("RSA key pair generated and stored in private_key.pem and public_key.pem.")


def rsa_encrypt():
    if public_key is None:
        print("RSA public key not available. Generate key pair first.")
        return

    message = input("Enter the message to encrypt: ").encode('utf-8')

    # Use PKCS1v15 padding for encryption
    encrypted_message = public_key.encrypt(message, padding.PKCS1v15())

    print("Encrypted message: ", encrypted_message)


def rsa_decrypt():
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    encrypted_message = input("Enter the message to decrypt (ciphertext): ").encode('utf-8')

    try:
        decrypted_message = private_key.decrypt(encrypted_message, padding.PKCS1v15()).decode('utf-8')
        print("Decrypted message: ", decrypted_message)
    except Exception as e:
        print("Decryption failed:", str(e))


def rsa_sign():
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    message = input("Enter the message to sign: ").encode('utf-8')
    global signature
    signature = hashlib.md5(message).digest()
    print("Signature created successfully.")


def rsa_verify():
    if public_key is None or signature is None:
        print("RSA public key or signature not available. Generate key pair and sign first.")
        return

    message = input("Enter the message to verify: ").encode('utf-8')
    new_signature = hashlib.md5(message).digest()
    if new_signature == signature:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")
