from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import hashlib
import datetime

public_key = None
private_key = None
certificate = None

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

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_pem)

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Serialize and store the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_pem)

    print("RSA key pair generated and stored in private_key.pem and public_key.pem.")

def generate_self_signed_certificate():
    global certificate
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "My Common Name"),
    ])

    issuer = subject  # Self-signed

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256())

    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    with open("certificate.pem", "wb") as certificate_file:
        certificate_file.write(certificate_bytes)

    print("Self-signed certificate generated and stored in certificate.pem.")

def rsa_encrypt():
    if public_key is None:
        print("RSA public key not available. Generate key pair first.")
        return

    message = input("Enter the message to encrypt: ").encode('utf-8')

    # Use OAEP padding for encryption
    encrypted_message = public_key.encrypt(message, asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    print("Encrypted message: ", encrypted_message)

def rsa_decrypt():
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    encrypted_message = input("Enter the message to decrypt (ciphertext): ").encode('utf-8')

    try:
        decrypted_message = private_key.decrypt(encrypted_message, asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )).decode('utf-8')
        print("Decrypted message: ", decrypted_message)
    except Exception as e:
        print("Decryption failed:", str(e))

if __name__ == "__main__":
    while True:
        print("Choose an option:")
        print("1. Generate RSA key pair")
        print("2. Generate self-signed certificate")
        print("3. Encrypt a message")
        print("4. Decrypt a message")
        print("5. Exit")

        choice = input("Enter your choice (1/2/3/4/5): ")

        if choice == "1":
            rsa_generate_key_pair()
        elif choice == "2":
            generate_self_signed_certificate()
        elif choice == "3":
            rsa_encrypt()
        elif choice == "4":
            rsa_decrypt()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please select a valid option.")
