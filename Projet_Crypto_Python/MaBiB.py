from functions.rsa import *
from functions.userData import *
from functions.hash import *
from functions.Certificate import *


def task_A():
    while True:
        print("""Menu A : Enregistrement 
A1- Sauvegarder Données utilisateur
 
A3- Revenir au menu principal""")

        choiceP = input("Enter your choice (A1/A2/A3): ").upper()

        if choiceP == 'A1':
            save_user_data()
        elif choiceP == 'A2':
            read_user_data()
        elif choiceP == 'A3':
            return
        else:
            print("Choix Invalide. Merci de choisir entre A1, A2, ou A3.")


def task_B():
    while True:
        print("""Menu B : Authentification
B1- Hachage
B2- Chiffrement
B3- Certificat
B4- Revenir au menu principal""")

        choiceB = input("Enter your choice (B1/B2/B3/B4): ").upper()

        if choiceB == 'B1':
            menu_B1()
        elif choiceB == 'B2':
            menu_B2()
        elif choiceB == 'B3':
            menu_B2()
        elif choiceB == 'B4':
            task_C()
            return
        else:
            print("Choix Invalide. Merci de choisir entre B1, B2, B3 ou B4.")


def task_C():
    print("Exiting the application.")
    exit()


def menu_B1():
    while True:
        print("""--------|       Menu B1 :  Hachage      |--------
B1-a  Hacher un message par SHA256
B1-b  Hacher un message par bcrypt
B1-c  Hacher un message par Brute force
B1-d  Cracker un message Haché
B1-e Revenir au menu MenuB""")

        choiceB1 = input("Enter your choice (a/b/c/d/e): ").upper()

        if choiceB1 == 'A':
            hash_messages("SHA256", ListeSHA256, ["Password", "azerty", "shadow", "hunter"])
        elif choiceB1 == 'B':
            message_to_hash = input("Enter the message to hash: ")
            hashed_message = bcrypt.hashpw(message_to_hash.encode('utf-8'), bcrypt.gensalt())
            print("Hashed message:", hashed_message)

        elif choiceB1 == 'C':
            hashed_passwords = []
            password_dictionary = ["Password", "azerty", "shadow", "hunter"]
            brute_force_bcrypt_hashes(hashed_passwords, password_dictionary)
        elif choiceB1 == 'D':
            crack_hashed_message()
        elif choiceB1 == 'E':
            return
        else:
            print("Invalid choice. Please choose from B1-a, B1-b, B1-c, B1-d, or B1-e.")


def menu_B2():
    while True:
        print("""--------|       Menu B2 :  Chiffrement      |--------
B2-a RSA
B1-b Revenir au menu MenuB
""")

        choiceB2 = input("Enter your choice (A/B): ").upper()

        if choiceB2 == 'A':
            menu_B2c()
        elif choiceB2 == 'B':
            return
        else:
            print("Invalid choice. Please choose from A, B, C, or D .")

def menu_B2c():
    rsa_generate_key_pair()
    while True:
        print("""--------| Menu B2c : Chiffrement RSA |--------
B2-c1 Chiffrement message
B2-c2 Déchiffrement message
B2-c3 Signature
B2-c4 Vérification Signature
B2-c5 Revenir au menu MenuB2""")

        choiceB2c = input("Enter your choice (C1/C2/C3/C4/C5): ").upper()

        if choiceB2c == 'C1':
            rsa_encrypt()
        elif choiceB2c == 'C2':
            rsa_decrypt()
        elif choiceB2c == 'C3':
            rsa_sign()
        elif choiceB2c == 'C4':
            rsa_verify()
        elif choiceB2c == 'C5':
            return
        else:
            print("Invalid choice. Please choose from C1, C2, C3, C4, or C5.")

def Menu_B3():
    while True:
        print("""--------| Menu B3 : Chiffrement RSA (Certificate)|--------
    B3-c1 Generate RSA key pair
    B3-c2 Generate self-signed certificate
    B3-c3 Encrypt a message
    B3-c4 Decrypt a message
    B3-c5 Exit""")

        choiceB2c = input("Enter your choice (C1/C2/C3/C4/C5): ").lower()

        if choice == "C1":
            rsa_generate_key_pair()
        elif choice == "C2":
            generate_self_signed_certificate()
        elif choice == "C3":
            rsa_encrypt()
        elif choice == "C4":
            rsa_decrypt()
        elif choice == "C5":
            break
        else:
            print("Invalid choice. Please select a valid option.")