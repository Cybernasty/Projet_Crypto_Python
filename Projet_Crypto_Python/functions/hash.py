import hashlib
import bcrypt

ListeSHA256 = []


def hash_messages(algorithm, result_list, messages):
    for message in messages:
        hasher = hashlib.new(algorithm)
        hasher.update(message.encode('utf-8'))
        hashed_message = hasher.hexdigest()
        result_list.append(hashed_message)
        print(f"{algorithm} hash of '{message}': {hashed_message}")

def brute_force_bcrypt_hashes(hashed_passwords, password_dictionary):
    for hashed_password in hashed_passwords:
        for password in password_dictionary:
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                print(f"Password found: {password}")
                return
    print("Password not found in the dictionary.")


def crack_hashed_message():
    hashed_message = input("Enter a hashed message: ")


    if hashed_message in ListeSHA256:
        print(f"Message found in SHA256 list.")

    else:
        print(f"Message not found in any list.")
