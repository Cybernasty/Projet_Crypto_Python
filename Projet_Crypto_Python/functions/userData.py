import getpass
import re

AuthDic = {}


def load_auth_data():
    try:
        with open("../Authentification.txt", "r") as file:
            for line in file:
                if line.startswith("Login&pwd: "):
                    login, pwd = line[len("Login&pwd: "):].strip().split('&')
                    AuthDic[login] = pwd
    except FileNotFoundError:
        print("No Authentification.txt file found. Please use MenuA to save user data.")


def authenticate_user():
    load_auth_data()
    login = input("Login: ")
    pwd = input("Password: ")
    # pwd = getpass(prompt = "Password: ")

    if login in AuthDic and AuthDic[login] == pwd:
        return True
    else:
        print("Authentication failed. Please register before attempting authentication.")
        return False


def save_user_data():
    with open("../Authentification.txt", "a") as file:
        print("Enter user information:")
        id_user = input("Id_user: ")
        login = input("Login: ")
        pwd = input("Password: ")
        #pwd = getpass.getpass(input ("Password: "))
        email = input("Email: ")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print("Invalid email address. Data not saved.")
            return

        classe = "CII-2-SIIR-" + input("Classe (N/P): ").upper()

        user_info = f"""
Id_user : {id_user}
Login&pwd: {login}&{pwd}
Classe : {classe}
Email : {email}
"""
        file.write(user_info)
        print("User data saved successfully!")


def read_user_data():
    try:
        with open("../Authentification.txt", "r") as file:
            user_data = file.read()
            print("User Data:")
            print(user_data)
    except FileNotFoundError:
        print("No user data found. Please use option A to save user data.")
