import MaBiB


def main():
    while True:
        print("""
Menu Principal
A- Enregistrement
B- Authentification
	B1- Hachage
	B2- Chiffrement
C- Quitter""")

        choiceP = input("Votre Choix (A/B/C): ").upper()

        if choiceP == 'A':
            MaBiB.task_A()
        elif choiceP == 'B':
            if MaBiB.authenticate_user():
                MaBiB.task_B()
        elif choiceP == 'C':
            MaBiB.task_C()
        else:
            print("Choix Invalide. Merci de choisir entre A, B, ou C.")


if __name__ == "__main__":
    main()
