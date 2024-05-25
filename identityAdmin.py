from blockchain import Blockchain


def populate_identity_admin(private_key, nume, data_nasterii, cnp, cazier, nationalitate):
    """Populează dicționarul Identity_dict cu o nouă identitate.

    Args:
        private_key: Adresa privată a utilizatorului.
        nume: Numele utilizatorului.
        data_nasterii: Data nașterii utilizatorului.
        cnp: CNP-ul utilizatorului.
        cazier: Starea cazierului utilizatorului.
        nationalitate: Cetățenia utilizatorului.

    Returns:
        None.
    """
    identity = {
        "nume": nume,
        "data_nasterii": data_nasterii,
        "cnp": cnp,
        "cazier": cazier,
        "nationalitate": nationalitate,
    }

    if private_key not in Blockchain.Identity_admin:
        Blockchain.Identity_admin[private_key] = []  # Adaugi o cheie nouă cu o listă goală

    # Apoi poți adăuga elemente sub cheia respectivă
    Blockchain.Identity_admin[private_key].append(identity)


        # Salvăm datele actualizate
    Blockchain.save_data( Blockchain.Identity_admin, "identity_admin_data.json")

# Exemple de utilizare:
private_key = Blockchain.generatePrivateKey()
nume = "Mister"
data_nasterii = "1980-01-01"
cnp = "1231244322"
cazier = "curat"
nationalitate = "română"

populate_identity_admin(private_key, nume, data_nasterii, cnp, cazier, nationalitate)

private_key = Blockchain.generatePrivateKey()
nume = "Mister2"
data_nasterii = "191230-01-01"
cnp = "1238764783"
cazier = "curat"
nationalitate = "maghiar"

populate_identity_admin(private_key, nume, data_nasterii, cnp, cazier, nationalitate)



print(Blockchain.Identity_admin)