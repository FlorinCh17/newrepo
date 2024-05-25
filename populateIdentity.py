from blockchain import Blockchain
import random

def populate_identity_dict(private_key, name, date_of_b, cnp, criminal_record, nationality, residence, alienated, email):
    if private_key not in Blockchain.Identity_dict:
        Blockchain.Identity_dict[private_key] = []
    
        identity = {
            "name": name,
            "date_of_b": date_of_b,
            "CNP": cnp,
            "criminal_records": criminal_record,
            "nationality": nationality,
            "residence": residence,
            "alienated": alienated,
            "public_key":Blockchain.generateAddress(private_key),
            "email": email
        }

        Blockchain.Identity_dict[private_key].append(identity)
        print("haide sa testam")
        print(Blockchain.Identity_dict)
        # Salvăm datele actualizate
        Blockchain.save_data(Blockchain.Identity_dict, "identity_data.json")


        print(Blockchain.Identity_dict)
    else:
        print("Error generating the key")