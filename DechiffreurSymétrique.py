import base64

def decalage_droit(caractere, cle): 
    return chr((ord(caractere) + cle) % 256)

def decalage_gauche(caractere, cle): 
    return chr((ord(caractere) - cle) % 256)

def xor_machin(caractere, cle): 
    return chr(ord(caractere) ^ cle)

def rot13_bizarre(caractere): 
    return chr((ord(caractere) + 13) % 256)

def derot13_bizarre(caractere): 
    return chr((ord(caractere) - 13) % 256)

def echange_bits(caractere):
    bits = ord(caractere)
    haut = (bits & 0xF0) >> 4
    bas = (bits & 0x0F) << 4
    return chr((bas | haut) % 256)
de_echange_bits = echange_bits

def miroir(caractere): 
    return chr(255 - ord(caractere))
demiroir = miroir

def decalage_dynamique(caractere, position): 
    return chr((ord(caractere) + (position % 10)) % 256)

def de_decalage_dynamique(caractere, position): 
    return chr((ord(caractere) - (position % 10)) % 256)

def negation_binaire(caractere): 
    return chr((~ord(caractere)) % 256)
denegation_binaire = negation_binaire

def applique_la_transfo_inverse(caractere, chiffre, position):
    code = int(chiffre)
    if code == 0: return decalage_gauche(caractere, 1)
    elif code == 1: return decalage_droit(caractere, 1)
    elif code == 2: return xor_machin(caractere, 42)
    elif code == 3: return decalage_gauche(caractere, 3)
    elif code == 4: return decalage_gauche(caractere, 5)
    elif code == 5: return miroir(caractere)
    elif code == 6: return decalage_gauche(caractere, 7)
    elif code == 7: return xor_machin(caractere, 127)
    elif code == 8: return decalage_gauche(caractere, 8)
    elif code == 9: return xor_machin(caractere, 99)
    elif code == 10: return derot13_bizarre(caractere)
    elif code == 11: return de_echange_bits(caractere)
    elif code == 12: return demiroir(caractere)
    elif code == 13: return de_decalage_dynamique(caractere, position)
    elif code == 14: return denegation_binaire(caractere)
    return caractere

def doof_dechiffre(texte_chiffre, cle):
    texte = ''.join(applique_la_transfo_inverse(c, cle[i % len(cle)], i) for i, c in enumerate(texte_chiffre))
    if not texte.startswith("MAGIC:"):
        raise ValueError("Clé incorrecte")
    return texte[6:]

if __name__ == "__main__":
    print("\n=== BIENVENUE DANS LE CHIFFRE-INATOR 3000 ===\n")
    texte_chiffre_base64 = input("Le message chiffré est : ")
    texte_chiffre = base64.b64decode(texte_chiffre_base64.encode("ascii")).decode("latin1")

    nb_fragments = int(input("Combien de fragments as-tu reçu ? : "))
    fragments = [input(f"Fragment {i+1} : ") for i in range(nb_fragments)]
    cle_reconstituee = ''.join(fragments)

    try:
        texte_clair = doof_dechiffre(texte_chiffre, cle_reconstituee)
        print("Message déchiffré :", texte_clair,"\n")
    except ValueError as e:
        print("Erreur :", e)
