import random
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

def applique_la_transfo(caractere, chiffre, position):
    code = int(chiffre)
    if code == 0: return decalage_droit(caractere, 1)
    elif code == 1: return decalage_gauche(caractere, 1)
    elif code == 2: return xor_machin(caractere, 42)
    elif code == 3: return decalage_droit(caractere, 3)
    elif code == 4: return decalage_droit(caractere, 5)
    elif code == 5: return miroir(caractere)
    elif code == 6: return decalage_droit(caractere, 7)
    elif code == 7: return xor_machin(caractere, 127)
    elif code == 8: return decalage_droit(caractere, 8)
    elif code == 9: return xor_machin(caractere, 99)
    elif code == 10: return rot13_bizarre(caractere)
    elif code == 11: return echange_bits(caractere)
    elif code == 12: return miroir(caractere)
    elif code == 13: return decalage_dynamique(caractere, position)
    elif code == 14: return negation_binaire(caractere)
    return caractere

def doof_chiffre(texte, cle):
    texte = "MAGIC:" + texte
    return ''.join(applique_la_transfo(c, cle[i % len(cle)], i) for i, c in enumerate(texte))

def genere_cle(longueur=10, max_code=14):
    return ''.join(str(random.randint(0, max_code)) for _ in range(longueur))

def fragmenter_cle(cle, nb_fragments):
    taille_base = len(cle) // nb_fragments
    reste = len(cle) % nb_fragments
    fragments = []
    index = 0
    for i in range(nb_fragments):
        taille = taille_base + (1 if i < reste else 0)
        fragments.append(cle[index:index+taille])
        index += taille
    return fragments

if __name__ == "__main__":
    print("\n=== BIENVENUE DANS LE CHIFFRE-INATOR 3000 ===\n")
    message = input("Tape ton message : ")
    longueur = len(message) + len("MAGIC:")
    nb_fragments = int(input(f"En combien de morceaux veux-tu diviser la clé ? (1 à {longueur}) : "))

    # clé FIXE
    cle_complete = "0123456789012345678901234567890123456789"

    # Tronquer la clé si jamais elle est trop longue
    cle_complete = cle_complete[:longueur]

    fragments = fragmenter_cle(cle_complete, nb_fragments)
    print("\nFragments de clé à transmettre :")
    for i, frag in enumerate(fragments):
        print(f"Fragment {i+1} : {frag}")
    
    texte_chiffre = doof_chiffre(message, cle_complete)
    texte_chiffre_base64 = base64.b64encode(texte_chiffre.encode("latin1")).decode("ascii")
    print("Message chiffré :", texte_chiffre_base64,"\n")

