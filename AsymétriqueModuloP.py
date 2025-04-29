# --- Importations des modules nécessaires ---
import os           # Pour générer des nombres aléatoires sécurisés (os.urandom)
from math import gcd # Pour calculer le Plus Grand Commun Diviseur (PGCD)
import base64       # Pour encoder/décoder le message chiffré en Base64 (lisible)
import struct       # Pour manipuler la longueur du message comme des octets

# --- Fonctions Cryptographiques ---

# Fonction pour vérifier si un nombre est premier (Test de Miller-Rabin)
def is_prime(n, k=20):
    """
    Vérifie si un nombre 'n' est probablement premier en utilisant le test
    probabiliste de Miller-Rabin. Ce test est efficace pour de grands nombres.

    :param n: Le nombre entier à tester.
    :param k: Le nombre d'itérations (témoins) à tester. Plus k est élevé,
              plus la probabilité que le nombre soit réellement premier augmente.
              Une valeur de 20 offre une très bonne fiabilité.
    :return: True si 'n' est probablement premier, False s'il est composé.
    """
    # Cas de base simples :
    if n <= 1: # 1 et les nombres négatifs ne sont pas premiers
        return False
    if n <= 3: # 2 et 3 sont premiers
        return True
    if n % 2 == 0: # Les nombres pairs > 2 ne sont pas premiers
        return False

    # Étape de préparation pour Miller-Rabin :
    # On écrit n-1 sous la forme 2^r * s, où s est impair.
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2 # Division entière par 2

    # Boucle principale du test : on effectue k tests avec des bases aléatoires 'a'
    for _ in range(k):
        # Choisir un témoin aléatoire 'a' tel que 2 <= a <= n-2
        try:
             # Génère des octets aléatoires de taille suffisante pour représenter n
             a_bytes = os.urandom((n.bit_length() + 7) // 8)
             # Convertit les octets en entier
             a = int.from_bytes(a_bytes, 'big')
             # Assure que 'a' est dans la plage [2, n-2]
             if n > 3:
                 a = 2 + (a % (n - 3)) # Formule pour obtenir un nombre dans [2, n-2]
             elif n == 3: # Cas spécial pour n=3, le seul 'a' possible est 2
                 a = 2
             else: # Normalement impossible d'arriver ici si n > 1
                 return False # Sécurité
        except Exception as e:
             # Gère les erreurs potentielles de os.urandom ou conversion
             print(f"[ERREUR] Erreur lors de la génération de 'a' pour Miller-Rabin : {e}")
             return False # En cas d'erreur, on considère n comme non premier

        # Calcul de x = a^s mod n
        x = pow(a, s, n)

        # Première condition de Miller-Rabin : si x == 1 ou x == n-1,
        # n pourrait être premier pour ce témoin 'a'. On passe au témoin suivant.
        if x == 1 or x == n - 1:
            continue

        # Deuxième condition : Mettre x au carré (r-1) fois modulo n.
        # Si on trouve x == n-1 à une étape, n pourrait être premier.
        for _ in range(r - 1):
            x = pow(x, 2, n) # x = x^2 mod n
            if x == n - 1:
                break # Sortir de la boucle interne, n pourrait être premier
        else:
            # Si la boucle interne se termine sans que x devienne n-1,
            # alors n est définitivement composé.
            return False

    # Si n a passé les k tests avec succès, il est très probablement premier.
    return True

# Fonction pour générer un grand nombre premier d'une taille spécifique
def generate_large_prime(bits):
    """
    Génère un grand nombre entier probablement premier ayant exactement 'bits' bits.

    :param bits: Le nombre de bits souhaité pour le nombre premier.
    :return: Un entier probablement premier de la taille spécifiée.
    :raises ValueError: Si aucun nombre premier n'est trouvé après max_attempts.
    """
    print(f"   Recherche d'un nombre premier de {bits} bits...") # Message pour l'utilisateur
    attempts = 0 # Compteur de tentatives
    max_attempts = 1000 # Limite pour éviter une boucle infinie

    # Boucle jusqu'à trouver un premier ou atteindre la limite
    while attempts < max_attempts:
        attempts += 1
        # Calculer le nombre d'octets nécessaires
        num_bytes = bits // 8
        # Générer des octets aléatoires sécurisés
        p_bytes = os.urandom(num_bytes)
        # Convertir les octets en un entier
        p_candidate = int.from_bytes(p_bytes, 'big')

        # Forcer le nombre à avoir la bonne taille et à être impair :
        # 1. Mettre le bit de poids le plus fort (MSB) à 1 : garantit la taille
        p_candidate |= (1 << (bits - 1))
        # 2. Mettre le bit de poids le plus faible (LSB) à 1 : garantit l'imparité
        p_candidate |= 1

        # Vérifier si le candidat a bien la bonne longueur en bits
        if p_candidate.bit_length() != bits:
            continue # Si non, générer un nouveau candidat

        # Tester si le candidat est probablement premier
        if is_prime(p_candidate):
            # Si oui, on l'a trouvé !
            print(f"   -> Nombre premier trouvé ({p_candidate.bit_length()} bits) après {attempts} tentatives.")
            return p_candidate # Retourner le nombre premier trouvé

    # Si on sort de la boucle sans trouver de premier
    raise ValueError(f"Impossible de générer un nombre premier de {bits} bits après {max_attempts} tentatives.")

# --- Génération des Clés (Système Exponentiel Modulo p) ---
def generate_keys_mod_p(bits):
    """
    Génère une paire de clés (publique, privée) pour notre système de
    chiffrement simplifié basé sur l'exponentiation modulo un nombre premier 'p'.
    Dans ce système, la clé privée 'd' est calculable directement à partir
    des composants de la clé publique (e, p), car phi(p) = p - 1.

    ATTENTION : Ce système est pédagogique et NON SÉCURISÉ pour un usage réel.
                Il est vulnérable à diverses attaques.

    :param bits: La taille souhaitée (en bits) pour le module premier 'p'.
    :return: Une paire de clés sous forme de tuples : (public_key, private_key)
             où public_key = (e, p) et private_key = (d, p).
    """
    print(f"\n--- Début de la Génération des Clés (Modulo p, {bits} bits) ---")

    # 1. Générer le grand nombre premier 'p' qui servira de module
    p = generate_large_prime(bits)

    # 2. Calculer 'phi'. Pour un module premier p, phi(p) = p - 1.
    # C'est la valeur utilisée pour trouver l'inverse modulaire pour 'd'.
    phi = p - 1

    # 3. Choisir l'exposant public 'e'.
    # Une valeur courante est 65537 car elle est première et a des propriétés
    # binaires qui rendent l'exponentiation rapide.
    e = 65537
    # Il faut s'assurer que 'e' est premier avec 'phi' (gcd(e, phi) == 1)
    # et que e < phi pour que l'inverse modulaire existe et soit unique.
    while gcd(e, phi) != 1 or e >= phi:
        # Si e=65537 ne convient pas (très improbable pour un grand p),
        # on pourrait chercher un autre 'e', mais ici on lève une erreur.
        raise ValueError(f"Impossible de trouver un e approprié (e=65537 ne convient pas pour p={p}).")

    # 4. Calculer l'exposant privé 'd'.
    # 'd' est l'inverse modulaire de 'e' modulo 'phi'.
    # C'est-à-dire : (e * d) % phi == 1
    # La fonction pow(e, -1, phi) calcule cet inverse efficacement.
    d = pow(e, -1, phi)

    print(f"--- Fin de la Génération des Clés ---")
    # Créer les tuples de clés
    public_key = (e, p) # Exposant public 'e', module premier 'p'
    private_key = (d, p) # Exposant privé 'd', module premier 'p'
    return public_key, private_key


# --- Fonctions de Padding et Chiffrement/Déchiffrement ---

# Fonction pour ajouter un remplissage (padding) au message
def add_padding(message_bytes, modulus):
    """
    Ajoute un remplissage (padding) simple et personnalisé au message avant chiffrement.
    Le but du padding est de :
    1. S'assurer que le message à chiffrer a une taille fixe liée à celle du module.
    2. Masquer la longueur réelle du message.
    3. Prévenir certaines attaques (bien que ce padding spécifique soit trop simple).

    Format utilisé ici : [Longueur (2 octets)][Message][Remplissage (0xFF...)]

    :param message_bytes: Le message original sous forme d'octets (bytes).
    :param modulus: Le module utilisé pour le chiffrement (ici 'p').
                    La taille du message paddé dépendra de la taille de ce module.
    :return: Le message avec remplissage, sous forme d'octets (bytes).
    :raises ValueError: Si le message original est trop long pour être paddé.
    """
    # Calculer la taille requise pour le message paddé en octets,
    # basée sur la taille en bits du module.
    key_size_bytes = (modulus.bit_length() + 7) // 8
    # Obtenir la longueur du message original en octets.
    message_len = len(message_bytes)

    # Vérifier si le message + 2 octets pour la longueur dépassent la taille cible.
    # Si oui, le message est trop long.
    if message_len + 2 > key_size_bytes:
        raise ValueError("Le message est trop long pour être chiffré avec ce padding et ce module.")

    # Calculer combien d'octets de remplissage sont nécessaires.
    padding_length = key_size_bytes - message_len - 2 # 2 octets réservés pour la longueur

    # Créer le remplissage : une séquence d'octets 0xFF.
    padding = bytes([0xFF] * padding_length)

    # Assembler le message paddé :
    # 1. La longueur du message original, encodée sur 2 octets (format '>H': big-endian unsigned short).
    # 2. Le message original en octets.
    # 3. Le remplissage d'octets 0xFF.
    padded_message = struct.pack('>H', message_len) + message_bytes + padding

    # Vérification interne (assertion) : s'assurer que la longueur finale est correcte.
    assert len(padded_message) == key_size_bytes, f"Erreur interne de padding: taille {len(padded_message)} != {key_size_bytes}"
    return padded_message

# Fonction de Chiffrement
def encrypt(message_str, public_key):
    """
    Chiffre un message (string) en utilisant la clé publique (e, p)
    et le schéma de padding personnalisé.

    :param message_str: Le message à chiffrer (chaîne de caractères).
    :param public_key: Le tuple de la clé publique (e, p).
    :return: Le message chiffré, encodé en Base64 pour faciliter l'affichage/transmission.
    :raises ValueError: Si le message est trop long ou si le message paddé >= p.
    """
    # Extraire les composants de la clé publique
    e, p = public_key
    print(f"   Chiffrement avec la clé publique...") # Message pour l'utilisateur

    # 1. Encoder le message string en octets (UTF-8 par défaut)
    message_bytes = message_str.encode('utf-8')

    # 2. Ajouter le padding au message en octets
    padded_message = add_padding(message_bytes, p)

    # 3. Convertir le message paddé (octets) en un grand entier
    message_int = int.from_bytes(padded_message, 'big')

    # 4. Vérification cruciale : l'entier à chiffrer doit être inférieur au module p.
    if message_int >= p:
         # Ce cas est rare mais possible si le padding génère une grande valeur.
         raise ValueError(f"Le message paddé ({message_int}) est >= au module p ({p}). Chiffrement impossible.")

    # 5. Effectuer l'opération de chiffrement : C = M^e mod p
    print(f"   -> Calcul de pow(message_paddé, e, p)...")
    ciphertext_int = pow(message_int, e, p)
    print(f"   -> Calcul effectué.")

    # 6. Convertir l'entier résultant (chiffré) en octets.
    # La taille en octets doit correspondre à celle du module p.
    ciphertext_bytes = ciphertext_int.to_bytes((p.bit_length() + 7) // 8, 'big')

    # 7. Encoder les octets chiffrés en Base64 (pour une représentation textuelle)
    return base64.b64encode(ciphertext_bytes).decode('utf-8')

# Fonction de Déchiffrement
def decrypt(ciphertext_b64, private_key):
    """
    Déchiffre un message (encodé en Base64) en utilisant la clé privée (d, p)
    et retire le padding personnalisé.

    :param ciphertext_b64: Le message chiffré, encodé en Base64 (string).
    :param private_key: Le tuple de la clé privée (d, p).
    :return: Le message original déchiffré (string).
    :raises ValueError: Si le décodage Base64 échoue, si le padding est invalide, etc.
    """
    # Extraire les composants de la clé privée
    d, p = private_key
    print(f"   Déchiffrement avec la clé privée...") # Message pour l'utilisateur
    # Calculer la taille attendue en octets, basée sur le module p
    key_size_bytes = (p.bit_length() + 7) // 8

    # 1. Décoder le message de Base64 en octets bruts
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
    except base64.binascii.Error as e:
        # Gérer les erreurs si l'entrée n'est pas du Base64 valide
        raise ValueError(f"Erreur de décodage Base64 : {e}")

    # 2. Convertir les octets chiffrés en un grand entier
    ciphertext_int = int.from_bytes(ciphertext_bytes, 'big')

    # 3. Effectuer l'opération de déchiffrement : M = C^d mod p
    print(f"   -> Calcul de pow(ciphertext, d, p)...")
    plaintext_int = pow(ciphertext_int, d, p)
    print(f"   -> Calcul effectué.")

    # 4. Convertir l'entier résultant (message paddé) en octets
    try:
        # La taille doit correspondre à celle du module p
        plaintext_padded_bytes = plaintext_int.to_bytes(key_size_bytes, 'big')
    except OverflowError:
         # Théoriquement impossible si tout s'est bien passé avant
         raise ValueError(f"Erreur: Le résultat déchiffré ({plaintext_int}) est trop grand pour {key_size_bytes} octets.")


    # --- 5. Retirer le Padding Personnalisé ---
    print("   Retrait du padding...")
    try:
        # Lire les 2 premiers octets pour obtenir la longueur du message original
        # '>H' : Big-endian unsigned short (2 octets)
        message_len = struct.unpack('>H', plaintext_padded_bytes[:2])[0]
    except struct.error:
        # Erreur si les 2 premiers octets ne forment pas un entier court valide
        print("   [ERREUR Padding] Impossible de lire la longueur du message (2 premiers octets invalides).")
        raise ValueError("Échec du déchiffrement : impossible d'interpréter les données résultantes (padding invalide?).")
    except IndexError:
        # Erreur si les données sont trop courtes (moins de 2 octets)
        print("   [ERREUR Padding] Données déchiffrées trop courtes pour lire la longueur.")
        raise ValueError("Échec du déchiffrement : données résultantes trop courtes.")


    # Vérifier si la longueur lue est cohérente avec la taille totale des données
    if 2 + message_len > len(plaintext_padded_bytes):
         print(f"   [ERREUR Padding] Longueur de message ({message_len}) invalide pour la taille des données ({len(plaintext_padded_bytes)}).")
         raise ValueError("Longueur de message invalide trouvée dans les données déchiffrées.")

    # Extraire les octets correspondant au message original
    message_bytes = plaintext_padded_bytes[2 : 2 + message_len]

    # Vérification (optionnelle mais recommandée) du reste du padding
    expected_padding_start_index = 2 + message_len
    actual_padding = plaintext_padded_bytes[expected_padding_start_index:]
    # Calculer la longueur attendue du padding
    expected_padding_len = key_size_bytes - expected_padding_start_index
    # Créer la séquence d'octets 0xFF attendue
    expected_padding = bytes([0xFF] * expected_padding_len)
    # Comparer le padding réel avec le padding attendu
    if actual_padding != expected_padding:
        # Avertissement si le padding n'est pas correct. Peut indiquer une erreur
        # de clé, un message corrompu, ou un problème dans l'implémentation.
        print(f"   [AVERTISSEMENT Padding] Le padding après le 'message' extrait (longueur {len(actual_padding)}) ne correspond pas aux {expected_padding_len} octets 0xFF attendus.")

    # 6. Tenter de décoder les octets du message en une chaîne de caractères UTF-8
    try:
        result_str = message_bytes.decode('utf-8')
        print(f"   -> Décodage UTF-8 réussi.")
        return result_str # Retourner le message original
    except UnicodeDecodeError:
        # Si le décodage échoue (les octets ne forment pas une chaîne UTF-8 valide)
        print("   [ERREUR Décodage] Impossible de décoder les bytes résultants en UTF-8.")
        # Retourner la représentation hexadécimale pour inspection
        return message_bytes.hex()

# --- Fonctions Utilitaires pour l'Interface Utilisateur ---

# Fonction pour obtenir une clé (publique ou privée) de l'utilisateur
def get_key_from_user(key_type):
    """
    Demande interactivement à l'utilisateur d'entrer les composants (nombres entiers)
    d'une clé publique ou privée. Gère les erreurs de saisie.

    :param key_type: Chaîne 'publique' ou 'privée' pour adapter les messages.
    :return: Un tuple contenant les deux composants de la clé (e, p) ou (d, p),
             ou None si l'utilisateur fait une erreur ou annule.
    """
    # Déterminer les noms des composants selon le type de clé
    if key_type == 'publique':
        comp1_name = 'e (exposant public)'
        comp2_name = 'p (module premier)'
    elif key_type == 'privée':
        comp1_name = 'd (exposant privé)'
        comp2_name = 'p (module premier)'
    else:
        # Type de clé non reconnu
        return None

    print(f"\n--- Saisie de la Clé {key_type.capitalize()} ---")
    # Boucle jusqu'à obtenir une saisie valide
    while True:
        try:
            # Demander le premier composant
            comp1_str = input(f"   Entrez la valeur de {comp1_name} : ")
            comp1 = int(comp1_str) # Convertir en entier
            # Demander le deuxième composant (le module p)
            comp2_str = input(f"   Entrez la valeur de {comp2_name} : ")
            comp2 = int(comp2_str) # Convertir en entier

            # Vérification simple : le module p doit être supérieur à 1
            if comp2 <= 1:
                print(f"   [ERREUR] Le module p ({comp2}) doit être supérieur à 1.")
                continue # Redemander la saisie

            # Si tout est valide, retourner le tuple de la clé
            print(f"   -> Clé {key_type} saisie.")
            return (comp1, comp2)

        except ValueError:
            # Gérer le cas où l'utilisateur n'entre pas un nombre entier
            print(f"   [ERREUR] Veuillez entrer des nombres entiers valides.")
            # La boucle continue pour redemander
        except Exception as e:
            # Gérer toute autre erreur imprévue pendant la saisie
            print(f"   [ERREUR] Une erreur inattendue s'est produite : {e}")
            return None # Abandonner la saisie en cas d'erreur grave

# Fonction pour afficher une clé de manière structurée et lisible
def display_key(key_tuple, key_type_name):
    """
    Affiche les composants d'une clé (publique ou privée) de manière formatée
    dans la console.

    :param key_tuple: Le tuple contenant la clé (e, p) ou (d, p).
    :param key_type_name: Le nom du type de clé à afficher (ex: "Publique", "Privée Entrée").
    """
    # Vérifier si la clé est disponible
    if not key_tuple:
        print(f"\n[INFO] Clé {key_type_name} non disponible.")
        return

    # Déterminer le nom du premier composant (e ou d)
    comp1_name = 'e' if 'Publique' in key_type_name else 'd'
    # Le deuxième composant est toujours 'p' dans ce système
    comp2_name = 'p'
    # Extraire les valeurs de la clé
    comp1_val, comp2_val = key_tuple

    # Affichage formaté
    print("\n" + ("-" * 45)) # Ligne de séparation
    print(f"   Clé {key_type_name}")
    print(  "_" * 45) # Autre ligne de séparation
    print(f"   Exposant ({comp1_name}) : {comp1_val}")
    print(f"   Module   ({comp2_name}) : {comp2_val}")
    print(  "-" * 45) # Ligne de séparation finale


# --- Programme Principal (Boucle d'Interaction) ---
def main_loop():
    """
    Fonction principale qui gère la boucle d'interaction avec l'utilisateur,
    permettant de générer/entrer des clés, chiffrer et déchiffrer des messages
    de manière répétée.
    """
    # Message de bienvenue
    print("="*60)
    print("=== Bienvenue dans l'outil de Chiffrement Exponentiel (Modulo p) ===")
    print("    (Version pédagogique, non sécurisée pour usage réel)")
    print("="*60)

    # Boucle principale : continue tant que l'utilisateur veut faire des opérations
    while True:
        # Afficher le début d'un nouveau cycle
        print("\n" + "#"*60)
        print("### Nouveau Cycle Chiffrement/Déchiffrement ###")
        print("#"*60)

        # Réinitialiser les variables pour ce cycle
        public_key = None
        private_key = None
        message = None # Stockera le message original si on chiffre dans ce cycle
        ciphertext_b64 = None # Stockera le message chiffré dans ce cycle

        # --- Étape 1: Obtenir les Clés ---
        print("\n*** Étape 1: Obtenir les Clés ***")
        # Boucle interne pour le choix 'g' ou 'e'
        while True:
            choice = input("   Voulez-vous [g]énérer une nouvelle paire de clés ou [e]ntrer des clés existantes ? (g/e) ").lower()

            # --- Option 'g': Générer les clés ---
            if choice == 'g':
                bits = 2048 # Taille de clé fixée pour le module p (modifiable si besoin)
                try:
                    # Appeler la fonction de génération de clés
                    public_key, private_key = generate_keys_mod_p(bits)
                    # Afficher les clés générées de manière structurée
                    print("\nClés générées avec succès :")
                    display_key(public_key, "Publique")
                    display_key(private_key, "Privée")
                    break # Sortir de la boucle de choix de clé, passer à l'étape 2

                except ValueError as e:
                    # Gérer les erreurs pendant la génération
                    print(f"   [ERREUR] Échec de la génération des clés : {e}")
                except Exception as e:
                    # Gérer les erreurs imprévues
                    print(f"   [ERREUR] Une erreur inattendue est survenue lors de la génération des clés : {e}")
                # Si erreur, la boucle continue pour redemander 'g' ou 'e'

            # --- Option 'e': Entrer les clés manuellement ---
            elif choice == 'e':
                # Demander et afficher la clé publique
                public_key_input = get_key_from_user('publique')
                if public_key_input:
                    public_key = public_key_input
                    display_key(public_key, "Publique Entrée")
                else:
                    print("   [INFO] Aucune clé publique valide n'a été entrée.")

                # Demander et afficher la clé privée
                private_key_input = get_key_from_user('privée')
                if private_key_input:
                    private_key = private_key_input
                    display_key(private_key, "Privée Entrée")
                else:
                    print("   [INFO] Aucune clé privée valide n'a été entrée.")

                # Vérifier si les modules 'p' correspondent (important !)
                if public_key and private_key and public_key[1] != private_key[1]:
                    print("\n   [ATTENTION] Le module 'p' de la clé publique ne correspond pas à celui de la clé privée !")
                    print("              Le chiffrement/déchiffrement risque d'échouer.")

                # Vérifier si au moins une clé a été fournie pour continuer
                if public_key or private_key:
                     print("\n   Clés manuelles enregistrées.")
                     break # Sortir de la boucle de choix de clé, passer à l'étape 2
                else:
                     # Si aucune clé n'a été entrée, on ne peut rien faire
                     print("\n   [ERREUR] Aucune clé valide n'a été entrée. Veuillez réessayer.")
                     # Reste dans la boucle de choix de clé

            # --- Choix invalide ---
            else:
                print("   [ERREUR] Choix invalide. Veuillez entrer 'g' ou 'e'.")


        # --- Étape 2: Chiffrement ---
        print("\n*** Étape 2: Chiffrement ***")
        # Vérifier si une clé publique est disponible
        if public_key:
            print("   Prêt à chiffrer avec la clé publique disponible.")
            # Demander le message à l'utilisateur
            message = input("   Entrez le message à chiffrer : ")
            try:
                # Appeler la fonction de chiffrement
                ciphertext_b64 = encrypt(message, public_key)
                # Afficher le résultat
                print(f"\n   Message chiffré (Base64) :\n   {ciphertext_b64}")
            except ValueError as e:
                # Gérer les erreurs de chiffrement (ex: message trop long)
                print(f"   [ERREUR] Erreur lors du chiffrement : {e}")
                ciphertext_b64 = None # Réinitialiser en cas d'erreur
            except Exception as e:
                # Gérer les erreurs imprévues
                print(f"   [ERREUR] Une erreur inattendue est survenue lors du chiffrement : {e}")
                ciphertext_b64 = None # Réinitialiser en cas d'erreur
        else:
            # Si pas de clé publique, on ne peut pas chiffrer
            print("   -> Aucune clé publique disponible. Chiffrement impossible.")
            ciphertext_b64 = None # S'assurer qu'il est None


        # --- Étape 3: Déchiffrement ---
        print("\n*** Étape 3: Déchiffrement ***")
        # Vérifier si une clé privée est disponible
        if private_key:
            print("   Prêt à déchiffrer avec la clé privée disponible.")
            # Demander quel message chiffré utiliser
            if ciphertext_b64: # Si on vient de chiffrer un message dans ce cycle
                 # Proposer d'utiliser le message chiffré précédent
                 confirm_use_generated = input(f"   Utiliser le message chiffré ci-dessus ({ciphertext_b64[:20]}...) ? ([o]ui/n) ").lower()
                 if confirm_use_generated != 'n': # Accepte 'o' ou juste Entrée par défaut
                     ciphertext_to_decrypt = ciphertext_b64
                 else:
                     # Sinon, demander un autre message chiffré
                     ciphertext_to_decrypt = input("   Entrez le message chiffré (Base64) à déchiffrer : ")
            else: # Si on n'a pas chiffré avant (pas de clé publique ou erreur)
                 # Demander directement le message chiffré
                 ciphertext_to_decrypt = input("   Entrez le message chiffré (Base64) à déchiffrer : ")

            # Vérifier si on a un message chiffré à déchiffrer
            if ciphertext_to_decrypt:
                try:
                    # Appeler la fonction de déchiffrement
                    plaintext = decrypt(ciphertext_to_decrypt, private_key)
                    # Afficher le résultat
                    print(f"\n   Résultat du déchiffrement : {plaintext}")

                    # Comparer avec le message original si on l'a chiffré dans ce cycle
                    if message is not None:
                        if plaintext == message:
                            print("\n   [SUCCES] Le message déchiffré correspond au message original.")
                        else:
                            print("\n   [ATTENTION] Le message déchiffré NE CORRESPOND PAS au message original.")
                            print("              Vérifiez les clés utilisées ou le message chiffré entré.")
                    # else: # Si 'message' est None, on ne peut pas comparer
                    #     print("\n   [INFO] Le message original n'est pas connu pour comparaison.")

                except ValueError as e:
                    # Gérer les erreurs de déchiffrement (Base64, padding...)
                    print(f"\n   [ERREUR] Échec du déchiffrement : {e}")
                except Exception as e:
                    # Gérer les erreurs imprévues
                    print(f"\n   [ERREUR INATTENDUE] Une erreur imprévue s'est produite lors du déchiffrement : {e}")
            else:
                # Si l'utilisateur n'a pas fourni de message chiffré
                print("   [INFO] Aucun message chiffré fourni, déchiffrement annulé.")

        else:
            # Si pas de clé privée, on ne peut pas déchiffrer
            print("   -> Aucune clé privée disponible. Déchiffrement impossible.")

        # --- Fin du Cycle ---
        # Demander à l'utilisateur s'il veut recommencer
        print("\n" + "-"*60)
        continuer = input("Voulez-vous commencer un nouveau cycle ? ([o]ui/n) ").lower()
        if continuer == 'n':
            break # Sortir de la boucle principale while True

    # Message de fin lorsque la boucle est terminée
    print("\n=== Fin du programme. Au revoir ! ===")


# Point d'entrée du programme : exécute la boucle principale
if __name__ == "__main__":
    main_loop()

