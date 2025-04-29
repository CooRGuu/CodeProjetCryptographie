# CodeProjetCryptographie

# Chiffrement Asymétrique Simplifié (Modulo p) - Version Pédagogique

Ce script Python implémente un système de chiffrement asymétrique simplifié basé sur l'exponentiation modulaire avec un grand nombre premier `p`.

**ATTENTION : Ce code est fourni à des fins purement éducatives. Il n'est PAS sécurisé et ne doit PAS être utilisé pour protéger des données réelles.** Le système présenté est vulnérable à diverses attaques cryptographiques.

## Fonctionnalités

* **Génération de Nombres Premiers** : Utilise le test probabiliste de Miller-Rabin pour trouver de grands nombres premiers.
* **Génération de Clés** : Crée une paire de clés:
    * Clé Publique : `(e, p)`
    * Clé Privée : `(d, p)`
    Où `p` est un grand nombre premier, `e` est l'exposant public (souvent 65537), et `d` est l'exposant privé, calculé comme l'inverse modulaire de `e` modulo `p-1`.
* **Padding Personnalisé** : Ajoute un remplissage simple au message avant le chiffrement pour masquer la longueur et tenter de standardiser la taille du bloc. Le format est `[Longueur (2 octets)][Message][Remplissage 0xFF...]`.
* **Chiffrement** : Chiffre un message $M$ en calculant $C = M^e \pmod{p}$.
* **Déchiffrement** : Déchiffre un texte chiffré $C$ en calculant $M = C^d \pmod{p}$ et en retirant le padding.
* **Interface Utilisateur** : Une boucle interactive permet de:
    * Générer une nouvelle paire de clés.
    * Entrer manuellement une clé publique et/ou privée.
    * Chiffrer un message avec la clé publique.
    * Déchiffrer un message (celui qui vient d'être chiffré ou un autre fourni par l'utilisateur) avec la clé privée.

## Composants Principaux du Code

* `is_prime(n, k)` : Teste si `n` est probablement premier.
* `generate_large_prime(bits)` : Génère un nombre premier probable d'une taille donnée en bits.
* `generate_keys_mod_p(bits)` : Génère la paire de clés publique/privée.
* `add_padding(message_bytes, modulus)` : Ajoute le padding au message.
* `encrypt(message_str, public_key)` : Chiffre un message texte.
* `decrypt(ciphertext_b64, private_key)` : Déchiffre un texte chiffré encodé en Base64.
* `get_key_from_user(key_type)` : Demande à l'utilisateur d'entrer une clé.
* `display_key(key_tuple, key_type_name)` : Affiche une clé de manière formatée.
* `main_loop()` : Gère l'interaction principale avec l'utilisateur.

## Comment Utiliser

1.  Exécutez le script Python : `python AsymétriqueModuloP.py`
2.  Suivez les instructions à l'écran :
    * Choisissez de générer (`g`) une nouvelle paire de clés (une taille de 2048 bits est utilisée par défaut) ou d'entrer (`e`) des clés existantes.
    * Si vous générez des clés, elles seront affichées.
    * Si une clé publique est disponible, entrez le message à chiffrer. Le résultat encodé en Base64 sera affiché.
    * Si une clé privée est disponible, vous pourrez déchiffrer un message. Vous pouvez choisir d'utiliser le message chiffré à l'étape précédente ou en entrer un nouveau (en Base64).
    * Le programme comparera le message déchiffré à l'original si les deux sont disponibles dans le même cycle.
    * Choisissez de recommencer un cycle ou de quitter.

## Dépendances

* `os` (pour `os.urandom`)
* `math` (pour `gcd`)
* `base64`
* `struct`

Ce script est autonome et ne nécessite pas d'installation de bibliothèques externes autres que celles fournies avec Python.
