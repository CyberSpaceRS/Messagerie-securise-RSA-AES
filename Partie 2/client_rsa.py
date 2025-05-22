# client_rsa.py — Client HTTP utilisant le chiffrement RSA
import requests  # Pour faire les requêtes HTTP
import rsa        # Pour chiffrer avec la clé publique

# -----------------------------
# Adresse du serveur Flask
url_serveur = "http://127.0.0.1:5000"

# -----------------------------
# Étape 1 : Récupération de la clé publique RSA depuis le serveur
reponse = requests.get(f"{url_serveur}/get_key")
cle_publique_data = reponse.json()  # n et e (composants de la clé publique RSA)

# Reconstruction de l'objet clé publique RSA
n = cle_publique_data['n']
e = cle_publique_data['e']
cle_publique = rsa.PublicKey(n, e)

# -----------------------------
# Étape 2 : Préparation et chiffrement du message
message = "Bonjour depuis le client RSA."
message_chiffre = rsa.encrypt(message.encode(), cle_publique)

# -----------------------------
# Étape 3 : Envoi du message chiffré au serveur via POST
reponse = requests.post(f"{url_serveur}/message", json={
    'message': message_chiffre.hex()  # Encodage hexadécimal pour JSON
})

# -----------------------------
# Étape 4 : Affichage de la réponse (texte clair déchiffré côté serveur)
if reponse.status_code == 200:
    print("Réponse du serveur :", reponse.json()['message_clair'])
else:
    print("Erreur côté client :", reponse.text)

