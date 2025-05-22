import requests         # Pour effectuer les requêtes HTTP
import rsa              # Pour le chiffrement, la signature et la génération de clés RSA
import base64           # Pour encoder/décoder les données binaires

# ---------------------------
# Étape 1 : Génération de la vraie paire de clés RSA (client légitime)
# ---------------------------
print("Génération de la vraie paire de clés du client légitime...")
true_pubkey, true_privkey = rsa.newkeys(2048)
print("Clés RSA du client légitime générées.")

# ---------------------------
# Message d'origine
# ---------------------------
message = "Message authentique signé par le client légitime.".encode('utf-8')
print(f"Message clair : {message.decode()}")

# ---------------------------
# Étape 2 : Récupération de la clé publique du serveur
# ---------------------------
print("Récupération de la clé publique du serveur...")
response = requests.get("http://127.0.0.1:5000/get_key")

try:
    server_pubkey_pem = response.json()["key"]
    print("Clé publique du serveur récupérée.")
except Exception:
    print("Erreur : réponse du serveur invalide (pas JSON)")
    print("Contenu brut :", response.text)
    exit(1)

# Reconstruction de la clé publique RSA du serveur
server_pubkey = rsa.PublicKey.load_pkcs1(server_pubkey_pem.encode())
print("Clé publique du serveur reconstruite.")

# ---------------------------
# Étape 3 : Chiffrement du message avec la clé publique du serveur
# ---------------------------
encrypted_message = rsa.encrypt(message, server_pubkey)
print("Message chiffré.")

# ---------------------------
# Étape 4 : Signature du message clair avec la vraie clé privée du client
# ---------------------------
signature = rsa.sign(message, true_privkey, 'SHA-256')
print("Signature du message générée avec la vraie clé du client.")

# ---------------------------
# Étape 5 : Génération d'une fausse clé publique (pour attaquer)
# ---------------------------
print("Génération d'une FAUSSE clé publique pour simuler une usurpation...")
fake_pubkey, _ = rsa.newkeys(2048)
print("Clé publique de l'attaquant prête.")

# ---------------------------
# Étape 6 : Construction du payload (attaque)
# ---------------------------
# L'attaquant remplace la clé publique du client par une fausse,
# alors que le message et la signature sont toujours valides.
payload = {
    "message": base64.b64encode(encrypted_message).decode(),
    "signature": base64.b64encode(signature).decode(),
    "client_pubkey": fake_pubkey.save_pkcs1().decode()
}
print("Payload d'attaque construit (avec clé publique falsifiée).")

# ---------------------------
# Étape 7 : Envoi de la requête POST au serveur
# ---------------------------
print("Envoi du payload falsifié au serveur...")
response = requests.post("http://127.0.0.1:5000/message", json=payload)

# ---------------------------
# Affichage de la réponse du serveur
# ---------------------------
try:
    print("Réponse du serveur :", response.json())
except Exception:
    print("Erreur brute :", response.status_code, response.text)
