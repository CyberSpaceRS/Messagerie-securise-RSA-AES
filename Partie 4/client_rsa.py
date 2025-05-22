import requests         # Pour effectuer les requêtes HTTP vers le serveur
import rsa              # Pour le chiffrement et la signature RSA
import base64           # Pour encoder les données binaires en base64

# ---------------------------
# Génération de la paire de clés RSA côté client
# ---------------------------
print("Génération de la paire de clés RSA du client...")
(pubkey_client, privkey_client) = rsa.newkeys(2048)
print("Clés RSA générées.")

# ---------------------------
# Récupération de la clé publique du serveur
# ---------------------------
print("Récupération de la clé publique du serveur...")
response = requests.get("http://127.0.0.1:5000/get_key")

try:
    server_pubkey_pem = response.json()["key"]
    print("Clé publique du serveur récupérée.")
except Exception:
    print("Erreur lors de la récupération de la clé.")
    print("Réponse brute :", response.text)
    exit(1)

# Reconstruction de la clé publique RSA du serveur
server_pubkey = rsa.PublicKey.load_pkcs1(server_pubkey_pem.encode())
print("Clé publique du serveur reconstruite.")

# ---------------------------
# Préparation du message à envoyer
# ---------------------------
message = "Weshhhhh depuis le client RSA avec signature.".encode()
print(f"Message préparé : {message.decode()}")

# Chiffrement du message avec la clé publique du serveur
message_chiffre = rsa.encrypt(message, server_pubkey)
print("Message chiffré.")

# Signature du message clair avec la clé privée du client
signature = rsa.sign(message, privkey_client, 'SHA-256')
print("Signature du message générée.")

# Construction du payload à envoyer
payload = {
    "message": base64.b64encode(message_chiffre).decode(),
    "signature": base64.b64encode(signature).decode(),
    "client_pubkey": pubkey_client.save_pkcs1().decode()
}
print("Payload prêt à être envoyé au serveur.")

# Envoi du message signé + chiffré au serveur
response = requests.post("http://127.0.0.1:5000/message", json=payload)

# Réponse du serveur
try:
    print("Réponse du serveur :", response.json())
except Exception:
    print("Erreur de réponse :", response.status_code, response.text)
