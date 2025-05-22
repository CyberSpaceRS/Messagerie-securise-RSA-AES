import requests         # Pour effectuer les requêtes HTTP vers le serveur
import rsa              # Pour générer des clés RSA, chiffrer et signer
import base64           # Pour encoder les données binaires en base64 (texte)

# ---------------------------
# Génération des clés RSA du client
# ---------------------------
print("Génération de la paire de clés RSA du client...")
(pubkey_client, privkey_client) = rsa.newkeys(2048)
print("Clés RSA générées !")

# ---------------------------
# Configuration du proxy mitmproxy (port 8888)
# ---------------------------
proxies = {
    "http": "http://127.0.0.1:8888"
}
print("Proxy MITM configuré sur 127.0.0.1:8888")

# ---------------------------
# Récupération de la clé publique du serveur (via proxy)
# ---------------------------
print("Récupération de la clé publique du serveur...")
response = requests.get("http://127.0.0.1:5000/get_key", proxies=proxies)
server_pubkey_pem = response.json()["key"]
print("Clé publique du serveur récupérée.")

# Reconstruction de l'objet clé publique RSA du serveur
server_pubkey = rsa.PublicKey.load_pkcs1(server_pubkey_pem.encode())
print("Clé publique du serveur reconstruite avec succès.")

# ---------------------------
# Préparation du message à chiffrer et signer
# ---------------------------
message = "Message légitime du client.".encode()
print(f"Message original préparé : {message.decode()}")

# ---------------------------
# Chiffrement du message avec la clé publique du serveur
# ---------------------------
message_chiffre = rsa.encrypt(message, server_pubkey)
print(f"Message chiffré (base64) : {base64.b64encode(message_chiffre).decode()}")

# ---------------------------
# Signature du message (non chiffré) avec la clé privée du client
# ---------------------------
signature = rsa.sign(message, privkey_client, 'SHA-256')
print(f"Signature générée (base64) : {base64.b64encode(signature).decode()}")

# ---------------------------
# Construction du payload JSON à envoyer
# ---------------------------
payload = {
    "message": base64.b64encode(message_chiffre).decode(),      # Message chiffré encodé en base64
    "signature": base64.b64encode(signature).decode(),          # Signature encodée
    "client_pubkey": pubkey_client.save_pkcs1().decode()        # Clé publique du client (PEM)
}
print("Payload construit :")
print(payload)

# ---------------------------
# Envoi de la requête POST au serveur via mitmproxy
# ---------------------------
print("Envoi du message au serveur via le proxy...")
response = requests.post("http://127.0.0.1:5000/message", json=payload, proxies=proxies)

# ---------------------------
# Réception de la réponse du serveur
# ---------------------------
try:
    print("Réponse du serveur :", response.json())
except Exception:
    print("Erreur brute :", response.status_code, response.text)
