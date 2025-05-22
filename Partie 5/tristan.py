import socket, json, threading
from flask import Flask, render_template, request, redirect
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from datetime import datetime
import base64

# Identité de l'utilisateur actuel
NAME = "Tristan"

# Configuration des ports
PORT = 8503              # Port HTTP pour Flask
SOCKET_PORT = 8603       # Port d'écoute des messages reçus
SERVER_ADDR = ("localhost", 5000)  # Adresse du serveur de confiance
PEERS = {'Alice': 8601, 'Bob': 8602}  # Autres utilisateurs

# --- Chargement des clés RSA personnelles ---
with open("keys/Tristan_private.pem", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)

with open("keys/Tristan_public.pem", "rb") as f:
    pubkey_pem = f.read()

# --- Connexion au serveur pour obtenir la clé AES (chiffrée avec RSA) ---
s = socket.socket()
s.connect(SERVER_ADDR)

# Envoi de la clé publique de Tristan
s.send(json.dumps({"name": NAME, "public_key": pubkey_pem.decode()}).encode())

# Réception de la clé AES chiffrée
enc_key = s.recv(4096)
s.close()

# Déchiffrement de la clé AES avec la clé privée
aes_key = privkey.decrypt(enc_key, padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))
fernet = Fernet(aes_key)  # Création du chiffrant Fernet

# --- Initialisation de l'application Flask ---
app = Flask(__name__)
conversations = {}  # Stocke les messages par paire d’utilisateurs
current_target = list(PEERS.keys())[0]  # Cible par défaut

# Page d'accueil : redirection vers le bon contact
@app.route("/")
def accueil():
    return redirect(f"/messenger?target={current_target}")

# Route principale de messagerie
@app.route("/messenger", methods=["GET", "POST"])
def messenger():
    global current_target

    # Changement de destinataire si GET
    if request.method == "GET":
        current_target = request.args.get("target", current_target)

    # Envoi d’un message (POST)
    if request.method == "POST":
        msg = request.form.get("msg")
        timestamp = datetime.now().strftime("%H:%M:%S")  # Ajout de l’heure
        content = f"{msg}  {timestamp}"

        # Signature RSA du message
        signature = privkey.sign(
            content.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Construction et chiffrement du message
        encrypted = fernet.encrypt(json.dumps({
            "from": NAME,
            "msg": content,
            "signature": base64.b64encode(signature).decode()
        }).encode())

        try:
            # Envoi vers le destinataire
            s = socket.socket()
            s.connect(("localhost", PEERS[current_target]))
            s.send(encrypted)
            s.close()

            # Ajout du message localement
            key = tuple(sorted([NAME, current_target]))
            conversations.setdefault(key, []).append((NAME, content))

        except Exception as e:
            # Gestion d'erreur (ajout local uniquement)
            key = tuple(sorted([NAME, current_target]))
            conversations.setdefault(key, []).append(("[ERREUR]", str(e)))

    # Rendu HTML de la conversation
    key = tuple(sorted([NAME, current_target]))
    messages = conversations.get(key, [])
    return render_template("chat.html", me=NAME, target=current_target, contacts=PEERS.keys(), messages=messages)

# Thread d’écoute des messages entrants
def receive():
    s = socket.socket()
    s.bind(("localhost", SOCKET_PORT))
    s.listen(1)
    while True:
        conn, _ = s.accept()
        data = conn.recv(4096)
        conn.close()

        try:
            # Déchiffrement et extraction du message
            payload = json.loads(fernet.decrypt(data).decode())
            sender = payload["from"]
            msg = payload["msg"]

            # Stockage dans la bonne conversation
            key = tuple(sorted([sender, NAME]))
            conversations.setdefault(key, []).append((sender, msg))

        except Exception as e:
            # Gestion d'erreur
            key = tuple(sorted(["Erreur", NAME]))
            conversations.setdefault(key, []).append(("[ERREUR]", str(e)))

# Lancement du thread de réception
threading.Thread(target=receive, daemon=True).start()

# Démarrage du serveur Flask
print(f"[{NAME}] Serveur Flask sur http://localhost:{PORT}")
app.run(port=PORT, host="127.0.0.1")
