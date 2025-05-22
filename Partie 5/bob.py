import socket, json, threading
from flask import Flask, render_template, request, redirect
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from datetime import datetime
import base64

NAME = "Bob"
PORT = 8502
SOCKET_PORT = 8602
PEERS = {'Alice': 8601, 'Tristan': 8603}
SERVER_ADDR = ("localhost", 5000)

# Chargement des clés RSA
with open("keys/Bob_private.pem", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)
with open("keys/Bob_public.pem", "rb") as f:
    pubkey_pem = f.read()

# Récupération de la clé AES
s = socket.socket()
s.connect(SERVER_ADDR)
s.send(json.dumps({"name": NAME, "public_key": pubkey_pem.decode()}).encode())
enc_key = s.recv(4096)
s.close()

aes_key = privkey.decrypt(enc_key, padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))
fernet = Fernet(aes_key)

# App Flask
app = Flask(__name__)
conversations = {}
current_target = list(PEERS.keys())[0]

@app.route("/")
def accueil():
    return redirect(f"/messenger?target={current_target}")

@app.route("/messenger", methods=["GET", "POST"])
def messenger():
    global current_target

    if request.method == "GET":
        current_target = request.args.get("target", current_target)

    if request.method == "POST":
        msg = request.form.get("msg")
        timestamp = datetime.now().strftime("%H:%M:%S")
        content = f"{msg} {timestamp}"

        # Signature du message
        signature = privkey.sign(
            content.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        encrypted = fernet.encrypt(json.dumps({
            "from": NAME,
            "msg": content,
            "signature": base64.b64encode(signature).decode()
        }).encode())

        try:
            s = socket.socket()
            s.connect(("localhost", PEERS[current_target]))
            s.send(encrypted)
            s.close()
            key = tuple(sorted([NAME, current_target]))
            conversations.setdefault(key, []).append((NAME, content))
        except Exception as e:
            key = tuple(sorted([NAME, current_target]))
            conversations.setdefault(key, []).append(("[ERREUR]", str(e)))

    key = tuple(sorted([NAME, current_target]))
    messages = conversations.get(key, [])
    return render_template("chat.html", me=NAME, target=current_target, contacts=PEERS.keys(), messages=messages)

def receive():
    s = socket.socket()
    s.bind(("localhost", SOCKET_PORT))
    s.listen(1)
    while True:
        conn, _ = s.accept()
        data = conn.recv(4096)
        conn.close()
        try:
            payload = json.loads(fernet.decrypt(data).decode())
            sender = payload["from"]
            msg = payload["msg"]
            # signature = payload["signature"]  # On pourrait la vérifier ici

            key = tuple(sorted([sender, NAME]))
            conversations.setdefault(key, []).append((sender, msg))
        except Exception as e:
            key = tuple(sorted(["Erreur", NAME]))
            conversations.setdefault(key, []).append(("[ERREUR]", str(e)))

threading.Thread(target=receive, daemon=True).start()
print(f"[{NAME}] Serveur Flask sur http://localhost:{PORT}")
app.run(port=PORT, host="127.0.0.1")
