import os
import json
import socket
import threading
from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Utilisateurs et ports associés
USERS = {
    "Alice": 5001,
    "Bob": 5002,
    "Tristan": 5003
}
SERVER_ADDR = ("localhost", 5000)
KEY_DIR = "keys"
app_instances = {}

def load_keys(name):
    with open(f"{KEY_DIR}/{name}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(f"{KEY_DIR}/{name}_public.pem", "rb") as f:
        public_key = f.read()
    
    return private_key, public_key

def fetch_aes_key(name, public_key_pem, private_key):
    s = socket.socket()
    s.connect(SERVER_ADDR)
    s.send(json.dumps({
        "name": name,
        "public_key": public_key_pem.decode()
    }).encode())
    enc_aes_key = s.recv(4096)
    s.close()

    if len(enc_aes_key) < 256:
        raise ValueError("Clé AES non valide reçue")

    aes_key = private_key.decrypt(
        enc_aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return Fernet(aes_key)

def create_app(name):
    app = Flask(__name__)
    private_key, public_key_pem = load_keys(name)
    fernet = fetch_aes_key(name, public_key_pem, private_key)

    other_users = [u for u in USERS if u != name]
    messages = []

    @app.route("/", methods=["GET"])
    def select_page():
        return render_template("select.html", me=name, users=other_users)

    @app.route("/messenger", methods=["GET", "POST"])
    def messenger():
        target = request.args.get("target")
        if request.method == "POST":
            msg = request.form.get("msg")
            enc = fernet.encrypt(msg.encode())

            try:
                s = socket.socket()
                s.connect(("localhost", USERS[target]))
                s.send(enc)
                s.close()
                messages.append((f"Moi ➡️ {target}", msg))
            except Exception as e:
                messages.append((f"[ERREUR]", str(e)))

        return render_template("chat.html", me=name, target=target, messages=messages)

    def receive():
        server = socket.socket()
        server.bind(("localhost", USERS[name]))
        server.listen(1)
        while True:
            conn, _ = server.accept()
            encrypted = conn.recv(4096)
            conn.close()
            try:
                msg = fernet.decrypt(encrypted).decode()
                messages.append((f"{name} ⬅️ Message reçu", msg))
            except Exception as e:
                messages.append((f"[ERREUR]", str(e)))

    threading.Thread(target=receive, daemon=True).start()
    return app

# Démarre un serveur Flask pour chaque utilisateur dans un thread
def launch_all():
    for name in USERS:
        port = USERS[name]
        app = create_app(name)
        threading.Thread(target=app.run, kwargs={"port": port}, daemon=True).start()
        print(f"[{name}] Flask lancé sur http://localhost:{port}")

if __name__ == "__main__":
    launch_all()
    input("✅ Tous les clients sont en ligne. Appuie sur Entrée pour quitter...\n")
