import socket
import json
import threading
import time
from flask import Flask, render_template, request, redirect
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Configuration
SOCKET_HOST = "0.0.0.0"
SOCKET_PORT = 5000
HTTP_PORT = 5005

EXPECTED_CLIENTS = {"Alice", "Bob", "Tristan"}
clients = {}
session_key = None

# --- Socket handler (clés RSA + clé AES) ---
def handle_client(conn):
    global session_key

    try:
        data = conn.recv(8192)
        payload = json.loads(data.decode())
        name = payload["name"]
        pubkey_pem = payload["public_key"].encode()
        public_key = serialization.load_pem_public_key(pubkey_pem)
        clients[name] = public_key
        print(f"[+] Clé publique enregistrée pour {name} ({len(clients)}/{len(EXPECTED_CLIENTS)})")

        if len(clients) == len(EXPECTED_CLIENTS) and session_key is None:
            session_key = Fernet.generate_key()
            print("[🔐] Clé de session AES générée")

        while session_key is None:
            time.sleep(0.1)

        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        conn.send(encrypted_key)
        print(f"[➡️] Clé AES envoyée à {name}")

    except Exception as e:
        print(f"[!] Erreur avec un client : {e}")
    finally:
        conn.close()

def start_socket_server():
    server = socket.socket()
    server.bind((SOCKET_HOST, SOCKET_PORT))
    server.listen(5)
    print(f"[SOCKET] En écoute sur le port {SOCKET_PORT}...")

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

# --- Flask server pour select.html ---
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("select.html")

@app.route("/redirect", methods=["POST"])
def redirect_user():
    user = request.form.get("user")
    port_map = {
        "Alice": 8501,
        "Bob": 8502,
        "Tristan": 8503
    }
    port = port_map.get(user)
    if port:
        return redirect(f"http://localhost:{port}/")
    return "Utilisateur inconnu", 400

# --- Lancement ---
if __name__ == "__main__":
    # Thread pour le socket sécurisé
    threading.Thread(target=start_socket_server, daemon=True).start()

    # Lancement de Flask
    print(f"[FLASK] Serveur web lancé sur http://localhost:{HTTP_PORT}")
    app.run(port=HTTP_PORT)
