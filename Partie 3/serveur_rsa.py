from flask import Flask, request, jsonify  # Flask : micro-framework web
import rsa                                # Librairie pour le chiffrement RSA
import base64                             # Encodage/décodage base64 (pour envoyer du binaire en JSON)

# ---------------------------
# Initialisation de l'application Flask
# ---------------------------
app = Flask(__name__)

# ---------------------------
# Génération des clés RSA du serveur
# ---------------------------
print("Génération de la paire de clés RSA du serveur...")
(pubkey_server, privkey_server) = rsa.newkeys(2048)
print("Clés RSA générées.\n")

# ---------------------------
# Route GET pour transmettre la clé publique du serveur au client
# ---------------------------
@app.route("/get_key", methods=["GET"])
def get_key():
    print("Envoi de la clé publique du serveur au client.")
    return jsonify({
        "key": pubkey_server.save_pkcs1().decode()  # Encodage en PEM (texte lisible)
    })

# ---------------------------
# Route POST pour recevoir un message chiffré et signé
# ---------------------------
@app.route("/message", methods=["POST"])
def receive_message():
    print("\nRequête POST /message reçue.")

    data = request.get_json()  # Récupération des données JSON
    print("Données reçues :", data)

    try:
        # ---------------------------
        # Décodage base64 des données reçues
        # ---------------------------
        encrypted_message = base64.b64decode(data["message"])          # Message chiffré
        signature = base64.b64decode(data["signature"])                # Signature numérique
        client_pubkey_pem = data["client_pubkey"].encode()             # Clé publique du client (format PEM)

        print("Reconstruction de la clé publique du client...")
        client_pubkey = rsa.PublicKey.load_pkcs1(client_pubkey_pem)
        print("Clé du client reconstruite.")

        # ---------------------------
        # Déchiffrement du message avec la clé privée du serveur
        # ---------------------------
        print("Déchiffrement du message...")
        message_clair = rsa.decrypt(encrypted_message, privkey_server)
        print("Message déchiffré :", message_clair.decode())

        # ---------------------------
        # Vérification de la signature du client
        # ---------------------------
        print("Vérification de la signature...")
        try:
            rsa.verify(message_clair, signature, client_pubkey)
            print("Signature valide.")
            return jsonify({
                "message_clair": message_clair.decode(),
                "status": "Signature valide"
            }), 200
        except rsa.VerificationError:
            print("Signature invalide.")
            return jsonify({
                "message_clair": None,
                "status": "Signature invalide"
            }), 400

    except Exception as e:
        # Gestion des erreurs inattendues (ex: clé invalide, base64 incorrect, etc.)
        print("Erreur serveur :", str(e))
        return jsonify({"error": str(e)}), 500

# ---------------------------
# Lancement du serveur Flask
# ---------------------------
if __name__ == "__main__":
    print("Lancement du serveur Flask sur http://127.0.0.1:5000")
    app.run(port=5000)
