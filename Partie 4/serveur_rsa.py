from flask import Flask, request, jsonify
import rsa
import base64

# ---------------------------
# Initialisation de l'application Flask
# ---------------------------
app = Flask(__name__)

# Génération de la paire de clés RSA du serveur
print("Génération des clés RSA du serveur...")
(pubkey_server, privkey_server) = rsa.newkeys(2048)
print("Clés générées.")

# ---------------------------
# Route GET pour envoyer la clé publique du serveur
# ---------------------------
@app.route("/get_key", methods=["GET"])
def get_key():
    print("Envoi de la clé publique du serveur.")
    return jsonify({
        "key": pubkey_server.save_pkcs1().decode()
    })

# ---------------------------
# Route POST pour recevoir le message signé et chiffré
# ---------------------------
@app.route("/message", methods=["POST"])
def receive_message():
    print("\nRequête POST reçue.")

    data = request.get_json()
    print("Payload reçu :", data)

    try:
        # Extraction des champs
        encrypted_message = base64.b64decode(data["message"])
        signature = base64.b64decode(data["signature"])
        client_pubkey_data = data["client_pubkey"].encode()

        # Reconstruction de la clé publique du client
        client_pubkey = rsa.PublicKey.load_pkcs1(client_pubkey_data)
        print("Clé publique du client reconstruite.")

        # Déchiffrement du message
        message_clair = rsa.decrypt(encrypted_message, privkey_server)
        print("Message déchiffré :", message_clair.decode())

        # Vérification de la signature
        try:
            rsa.verify(message_clair, signature, client_pubkey)
            print("Signature VALIDE.")
            return jsonify({
                "message_clair": message_clair.decode(),
                "status": "Signature valide"
            }), 200
        except rsa.VerificationError:
            print("Signature INVALIDE.")
            return jsonify({
                "message_clair": None,
                "status": "Signature invalide"
            }), 400

    except Exception as e:
        print("Erreur serveur :", str(e))
        return jsonify({"error": str(e)}), 500

# ---------------------------
# Lancement de l'application Flask
# ---------------------------
if __name__ == "__main__":
    print("Serveur lancé sur http://127.0.0.1:5000")
    app.run(port=5000)
