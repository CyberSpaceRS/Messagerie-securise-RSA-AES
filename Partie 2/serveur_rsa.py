from flask import Flask, request, jsonify  # Framework web et gestion JSON
import rsa  # Bibliothèque de chiffrement RSA

# Étape 1 : Création de l'application Flask
application = Flask(__name__)

# Étape 2 : Génération de la paire de clés RSA (clé publique et clé privée)
cle_publique, cle_privee = rsa.newkeys(512)  # 512 bits pour test local (éviter >245 octets)

# Étape 3 : Définition de la route pour fournir la clé publique au client
@application.route('/get_key', methods=['GET'])
def fournir_cle_publique():
    return jsonify({
        'n': cle_publique.n,  # Modulus RSA
        'e': cle_publique.e   # Exposant public
    })

# Étape 4 : Définition de la route pour recevoir un message chiffré
@application.route('/message', methods=['POST'])
def recevoir_message():
    donnees = request.get_json()  # Récupération des données JSON du client
    message_chiffre_hex = donnees['message']  # Le message est reçu sous forme hexadécimale
    message_chiffre = bytes.fromhex(message_chiffre_hex)  # Conversion hexadécimal -> binaire

    try:
        # Étape 5 : Déchiffrement du message avec la clé privée RSA
        message_clair = rsa.decrypt(message_chiffre, cle_privee)
        return jsonify({ 'message_clair': message_clair.decode() })  # Renvoi du texte en clair au client
    except Exception as erreur:
        return jsonify({ 'erreur': str(erreur) }), 400  # Gestion des erreurs de déchiffrement

# Étape 6 : Lancement du serveur Flask sur le port 5000
if __name__ == '__main__':
    application.run(port=5000)


