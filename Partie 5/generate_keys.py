import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Dossier où seront stockées les clés
KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

# Liste des utilisateurs
USERS = ["Alice", "Bob", "Tristan"]

def save_keys(name):
    priv_path = f"{KEY_DIR}/{name}_private.pem"
    pub_path = f"{KEY_DIR}/{name}_public.pem"

    # Ne recrée pas les clés si elles existent déjà
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print(f"[!] Clés déjà existantes pour {name}.")
        return

    # Génération de la paire de clés
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Sauvegarde de la clé privée
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sauvegarde de la clé publique
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[+] Clés générées pour {name}.")

# Génération des clés pour tous les utilisateurs
for user in USERS:
    save_keys(user)

# Affichage du contenu du dossier keys
print(f"[📁] Contenu du dossier '{KEY_DIR}':")
for file in os.listdir(KEY_DIR):
    print(" -", file)
