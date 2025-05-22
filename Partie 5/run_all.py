import subprocess
import webbrowser
import time
import os

# Chemin des scripts
KEYS = "generate_keys.py"
SERVER = "server.py"
ALICE = "alice.py"
BOB = "bob.py"
TRISTAN = "tristan.py"

# Génération des clés RSA
print("[🔑] Génération des clés RSA...")
server_proc = subprocess.Popen(["python", KEYS])

# Lancement du serveur central AES
print("[🟢] Lancement du serveur central (port 5000)...")
server_proc = subprocess.Popen(["python", SERVER])

# Petite pause pour laisser le serveur démarrer
time.sleep(1)

# Lancement des clients
print("[🟠] Lancement de Alice (port 8501)...")
alice_proc = subprocess.Popen(["python", ALICE])

print("[🟠] Lancement de Bob (port 8502)...")
bob_proc = subprocess.Popen(["python", BOB])

print("[🟠] Lancement de Tristan (port 8503)...")
tristan_proc = subprocess.Popen(["python", TRISTAN])

# Pause pour laisser les Flask démarrer
time.sleep(2)

# Ouverture du navigateur sur le sélecteur utilisateur
print("[🌐] Ouverture de l'interface de sélection utilisateur...")
webbrowser.open("http://localhost:5005")
webbrowser.open("http://localhost:5005")

print("[✅] Tous les services sont lancés. Appuyez sur CTRL+C pour arrêter.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[🔴] Fermeture des processus...")
    server_proc.kill()
    alice_proc.kill()
    bob_proc.kill()
    tristan_proc.kill()
    print("[✅] Terminé.")
