from mitmproxy import http  # Permet d'intercepter et modifier les requêtes HTTP
import json                 # Pour lire et modifier le corps JSON de la requête
import base64               # Pour encoder les données binaires en base64

# ---------------------------
# Fonction appelée automatiquement à chaque requête HTTP interceptée
# ---------------------------
def request(flow: http.HTTPFlow) -> None:
    # On cible uniquement les requêtes POST envoyées à l'URL "/message"
    if flow.request.method == "POST" and "/message" in flow.request.pretty_url:
        try:
            # ---------------------------
            # Décodage du corps de la requête JSON (envoyée par le client)
            # ---------------------------
            data = json.loads(flow.request.content)

            print("[MITM] Requête originale interceptée :", data)

            # ---------------------------
            # CORRUPTION du contenu : modification du message chiffré
            # ---------------------------
            # Injection de 64 octets à zéro (faux message), encodés en base64
            data["message"] = base64.b64encode(b"\x00" * 64).decode()

            # ---------------------------
            # Remplacement du corps de la requête avec les nouvelles données corrompues
            # ---------------------------
            flow.request.text = json.dumps(data)

            print("[MITM] Requête modifiée envoyée au serveur.")
        except Exception as e:
            print("[MITM] Erreur de modification :", e)
