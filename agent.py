import os
import re
import json
import socket
import hashlib
from openai import OpenAI

# ── Charger le fichier .env ──────────────────────────────────
with open(".env") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ.get("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"),
)
MODEL = os.environ.get("MODEL_NAME", "llama-3.3-70b-versatile")


# ════════════════════════════════════════════════════════════
# OUTIL 1 : Analyse de mot de passe
# ════════════════════════════════════════════════════════════
def check_password(password: str) -> dict:
    score = 0
    problems = []

    if len(password) >= 8:   score += 1
    else: problems.append("Trop court (min 8 caractères)")

    if len(password) >= 12:  score += 1

    if re.search(r"[A-Z]", password): score += 1
    else: problems.append("Pas de majuscule")

    if re.search(r"[a-z]", password): score += 1
    else: problems.append("Pas de minuscule")

    if re.search(r"\d", password):    score += 1
    else: problems.append("Pas de chiffre")

    if re.search(r"[!@#$%^&*]", password): score += 1
    else: problems.append("Pas de caractère spécial (!@#...)")

    mots_courants = ["password", "123456", "azerty", "admin", "qwerty"]
    if any(m in password.lower() for m in mots_courants):
        score -= 2
        problems.append("Contient un mot de passe trop courant !")

    niveaux = {0: "🔴 TRÈS FAIBLE", 1: "🔴 TRÈS FAIBLE", 2: "🟠 FAIBLE",
               3: "🟡 MOYEN", 4: "🟡 MOYEN", 5: "🟢 FORT", 6: "✅ TRÈS FORT"}
    niveau = niveaux.get(max(0, score), "✅ TRÈS FORT")

    return {
        "score": f"{max(0,score)}/6",
        "niveau": niveau,
        "problemes": problems if problems else ["Aucun problème détecté ✅"],
        "hash_md5": hashlib.md5(password.encode()).hexdigest(),
    }


# ════════════════════════════════════════════════════════════
# OUTIL 2 : Scan d'une cible (URL ou IP)
# ════════════════════════════════════════════════════════════
def scan_cible(cible: str) -> dict:
    host = cible.replace("https://", "").replace("http://", "").split("/")[0]

    # Résolution DNS
    try:
        ip = socket.gethostbyname(host)
        dns = f"✅ {host} → {ip}"
    except:
        return {"erreur": f"Impossible de résoudre {host}"}

    # Scan de ports
    ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
             3306: "MySQL", 8080: "HTTP-Alt"}
    ports_ouverts = []
    for port, nom in ports.items():
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            ports_ouverts.append(f"{port}/{nom}")
        s.close()

    # Headers HTTP
    try:
        import urllib.request
        url = cible if cible.startswith("http") else f"http://{cible}"
        resp = urllib.request.urlopen(url, timeout=3)
        headers = dict(resp.headers)
        headers_securite = {
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Anti-clickjacking",
            "Content-Security-Policy": "Anti-XSS",
        }
        manquants = [f"{h} ({desc})"
                     for h, desc in headers_securite.items()
                     if h not in headers]
    except:
        manquants = ["Impossible d'analyser les headers"]

    risque = "🔴 ÉLEVÉ" if len(manquants) >= 2 else "🟢 FAIBLE"

    return {
        "dns": dns,
        "ports_ouverts": ports_ouverts or ["Aucun port ouvert détecté"],
        "headers_manquants": manquants or ["Tous les headers sont présents ✅"],
        "niveau_risque": risque,
    }


# ════════════════════════════════════════════════════════════
# OUTIL 3 : Explication d'une attaque cyber
# ════════════════════════════════════════════════════════════
def expliquer_attaque(attaque: str) -> dict:
    base = {
        "sql injection": {
            "description": "Injection de code SQL malveillant dans une requête via un champ non filtré.",
            "exemple": "' OR '1'='1' -- dans un champ login",
            "impact": "Vol de données, bypass d'authentification",
            "prevention": ["Requêtes préparées (parameterized queries)", "Valider toutes les entrées"],
        },
        "xss": {
            "description": "Injection de scripts malveillants dans une page web vue par d'autres utilisateurs.",
            "exemple": "<script>alert(document.cookie)</script>",
            "impact": "Vol de cookies, redirection malveillante",
            "prevention": ["Échapper les sorties HTML", "Content Security Policy (CSP)"],
        },
        "phishing": {
            "description": "Imitation d'une entité de confiance pour voler des identifiants.",
            "exemple": "Email imitant ta banque avec un faux lien de connexion",
            "impact": "Vol de credentials, accès non autorisé",
            "prevention": ["Vérifier l'URL avant de cliquer", "Activer le MFA"],
        },
        "ddos": {
            "description": "Saturation d'un serveur avec des millions de requêtes simultanées.",
            "exemple": "Botnet de 100 000 machines qui inondent un site",
            "impact": "Indisponibilité du service",
            "prevention": ["CDN avec protection DDoS (Cloudflare)", "Rate limiting"],
        },
        "brute force": {
            "description": "Essai systématique de tous les mots de passe possibles.",
            "exemple": "Tester admin/admin, admin/123456, admin/password...",
            "impact": "Accès non autorisé à des comptes",
            "prevention": ["Limiter les tentatives de connexion", "MFA obligatoire"],
        },
        "ransomware": {
            "description": "Logiciel qui chiffre tes fichiers et réclame une rançon.",
            "exemple": "WannaCry (2017) : 200 000 systèmes infectés dans 150 pays",
            "impact": "Perte de données, arrêt d'activité",
            "prevention": ["Sauvegardes régulières hors-ligne", "Mises à jour de sécurité"],
        },
    }

    for cle, data in base.items():
        if cle in attaque.lower():
            return {"attaque": cle, **data}

    return {"message": f"'{attaque}' non trouvé dans la base locale. L'agent va répondre avec ses connaissances."}


# ════════════════════════════════════════════════════════════
# Définition des tools pour l'API
# ════════════════════════════════════════════════════════════
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_password",
            "description": "Analyse la robustesse d'un mot de passe.",
            "parameters": {
                "type": "object",
                "properties": {
                    "password": {"type": "string", "description": "Le mot de passe à analyser"}
                },
                "required": ["password"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_cible",
            "description": "Scanne une URL ou IP : ports ouverts, headers HTTP, niveau de risque.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cible": {"type": "string", "description": "URL ou IP à analyser"}
                },
                "required": ["cible"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "expliquer_attaque",
            "description": "Explique une attaque cyber : SQLi, XSS, phishing, DDoS, brute force, ransomware.",
            "parameters": {
                "type": "object",
                "properties": {
                    "attaque": {"type": "string", "description": "Nom de l'attaque à expliquer"}
                },
                "required": ["attaque"]
            }
        }
    }
]

TOOL_MAP = {
    "check_password": check_password,
    "scan_cible": scan_cible,
    "expliquer_attaque": expliquer_attaque,
}

SYSTEM = """Tu es CyberSec Agent, un expert en cybersécurité.
Tu aides à analyser des mots de passe, scanner des sites, et expliquer des attaques.
Utilise les outils disponibles quand c'est pertinent.
Réponds toujours en français, de façon claire et pédagogique.
Usage éducatif et défensif uniquement."""


# ════════════════════════════════════════════════════════════
# Boucle principale de l'agent (raisonnement multi-étapes)
# ════════════════════════════════════════════════════════════
def run_agent(message: str, historique: list) -> str:
    messages = [{"role": "system", "content": SYSTEM}]
    messages += historique
    messages.append({"role": "user", "content": message})

    # Étape 1 : le LLM décide s'il utilise un outil
    reponse = client.chat.completions.create(
        model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto", max_tokens=1000
    )
    msg = reponse.choices[0].message

    # Étape 2 : exécution des outils si nécessaire
    while msg.tool_calls:
        messages.append(msg)
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)
            resultat = TOOL_MAP[tc.function.name](**args)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(resultat, ensure_ascii=False)
            })
        # Étape 3 : réponse finale du LLM avec les résultats
        reponse = client.chat.completions.create(
            model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto", max_tokens=1000
        )
        msg = reponse.choices[0].message

    return msg.content or "Désolé, je n'ai pas pu répondre."
