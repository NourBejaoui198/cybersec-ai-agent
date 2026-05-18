# 🔐 CyberSec AI Agent

Un Agent IA de premier niveau spécialisé en cybersécurité, capable de réaliser des audits simples (mots de passe, scans réseau basiques) et de faire de la vulgarisation pédagogique en français.

L'application utilise l'architecture **ReAct (Reasoning + Acting)** pour lier la puissance de planification du modèle **Llama 3.3 (70B)** sur Groq Cloud avec la rigueur de scripts d'exécution locaux en Python.

---

## 🚀 Fonctionnalités

* **Analyse de Mot de Passe :** Vérification de la robustesse par expressions régulières (Regex) et génération instantanée de l'empreinte cryptographique MD5.
* **Audit Réseau Basique :** Résolution DNS, test d'ouverture des ports TCP (80, 443) via sockets système, et analyse des en-têtes HTTP.
* **Module Éducatif :** Explications claires, exemples concrets d'attaques (SQLi, Phishing) et plans de remédiation en français.
* **Interface Intuitive :** Interface web dynamique et interactive développée avec Gradio.

---

## 🛠️ Installation et Lancement

### 1. Cloner le projet
```bash
git clone [https://github.com/ton-pseudo/cybersec-ai-agent.git](https://github.com/ton-pseudo/cybersec-ai-agent.git)
cd cybersec-ai-agent