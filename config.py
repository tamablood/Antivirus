"""
Configuration du projet de détection de malwares.

Ce module centralise les paramètres tels que la clé API VirusTotal
et l'URL de base du service.

IMPORTANT :
------------
Pour que l'application fonctionne réellement avec VirusTotal, vous devez
obtenir une clé API gratuite (ou payante) sur votre compte VirusTotal
et la renseigner dans `VIRUSTOTAL_API_KEY` ci-dessous.
"""

# Remplacez la valeur ci-dessous par votre clé réelle VirusTotal.
# Exemple: VIRUSTOTAL_API_KEY = "0123456789abcdef...."
VIRUSTOTAL_API_KEY: str = "8f7e91dfbb3cf7a2f1dc377800ea21b9499e1ad2fcdb3410b0a9633ba558c291"

# URL de base de l'API VirusTotal (v3)
VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

# Fichier de logs où seront enregistrés les résultats des analyses
LOG_FILE: str = "logs.txt"



