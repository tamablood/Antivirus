"""
virustotal.py
--------------
Communication simple avec l'API VirusTotal en utilisant uniquement
la bibliothèque standard (urllib + json).

Ce module travaille uniquement avec des empreintes SHA-256 (pas d'upload
de fichiers).
"""

from __future__ import annotations

import json
from typing import Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL


def _build_headers() -> dict:
    """Construit les en-têtes HTTP nécessaires pour VirusTotal."""

    return {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }


def _vt_get(url: str) -> Tuple[int, bytes]:
    """Effectue une requête GET vers VirusTotal et renvoie (status_code, body)."""

    req = Request(url, headers=_build_headers(), method="GET")
    try:
        with urlopen(req) as resp:
            return int(getattr(resp, "status", 200)), resp.read()
    except HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return int(e.code), body


def _parse_last_analysis_stats(data_bytes: bytes) -> dict:
    """Extrait `last_analysis_stats` depuis une réponse VT v3."""

    try:
        payload = json.loads(data_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Réponse API illisible ou invalide") from exc

    try:
        return payload["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError) as exc:
        raise KeyError("Format de réponse inattendu de VirusTotal") from exc


def query_hash_sha256(file_hash: str) -> Tuple[str, str]:
    """Interroge VirusTotal pour un hash SHA-256 donné.

    Retourne un tuple (status, details) :
      - status: "clean", "malicious" ou "unknown" (ou "error" en cas de problème réseau)
      - details: message humainement lisible (ex: "5 engines detected this file")
    """

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "VOTRE_CLE_API_ICI":
        # Clé non configurée : on signale une erreur contrôlée.
        return "error", "Clé API VirusTotal non configurée dans config.py"

    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
    try:
        status_code, data_bytes = _vt_get(url)
    except URLError as e:
        return "error", f"Erreur réseau: {e.reason}"

    # Exemple: 404 lorsque le hash est inconnu, ou 401 si la clé est invalide.
    if status_code == 404:
        return "unknown", "Hash inconnu de VirusTotal (0 détection connue)"
    if status_code == 401:
        return "error", "Erreur d'authentification API (clé invalide ?)"
    if status_code == 429:
        return "error", "Limite de requêtes VirusTotal atteinte (HTTP 429)"
    if status_code >= 400:
        return "error", f"Erreur HTTP {status_code}"

    # La structure pour VT v3 est de la forme:
    # {
    #   "data": {
    #     "attributes": {
    #       "last_analysis_stats": {
    #         "harmless": ...,
    #         "malicious": ...,
    #         "suspicious": ...,
    #         "undetected": ...,
    #         "timeout": ...
    #       }
    #     }
    #   }
    # }
    try:
        stats = _parse_last_analysis_stats(data_bytes)
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
    except (KeyError, TypeError, ValueError):
        return "error", "Format de réponse inattendu de VirusTotal"

    detections = malicious + suspicious
    if detections > 0:
        return "malicious", f"{detections} moteur(s) ont signalé ce fichier"
    return "clean", "Aucune détection signalée par VirusTotal"


def query_ip_reputation(ip_address: str) -> Tuple[str, str]:
    """Interroge VirusTotal pour la réputation d'une adresse IP.

    Règle de classification demandée :
    - si `malicious` > 0 => "malicious"
    - sinon => "clean"
    """

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "VOTRE_CLE_API_ICI":
        return "error", "Clé API VirusTotal non configurée dans config.py"

    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"
    try:
        status_code, data_bytes = _vt_get(url)
    except URLError as e:
        return "error", f"Erreur réseau: {e.reason}"

    if status_code == 401:
        return "error", "Erreur d'authentification API (clé invalide ?)"
    if status_code == 429:
        return "error", "Limite de requêtes VirusTotal atteinte (HTTP 429)"
    if status_code == 404:
        return "clean", "Aucun rapport malveillant connu (ressource inconnue de VirusTotal)"
    if status_code >= 400:
        return "error", f"Erreur HTTP {status_code}"

    try:
        stats = _parse_last_analysis_stats(data_bytes)
        malicious = int(stats.get("malicious", 0))
    except (KeyError, TypeError, ValueError):
        return "error", "Format de réponse inattendu de VirusTotal"

    if malicious > 0:
        return "malicious", f"{malicious} rapport(s) malveillant(s) détecté(s)"
    return "clean", "0 rapport malveillant détecté"


def query_domain_reputation(domain: str) -> Tuple[str, str]:
    """Interroge VirusTotal pour la réputation d'un nom de domaine.

    Règle de classification demandée :
    - si `malicious` > 0 => "malicious"
    - sinon => "clean"
    """

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "VOTRE_CLE_API_ICI":
        return "error", "Clé API VirusTotal non configurée dans config.py"

    url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
    try:
        status_code, data_bytes = _vt_get(url)
    except URLError as e:
        return "error", f"Erreur réseau: {e.reason}"

    if status_code == 401:
        return "error", "Erreur d'authentification API (clé invalide ?)"
    if status_code == 429:
        return "error", "Limite de requêtes VirusTotal atteinte (HTTP 429)"
    if status_code == 404:
        return "clean", "Aucun rapport malveillant connu (ressource inconnue de VirusTotal)"
    if status_code >= 400:
        return "error", f"Erreur HTTP {status_code}"

    try:
        stats = _parse_last_analysis_stats(data_bytes)
        malicious = int(stats.get("malicious", 0))
    except (KeyError, TypeError, ValueError):
        return "error", "Format de réponse inattendu de VirusTotal"

    if malicious > 0:
        return "malicious", f"{malicious} rapport(s) malveillant(s) détecté(s)"
    return "clean", "0 rapport malveillant détecté"


