"""
scanner.py
-----------
Logique de parcours de fichiers et de calcul de hachages SHA-256.

Ce module ne dépend que de la bibliothèque standard.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple


@dataclass
class ScanResult:
    """Représente le résultat d'analyse pour un fichier.

    Attributes:
        path: Chemin absolu du fichier.
        sha256: Empreinte SHA-256 du fichier.
        status: Résultat de l'analyse (ex: "clean", "malicious", "error").
        details: Message optionnel (ex: erreur ou nombre de détections).
    """

    path: str
    sha256: str
    status: str
    details: str = ""


def iter_files_from_paths(paths: Iterable[str]) -> Iterable[str]:
    """Itère sur tous les fichiers à partir d'une liste de chemins.

    - Si un chemin est un fichier, il est renvoyé tel quel.
    - Si un chemin est un dossier, tous les fichiers (récursivement) sont renvoyés.
    """

    for p in paths:
        if os.path.isfile(p):
            yield os.path.abspath(p)
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    full_path = os.path.join(root, name)
                    yield os.path.abspath(full_path)
        else:
            # Chemin invalide : on ignore simplement ici;
            # la couche supérieure pourra gérer ce cas si besoin.
            continue


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Calcule l'empreinte SHA-256 d'un fichier.

    Le fichier est lu en binaire et par morceaux (chunks) pour
    supporter les gros fichiers sans les charger en mémoire.
    """

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_paths(
    paths: Iterable[str],
    scan_function: Callable[[str], Tuple[str, str]],
    max_workers: int = 4,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> List[ScanResult]:
    """Effectue une analyse sur tous les fichiers issus de `paths`.

    Optimisation multithread :
      - le calcul de hash est effectué séquentiellement (I/O disque),
      - les appels à `scan_function` (généralement réseau / API) sont
        parallélisés à l'aide d'un ThreadPoolExecutor.

    `scan_function` est une fonction qui reçoit un hash SHA-256 et
    retourne un tuple `(status: str, details: str)`.

    `progress_callback` est une fonction optionnelle appelée avec (index, file_path)
    pour mettre à jour la progression en temps réel.
    """

    # Étape 1: parcours des fichiers et calcul des hashes
    hashed_files: List[Tuple[str, str]] = []
    results: List[ScanResult] = []

    file_index = 0
    for file_path in iter_files_from_paths(paths):
        file_index += 1
        if progress_callback:
            progress_callback(file_index, file_path)

        try:
            sha = compute_sha256(file_path)
        except (IOError, OSError) as exc:
            results.append(
                ScanResult(
                    path=file_path,
                    sha256="",
                    status="error",
                    details=f"Erreur de lecture: {exc}",
                )
            )
            continue

        hashed_files.append((file_path, sha))

    # Étape 2: appels API en parallèle
    def _worker(path_and_hash: Tuple[str, str]) -> ScanResult:
        file_path, sha = path_and_hash
        try:
            status, details = scan_function(sha)
        except Exception as exc:  # noqa: BLE001 - capture toute erreur d'API
            return ScanResult(
                path=file_path,
                sha256=sha,
                status="error",
                details=f"Erreur API: {exc}",
            )

        return ScanResult(
            path=file_path,
            sha256=sha,
            status=status,
            details=details,
        )

    if hashed_files:
        # On limite le nombre de threads pour rester raisonnable vis-à-vis de l'API.
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_item = {
                executor.submit(_worker, item): item for item in hashed_files
            }
            for future in as_completed(future_to_item):
                results.append(future.result())

    return results


