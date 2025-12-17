"""
behavior_analyzer.py
--------------------
Module d'analyse comportementale.
Surveille un dossier pour détecter des activités suspectes (création/suppression/modification massive).
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

@dataclass
class FileState:
    """Snapshot de l'état d'un fichier (pour détection modif)."""
    mtime: float
    size: int

@dataclass
class BehaviorAlert:
    """Alerte générée par l'analyseur."""
    level: str  # "warning", "critical"
    message: str
    timestamp: float = field(default_factory=time.time)

class BehaviorMonitor:
    """
    Surveille un répertoire (et sous-répertoires) par polling périodique.
    Détecte les créations, modifications et suppressions.
    Analyse la fréquence de ces événements pour lever des alertes.
    """

    def __init__(self, root_path: str, interval: float = 1.0) -> None:
        self.root_path = os.path.abspath(root_path)
        self.interval = interval
        self.running = False
        
        # État précédent : path -> FileState
        self._previous_state: Dict[str, FileState] = {}
        
        # Historique des événements pour l'analyse heuristique
        # Liste de timestamps
        self._creations: deque[float] = deque()
        self._deletions: deque[float] = deque()
        self._modifications: deque[float] = deque()

        # Configuration des seuils (ex: 5 events en 10 sec)
        self.time_window = 10.0
        self.threshold_create = 5
        self.threshold_delete = 5
        self.threshold_modify = 10  # modifs peuvent être plus fréquentes légitimement

    def snapshot(self) -> Dict[str, FileState]:
        """Parcourt récursivement le dossier et retourne l'état actuel."""
        state = {}
        try:
            for root, _, files in os.walk(self.root_path):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        st = os.stat(path)
                        state[path] = FileState(st.st_mtime, st.st_size)
                    except (OSError, ValueError):
                        # Fichier disparu entre temps ou inaccessible
                        continue
        except OSError:
            pass  # Dossier racine peut-être supprimé ou inaccessible
        return state

    def check_diff(self, current_state: Dict[str, FileState]) -> List[str]:
        """
        Compare l'état actuel avec le précédent.
        Retourne une liste de descriptions d'événements.
        Met à jour les compteurs pour l'heuristique.
        """
        events = []
        now = time.time()

        old_paths = set(self._previous_state.keys())
        new_paths = set(current_state.keys())

        # Détections
        created = new_paths - old_paths
        deleted = old_paths - new_paths
        # Intersection pour voir les modifs
        common = old_paths & new_paths

        # Traitement Créations
        for p in created:
            events.append(f"[CREATION] {p}")
            self._creations.append(now)

        # Traitement Suppressions
        for p in deleted:
            events.append(f"[SUPPRESSION] {p}")
            self._deletions.append(now)

        # Traitement Modifications
        for p in common:
            old_s = self._previous_state[p]
            new_s = current_state[p]
            if new_s.mtime != old_s.mtime or new_s.size != old_s.size:
                events.append(f"[MODIFICATION] {p}")
                self._modifications.append(now)

        self._previous_state = current_state
        return events

    def analyze_patterns(self) -> List[BehaviorAlert]:
        """Vérifie si les seuils sont dépassés."""
        alerts = []
        now = time.time()
        
        # Nettoyage des vieux événements (hors fenêtre)
        self._clean_deque(self._creations, now)
        self._clean_deque(self._deletions, now)
        self._clean_deque(self._modifications, now)

        # Vérification des seuils
        if len(self._creations) >= self.threshold_create:
            alerts.append(BehaviorAlert(
                "warning", 
                f"Activité suspecte: {len(self._creations)} fichiers créés en < {self.time_window}s."
            ))
            # On vide pour ne pas spammer l'alerte à chaque tick si ça continue
            self._creations.clear()

        if len(self._deletions) >= self.threshold_delete:
            alerts.append(BehaviorAlert(
                "critical", 
                f"ALERTE RANSOMWARE POSSIBL: {len(self._deletions)} fichiers supprimés en < {self.time_window}s."
            ))
            self._deletions.clear()
            
        if len(self._modifications) >= self.threshold_modify:
            alerts.append(BehaviorAlert(
                "warning", 
                f"Modifications intensives: {len(self._modifications)} fichiers modifiés en < {self.time_window}s."
            ))
            self._modifications.clear()

        return alerts

    def _clean_deque(self, d: deque[float], now: float) -> None:
        while d and (now - d[0] > self.time_window):
            d.popleft()

    def start(self) -> None:
        """Initialise l'état de référence."""
        self._previous_state = self.snapshot()
        self.running = True

    def stop(self) -> None:
        self.running = False
