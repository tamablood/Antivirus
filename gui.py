"""
Interface PyQt5 pour l'application de détection de malwares.

Remplace la précédente interface Tkinter par une fenêtre moderne,
plus interactive, avec barre de progression et résultats colorés.

Prérequis : `pip install PyQt5`
"""

from __future__ import annotations

import logging
import os
import re
from typing import List

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from scanner import ScanResult, iter_files_from_paths, scan_paths
from virustotal import query_domain_reputation, query_hash_sha256, query_ip_reputation


class ScanWorker(QThread):
    """Thread de scan pour ne pas bloquer l'interface PyQt."""

    progress = pyqtSignal(int, int, str)  # current, total, file_path
    result = pyqtSignal(object)  # ScanResult
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, paths: List[str]) -> None:
        super().__init__()
        self.paths = paths

    def run(self) -> None:
        try:
            files = list(iter_files_from_paths(self.paths))
            total = len(files)
            if total == 0:
                self.error.emit("Aucun fichier à analyser.")
                return

            def progress_cb(idx: int, file_path: str) -> None:
                self.progress.emit(idx, total, file_path)

            results = scan_paths(
                files,
                scan_function=query_hash_sha256,
                progress_callback=progress_cb,
            )

            for res in results:
                self.result.emit(res)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class ReputationWorker(QThread):
    """Thread de requête réputation (IP / domaine) via VirusTotal."""

    result = pyqtSignal(str, str, str)  # target, status, details
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target.strip()

    def run(self) -> None:
        try:
            target = self.target
            if not target:
                self.error.emit("Veuillez saisir une adresse IP ou un nom de domaine.")
                return

            # Détection simple: IPv4/IPv6 => IP, sinon domaine.
            looks_like_ip = bool(re.fullmatch(r"[0-9a-fA-F:.]+", target)) and (
                ":" in target or "." in target
            )
            if looks_like_ip:
                status, details = query_ip_reputation(target)
            else:
                cleaned = re.sub(r"^https?://", "", target, flags=re.IGNORECASE).strip("/")
                status, details = query_domain_reputation(cleaned)
                target = cleaned

            self.result.emit(target, status, details)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    """Fenêtre principale PyQt5."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("🛡️ Antivirus Scanner Pro - VirusTotal (PyQt)")
        self.resize(1100, 750)

        self.selected_paths: List[str] = []
        self.worker: ScanWorker | None = None
        self.rep_worker: ReputationWorker | None = None

        # Statistiques
        self.files_scanned = 0
        self.threats = 0
        self.clean = 0

        self._build_ui()
        self._apply_styles()

    # --- Construction UI ------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(18, 18, 18, 14)
        root.setSpacing(14)

        # --- Top header ---------------------------------------------------------------
        header_wrap = QWidget()
        header_layout = QVBoxLayout(header_wrap)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)

        header = QLabel("Antivirus Scanner Pro")
        header.setObjectName("Header")
        subheader = QLabel("VirusTotal • Analyse par hash SHA-256 • Réputation réseau")
        subheader.setObjectName("SubHeader")

        header_layout.addWidget(header)
        header_layout.addWidget(subheader)
        root.addWidget(header_wrap)

        # --- Main body: two-column dashboard -----------------------------------------
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        # Left column (controls) inside a scroll area for small screens
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.NoFrame)
        splitter.addWidget(left_scroll)

        left = QWidget()
        left_scroll.setWidget(left)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        # Card: file scanning actions
        card_scan = QFrame()
        card_scan.setObjectName("Card")
        card_scan_layout = QVBoxLayout(card_scan)
        card_scan_layout.setContentsMargins(14, 14, 14, 14)
        card_scan_layout.setSpacing(10)

        title_scan = QLabel("Analyse de fichiers")
        title_scan.setObjectName("SectionTitle")
        subtitle_scan = QLabel("Sélectionnez des fichiers / dossiers puis lancez l'analyse.")
        subtitle_scan.setObjectName("SectionHint")
        card_scan_layout.addWidget(title_scan)
        card_scan_layout.addWidget(subtitle_scan)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.btn_file = QPushButton("📄 Fichier(s)")
        self.btn_file.setObjectName("SecondaryButton")
        self.btn_file.clicked.connect(self.select_file)
        self.btn_folder = QPushButton("📁 Dossier")
        self.btn_folder.setObjectName("SecondaryButton")
        self.btn_folder.clicked.connect(self.select_folder)
        btn_row.addWidget(self.btn_file)
        btn_row.addWidget(self.btn_folder)
        card_scan_layout.addLayout(btn_row)

        btn_row2 = QHBoxLayout()
        btn_row2.setSpacing(10)
        self.btn_start = QPushButton("▶ Lancer l'analyse")
        self.btn_start.setObjectName("PrimaryButton")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_clear = QPushButton("✖ Vider")
        self.btn_clear.setObjectName("GhostButton")
        self.btn_clear.clicked.connect(self.clear_selection)
        btn_row2.addWidget(self.btn_start, 2)
        btn_row2.addWidget(self.btn_clear, 1)
        card_scan_layout.addLayout(btn_row2)

        # Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFormat("%p%")
        self.progress.setObjectName("Progress")
        self.lbl_current_file = QLabel("Prêt")
        self.lbl_current_file.setObjectName("Muted")
        card_scan_layout.addWidget(self.progress)
        card_scan_layout.addWidget(self.lbl_current_file)

        left_layout.addWidget(card_scan)

        # Card: selection list
        card_sel = QFrame()
        card_sel.setObjectName("Card")
        card_sel_layout = QVBoxLayout(card_sel)
        card_sel_layout.setContentsMargins(14, 14, 14, 14)
        card_sel_layout.setSpacing(10)
        title_sel = QLabel("Sélection")
        title_sel.setObjectName("SectionTitle")
        card_sel_layout.addWidget(title_sel)
        self.list_paths = QListWidget()
        self.list_paths.setObjectName("List")
        self.list_paths.setMinimumHeight(140)
        card_sel_layout.addWidget(self.list_paths)
        left_layout.addWidget(card_sel)

        # Card: reputation lookup
        card_rep = QFrame()
        card_rep.setObjectName("Card")
        card_rep_layout = QVBoxLayout(card_rep)
        card_rep_layout.setContentsMargins(14, 14, 14, 14)
        card_rep_layout.setSpacing(10)
        title_rep = QLabel("Réputation IP / Domaine")
        title_rep.setObjectName("SectionTitle")
        subtitle_rep = QLabel("Renseignez une IP ou un domaine pour une vérification de réputation (lookup).")
        subtitle_rep.setObjectName("SectionHint")
        card_rep_layout.addWidget(title_rep)
        card_rep_layout.addWidget(subtitle_rep)
        rep_row = QHBoxLayout()
        rep_row.setSpacing(10)
        self.rep_input = QLineEdit()
        self.rep_input.setObjectName("Input")
        self.rep_input.setPlaceholderText("Ex: 8.8.8.8 ou example.com")
        self.btn_rep_check = QPushButton("🔎 Vérifier")
        self.btn_rep_check.setObjectName("PrimaryButton")
        self.btn_rep_check.clicked.connect(self.check_reputation)
        rep_row.addWidget(self.rep_input, 2)
        rep_row.addWidget(self.btn_rep_check, 1)
        card_rep_layout.addLayout(rep_row)
        left_layout.addWidget(card_rep)

        left_layout.addItem(QSpacerItem(0, 10, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Right column (results & stats)
        right = QWidget()
        splitter.addWidget(right)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        # Stats as cards (unchanged logic, just restyled)
        stats_wrap = QWidget()
        stats_row = QHBoxLayout(stats_wrap)
        stats_row.setContentsMargins(0, 0, 0, 0)
        stats_row.setSpacing(10)

        self.lbl_scanned = QLabel("Fichiers scannés : 0")
        self.lbl_clean = QLabel("Propre : 0")
        self.lbl_threats = QLabel("Menaces : 0")
        for lbl in (self.lbl_scanned, self.lbl_clean, self.lbl_threats):
            lbl.setFrameShape(QFrame.NoFrame)
            lbl.setObjectName("StatCard")
            lbl.setMinimumHeight(54)
            lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            lbl.setContentsMargins(14, 0, 14, 0)
        stats_row.addWidget(self.lbl_scanned)
        stats_row.addWidget(self.lbl_clean)
        stats_row.addWidget(self.lbl_threats)
        right_layout.addWidget(stats_wrap)

        # Results panel
        results_card = QFrame()
        results_card.setObjectName("Card")
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(14, 14, 14, 14)
        results_layout.setSpacing(10)
        title_results = QLabel("Résultats")
        title_results.setObjectName("SectionTitle")
        hint_results = QLabel("Les résultats apparaissent ici en temps réel.")
        hint_results.setObjectName("SectionHint")
        results_layout.addWidget(title_results)
        results_layout.addWidget(hint_results)
        self.text_results = QTextEdit()
        self.text_results.setObjectName("Results")
        self.text_results.setReadOnly(True)
        results_layout.addWidget(self.text_results, 1)
        right_layout.addWidget(results_card, 1)

        # Column sizing
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([380, 720])

        # Status bar (unchanged behavior)
        self.status_label = QLabel("🟢 Système prêt")
        self.status_label.setObjectName("StatusPill")
        self.statusBar().addWidget(self.status_label)

    def _apply_styles(self) -> None:
        # Feuille de style simple pour moderniser l'interface
        self.setStyleSheet(
            """
            /* Base ---------------------------------------------------------------- */
            QWidget {
                background: #0b1020;
                color: #e5e7eb;
                font-family: "Segoe UI";
                font-size: 12px;
            }

            /* Header -------------------------------------------------------------- */
            QLabel#Header { font-size: 22px; font-weight: 800; color: #eaf2ff; }
            QLabel#SubHeader { color: #9aa8c1; font-size: 12px; }

            /* Cards --------------------------------------------------------------- */
            QFrame#Card {
                background: #0f172a;
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 12px;
            }
            QLabel#SectionTitle { font-size: 13px; font-weight: 700; color: #dbeafe; }
            QLabel#SectionHint { color: #93a4bf; }
            QLabel#Muted { color: #93a4bf; }

            /* Buttons ------------------------------------------------------------- */
            QPushButton {
                border-radius: 10px;
                padding: 10px 12px;
                border: 1px solid rgba(148, 163, 184, 0.22);
                background: rgba(30, 41, 59, 0.7);
            }
            QPushButton:hover { background: rgba(39, 52, 73, 0.85); }
            QPushButton:pressed { background: rgba(30, 41, 59, 1.0); }
            QPushButton:disabled { color: rgba(148, 163, 184, 0.55); background: rgba(30, 41, 59, 0.35); }

            QPushButton#PrimaryButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2563eb, stop:1 #3b82f6);
                border: 1px solid rgba(59, 130, 246, 0.65);
                font-weight: 700;
            }
            QPushButton#PrimaryButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1d4ed8, stop:1 #2563eb);
            }
            QPushButton#SecondaryButton { background: rgba(30, 41, 59, 0.75); }
            QPushButton#GhostButton { background: rgba(15, 23, 42, 0.35); }

            /* Inputs / Lists / Results ------------------------------------------- */
            QLineEdit#Input {
                background: #0b1220;
                border: 1px solid rgba(148, 163, 184, 0.22);
                border-radius: 10px;
                padding: 10px 12px;
                color: #e5e7eb;
            }
            QLineEdit#Input:focus { border: 1px solid rgba(59, 130, 246, 0.85); }

            QListWidget#List, QTextEdit#Results {
                background: #0b1220;
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 10px;
            }
            QTextEdit#Results { padding: 10px; }

            /* Stats --------------------------------------------------------------- */
            QLabel#StatCard {
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 12px;
                font-weight: 600;
                color: #e5e7eb;
            }

            /* Progress ------------------------------------------------------------ */
            QProgressBar#Progress {
                background: rgba(15, 23, 42, 0.35);
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 10px;
                text-align: center;
                height: 18px;
            }
            QProgressBar#Progress::chunk {
                background-color: #3b82f6;
                border-radius: 10px;
            }

            /* Splitter ------------------------------------------------------------ */
            QSplitter::handle {
                background: rgba(148, 163, 184, 0.10);
            }
            QSplitter::handle:hover {
                background: rgba(59, 130, 246, 0.30);
            }

            /* Status pill --------------------------------------------------------- */
            QLabel#StatusPill {
                padding: 6px 10px;
                border-radius: 999px;
                background: rgba(15, 23, 42, 0.55);
                border: 1px solid rgba(148, 163, 184, 0.18);
                color: #dbeafe;
            }
            """
        )

    # --- Actions ------------------------------------------------------------------------
    def select_file(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choisir des fichiers")
        if files:
            self.selected_paths.extend(files)
            self._refresh_selection()

    def select_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choisir un dossier")
        if folder:
            self.selected_paths.append(folder)
            self._refresh_selection()

    def clear_selection(self) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Scan en cours", "Veuillez attendre la fin du scan.")
            return
        self.selected_paths.clear()
        self._refresh_selection()
        self.status_label.setText("🟢 Sélection vidée")

    def start_scan(self) -> None:
        if not self.selected_paths:
            QMessageBox.warning(self, "Aucun fichier", "Sélectionnez au moins un fichier ou dossier.")
            return
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Scan en cours", "Une analyse est déjà en cours.")
            return
        if self.rep_worker and self.rep_worker.isRunning():
            QMessageBox.information(self, "Requête en cours", "Une requête de réputation est déjà en cours.")
            return

        # Reset UI
        self.files_scanned = 0
        self.threats = 0
        self.clean = 0
        self.lbl_scanned.setText("Fichiers scannés : 0")
        self.lbl_clean.setText("Propre : 0")
        self.lbl_threats.setText("Menaces : 0")
        self.progress.setValue(0)
        self.text_results.clear()
        self.status_label.setText("🟡 Analyse en cours...")
        self.lbl_current_file.setText("Préparation...")
        self._set_buttons_enabled(False)

        self.worker = ScanWorker(self.selected_paths)
        self.worker.progress.connect(self._on_progress)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def check_reputation(self) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Scan en cours", "Veuillez attendre la fin du scan.")
            return
        if self.rep_worker and self.rep_worker.isRunning():
            QMessageBox.information(self, "Requête en cours", "Une requête de réputation est déjà en cours.")
            return

        target = self.rep_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Champ vide", "Saisissez une adresse IP ou un nom de domaine.")
            return

        self.status_label.setText("🟡 Vérification réputation en cours...")
        self.btn_rep_check.setEnabled(False)

        self.rep_worker = ReputationWorker(target)
        self.rep_worker.result.connect(self._on_reputation_result)
        self.rep_worker.error.connect(self._on_error)
        self.rep_worker.finished.connect(self._on_reputation_finished)
        self.rep_worker.start()

    # --- Slots -------------------------------------------------------------------------
    def _on_progress(self, current: int, total: int, file_path: str) -> None:
        percent = int((current / total) * 100)
        self.progress.setValue(percent)
        base = os.path.basename(file_path) or file_path
        self.lbl_current_file.setText(f"Analyse: {base}")

    def _on_result(self, res: ScanResult) -> None:
        # Mise à jour statistiques
        self.files_scanned += 1
        if res.status == "malicious":
            self.threats += 1
        elif res.status == "clean" or res.status == "unknown":
            # "unknown" signifie qu'il n'y a pas de détection connue, donc on le compte comme propre
            self.clean += 1

        self.lbl_scanned.setText(f"Fichiers scannés : {self.files_scanned}")
        self.lbl_clean.setText(f"Propre : {self.clean}")
        self.lbl_threats.setText(f"Menaces : {self.threats}")

        # Couleur par statut
        color = {
            "clean": "#22c55e",
            "malicious": "#f97316",
            "error": "#f43f5e",
            "unknown": "#eab308",
        }.get(res.status, "#e5e7eb")

        user_status = {
            "clean": "Propre",
            "malicious": "Malveillant",
            "unknown": "Inconnu",
            "error": "Erreur",
        }.get(res.status, res.status)

        line = f"{res.path} | {user_status} | {res.details}"
        self.text_results.append(f'<span style="color:{color}">{line}</span>')
        self.text_results.moveCursor(QTextCursor.End)

        # Logging
        logging.info("FILE_SCAN | %s | %s | %s | %s", res.path, res.sha256, res.status, res.details)

    def _on_reputation_result(self, target: str, status: str, details: str) -> None:
        rep_label = "Malicious" if status == "malicious" else "Clean"
        color = "#f97316" if rep_label == "Malicious" else "#22c55e"

        line = f"REPUTATION | {target} | {rep_label}"
        if details:
            line += f" | {details}"

        self.text_results.append(f'<span style="color:{color}">{line}</span>')
        self.text_results.moveCursor(QTextCursor.End)

        # Le `Date` est fourni par le format logging (asctime).
        logging.info("REPUTATION | %s | %s", target, rep_label)
        self.status_label.setText(f"🟢 Réputation: {rep_label}")

    def _on_error(self, message: str) -> None:
        QMessageBox.warning(self, "Erreur", message)
        self.status_label.setText("🔴 Erreur: " + message)

    def _on_finished(self) -> None:
        self.status_label.setText("🟢 Analyse terminée")
        self.lbl_current_file.setText("Terminé")
        self.progress.setValue(100)
        self._set_buttons_enabled(True)

    def _on_reputation_finished(self) -> None:
        self.btn_rep_check.setEnabled(True)

    # --- Helpers -----------------------------------------------------------------------
    def _refresh_selection(self) -> None:
        self.list_paths.clear()
        for p in self.selected_paths:
            item = QListWidgetItem(p)
            self.list_paths.addItem(item)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        for b in (self.btn_file, self.btn_folder, self.btn_start, self.btn_clear):
            b.setEnabled(enabled)


def run_app() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()

