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

from PyQt5 import uic
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
from behavior_analyzer import BehaviorMonitor
import time


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
            self.result.emit(target, status, details)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class BehaviorWorker(QThread):
    """Thread de surveillance comportementale."""

    event_detected = pyqtSignal(str)       # message log
    alert_triggered = pyqtSignal(str, str) # level, message
    error = pyqtSignal(str)

    def __init__(self, folder: str) -> None:
        super().__init__()
        self.monitor = BehaviorMonitor(folder)
        self._stopped = False

    def run(self) -> None:
        try:
            self.monitor.start()
            while not self._stopped:
                # Polling loop
                current = self.monitor.snapshot()
                diffs = self.monitor.check_diff(current)
                for d in diffs:
                    self.event_detected.emit(d)

                alerts = self.monitor.analyze_patterns()
                for a in alerts:
                    self.alert_triggered.emit(a.level, a.message)

                time.sleep(1.0)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.monitor.stop()

    def stop(self) -> None:
        self._stopped = True


class MainWindow(QMainWindow):
    """Fenêtre principale PyQt5."""

    def __init__(self) -> None:
        super().__init__()
        self.worker: ScanWorker | None = None
        self.rep_worker: ReputationWorker | None = None
        self.behavior_worker: BehaviorWorker | None = None

        self.current_mode: str | None = None  # "file" | "folder" | None
        
        # Stats counters
        self.stats = {"created": 0, "modified": 0, "deleted": 0}

        self._load_ui()
        self._connect_signals()
        self._apply_qss()
        self._set_active_nav(self.btn_home)

    # --- UI / Styles -------------------------------------------------------------------
    def _load_ui(self) -> None:
        ui_path = os.path.join(os.path.dirname(__file__), "ui", "mainwindow.ui")
        uic.loadUi(ui_path, self)
        self.setWindowTitle("🛡️ Antivirus Scanner Pro - VirusTotal (PyQt)")

        # defensive: ensure these text areas are read-only
        for w in (self.txt_file_log, self.txt_file_report, self.txt_folder_log, self.txt_folder_report, self.txt_ip_log, self.txt_ip_report):
            w.setReadOnly(True)

    def _apply_qss(self) -> None:
        qss_path = os.path.join(os.path.dirname(__file__), "ui", "style.qss")
        try:
            with open(qss_path, "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except OSError as exc:
            # don't crash the app just because the stylesheet isn't readable
            logging.warning("Unable to load QSS (%s): %s", qss_path, exc)

    def _connect_signals(self) -> None:
        # Sidebar navigation
        self.btn_home.clicked.connect(lambda: self._navigate(self.page_home, self.btn_home))
        self.btn_file.clicked.connect(lambda: self._navigate(self.page_file, self.btn_file))
        self.btn_folder.clicked.connect(lambda: self._navigate(self.page_folder, self.btn_folder))
        self.btn_ip.clicked.connect(lambda: self._navigate(self.page_ip, self.btn_ip))
        self.btn_behavior.clicked.connect(lambda: self._navigate(self.page_behavior, self.btn_behavior))

        # Actions
        self.btn_select_file.clicked.connect(self.select_file)
        self.btn_select_folder.clicked.connect(self.select_folder)
        self.btn_scan_file.clicked.connect(self.start_file_scan)
        self.btn_scan_folder.clicked.connect(self.start_folder_scan)
        self.btn_scan_ip.clicked.connect(self.check_reputation)
        
        # Behavior Actions
        self.btn_select_behavior_folder.clicked.connect(self.select_behavior_folder)
        self.btn_start_behavior.clicked.connect(self.start_behavior_monitoring)
        self.btn_stop_behavior.clicked.connect(self.stop_behavior_monitoring)

    def _set_active_nav(self, active_btn: QPushButton) -> None:
        for b in (self.btn_home, self.btn_file, self.btn_folder, self.btn_ip, self.btn_behavior):
            b.setProperty("active", b is active_btn)
            b.style().unpolish(b)
            b.style().polish(b)

    def _navigate(self, page: QWidget, active_btn: QPushButton) -> None:
        self.stacked_pages.setCurrentWidget(page)
        self._set_active_nav(active_btn)

    # --- Actions ------------------------------------------------------------------------
    def select_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Choisir un fichier")
        if file_path:
            self.input_file_path.setText(file_path)
            self._append_log("file", f"Fichier sélectionné: {file_path}")

    def select_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choisir un dossier")
        if folder:
            self.input_folder_path.setText(folder)
            self._append_log("folder", f"Dossier sélectionné: {folder}")

    def start_file_scan(self) -> None:
        file_path = self.input_file_path.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Aucun fichier", "Veuillez choisir un fichier.")
            return
        self._start_scan([file_path], mode="file")

    def start_folder_scan(self) -> None:
        folder = self.input_folder_path.text().strip()
        if not folder:
            QMessageBox.warning(self, "Aucun dossier", "Veuillez choisir un dossier.")
            return
        self._start_scan([folder], mode="folder")

    def _start_scan(self, paths: List[str], mode: str) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Scan en cours", "Une analyse est déjà en cours.")
            return
        if self.rep_worker and self.rep_worker.isRunning():
            QMessageBox.information(self, "Requête en cours", "Une requête de réputation est déjà en cours.")
            return

        self.current_mode = mode
        self._clear_outputs(mode)
        self._append_log(mode, "Démarrage du scan…")
        self._set_scan_buttons_enabled(False)

        self.worker = ScanWorker(paths)
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

        target = self.input_ip.text().strip()
        if not target:
            QMessageBox.warning(self, "Champ vide", "Saisissez une adresse IP ou un nom de domaine.")
            return

        self._clear_outputs("ip")
        self._append_log("ip", f"Vérification réputation: {target}")
        self.btn_scan_ip.setEnabled(False)

        self.rep_worker = ReputationWorker(target)
        self.rep_worker.result.connect(self._on_reputation_result)
        self.rep_worker.error.connect(self._on_error)
        self.rep_worker.finished.connect(self._on_reputation_finished)
        self.rep_worker.start()

    # --- Slots -------------------------------------------------------------------------
    def _on_progress(self, current: int, total: int, file_path: str) -> None:
        base = os.path.basename(file_path) or file_path
        mode = self.current_mode or "file"
        self._append_log(mode, f"[{current}/{total}] Analyse: {base}")

    def _on_result(self, res: ScanResult) -> None:
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
        mode = self.current_mode or "file"
        self._append_report(mode, f'<span style="color:{color}">{line}</span>')

        # Logging
        logging.info("FILE_SCAN | %s | %s | %s | %s", res.path, res.sha256, res.status, res.details)

    def _on_reputation_result(self, target: str, status: str, details: str) -> None:
        rep_label = "Malicious" if status == "malicious" else "Clean"
        color = "#f97316" if rep_label == "Malicious" else "#22c55e"

        line = f"REPUTATION | {target} | {rep_label}"
        if details:
            line += f" | {details}"

        self._append_report("ip", f'<span style="color:{color}">{line}</span>')

        # Le `Date` est fourni par le format logging (asctime).
        logging.info("REPUTATION | %s | %s", target, rep_label)
        self._append_log("ip", f"Réputation: {rep_label}")

    def _on_error(self, message: str) -> None:
        QMessageBox.warning(self, "Erreur", message)
        # Log the error in the most relevant panel
        mode = self.current_mode or "ip"
        self._append_log(mode, "ERREUR: " + message)

    def _on_finished(self) -> None:
        mode = self.current_mode or "file"
        self._append_log(mode, "Scan terminé.")
        self._set_scan_buttons_enabled(True)

    def _on_reputation_finished(self) -> None:
        self.btn_scan_ip.setEnabled(True)

    # --- Behavior Analyzer -------------------------------------------------------------
    def select_behavior_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choisir un dossier à surveiller")
        if folder:
            self.input_behavior_path.setText(folder)
            self.txt_behavior_log.append(f"Dossier cible: {folder}")

    def start_behavior_monitoring(self) -> None:
        if self.behavior_worker and self.behavior_worker.isRunning():
            return

        folder = self.input_behavior_path.text().strip()
        if not folder:
            QMessageBox.warning(self, "Aucun dossier", "Veuillez choisir un dossier.")
            return

        self.txt_behavior_log.clear()
        self.list_behavior_alerts.clear()
        self.txt_behavior_log.append("Démarrage de la surveillance...")
        
        # Reset Stats
        self.stats = {"created": 0, "modified": 0, "deleted": 0}
        self._update_stats_ui()
        self.lbl_behavior_status.setText("🟢 En cours")
        
        # UI Toggle
        self.btn_start_behavior.setEnabled(False)
        self.btn_stop_behavior.setEnabled(True)
        self.input_behavior_path.setEnabled(False)
        self.btn_select_behavior_folder.setEnabled(False)

        self.behavior_worker = BehaviorWorker(folder)
        self.behavior_worker.event_detected.connect(self._on_behavior_event)
        self.behavior_worker.alert_triggered.connect(self._on_behavior_alert)
        self.behavior_worker.error.connect(self._on_behavior_error)
        self.behavior_worker.start()

    def stop_behavior_monitoring(self) -> None:
        if self.behavior_worker:
            self.behavior_worker.stop()
            self.behavior_worker.wait()
            self.behavior_worker = None
        
        self.txt_behavior_log.append("Surveillance arrêtée.")
        self.lbl_behavior_status.setText("🔴 Arrêté")
        
        self.btn_start_behavior.setEnabled(True)
        self.btn_stop_behavior.setEnabled(False)
        self.input_behavior_path.setEnabled(True)
        self.btn_select_behavior_folder.setEnabled(True)

    def _on_behavior_event(self, message: str) -> None:
        self.txt_behavior_log.append(message)
        self.txt_behavior_log.moveCursor(QTextCursor.End)
        
        # Update stats
        if "[CREATION]" in message:
            self.stats["created"] += 1
        elif "[SUPPRESSION]" in message:
            self.stats["deleted"] += 1
        elif "[MODIFICATION]" in message:
            self.stats["modified"] += 1
        self._update_stats_ui()

    def _on_behavior_alert(self, level: str, message: str) -> None:
        # Add to list widget with color
        item = QListWidgetItem(f"[{level.upper()}] {message}")
        if level == "critical":
            item.setForeground(Qt.white)
            item.setBackground(Qt.red)
        else:
            item.setForeground(Qt.black)
            item.setBackground(Qt.yellow)
        
        self.list_behavior_alerts.addItem(item)
        self.list_behavior_alerts.scrollToBottom()
        
        # Also log
        logging.warning("BEHAVIOR_ALERT: %s - %s", level, message)

    def _on_behavior_error(self, message: str) -> None:
        self.txt_behavior_log.append(f"ERREUR: {message}")
        # Stop everything if error
        self.stop_behavior_monitoring()

    def _update_stats_ui(self) -> None:
        self.lbl_stat_created.setText(f"Créés: {self.stats['created']}")
        self.lbl_stat_deleted.setText(f"Supprimés: {self.stats['deleted']}")
        self.lbl_stat_modified.setText(f"Modifiés: {self.stats['modified']}")

    # --- Helpers -----------------------------------------------------------------------
    def _text_widgets_for_mode(self, mode: str) -> tuple[QTextEdit, QTextEdit]:
        if mode == "folder":
            return self.txt_folder_log, self.txt_folder_report
        if mode == "ip":
            return self.txt_ip_log, self.txt_ip_report
        return self.txt_file_log, self.txt_file_report

    def _append_log(self, mode: str, message: str) -> None:
        log_w, _ = self._text_widgets_for_mode(mode)
        log_w.append(message)
        log_w.moveCursor(QTextCursor.End)

    def _append_report(self, mode: str, html_line: str) -> None:
        _, report_w = self._text_widgets_for_mode(mode)
        report_w.append(html_line)
        report_w.moveCursor(QTextCursor.End)

    def _clear_outputs(self, mode: str) -> None:
        log_w, report_w = self._text_widgets_for_mode(mode)
        log_w.clear()
        report_w.clear()

    def _set_scan_buttons_enabled(self, enabled: bool) -> None:
        for b in (self.btn_select_file, self.btn_select_folder, self.btn_scan_file, self.btn_scan_folder, self.btn_scan_ip):
            b.setEnabled(enabled)


def run_app() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()

