"""
main.py
--------
Point d'entrée principal de l'application (interface PyQt5).
"""

from __future__ import annotations

import logging

import config
from gui import run_app


def configure_logging() -> None:
    """Configure le module logging pour écrire dans le fichier `logs.txt`."""

    logging.basicConfig(
        filename=config.LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def main() -> None:
    configure_logging()
    run_app()


if __name__ == "__main__":
    main()


