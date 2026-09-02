# CTF Helper Tools Suite
#
# `offsetfind` butuh pwntools yang baru tersedia wheel untuk Python 3.13,
# jadi setup memakai python3.13 kalau ada.

PYTHON ?= $(shell command -v python3.13 || command -v python3)
VENV   := .venv
BIN    := $(VENV)/bin

.PHONY: setup test clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet \
		-e ./autodecode -e ./fscan -e ./rsatool -e ./offsetfind -e .

test:
	$(BIN)/python -m unittest discover -s autodecode/tests
	$(BIN)/python -m unittest discover -s fscan/tests
	$(BIN)/python -m unittest discover -s rsatool/tests
	$(BIN)/python -m unittest discover -s offsetfind/tests

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name "*.egg-info" -type d -prune -exec rm -rf {} +