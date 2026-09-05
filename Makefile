PYTHON ?= $(shell command -v python3.13 || command -v python3)
VENV   := .venv
BIN    := $(VENV)/bin

.PHONY: setup test clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet \
		-e ./autodecode -e ./fscan -e ./rsatool -e ./offsetfind \
		-e ./hashcrack -e ./stego -e ./revshell \
		-e ./netcat-recon -e ./binwalk-extract -e ./z3-solver \
		-e .

test:
	$(BIN)/python -m unittest discover -s autodecode/tests
	$(BIN)/python -m unittest discover -s fscan/tests
	$(BIN)/python -m unittest discover -s rsatool/tests
	$(BIN)/python -m unittest discover -s offsetfind/tests
	$(BIN)/python -m unittest discover -s hashcrack/tests
	$(BIN)/python -m unittest discover -s stego/tests
	$(BIN)/python -m unittest discover -s revshell/tests
	$(BIN)/python -m unittest discover -s netcat-recon/tests
	$(BIN)/python -m unittest discover -s binwalk-extract/tests
	$(BIN)/python -m unittest discover -s z3-solver/tests

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name "*.egg-info" -type d -prune -exec rm -rf {} +
