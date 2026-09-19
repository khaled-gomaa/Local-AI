#!/usr/bin/env bash
set -u
echo "== Python =="
python3 --version || true
echo "== Java =="
java -version 2>&1 || true
echo "== Ollama =="
ollama --version 2>&1 || true
echo "== Ollama models =="
ollama list 2>&1 || true
echo "== Local API =="
curl -sS http://127.0.0.1:5000/health || true
