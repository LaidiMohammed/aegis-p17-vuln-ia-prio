# AEGIS — P17 — Analyse vulnérabilités + priorité (IA light)

[![Vercel](https://img.shields.io/badge/Vercel-aegis-p17--blue?logo=vercel)](https://aegis-p17-vuln-ia-prio.vercel.app)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)]

Analyse vulnérabilités + priorité (IA light) — PFE P13 style AEGIS (Master 1 Sécurité informatique).

## Infos rapides

| Élément | Valeur |
|---|---|
| **GitHub** | https://github.com/LaidiMohammed/aegis-p17-vuln-ia-prio |
| **Vercel** | https://aegis-p17-vuln-ia-prio.vercel.app |
| **Stacks** | nmap, NVD API, scikit-learn |
| **Type** | pen |
| **Ethique** | Labo local, anti-GPU, anti-cloud, stand-alone |

## Install

```bash
pip install -r requirements.txt
make install  # (venv)
```

## Smoke & tests (démo à la prof)

```bash
make smoke   # ou: scripts/run_smoke.sh
make test
```

## Fonctions à exécuter à la démo

Voir [`docs/ETHICS.md`](docs/ETHICS.md), [`docs/SPEC.md`](docs/SPEC.md).
