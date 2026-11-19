# ETHICS — P17 — Analyse vulnérabilités + priorité (IA light) (AEGIS)

Engagements éthiques du projet — stand-alone, labo local, GPU refused, anti-cloud.

- **Cible** : [AEGIS Analyse vulnérabilités + priorité (IA light)](https://github.com/LaidiMohammed/aegis-p17-vuln-ia-prio)
- **Périmètre** : [AEGIS Analyse vulnérabilités + priorité (IA light)](https://aegis-p17-vuln-ia-prio.vercel.app) — smoke + fonctions CLI.
- **GPU refused** : implementation uniquement CPU/pure Python.
- **Données locales** : sources acceptées : labo local (localhost, Juice Shop, DVWA, etc.).
- **Smoke au prof** : cmds à exécuter — voir README/scripts/run_smoke.sh.
- **Smoke clé de validation** : voir `smoke()` dans `src/vuln-ia-prio_main.py` — doit retourner `{"ok": true, ...}`.
- **Site statique Vercel** : disponible pour la démo statique (smoke uniquement).

See SPEC.md (avec use cases + tableaux attendus).
