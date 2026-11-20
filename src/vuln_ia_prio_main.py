"""Module principal — P17 Analyse vulnérabilités + priorité (IA light) — AEGIS.

Fonctions :
  - analyze_vulnerability(cve_id, description) -> dict : analyse d'une vulnérabilité
  - prioritize_vulnerabilities(vulns) -> dict : priorisation IA light
  - generate_remediation(vuln) -> list[str] : recommandations de correction
  - main(argv) -> int : CLI

Éthique : analyse locale uniquement, pas de dépendance GPU, pas d'API distante.
Méthode : heuristiques basées sur CVSS lite + facteurs d'exploitation.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from typing import Any, Dict, List, Optional

# Facteurs de priorisation IA light
PRIORITY_FACTORS = {
    "cvss_base": 0.4,      # 40% du score depuis CVSS de base
    "exploit_available": 0.3,  # 30% si exploit publique disponible
    "asset_criticality": 0.2,  # 20% criticité de l'actif touché
    "recent_activity": 0.1,    # 10% activité récente exploitable
}

# Niveaux de criticité des actifs
ASSET_CRITICALITY = {
    "serveur-web": 1.0,
    "serveur-bdd": 1.0,
    "poste-travail": 0.5,
    "poste-admin": 0.8,
    "routeur": 0.9,
    "application": 0.7,
    "non-critique": 0.3,
}


def analyze_vulnerability(cve_id: str, description: str, asset_type: str = "non-critique") -> Dict[str, Any]:
    """Effectue une analyse légère d'une vulnérabilité CVE."""
    # Extraction approximée du CVSS si présent dans la description
    cvss_match = re.search(r"CVSS[:\s]+([0-9]\.[0-9])", description, re.IGNORECASE)
    cvss_base = float(cvss_match.group(1)) if cvss_match else 5.0  # Valeur par défaut moyenne
    
    # Calculer le score de priorisation pondéré
    exploit_factor = random.random()  # Simulation: exploit disponible ou non
    asset_criticality = ASSET_CRITICALITY.get(asset_type, ASSET_CRITICALITY["non-critique"])
    
    priority_score = (
        PRIORITY_FACTORS["cvss_base"] * cvss_base +
        PRIORITY_FACTORS["exploit_available"] * exploit_factor +
        PRIORITY_FACTORS["asset_criticality"] * asset_criticality +
        PRIORITY_FACTORS["recent_activity"] * random.random()
    )
    
    # Déterminer le niveau de priorité
    if priority_score >= 7.0:
        priority = "critique"
    elif priority_score >= 5.0:
        priority = "élevée"
    elif priority_score >= 3.0:
        priority = "moyenne"
    else:
        priority = "faible"
    
    # Générer des recommandations de correction
    remediation: List[str] = []
    if cvss_base >= 9.0:
        remediation.append("Mise à jour urgente - vulnérabilité critique")
    if cvss_base >= 7.0:
        remediation.append("Planifier la mise à jour dans les 30 jours")
    if cvss_base >= 4.0:
        remediation.append("Appliquer les correctifs disponibles")
    if not remediation:
        remediation.append("Surveiller et réévaluer dans prochain cycle de patch")
    
    # Facteurs d'exploitabilité
    exploit_indicators: List[str] = []
    if cvss_base >= 9.0:
        exploit_indicators.append("Exploit publique probablement disponible")
    if "remote" in description.lower():
        exploit_indicators.append("Vulnérabilité distante")
    if "authentication" in description.lower() or "login" in description.lower():
        exploit_indicators.append("Contourne authentification")
    
    return {
        "cve_id": cve_id,
        "cvss_base": round(cvss_base, 1),
        "priority_score": round(priority_score, 2),
        "priority_level": priority,
        "asset_type": asset_type,
        "remediation": remediation,
        "exploit_indicators": exploit_indicators,
        "description": description[:100] + "..." if len(description) > 100 else description,
    }


def prioritize_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Trie et priorise une liste de vulnérabilités par score de priorisation."""
    # Analyser chacune et ajouter le score
    analyzed: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        analyzed_vuln = analyze_vulnerability(
            vuln.get("cve_id", "UNKNOWN"),
            vuln.get("description", ""),
            vuln.get("asset_type", "non-critique")
        )
        analyzed.append(analyzed_vuln)
    
    # Trier par score de priorité (décroissant)
    sorted_vulns = sorted(analyzed, key=lambda x: x["priority_score"], reverse=True)
    
    # Calculer la répartition des priorités
    priority_counts: Dict[str, int] = {"critique": 0, "élevée": 0, "moyenne": 0, "faible": 0}
    for v in sorted_vulns:
        priority_counts[v["priority_level"]] += 1
    
    return {
        "total_analyzed": len(sorted_vulns),
        "sorted_vulnerabilities": sorted_vulns,
        "priority_distribution": priority_counts,
        "highest_priority": sorted_vulns[0]["priority_level"] if sorted_vulns else "aucun",
        "recommendation_order": [v["cve_id"] for v in sorted_vulns[:5]],  # Top 5 prioritaires
    }


def generate_remediation(vuln: Dict[str, Any]) -> List[str]:
    """Génère des recommandations de correction pour une vulnérabilité."""
    recs: List[str] = []
    priority = vuln.get("priority_level", "faible")
    cvss = vuln.get("cvss_base", 0)
    
    if priority in ("critique", "élevée"):
        recs.append("Mise à jour de sécurité immédiate")
        recs.append("Isolement du système affecté le cas échéant")
    
    if cvss >= 9.0:
        recs.append("Application du correctif dans les 24-48 heures")
    
    if cvss >= 7.0:
        recs.append("Tester le correctif dans un environnement de staging d'abord")
    
    recs.append(" Revue de sécurité après application du correctif")
    recs.append(" Mise à jour de la documentation de sécurité")
    
    return recs


def main(argv: list[str] | None = None) -> int:
    import warnings
    warnings.filterwarnings("ignore")

    ap = argparse.ArgumentParser(prog="vuln_ia_prio",
                                 description="AEGIS - P17 - Analyse vulnérabilités + priorité (IA light)")
    ap.add_argument("--cve", default=None, help="ID CVE à analyser")
    ap.add_argument("--asset", default="non-critique", help="Type d'actif (serveur-web, poste-travail, etc.)")
    ap.add_argument("--json", action="store_true", help="Sortir en JSON")
    ap.add_argument("--save-json", default=None, help="Écrire le résultat JSON")
    ap.add_argument("--pdf", default="outputs/rapport-p17.pdf", help="Chemin du PDF")
    ap.add_argument("--list", action="store_true", help="Lister les priorités types")
    args = ap.parse_args(argv)

    try:
        if args.list:
            # Afficher les facteurs de priorisation
            out = {
                "project": "P17",
                "priority_factors": PRIORITY_FACTORS,
                "asset_criticality": ASSET_CRITICALITY,
            }
        elif args.cve:
            # Analyser une CVE unique
            # Description mock si non fournie
            description = args.cve  # Utiliser l'ID comme description de base
            out = analyze_vulnerability(args.cve, description, args.asset)
            out["project"] = "P17"
        else:
            # Analyse de priorisation exemple
            example_vulns = [
                {"cve_id": "CVE-2021-44228", "description": "Log4Shell remote code execution in Log4j", "asset_type": "serveur-web"},
                {"cve_id": "CVE-2022-22965", "description": "Authentication bypass in PHP server", "asset_type": "application"},
                {"cve_id": "CVE-2021-34527", "description": "Windows Print Spooler elevation of privilege", "asset_type": "serveur-web"},
            ]
            out = prioritize_vulnerabilities(example_vulns)
            out["project"] = "P17"
    except Exception as exc:  # noqa: BLE001
        print(f"[ERREUR] {exc}")
        return 1

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        if args.list:
            print(f"[SUMMARY] P17 - Facteurs de priorisation IA light")
            print(f"  Factors: {PRIORITY_FACTORS}")
            print(f"  Asset criticality: {ASSET_CRITICALITY}")
        elif args.cve:
            r = out.get("priority_level", "faible")
            cvss = out.get("cvss_base", "?")
            print(f"[SUMMARY] P17 - Analyse vulnérabilité {out.get('cve_id', '?')}")
            print(f"  CVSS de base: {cvss}")
            print(f"  Niveau de priorité: {r}")
            print(f"  Recommandations: {'; '.join(out.get('remediation', []))}")
        else:
            ta = out.get("priority_distribution", {})
            print(f"[SUMMARY] P17 - Prioritisation de vulnérabilités")
            print(f"  Total analysé: {out.get('total_analyzed', 0)}")
            print(f"  Distribution: critique={ta.get('critique', 0)}, élevée={ta.get('élevée', 0)}, "
                  f"moyenne={ta.get('moyenne', 0)}, faible={ta.get('faible', 0)}")
            print(f"  Hautes priorités: {', '.join(out.get('recommendation_order', []))}")

    if args.save_json:
        p = Path(args.save_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] écriture : {p}")

    if args.save_json and args.pdf:
        from src.generate_report import main as gen_main
        rc = gen_main(["--json", args.save_json, "--pdf", args.pdf])
        if rc != 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())