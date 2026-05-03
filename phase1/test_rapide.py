# Test rapide — vérifie chaque étape de main() manuellement
import sys
print("Etape 0 : script démarré", flush=True)

from utils.logger import get_logger, log_separateur, log_resultat
print("Etape 1 : logger importé", flush=True)

logger = get_logger("test_rapide")
logger.info("Logger fonctionne")
print("Etape 2 : logger initialisé", flush=True)

from parsers import parser_environnement
print("Etape 3 : parsers importé", flush=True)

donnees = parser_environnement()
print(f"Etape 4 : parsing terminé — {len(donnees['services']) if donnees else 0} services", flush=True)

if donnees is None:
    print("ERREUR : parser_environnement() a retourné None", flush=True)
    sys.exit(1)

from graph.builder import construire_G0
G0 = construire_G0(donnees)
print(f"Etape 5 : G0 construit — {G0.number_of_nodes()} noeuds", flush=True)

from graph.scorer import calculer_criticites, calculer_score_global
G0 = calculer_criticites(G0)
print("Etape 6 : criticités calculées", flush=True)

from cve.cve_scorer import simuler_scores_cve
G0 = simuler_scores_cve(G0)
print("Etape 7 : scores CVE simulés", flush=True)

resultat = calculer_score_global(G0)
print(f"Etape 8 : score global = {resultat['score_global']}/100 → {resultat['niveau']}", flush=True)

from graph.exporter import exporter_graphe, exporter_scores_csv
chemin_json = exporter_graphe(G0)
chemin_csv  = exporter_scores_csv(G0)
print(f"Etape 9 : fichiers exportés", flush=True)
print(f"  JSON : {chemin_json}", flush=True)
print(f"  CSV  : {chemin_csv}", flush=True)

print("\n" + "="*50, flush=True)
print(f"RÉSULTAT FINAL : {resultat['score_global']}/100 → {resultat['niveau']}", flush=True)
print("="*50, flush=True)

print("\nServices (du plus vulnérable au plus sain) :", flush=True)
for d in resultat.get('details', []):
    print(f"  {d['service']:<20} score={d['score_cve']}/100  criticité={d['criticite']}", flush=True)