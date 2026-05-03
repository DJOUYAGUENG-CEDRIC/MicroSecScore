# Fichier de diagnostic — MicroSecScore Phase 1
import traceback
import sys

tests = [
    ("config.settings",        "from config.settings import NEO4J_URI, DOCKER_COMPOSE_PATH"),
    ("utils.logger",           "from utils.logger import get_logger"),
    ("parsers.detector",       "from parsers.detector import detecter_environnement"),
    ("parsers.docker_parser",  "from parsers.docker_parser import parser_docker_compose"),
    ("graph.builder",          "from graph.builder import construire_G0"),
    ("graph.scorer",           "from graph.scorer import calculer_criticites"),
    ("graph.exporter",         "from graph.exporter import exporter_graphe"),
    ("cve.cve_scorer",         "from cve.cve_scorer import simuler_scores_cve"),
    ("neo4j_db.connector",     "from neo4j_db.connector import tester_connexion"),
    ("neo4j_db.sync",          "from neo4j_db.sync import synchroniser_G0"),
    ("visualizer",             "from visualizer import visualiser_G0"),
    ("parsers.__init__",       "from parsers import parser_environnement"),
    ("phase1_topology",        "import phase1_topology"),
]

print("=" * 60)
print("DIAGNOSTIC MicroSecScore — Phase 1")
print("=" * 60)

erreurs = []
for nom, commande in tests:
    try:
        exec(commande)
        print(f"  OK      {nom}")
    except Exception as e:
        print(f"  ERREUR  {nom}")
        print(f"          {type(e).__name__}: {e}")
        erreurs.append((nom, str(e)))

print("=" * 60)
if erreurs:
    print(f"\n{len(erreurs)} erreur(s) trouvée(s) :")
    for nom, msg in erreurs:
        print(f"  - {nom} : {msg}")
else:
    print("\nTous les imports fonctionnent — prêt à lancer !")

print("\nVersion Python :", sys.version)

# Vérification dossiers critiques
import os
print("\nVérification des dossiers :")
dossiers = [
    "../data/input",
    "../data/output",
    "../logs",
    "../data/input/docker-compose.yml"
]
for d in dossiers:
    existe = os.path.exists(d)
    print(f"  {'OK' if existe else 'MANQUANT'}  {d}")