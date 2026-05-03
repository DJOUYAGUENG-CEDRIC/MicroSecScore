import yaml
from neo4j import GraphDatabase

# ── Configuration Neo4j ──────────────────────────────────────────
NEO4J_URI      = "neo4j://127.0.0.1:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "microsec123"

# ── Scores CVE simulés par nom de service ────────────────────────
# Ces valeurs simulent les résultats qu'un scan Trivy produirait
# sur les images officielles de Sock Shop
# CRIT=Critical, HIGH=High, MED=Medium, LOW=Low
CVE_SCORES_PAR_SERVICE = {
    "front-end":    {"CRIT": 2, "HIGH": 5, "MED": 8,  "LOW": 12},
    "catalogue":    {"CRIT": 1, "HIGH": 3, "MED": 6,  "LOW": 9},
    "catalogue-db": {"CRIT": 3, "HIGH": 4, "MED": 5,  "LOW": 7},
    "orders":       {"CRIT": 1, "HIGH": 2, "MED": 4,  "LOW": 6},
    "orders-db":    {"CRIT": 4, "HIGH": 6, "MED": 10, "LOW": 15},
    "cart":         {"CRIT": 0, "HIGH": 2, "MED": 3,  "LOW": 5},
    "cart-db":      {"CRIT": 0, "HIGH": 1, "MED": 2,  "LOW": 4},
    "user":         {"CRIT": 2, "HIGH": 3, "MED": 5,  "LOW": 8},
    "user-db":      {"CRIT": 3, "HIGH": 5, "MED": 7,  "LOW": 10},
    "payment":      {"CRIT": 5, "HIGH": 7, "MED": 9,  "LOW": 11},
    "shipping":     {"CRIT": 1, "HIGH": 2, "MED": 3,  "LOW": 6},
    "rabbitmq":     {"CRIT": 2, "HIGH": 3, "MED": 6,  "LOW": 9},
    "edge-router":  {"CRIT": 1, "HIGH": 2, "MED": 4,  "LOW": 7},
    "queue-master": {"CRIT": 1, "HIGH": 2, "MED": 3,  "LOW": 5},
    "session-db":   {"CRIT": 0, "HIGH": 1, "MED": 2,  "LOW": 3},
}

def calculer_score_cve(image, service_nom):
    """
    Calcule le score CVE d'un service (0 = très vulnérable, 100 = sain).
    Formule : Score = 100 - (CRIT×8 + HIGH×4 + MED×2)
    Chaque CVE CRITICAL enlève 8 points, HIGH 4 points, MED 2 points.
    """
    if service_nom in CVE_SCORES_PAR_SERVICE:
        v = CVE_SCORES_PAR_SERVICE[service_nom]
    else:
        print(f"  [AVERTISSEMENT] Service '{service_nom}' inconnu — score CVE = 50")
        return 50

    penalite = v["CRIT"] * 8 + v["HIGH"] * 4 + v["MED"] * 2
    score    = max(0, 100 - penalite)
    return score
    """
    Calcule le score CVE d'un service (0 = très vulnérable, 100 = sain).
    Recherche par nom de service en priorité, puis valeur par défaut.

    Formule : Score = 100 - (CRIT×40 + HIGH×20 + MED×10) / max × 100
    """
    if service_nom in CVE_SCORES_PAR_SERVICE:
        v = CVE_SCORES_PAR_SERVICE[service_nom]
    else:
        # Service inconnu : score prudent par défaut
        print(f"  [AVERTISSEMENT] Service '{service_nom}' inconnu, score CVE = 50")
        return 50

    total        = v["CRIT"] * 40 + v["HIGH"] * 20 + v["MED"] * 10
    max_possible = max(total, 100)
    score        = max(0, 100 - int((total / max_possible) * 100))
    return score


def calculer_criticite(service_nom, depends_on_count, depended_by_count):
    """
    Calcule la criticité d'un service selon sa centralité dans le graphe.
    Plus un service a de connexions entrantes et sortantes, plus il est critique.
    Echelle : 1 (peu critique) à 5 (très critique).

    Règle métier additionnelle : les bases de données et services de paiement
    reçoivent un bonus de criticité car ils contiennent des données sensibles.
    """
    total_connexions = depends_on_count + depended_by_count

    # Bonus pour les services sensibles par nature
    services_sensibles = ["payment", "user-db", "orders-db",
                          "catalogue-db", "cart-db", "session-db"]
    bonus = 1 if service_nom in services_sensibles else 0

    if total_connexions >= 6:
        criticite = 5
    elif total_connexions >= 4:
        criticite = 4
    elif total_connexions >= 2:
        criticite = 3
    elif total_connexions >= 1:
        criticite = 2
    else:
        criticite = 1

    return min(5, criticite + bonus)


def parser_docker_compose(fichier):
    """
    Parse le fichier docker-compose.yml et extrait la topologie complète.

    Retourne un dictionnaire de services avec leurs attributs de sécurité.
    """
    with open(fichier, 'r', encoding='utf-8') as f:
        compose = yaml.safe_load(f)

    services = {}

    for nom, config in compose.get('services', {}).items():
        if config is None:
            config = {}

        # Extraction des dépendances (depends_on peut être liste ou dict)
        depends_on_raw = config.get('depends_on', [])
        if isinstance(depends_on_raw, dict):
            depends_on = list(depends_on_raw.keys())
        elif isinstance(depends_on_raw, list):
            depends_on = depends_on_raw
        else:
            depends_on = []

        # Extraction des réseaux
        networks_raw = config.get('networks', {})
        if isinstance(networks_raw, dict):
            networks = list(networks_raw.keys())
        elif isinstance(networks_raw, list):
            networks = networks_raw
        else:
            networks = []

        # Détermination si le service expose des ports vers l'extérieur
        ports        = config.get('ports', [])
        expose_port  = len(ports) > 0

        # Détection des accès privilégiés
        privileged   = config.get('privileged', False)

        # Détection des secrets exposés dans les variables d'environnement
        env_vars     = config.get('environment', {})
        if isinstance(env_vars, list):
            env_str  = ' '.join(str(e) for e in env_vars).upper()
        else:
            env_str  = ' '.join(str(v) for v in env_vars.values()).upper() if env_vars else ''

        expose_secret = any(mot in env_str for mot in
                           ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'PASSWD'])

        services[nom] = {
            'nom':          nom,
            'image':        config.get('image', 'unknown'),
            'ports':        ports,
            'networks':     networks,
            'depends_on':   depends_on,
            'privileged':   privileged,
            'expose_port':  expose_port,
            'expose_secret': expose_secret,
        }

        # Calcul du score CVE par nom de service
        services[nom]['score_cve'] = calculer_score_cve(
            services[nom]['image'], nom)

    # ── Calcul de la criticité (centralité dans le graphe) ────────
    # Compter combien de services dépendent de chaque service (in-degree)
    depended_by = {nom: 0 for nom in services}
    for nom, config in services.items():
        for dep in config['depends_on']:
            if dep in depended_by:
                depended_by[dep] += 1

    for nom in services:
        dep_count    = len(services[nom]['depends_on'])
        dep_by_count = depended_by[nom]
        services[nom]['criticite']   = calculer_criticite(
            nom, dep_count, dep_by_count)
        services[nom]['depended_by'] = dep_by_count

    return services


def construire_g0_dans_neo4j(services, driver):
    """
    Insère tous les noeuds et arêtes du graphe G0 dans Neo4j.

    Structure du graphe :
      - Noeuds  : Service (microservice) + Outside (attaquant externe)
      - Arêtes  : DEPENDS_ON (communication autorisée)
                  PEUT_ATTAQUER (point d'entrée pour attaquant)
    """
    with driver.session() as session:

        # ── Nettoyage de la base ──────────────────────────────────
        session.run("MATCH (n) DETACH DELETE n")
        print("  Base Neo4j vidée.")

        # ── Noeud spécial : Outside (attaquant externe) ───────────
        session.run("""
            CREATE (o:Service {
                nom:         'Outside',
                type:        'external',
                score_cve:   0,
                criticite:   0,
                description: 'Attaquant externe — point d entree du systeme'
            })
        """)

        # ── Création des noeuds microservices ─────────────────────
        for nom, s in services.items():
            session.run("""
                CREATE (n:Service {
                    nom:           $nom,
                    image:         $image,
                    score_cve:     $score_cve,
                    criticite:     $criticite,
                    expose_port:   $expose_port,
                    expose_secret: $expose_secret,
                    privileged:    $privileged,
                    type:          'microservice'
                })
            """,
            nom           = nom,
            image         = s['image'],
            score_cve     = s['score_cve'],
            criticite     = s['criticite'],
            expose_port   = s['expose_port'],
            expose_secret = s['expose_secret'],
            privileged    = s['privileged'])

        print(f"  {len(services)} services insérés dans Neo4j.")

        # ── Création des arêtes DEPENDS_ON ────────────────────────
        nb_aretes = 0
        for nom, s in services.items():
            for dep in s['depends_on']:
                if dep in services:
                    session.run("""
                        MATCH (a:Service {nom: $source})
                        MATCH (b:Service {nom: $cible})
                        CREATE (a)-[:DEPENDS_ON {
                            type:    'communication',
                            autorise: true
                        }]->(b)
                    """, source=nom, cible=dep)
                    nb_aretes += 1

        # ── Connexion Outside → services exposés ──────────────────
        for nom, s in services.items():
            if s['expose_port']:
                session.run("""
                    MATCH (o:Service {nom: 'Outside'})
                    MATCH (t:Service {nom: $cible})
                    CREATE (o)-[:PEUT_ATTAQUER {
                        type:    'point_entree',
                        autorise: false
                    }]->(t)
                """, cible=nom)

        print(f"  {nb_aretes} arêtes DEPENDS_ON créées.")
        print(f"  Points d'entrée externes connectés à 'Outside'.")


def calculer_score_global(services):
    """
    Calcule le score de sécurité global du système.

    Formule : S_global = Σ(criticité(s) × Score_CVE(s)) / Σ criticité(s)
    Un service plus critique pèse plus lourd dans le score final.
    """
    total_poids  = sum(s['criticite'] for s in services.values())
    if total_poids == 0:
        return 0
    score_global = sum(
        s['criticite'] * s['score_cve'] for s in services.values()
    ) / total_poids
    return round(score_global, 1)


def afficher_statistiques(services):
    """
    Affiche un résumé complet du graphe G0 construit,
    avec les scores CVE, la criticité et le niveau de sécurité global.
    """
    print()
    print("=" * 62)
    print("   GRAPHE G0 — STATISTIQUES MICROSECSCOPE")
    print("=" * 62)

    nb_aretes = sum(len(s['depends_on']) for s in services.values())
    print(f"  Nombre de services (noeuds) : {len(services)}")
    print(f"  Nombre de dépendances (arêtes) : {nb_aretes}")

    # ── Tableau des scores ────────────────────────────────────────
    print()
    print(f"  {'Service':<16} {'Score CVE':>10} {'Criticité':>10}  "
          f"{'CVE':>5}  {'Visualisation'}")
    print("  " + "-" * 58)

    # Tri par score CVE croissant (les plus vulnérables en premier)
    services_tries = sorted(
        services.items(),
        key=lambda x: x[1]['score_cve']
    )

    for nom, s in services_tries:
        score      = s['score_cve']
        criticite  = s['criticite']
        v          = CVE_SCORES_PAR_SERVICE.get(nom, {})
        crit_count = v.get("CRIT", 0)

        # Barre visuelle du score (10 segments)
        nb_pleins  = score // 10
        barre      = "█" * nb_pleins + "░" * (10 - nb_pleins)

        # Indicateur de danger
        if score < 30:
            danger = "⚠ DANGER"
        elif score < 60:
            danger = "~ Moyen"
        else:
            danger = "✓ OK"

        print(f"  {nom:<16} {score:>6}/100  criticité={criticite}   "
              f"CVE-C={crit_count}  {barre}  {danger}")

    # ── Score global ──────────────────────────────────────────────
    score_global = calculer_score_global(services)

    print()
    print("  " + "─" * 58)
    print(f"  Score Global Système : {score_global}/100")

    if score_global >= 80:
        niveau   = "SAIN        — Monitoring normal"
        symbole  = "✓"
    elif score_global >= 50:
        niveau   = "DÉGRADÉ     — Alerte + surveillance renforcée"
        symbole  = "~"
    else:
        niveau   = "CRITIQUE    — Remédiation automatique immédiate"
        symbole  = "⚠"

    print(f"  Niveau de sécurité   : {symbole} {niveau}")
    print("=" * 62)

    # ── Services les plus dangereux ───────────────────────────────
    print()
    print("  TOP 3 — Services les plus vulnérables :")
    top3 = sorted(services.items(), key=lambda x: x[1]['score_cve'])[:3]
    for i, (nom, s) in enumerate(top3, 1):
        print(f"    {i}. {nom:<16} score={s['score_cve']}/100  "
              f"criticité={s['criticite']}")

    return score_global


def afficher_requetes_neo4j():
    """Affiche les requêtes Cypher utiles pour explorer G0."""
    print()
    print("=" * 62)
    print("  REQUÊTES CYPHER UTILES — Neo4j Browser")
    print("=" * 62)
    print()
    print("  1. Voir tout le graphe G0 :")
    print("     MATCH (n)-[r]->(m) RETURN n, r, m")
    print()
    print("  2. Voir les services les plus vulnérables (score < 30) :")
    print("     MATCH (n:Service) WHERE n.score_cve < 30")
    print("     RETURN n.nom, n.score_cve, n.criticite")
    print("     ORDER BY n.score_cve ASC")
    print()
    print("  3. Voir les chemins d'attaque depuis Outside :")
    print("     MATCH p=(o:Service {nom:'Outside'})-[*]->(t:Service)")
    print("     RETURN p LIMIT 20")
    print()
    print("  4. Voir les services exposant des ports :")
    print("     MATCH (n:Service {expose_port: true})")
    print("     RETURN n.nom, n.score_cve, n.criticite")
    print()
    print("  5. Score global pondéré (calcul Cypher) :")
    print("     MATCH (n:Service) WHERE n.type='microservice'")
    print("     RETURN sum(n.criticite * n.score_cve) / sum(n.criticite)")
    print("     AS score_global")
    print("=" * 62)


def main():
    print()
    print("=" * 62)
    print("  MicroSecScore — Construction du Graphe G0")
    print("  Phase 1 : Analyse statique de l'architecture")
    print("=" * 62)
    print()

    # ── 1. Parser le docker-compose.yml ──────────────────────────
    print("[1/4] Parsing du docker-compose.yml...")
    try:
        services = parser_docker_compose('docker-compose.yml')
        print(f"      {len(services)} services détectés.")
    except FileNotFoundError:
        print("ERREUR : fichier docker-compose.yml introuvable.")
        print("Vérifiez qu'il est dans le même dossier que ce script.")
        return
    except Exception as e:
        print(f"ERREUR lors du parsing : {e}")
        return

    # ── 2. Connexion Neo4j ────────────────────────────────────────
    print()
    print("[2/4] Connexion à Neo4j...")
    try:
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )
        # Test de connexion
        with driver.session() as session:
            session.run("RETURN 1")
        print("      Connexion réussie.")
    except Exception as e:
        print(f"ERREUR de connexion Neo4j : {e}")
        print("Vérifiez que votre instance Neo4j est bien démarrée.")
        return

    # ── 3. Construire G0 dans Neo4j ───────────────────────────────
    print()
    print("[3/4] Construction du graphe G0 dans Neo4j...")
    try:
        construire_g0_dans_neo4j(services, driver)
        print("      G0 construit avec succès.")
    except Exception as e:
        print(f"ERREUR lors de la construction du graphe : {e}")
        driver.close()
        return

    # ── 4. Afficher les statistiques ──────────────────────────────
    print()
    print("[4/4] Calcul des scores de sécurité...")
    score_global = afficher_statistiques(services)

    # ── Requêtes utiles ───────────────────────────────────────────
    afficher_requetes_neo4j()

    driver.close()

    print()
    print("  G0 prêt. Ouvre Neo4j Browser et tape :")
    print("  MATCH (n)-[r]->(m) RETURN n, r, m")
    print()


if __name__ == "__main__":
    main()