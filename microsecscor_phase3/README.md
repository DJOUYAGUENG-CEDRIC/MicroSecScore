# MicroSecScore — Phase 3 : Moteur CEP

## Prérequis
- Python 3.13
- Kafka sur localhost:9092 (démarrer via phase2/kafka/docker-compose-kafka.yml)
- Neo4j sur olt://localhost:7687 (optionnel — G0Cache fonctionne sans Neo4j)

## Installation
```bash
pip install -r requirements.txt
```

## Lancement
```bash
python -X utf8 cep_engine.py
```

## Tests (sans Kafka ni Neo4j)
```bash
python -X utf8 tests/test_rules.py
```
Résultat attendu : **28+ tests réussis, 0 échoués**

## Topics Kafka

| Rôle      | Topic              | Produit par    |
|-----------|--------------------|----------------|
| Source P1-P4 | logs-applicatifs  | docker_log_collector |
| Source P5    | lertes-securite  | falco_generator      |
| Source P6-P7 | metriques-systeme | prometheus_collector |
| Sortie CEP   | lertes-cep       | cep_engine (Phase 4) |

## 7 Règles de détection

| Règle | Technique MITRE | Sévérité | Déclenchement                         |
|-------|----------------|----------|---------------------------------------|
| P1    | T1046 Scan     | MEDIUM   | > 50 ports distincts en 2s            |
| P2    | T1110 BruteForce | HIGH   | > 100 échecs en 30s par paire         |
| P3    | T1550 Lateral  | CRITICAL | Appel inter-service absent de G0      |
| P4    | T1078 Compromise | CRITICAL | Auth success après ≥ 5 échecs en 120s |
| P5    | T1611 Escape   | CRITICAL | Alerte Falco avec mot-clé évasion     |
| P6    | T1041 Exfiltration | CRITICAL/HIGH | Net_out > baseline × 5          |
| P7    | T1499 DoS      | HIGH     | CPU ≥ 90% ET erreurs ≥ 10 sur 30s    |

---
*DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang*
