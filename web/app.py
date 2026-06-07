"""
app.py — Interface web MicroSecScore
=====================================
Permet d'uploader un docker-compose.yml ou des manifestes Kubernetes
et lance le pipeline Phase 1 pour générer le graphe G0 et les scores CVE.

Usage :
    pip install flask
    python web/app.py

Puis ouvrir : http://localhost:5000

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)

app = Flask(__name__)
app.secret_key = "microsecstore_dev_key_change_in_prod"

# ─────────────────────────────────────────────────────────────────────────────
# État global Phase 2 (processus de surveillance)
# ─────────────────────────────────────────────────────────────────────────────
_phase2_proc: subprocess.Popen | None = None
_phase2_lock = threading.Lock()
_phase2_session_id: str | None = None
_phase2_started_at: str | None = None

# ─────────────────────────────────────────────────────────────────────────────
# Chemins absolus
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
PHASE1_DIR   = os.path.join(PROJECT_ROOT, "phase1")
PHASE2_DIR   = os.path.join(PROJECT_ROOT, "phase2")
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "data", "output")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
UPLOAD_DIR   = os.path.join(BASE_DIR, "uploads")

PHASE2_OUTPUT_DIR  = os.path.join(PROJECT_ROOT, "phase2", "data", "output")
PHASE2_EVENTS_FILE = os.path.join(PHASE2_OUTPUT_DIR, "events_collected.jsonl")
PHASE2_REPORT_FILE = os.path.join(PHASE2_OUTPUT_DIR, "phase2_rapport.json")
GRAPH_G0_FILE      = os.path.join(OUTPUT_DIR, "graph_G0.json")

PHASE3_DIR         = os.path.join(PROJECT_ROOT, "microsecscor_phase3")
PHASE3_ALERTS_FILE = os.path.join(PHASE3_DIR, "data", "alertes_cep.jsonl")
PHASE3_STATUS_FILE = os.path.join(PHASE3_DIR, "data", "cep_status.json")

# ─── État global Phase 3 ───────────────────────────────────────────────────────
_phase3_proc: subprocess.Popen | None = None
_phase3_lock = threading.Lock()
_phase3_started_at: str | None = None

os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR,   exist_ok=True)

EXTS_YAML = {".yml", ".yaml"}


def _ext_valide(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in EXTS_YAML


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    env_type   = request.form.get("env_type", "docker")
    simulation = "simulation" in request.form
    session_id = str(uuid.uuid4())[:8]

    upload_path = os.path.join(UPLOAD_DIR, session_id)
    os.makedirs(upload_path, exist_ok=True)

    cmd = [sys.executable, "phase1_topology.py", "--no-neo4j"]
    if simulation:
        cmd.append("--simulation")

    # ── Docker Compose ────────────────────────────────────────────────────────
    if env_type == "docker":
        fichier = request.files.get("compose_file")
        if not fichier or not fichier.filename or not _ext_valide(fichier.filename):
            flash("Veuillez uploader un fichier docker-compose.yml (.yml ou .yaml).")
            return redirect(url_for("index"))

        compose_path = os.path.join(upload_path, "docker-compose.yml")
        fichier.save(compose_path)
        cmd += ["--file", compose_path, "--env", "docker"]

    # ── Kubernetes ────────────────────────────────────────────────────────────
    else:
        k8s_path = os.path.join(upload_path, "k8s")
        os.makedirs(k8s_path, exist_ok=True)

        correspondances = {
            "deployments_file"      : "deployments.yaml",
            "services_file"         : "services.yaml",
            "networkpolicies_file"  : "networkpolicies.yaml",
        }
        for champ, nom_dest in correspondances.items():
            f = request.files.get(champ)
            if f and f.filename and _ext_valide(f.filename):
                f.save(os.path.join(k8s_path, nom_dest))

        if not os.path.isfile(os.path.join(k8s_path, "deployments.yaml")):
            flash("Le fichier deployments.yaml est obligatoire pour l'analyse Kubernetes.")
            return redirect(url_for("index"))

        cmd += ["--k8s-dir", k8s_path, "--env", "kubernetes"]

    # ── Lancement Phase 1 ─────────────────────────────────────────────────────
    print(f"\n[ANALYZE] Commande : {' '.join(cmd)}")
    print(f"[ANALYZE] Répertoire : {PHASE1_DIR}")

    env_subprocess = os.environ.copy()
    env_subprocess["PYTHONIOENCODING"] = "utf-8"
    env_subprocess["PYTHONUTF8"] = "1"

    try:
        proc = subprocess.run(
            cmd,
            cwd=PHASE1_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,   # 30 min — scans Trivy parallèles
            env=env_subprocess,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        print(f"[ANALYZE] TIMEOUT après {e.timeout}s")
        flash("L'analyse a dépassé 10 minutes. Activez le mode Simulation.")
        return redirect(url_for("index"))
    except Exception as e:
        print(f"[ANALYZE] EXCEPTION {type(e).__name__}: {e}")
        flash(f"Erreur : {type(e).__name__}: {e}")
        return redirect(url_for("index"))

    print(f"[ANALYZE] Code retour : {proc.returncode}")
    if stderr:
        print(f"[ANALYZE] STDERR :\n{stderr[-1000:]}")
    if stdout:
        print(f"[ANALYZE] STDOUT (fin) :\n{stdout[-500:]}")

    # ── Copie des résultats dans le dossier de session ────────────────────────
    session_path = os.path.join(SESSIONS_DIR, session_id)
    os.makedirs(session_path, exist_ok=True)

    fichiers_sortie = ["graph_G0.json", "security_scores.csv",
                       "graph_G0.html", "graph_G0.png"]
    for fname in fichiers_sortie:
        src = os.path.join(OUTPUT_DIR, fname)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(session_path, fname))

    # Sauvegarder le log complet dans la session
    session_path_log = os.path.join(session_path, "run.log")
    with open(session_path_log, "w", encoding="utf-8") as f:
        f.write(f"Commande : {' '.join(cmd)}\n")
        f.write(f"Code retour : {proc.returncode}\n\n")
        f.write("=== STDOUT ===\n")
        f.write(stdout)
        f.write("\n=== STDERR ===\n")
        f.write(stderr)

    # Si aucun fichier de sortie → erreur réelle
    if not os.path.isfile(os.path.join(session_path, "security_scores.csv")):
        extrait = (stderr or stdout or "Aucune sortie capturée")[-1000:]
        flash(f"L'analyse a échoué (code {proc.returncode}). Détail : {extrait}")
        return redirect(url_for("index"))

    return redirect(url_for("results", session_id=session_id))


@app.route("/results/<session_id>")
def results(session_id):
    session_path = os.path.join(SESSIONS_DIR, session_id)

    if not os.path.isdir(session_path):
        flash("Session introuvable.")
        return redirect(url_for("index"))

    # Lecture du CSV pour le tableau
    csv_path = os.path.join(session_path, "security_scores.csv")
    scores = []
    if os.path.isfile(csv_path):
        with open(csv_path, encoding="utf-8") as f:
            scores = list(csv.DictReader(f))

    # Score global : moyenne des scores CVE numériques
    score_global = None
    niveau_global = "N/A"
    if scores:
        valeurs = [float(s["score_cve"]) for s in scores
                   if s.get("score_cve") not in ("N/A", "", None)]
        if valeurs:
            score_global = round(sum(valeurs) / len(valeurs), 1)
            if score_global >= 90:
                niveau_global = "SAIN"
            elif score_global >= 70:
                niveau_global = "STABLE"
            elif score_global >= 50:
                niveau_global = "DÉGRADÉ"
            else:
                niveau_global = "CRITIQUE"

    has_graph = os.path.isfile(os.path.join(session_path, "graph_G0.html"))

    return render_template(
        "results.html",
        session_id=session_id,
        scores=scores,
        score_global=score_global,
        niveau_global=niveau_global,
        has_graph=has_graph,
        nb_services=len(scores),
    )


@app.route("/results/<session_id>/graph")
def serve_graph(session_id):
    graph_path = os.path.join(SESSIONS_DIR, session_id, "graph_G0.html")
    if not os.path.isfile(graph_path):
        return "Graphe non disponible", 404
    return send_file(graph_path)


@app.route("/results/<session_id>/download/csv")
def download_csv(session_id):
    csv_path = os.path.join(SESSIONS_DIR, session_id, "security_scores.csv")
    if not os.path.isfile(csv_path):
        return "Fichier non disponible", 404
    return send_file(csv_path, as_attachment=True,
                     download_name="security_scores.csv")


@app.route("/diagnostic")
def diagnostic():
    """
    Lance un test minimal du pipeline Docker et affiche le résultat complet.
    Accéder à http://localhost:8080/diagnostic pour diagnostiquer.
    """
    import tempfile, textwrap

    compose_minimal = textwrap.dedent("""\
        services:
          frontend:
            image: nginx:1.21
            ports:
              - "80:80"
          backend:
            image: node:18-alpine
            depends_on:
              - database
          database:
            image: postgres:14
    """)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(compose_minimal)
        tmp_path = tmp.name

    cmd = [sys.executable, "phase1_topology.py",
           "--no-neo4j", "--simulation",
           "--file", tmp_path, "--env", "docker"]

    env_sub = os.environ.copy()
    env_sub["PYTHONIOENCODING"] = "utf-8"
    env_sub["PYTHONUTF8"] = "1"

    try:
        proc = subprocess.run(
            cmd, cwd=PHASE1_DIR,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, env=env_sub,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        code   = proc.returncode
    except Exception as e:
        return f"<pre>Erreur subprocess : {e}</pre>", 500

    os.unlink(tmp_path)

    html = f"""<html><body style="font-family:monospace;padding:20px">
    <h2>Diagnostic MicroSecScore — Pipeline Docker</h2>
    <p><b>Commande :</b> {' '.join(cmd)}</p>
    <p><b>Code retour :</b> {code}
       {'✅ OK' if code in (0,1,2) else '❌ ERREUR'}</p>
    <h3>STDOUT</h3><pre style="background:#f5f5f5;padding:10px">{stdout or "(vide)"}</pre>
    <h3>STDERR</h3><pre style="background:#fff3e0;padding:10px">{stderr or "(vide)"}</pre>
    </body></html>"""
    return html


@app.route("/results/<session_id>/log")
def view_log(session_id):
    log_path = os.path.join(SESSIONS_DIR, session_id, "run.log")
    if not os.path.isfile(log_path):
        return "Log introuvable", 404
    with open(log_path, encoding="utf-8") as f:
        contenu = f.read()
    return f"<pre style='font-family:monospace;font-size:12px;padding:20px'>{contenu}</pre>"


@app.route("/results/<session_id>/download/json")
def download_json(session_id):
    json_path = os.path.join(SESSIONS_DIR, session_id, "graph_G0.json")
    if not os.path.isfile(json_path):
        return "Fichier non disponible", 404
    return send_file(json_path, as_attachment=True,
                     download_name="graph_G0.json")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — helpers et routes
# ─────────────────────────────────────────────────────────────────────────────

def _charger_topologie_g0() -> dict:
    """Lit graph_G0.json et retourne {service: {score_cve, criticite, image}}."""
    if not os.path.isfile(GRAPH_G0_FILE):
        return {}
    try:
        with open(GRAPH_G0_FILE, encoding="utf-8") as f:
            g0 = json.load(f)
        topo = {}
        for node in g0.get("nodes", []):
            nom = node.get("id")
            if nom and nom != "Outside":
                topo[nom] = {
                    "score_cve": float(node.get("score_cve", 50.0)),
                    "criticite": int(node.get("criticite", 1)),
                    "image":     str(node.get("image", "unknown")),
                }
        return topo
    except Exception:
        return {}


def _lire_stats_phase2() -> dict:
    """
    Lit UNIQUEMENT events_collected.jsonl comme source de vérité.
    Aucune donnée simulée ou injectée — miroir fidèle du pipeline réel.
    """
    events = []
    if os.path.isfile(PHASE2_EVENTS_FILE):
        with open(PHASE2_EVENTS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    now_ts = time.time()

    by_type     = {}
    by_service  = {}
    by_source   = {}
    by_severity = {}
    phase1_enriched = 0

    # Dernier horodatage unix par source (pour calcul statut ACTIF/INACTIF)
    source_last_unix = {}

    for e in events:
        t   = e.get("event_type", "UNKNOWN")
        s   = e.get("service",    "unknown")
        src = e.get("source",     "unknown")
        sev = e.get("severity",   "INFO")

        by_type[t]       = by_type.get(t, 0)       + 1
        by_service[s]    = by_service.get(s, 0)     + 1
        by_source[src]   = by_source.get(src, 0)    + 1
        by_severity[sev] = by_severity.get(sev, 0)  + 1

        if "phase1" in e:
            phase1_enriched += 1

        # Mémoriser le dernier timestamp par source
        ts_str = e.get("timestamp_utc", "")
        if ts_str:
            try:
                ts_dt   = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                unix_ts = ts_dt.timestamp()
                if unix_ts > source_last_unix.get(src, 0):
                    source_last_unix[src] = unix_ts
            except Exception:
                pass

    # Statut par source : ACTIF si dernier événement < 60 s
    SOURCE_LABELS = {
        "docker_logs":     "Logs Docker",
        "falco_generator": "Falco (simulation)",
        "falco_simulator": "Falco (simulation)",
        "prometheus":      "Métriques Prometheus",
        "cadvisor":        "Métriques cAdvisor",
    }
    source_status = {}
    for src, last_unix in source_last_unix.items():
        age_s  = now_ts - last_unix
        active = age_s < 60
        source_status[src] = {
            "label":       SOURCE_LABELS.get(src, src),
            "active":      active,
            "last_event":  datetime.fromtimestamp(last_unix, tz=timezone.utc)
                           .strftime("%Y-%m-%d %H:%M:%S UTC"),
            "age_seconds": int(age_s),
            "count":       by_source.get(src, 0),
        }

    # Statut global du pipeline
    is_active     = False
    last_modified = None
    if os.path.isfile(PHASE2_EVENTS_FILE):
        mtime = os.path.getmtime(PHASE2_EVENTS_FILE)
        last_modified = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        is_active = (now_ts - mtime) < 60

    # 50 derniers événements réels (antéchronologique)
    recent = list(reversed(events[-50:]))

    # Rapport de session si disponible
    rapport = {}
    if os.path.isfile(PHASE2_REPORT_FILE):
        try:
            with open(PHASE2_REPORT_FILE, encoding="utf-8") as f:
                rapport = json.load(f)
        except Exception:
            pass

    return {
        "total":            len(events),
        "by_type":          by_type,
        "by_service":       by_service,
        "by_source":        by_source,
        "by_severity":      by_severity,
        "phase1_enriched":  phase1_enriched,
        "source_status":    source_status,   # ACTIF/INACTIF par source réelle
        "recent":           recent,
        "is_active":        is_active,
        "last_modified":    last_modified,
        "topologie":        _charger_topologie_g0(),
        "rapport":          rapport,
    }


@app.route("/phase2")
def phase2_dashboard():
    stats = _lire_stats_phase2()
    return render_template("phase2.html", **stats)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Contrôle du processus de surveillance (start / stop / status)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/phase2/start", methods=["POST"])
def phase2_start():
    """
    Démarre Phase 2 comme subprocess.
    Si session_id est fourni, copie le graph_G0.json de cette session
    vers data/output/ afin que Phase 2 surveille les bons services.
    """
    global _phase2_proc, _phase2_session_id, _phase2_started_at

    session_id = (request.form.get("session_id")
                  or (request.json or {}).get("session_id", ""))

    with _phase2_lock:
        # Déjà en cours → retourner le statut sans redémarrer
        if _phase2_proc and _phase2_proc.poll() is None:
            return jsonify({
                "status":     "already_running",
                "session_id": _phase2_session_id,
                "pid":        _phase2_proc.pid,
            })

        # Copier le G0 de la session Phase 1 vers le chemin global de Phase 2
        if session_id:
            session_g0 = os.path.join(SESSIONS_DIR, session_id, "graph_G0.json")
            if os.path.isfile(session_g0):
                os.makedirs(OUTPUT_DIR, exist_ok=True)
                shutil.copy2(session_g0, GRAPH_G0_FILE)
                print(f"[Phase2/start] G0 copié depuis session {session_id}")

        # Lancer phase2_runtime.py comme subprocess indépendant
        phase2_script = os.path.join(PHASE2_DIR, "phase2_runtime.py")
        env_sub = os.environ.copy()
        env_sub["PYTHONIOENCODING"] = "utf-8"
        env_sub["PYTHONUTF8"]       = "1"

        try:
            _phase2_proc     = subprocess.Popen(
                [sys.executable, phase2_script],
                cwd=PHASE2_DIR,
                env=env_sub,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _phase2_session_id = session_id
            _phase2_started_at = datetime.now(timezone.utc).isoformat()
            print(f"[Phase2/start] PID={_phase2_proc.pid} session={session_id}")
            return jsonify({
                "status":     "started",
                "pid":        _phase2_proc.pid,
                "session_id": session_id,
                "started_at": _phase2_started_at,
            })
        except Exception as exc:
            return jsonify({"status": "error", "detail": str(exc)}), 500


@app.route("/phase2/stop", methods=["POST"])
def phase2_stop():
    """Arrête proprement le processus Phase 2."""
    global _phase2_proc, _phase2_session_id, _phase2_started_at

    with _phase2_lock:
        if _phase2_proc and _phase2_proc.poll() is None:
            _phase2_proc.terminate()
            try:
                _phase2_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _phase2_proc.kill()
            _phase2_proc       = None
            _phase2_session_id = None
            _phase2_started_at = None
            return jsonify({"status": "stopped"})
        return jsonify({"status": "not_running"})


@app.route("/phase2/status")
def phase2_status():
    """Retourne l'état courant du processus Phase 2."""
    with _phase2_lock:
        running = _phase2_proc is not None and _phase2_proc.poll() is None
        return jsonify({
            "running":    running,
            "session_id": _phase2_session_id,
            "started_at": _phase2_started_at,
            "pid":        _phase2_proc.pid if running else None,
        })


@app.route("/phase2/api/stats")
def phase2_api_stats():
    stats = _lire_stats_phase2()
    stats.pop("recent", None)       # trop lourd pour le polling
    stats.pop("rapport", None)
    return jsonify(stats)


@app.route("/phase2/api/events")
def phase2_api_events():
    stats = _lire_stats_phase2()
    return jsonify({"events": stats["recent"], "total": stats["total"]})


# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — CEP Engine : helpers et routes
# ─────────────────────────────────────────────────────────────────────────────

_MITRE_LABELS = {
    "T1046": "Network Service Discovery",
    "T1110": "Brute Force",
    "T1550": "Application Access Token",
    "T1078": "Valid Accounts",
    "T1611": "Escape to Host",
    "T1041": "Exfiltration Over C2",
    "T1499": "Endpoint DoS",
}

_RULE_LABELS = {
    "SCAN_RECONN":       {"nom": "P1 — Scan de reconnaissance",    "mitre": "T1046"},
    "BRUTE_FORCE":       {"nom": "P2 — Force brute",               "mitre": "T1110"},
    "LATERAL_MOVE":      {"nom": "P3 — Mouvement latéral",         "mitre": "T1550"},
    "COMPROMISE":        {"nom": "P4 — Compromission de compte",   "mitre": "T1078"},
    "CONTAINER_ESCAPE":  {"nom": "P5 — Évasion de conteneur",      "mitre": "T1611"},
    "EXFILTRATION":      {"nom": "P6 — Exfiltration de données",   "mitre": "T1041"},
    "DOS_DETECTED":      {"nom": "P7 — Déni de service",           "mitre": "T1499"},
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _lire_stats_phase3() -> dict:
    alertes = []
    if os.path.isfile(PHASE3_ALERTS_FILE):
        with open(PHASE3_ALERTS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alertes.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    by_type     = {}
    by_severity = {}
    by_mitre    = {}

    for a in alertes:
        t   = a.get("type",     "UNKNOWN")
        sev = a.get("severity", "INFO")
        mit = a.get("mitre",    "")
        by_type[t]      = by_type.get(t, 0)      + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if mit:
            by_mitre[mit] = by_mitre.get(mit, 0) + 1

    # Statut du moteur CEP
    statut_cep = {"running": False, "threads_total": 7, "threads_actifs": 0,
                  "alertes_total": 0, "rules": []}
    if os.path.isfile(PHASE3_STATUS_FILE):
        try:
            with open(PHASE3_STATUS_FILE, encoding="utf-8") as f:
                statut_cep = json.load(f)
        except Exception:
            pass

    # Vérifier si le process est vraiment vivant
    with _phase3_lock:
        proc_running = _phase3_proc is not None and _phase3_proc.poll() is None
        proc_pid     = _phase3_proc.pid if proc_running else None
    if not proc_running and statut_cep.get("running"):
        statut_cep["running"] = False

    recentes = list(reversed(alertes[-30:]))

    return {
        "total":        len(alertes),
        "by_type":      by_type,
        "by_severity":  by_severity,
        "by_mitre":     by_mitre,
        "recentes":     recentes,
        "statut_cep":   statut_cep,
        "mitre_labels": _MITRE_LABELS,
        "rule_labels":  _RULE_LABELS,
        "proc_running": proc_running,
        "proc_pid":     proc_pid,
        "started_at":   _phase3_started_at,
    }


@app.route("/phase3")
def phase3_dashboard():
    stats = _lire_stats_phase3()
    return render_template("phase3.html", **stats)


@app.route("/phase3/start", methods=["POST"])
def phase3_start():
    global _phase3_proc, _phase3_started_at
    with _phase3_lock:
        if _phase3_proc and _phase3_proc.poll() is None:
            return jsonify({"status": "already_running", "pid": _phase3_proc.pid})

        cep_script = os.path.join(PHASE3_DIR, "cep_engine.py")
        env_sub = os.environ.copy()
        env_sub["PYTHONIOENCODING"] = "utf-8"
        env_sub["PYTHONUTF8"]       = "1"
        try:
            _phase3_proc     = subprocess.Popen(
                [sys.executable, "-X", "utf8", cep_script],
                cwd=PHASE3_DIR,
                env=env_sub,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _phase3_started_at = datetime.now(timezone.utc).isoformat()
            return jsonify({
                "status":     "started",
                "pid":        _phase3_proc.pid,
                "started_at": _phase3_started_at,
            })
        except Exception as exc:
            return jsonify({"status": "error", "detail": str(exc)}), 500


@app.route("/phase3/stop", methods=["POST"])
def phase3_stop():
    global _phase3_proc, _phase3_started_at
    with _phase3_lock:
        if _phase3_proc and _phase3_proc.poll() is None:
            _phase3_proc.terminate()
            try:
                _phase3_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _phase3_proc.kill()
            _phase3_proc       = None
            _phase3_started_at = None
            return jsonify({"status": "stopped"})
        return jsonify({"status": "not_running"})


@app.route("/phase3/status")
def phase3_status():
    with _phase3_lock:
        running = _phase3_proc is not None and _phase3_proc.poll() is None
    return jsonify({
        "running":    running,
        "started_at": _phase3_started_at,
        "pid":        _phase3_proc.pid if running else None,
    })


@app.route("/phase3/api/stats")
def phase3_api_stats():
    return jsonify(_lire_stats_phase3())


@app.route("/phase3/inject", methods=["POST"])
def phase3_inject():
    """Injecte un scénario d'attaque APT via phase2_runtime --inject-attack."""
    env_sub = os.environ.copy()
    env_sub["PYTHONIOENCODING"] = "utf-8"
    env_sub["PYTHONUTF8"]       = "1"
    try:
        subprocess.Popen(
            [sys.executable, "phase2_runtime.py", "--inject-attack"],
            cwd=PHASE2_DIR,
            env=env_sub,
        )
        return jsonify({"status": "injected"})
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 500


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8092))
    print("MicroSecScore — Interface Web")
    print(f"  Ouvrir : http://localhost:{port}")
    app.run(debug=True, host="127.0.0.1", port=port)
