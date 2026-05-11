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
import os
import shutil
import subprocess
import sys
import uuid

from flask import (Flask, flash, redirect, render_template,
                   request, send_file, url_for)

app = Flask(__name__)
app.secret_key = "microsecstore_dev_key_change_in_prod"

# ─────────────────────────────────────────────────────────────────────────────
# Chemins absolus
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
PHASE1_DIR   = os.path.join(PROJECT_ROOT, "phase1")
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "data", "output")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
UPLOAD_DIR   = os.path.join(BASE_DIR, "uploads")

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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print("MicroSecScore — Interface Web")
    print(f"  Ouvrir : http://localhost:{port}")
    app.run(debug=True, host="127.0.0.1", port=port)
