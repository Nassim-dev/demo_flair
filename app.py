"""FLAIR — interface de démonstration.

Ce fichier ne fait que trois choses :
  1. appeler l'API,
  2. dessiner la page,
  3. orchestrer l'attente et l'affichage du résultat.

Toute la logique de lecture de l'API vit dans flair/adapter.py.
Tout le style vit dans flair/theme.py.
"""

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import time

import httpx
from nicegui import events, ui

# Fait utiliser à Python le magasin de certificats du système d'exploitation.
# Indispensable derrière un antivirus qui inspecte le HTTPS (Avast, Kaspersky…)
# ou un proxy d'entreprise — cas de figure courant chez les assureurs.
# Sans cela : "CERTIFICATE_VERIFY_FAILED" à chaque appel API.
try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

from flair import components as fc
from flair import feedback, preview, theme
from flair.adapter import build_report

logger = logging.getLogger(__name__)

print(f"[flair] base de retours : {feedback.init()}")

API_URL = os.getenv("FLAIR_API_URL", "https://api.myflair.app/v1/analyze")
API_KEY = os.getenv("FLAIR_API_KEY", "")

# La racine de l'API, déduite de FLAIR_API_URL : rien n'est à reconfigurer sur
# les déploiements existants, qui pointent tous vers une route synchrone.
API_BASE = re.sub(r"/v1/(analyze|documents:sync)/?$", "", API_URL).rstrip("/")

# Attente maximale de l'analyse. Généreuse sans risque : contrairement à la voie
# synchrone, aucune requête HTTP ne reste ouverte pendant ce temps — c'est le
# client qui revient demander, donc aucune passerelle n'a de raison de couper.
ATTENTE_MAX_S = float(os.getenv("FLAIR_ATTENTE_MAX_S", "300"))
SONDAGE_S = 1.0
# Chaque requête prise séparément est courte : un ticket, un PUT, une soumission,
# un SELECT indexé. Ce timeout borne une requête, jamais l'analyse.
TIMEOUT_REQUETE_S = 60.0

# Le formulaire de retour s'affiche et s'enregistre toujours. Ce réglage décide
# seulement s'il *bloque* le dépôt d'un nouveau document tant qu'on n'a pas
# répondu. Désactivé pour les tests internes, à passer à 1 pour de vrais
# utilisateurs — c'est ce qui garantit le taux de réponse.
RETOUR_BLOQUANT = os.getenv("FLAIR_RETOUR_BLOQUANT", "0") == "1"

# Squelettes affichés pendant l'attente de la réponse (mêmes noms que l'adapter).
PENDING_LAYERS = [
    (1, "Historique & modifications", "Enregistrements successifs · différences de contenu"),
    (2, "Métadonnées", "Logiciel de création et de modification · dates"),
    (3, "2D-DOC & QR code", "Lecture de l'ancre cryptographique · recoupement"),
    (4, "Images générées par IA", "Modèle générateur · deepfake · photo d'écran"),
    (5, "Cohérence", "Recoupement des données du document par IA"),
]


async def read_upload(e: events.UploadEventArguments) -> tuple[str, bytes]:
    """Récupère (nom, octets) du fichier déposé, quelle que soit la version de NiceGUI."""
    upload = getattr(e, "file", None)
    if upload is not None:
        data = upload.read()
        if inspect.isawaitable(data):
            data = await data
        return upload.name, data
    data = e.content.read()
    if inspect.isawaitable(data):
        data = await data
    return e.name, data


# Ce que chaque statut veut réellement dire, parce que le message d'erreur est
# la seule chose que le visiteur lit. « Vérifiez la clé d'accès et le format du
# document » sur un 504 envoyait chercher là où il n'y a rien : une clé refusée
# est un 401, un format refusé un 415 — un 5xx ne parle jamais du document.
ERREURS_API = {
    401: "Clé d'accès refusée. Vérifiez FLAIR_API_KEY.",
    403: "Clé d'accès refusée. Vérifiez FLAIR_API_KEY.",
    413: "Document trop volumineux pour la démonstration.",
    415: "Format non reconnu. PDF, JPEG, PNG, TIFF ou WebP.",
    422: "Document illisible ou refusé à l'ingestion.",
    402: "Quota de la clé de démonstration épuisé.",
    429: "Trop de demandes en cours. Réessayez dans quelques secondes.",
}

# Un 504 n'est jamais la réponse de l'API : c'est un intermédiaire (Traefik,
# devant les conteneurs) qui a cessé d'attendre. L'API, elle, répond 503 quand
# son analyse dépasse son budget — et ce 503 nomme la route asynchrone.
ERREUR_TROP_LONG = (
    "L'analyse n'a pas abouti dans le temps imparti. Réessayez, ou avec un "
    "document plus léger."
)


# Pourquoi une analyse s'est terminée en échec. L'API rend ce code sur le
# document (`failure_code`), du même vocabulaire fermé que sa colonne : sans lui
# la démo ne pourrait dire que « échec », qui est le genre de message dont cette
# page vient justement de se débarrasser.
ECHECS_ANALYSE = {
    "unsupported_mime": "Format non reconnu. PDF, JPEG, PNG, TIFF ou WebP.",
    "limit_exceeded": "Document trop volumineux ou trop de pages pour la démonstration.",
    "malware": "Fichier refusé par le contrôle antivirus.",
    "scanner_unavailable": "Contrôle antivirus indisponible. Réessayez dans un moment.",
    "download_failed": "Le document n'a pas pu être relu depuis le stockage.",
    "no_storage_key": "Le document n'a pas pu être relu depuis le stockage.",
    "sync_deadline_exceeded": ERREUR_TROP_LONG,
}


def message_echec(failure_code) -> str:
    return ECHECS_ANALYSE.get(
        failure_code or "", "L'analyse n'a pas abouti. Réessayez ou changez de document."
    )


ETATS = {"queued": "En file d'attente…", "processing": "Analyse en cours…"}


def message_erreur(status_code: int) -> str:
    if status_code in ERREURS_API:
        return ERREURS_API[status_code]
    if status_code in (503, 504, 502, 408):
        return ERREUR_TROP_LONG
    return f"L'API a répondu {status_code}."


async def call_flair_api(filename: str, content: bytes, on_status=None) -> dict:
    """Voie asynchrone : ticket d'upload -> PUT direct -> soumission -> sondage.

    L'ancienne voie (`POST /v1/analyze`) tenait une requête HTTP ouverte pendant
    toute l'analyse. Passé le délai de la passerelle qui est devant l'API, celle-ci
    répondait 504 au visiteur pendant que le serveur travaillait encore — et le
    message d'erreur accusait la clé ou le document. Ici, la requête la plus
    longue est un PUT vers le stockage : plus rien n'attend sur un socket.
    """
    auth = {"Authorization": f"Bearer {API_KEY}"}
    # Pas d'en-tête par défaut sur le client : le PUT part vers une URL
    # pré-signée, et S3 refuse une requête qui porte deux mécanismes
    # d'authentification (la signature dans l'URL + un Authorization).
    async with httpx.AsyncClient(timeout=TIMEOUT_REQUETE_S) as client:
        # 1. Un ticket d'upload. La taille est déclarée ici, donc signée dans
        #    l'URL : le corps du PUT devra faire exactement ce nombre d'octets,
        #    ce dont httpx se charge seul.
        reponse = await client.post(
            f"{API_BASE}/v1/uploads",
            headers=auth,
            json={"files": [{"filename": filename, "size": len(content)}]},
        )
        reponse.raise_for_status()
        ticket = reponse.json()["uploads"][0]

        # 2. Les octets vont droit au stockage — l'API ne les voit jamais.
        depot = await client.put(ticket["url"], content=content)
        depot.raise_for_status()

        # 3. Soumission : 202 immédiat, l'analyse part en tâche de fond.
        reponse = await client.post(
            f"{API_BASE}/v1/documents",
            headers=auth,
            json={"documents": [{"upload_id": ticket["upload_id"], "filename": filename}]},
        )
        reponse.raise_for_status()
        document_id = reponse.json()["document_ids"][0]

        # 4. On redemande le document jusqu'à son état terminal. La lecture a son
        #    propre budget de débit côté API, dix fois celui de l'écriture :
        #    sonder ne consomme pas ce qu'il faut pour soumettre le suivant.
        debut = time.monotonic()
        while True:
            reponse = await client.get(
                f"{API_BASE}/v1/documents/{document_id}", headers=auth
            )
            reponse.raise_for_status()
            document = reponse.json()
            if document["status"] in ("completed", "failed"):
                return {"document": document}
            if on_status is not None:
                on_status(document["status"])
            if time.monotonic() - debut > ATTENTE_MAX_S:
                raise TimeoutError(f"analyse toujours {document['status']}")
            await asyncio.sleep(SONDAGE_S)


@ui.page("/")
def main_page():
    ui.add_head_html(theme.HEAD)
    ui.add_body_html(theme.CLICK_RELAY)

    with ui.element("div").classes("topbar"):
        with ui.row().classes("topbar-inner w-full items-center justify-between no-wrap"):
            ui.html(theme.LOGO)
            with ui.element("div").classes("live-badge"):
                ui.element("div").classes("live-dot")
                ui.label("api.myflair.app").classes("mono text-xs").style(
                    "color:var(--ink-2)"
                )

    with ui.column().classes("w-full max-w-4xl mx-auto px-6 pt-14 pb-6 gap-10"):

        with ui.column().classes("gap-4"):
            ui.label("Moteur d'analyse — démonstration").classes("eyebrow")
            ui.html("Cinq couches de détection.<br><em>Un verdict.</em>").classes(
                "hero-title"
            )
            ui.label(
                "Soumettez une pièce justificative — fiche de paie, justificatif de "
                "domicile, pièce d'identité, facture. Le moteur exécute ses couches "
                "déterministes, puis n'escalade vers l'IA que si aucune ancre forte "
                "ne peut être vérifiée."
            ).classes("hero-sub")

        zone = ui.element("div").classes("dropzone")
        with zone:
            for pos in ("tl", "tr", "bl", "br"):
                ui.element("div").classes(f"corner {pos}")
            with ui.column().classes("w-full items-center gap-2"):
                ui.label("⌖").classes("dz-icon mono")
                ui.label("Glissez une pièce justificative").classes("dz-title")
                ui.label("PDF · JPEG · PNG — ou cliquez pour parcourir").classes("dz-hint")
            with ui.element("div").classes("overlay-upload"):
                upload = ui.upload(
                    auto_upload=True,
                    on_upload=lambda e: analyze(e),
                ).props('accept=".pdf,image/*" flat')

        notice = ui.label(
            "Donnez votre avis sur le verdict ci-dessous pour analyser un autre document."
        ).classes("dropzone-notice w-full")
        notice.set_visibility(False)

        doc_slot = ui.column().classes("w-full")
        verdict_slot = ui.column().classes("w-full")
        layers_slot = ui.column().classes("w-full gap-3")
        feedback_slot = ui.column().classes("w-full")
        raw_slot = ui.column().classes("w-full")

        with ui.column().classes("footer w-full pt-5 gap-1 items-center"):
            ui.label(
                "Le document n'est jamais écrit sur le disque : ses octets restent "
                "en mémoire vive le temps de l'aperçu, puis sont libérés. Seuls "
                "l'empreinte SHA-256 et les résultats d'analyse sont conservés."
            ).classes("smallprint text-center").style("max-width:34rem")
            ui.html(theme.LOGO.replace('class="logo"', 'class="logo-footer"'))

        # ------------------------------------------------------------------
        # Orchestration
        # ------------------------------------------------------------------

        def verrouiller(actif: bool) -> None:
            """Bloque la zone de dépôt tant que le retour n'est pas donné."""
            upload.set_enabled(not actif)
            notice.set_visibility(actif)
            if actif:
                zone.classes(add="dropzone-locked")
            else:
                zone.classes(remove="dropzone-locked")

        def show_error(message: str) -> None:
            layers_slot.clear()
            verdict_slot.clear()
            with verdict_slot:
                with ui.column().classes("panel verdict verdict-fraud w-full p-5 gap-2 fade-in"):
                    ui.label("Analyse impossible").classes("signal-title").style(
                        "color:var(--fraud)"
                    )
                    ui.label(message).classes("signal-verdict")

        async def analyze(e: events.UploadEventArguments):
            filename, content = await read_upload(e)
            sha256 = hashlib.sha256(content).hexdigest()
            size_kb = len(content) / 1024
            upload.reset()

            for slot in (doc_slot, verdict_slot, layers_slot, feedback_slot, raw_slot):
                slot.clear()

            # Aperçu : les octets restent en mémoire vive, jamais sur le disque.
            preview_url, preview_kind, preview_msg = preview.store(filename, content)

            with doc_slot:
                with ui.column().classes("panel doc-card w-full p-4 gap-3 fade-in"):
                    scan = ui.element("div").classes("scanline")
                    with ui.column().classes("gap-1"):
                        ui.label(filename).classes("mono text-sm font-medium")
                        ui.label(f"{size_kb:,.0f} Ko · SHA-256 {sha256[:20]}…").classes(
                            "mono text-xs"
                        ).style("color:var(--ink-2)")
                    ui.label("Document soumis").classes("preview-caption")
                    fc.document_preview(preview_url, preview_kind, preview_msg)

            with layers_slot:
                # Un état réel, pas une animation : la voie asynchrone dit où en
                # est le document. Elle ne dit pas quelle couche tourne — les
                # couches n'arrivent qu'une fois l'analyse terminée.
                etat = ui.label(ETATS["queued"]).classes("preview-caption")
                for number, name, subtitle in PENDING_LAYERS:
                    fc.pending_layer(number, name, subtitle)

            try:
                raw = await call_flair_api(
                    filename, content,
                    on_status=lambda s: etat.set_text(ETATS.get(s, "Analyse en cours…")),
                )
            except httpx.HTTPStatusError as exc:
                scan.delete()
                show_error(message_erreur(exc.response.status_code))
                return
            except (httpx.TimeoutException, TimeoutError):
                scan.delete()
                show_error(ERREUR_TROP_LONG)
                return
            except Exception:  # réseau, JSON invalide…
                # Sans le texte de l'exception : il porte l'URL interne, le nom
                # d'hôte et la chaîne de proxy. Une panne ne raconte pas notre
                # infrastructure au visiteur — elle va dans les logs.
                logger.exception("Appel API en échec")
                show_error("Connexion à l'API impossible.")
                return

            scan.delete()

            if raw["document"]["status"] == "failed":
                show_error(message_echec(raw["document"].get("failure_code")))
                return

            try:
                report = build_report(raw)
            except Exception as exc:
                show_error(
                    "L'API a répondu, mais le format reçu n'est pas celui attendu "
                    f"({exc}). La réponse brute reste consultable ci-dessous."
                )
                with raw_slot:
                    with ui.expansion("Réponse JSON de l'API").classes(
                        "panel w-full mono text-sm"
                    ):
                        ui.code(
                            json.dumps(raw, indent=2, ensure_ascii=False), language="json"
                        ).classes("w-full")
                return

            # Couche 0 — verdict global
            with verdict_slot:
                fc.verdict_card(report)

            # Les 5 couches, révélées une à une pour l'effet de démonstration.
            layers_slot.clear()
            for layer in report.layers:
                await asyncio.sleep(0.18)
                with layers_slot:
                    fc.layer_block(layer, open_=layer.alert_count > 0)

            verrouiller(RETOUR_BLOQUANT)
            with feedback_slot:
                fc.feedback_form(
                    filename=filename,
                    verdict=report.verdict_label,
                    on_submit=lambda: verrouiller(False),
                )

            with raw_slot:
                with ui.expansion("Réponse JSON de l'API").classes(
                    "panel w-full mono text-sm"
                ):
                    ui.code(
                        json.dumps(raw, indent=2, ensure_ascii=False), language="json"
                    ).classes("w-full")


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        title="FLAIR",
        favicon="🛡️",
        # FLAIR_RELOAD=1 => la page se rafraîchit toute seule quand tu modifies le code.
        reload=os.getenv("FLAIR_RELOAD", "0") == "1",
        show=False,
    )
