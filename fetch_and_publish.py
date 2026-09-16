#!/usr/bin/env python3
"""
Récupère le rapport quotidien de veille (déjà généré gratuitement par la
tâche planifiée Cowork "Daily report", qui l'écrit dans un fichier JSON sur
le site SharePoint dédié "Veillepublication") et génère la page HTML
publiée sur GitHub Pages, en écrasant la version précédente.

Archive aussi le rapport du jour dans le dépôt (dossier data/) et régénère
un petit historique de la semaine en cours (du lundi à aujourd'hui), avec
une barre latérale de navigation entre les jours déjà publiés.

AUCUN appel à l'API Anthropic ici — ce script ne fait que lire un fichier
JSON déjà produit ailleurs et le transformer en pages HTML. Objectif :
coût récurrent nul (GitHub Actions + GitHub Pages, gratuits pour un dépôt
public dans ce volume d'usage).

Pas d'hébergement web tiers, pas de SFTP : GitHub héberge directement les
pages générées. Ça réduit aussi la surface — un système en moins avec des
identifiants à protéger.

───────────────────────────────────────────────────────────────────────
POSTURE SÉCURITÉ (voir aussi le README)
───────────────────────────────────────────────────────────────────────
Le fichier lu depuis SharePoint contient du texte qui provient in fine
d'une recherche web faite par un modèle — donc potentiellement influencé
par du contenu web piégé (injection de prompt indirecte). Ce script ne
fait donc JAMAIS confiance à ce fichier tel quel :
  - échappement systématique de tout texte (html.escape) avant insertion
    dans le HTML final
  - validation stricte des URLs (http:// ou https:// uniquement)
  - validation de la criticité et de la catégorie contre des listes fermées
  - le rendu HTML vient d'un template FIXE dans ce script, jamais du
    contenu récupéré directement
  - les fichiers archivés dans data/ sont re-validés avec la même logique
    à la relecture (défense en profondeur, même si déjà nettoyés à l'écriture)

Côté SharePoint, l'accès est volontairement le plus étroit possible :
une app Azure AD dédiée à cette seule tâche, en lecture seule, autorisée
via Sites.Selected sur le site "Veillepublication" uniquement (pas
Sites.Read.All, pas d'accès au reste du tenant) — voir README pour la
procédure de création/octroi. Même en cas de fuite totale du secret
GitHub, l'accès obtenu se limite à la lecture de ce site précis.

Variables d'environnement attendues :
  AZURE_TENANT_ID       (obligatoire) ID du tenant Entra (PMIT)
  AZURE_CLIENT_ID       (obligatoire) ID client de l'app Azure AD dédiée
  AZURE_CLIENT_SECRET   (obligatoire) secret client de cette app (à expiration)
  SHAREPOINT_DRIVE_ID   (obligatoire) driveId de la bibliothèque "Documents
                        partagés" du site Veillepublication
  SHAREPOINT_FILE_NAME  (optionnel, défaut : veille-daily-items.json)
  OUTPUT_DIR            (optionnel, défaut : public) dossier où écrire les
                        pages générées, repris ensuite par
                        actions/upload-pages-artifact dans le workflow
  ARCHIVE_DIR           (optionnel, défaut : data) dossier du dépôt où sont
                        archivés les JSON quotidiens (committé par le
                        workflow via git, pas par ce script)
"""

import calendar
import html as html_lib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote, urlparse

ALLOWED_CATEGORIES = {
    "reseau_securite": ("📡", "Pare-feu, routeurs & réseau (Fortinet, pfSense, Unifi)"),
    "systemes": ("💻", "Systèmes d'exploitation (Windows, macOS)"),
    "cloud_m365": ("☁️", "Cloud & Microsoft 365"),
    "securite_endpoint": ("🛡️", "Sécurité endpoint (ThreatDown)"),
    "sauvegarde": ("💾", "Sauvegarde (Veeam, Tri-Backup)"),
    "gestion_parc": ("🔧", "Gestion de parc (NinjaOne)"),
    "navigateurs": ("🌐", "Navigateurs (Chrome, Safari, Firefox)"),
    "stockage_nas": ("🗄️", "Stockage & NAS (Synology)"),
    "transfert_fichiers": ("📁", "Transfert de fichiers (FileZilla, Rumpus)"),
    "acces_distant": ("🖥️", "Accès à distance (TeamViewer, AnyDesk)"),
    "mot_de_passe": ("🔑", "Gestionnaire de mots de passe (1Password)"),
    "autres_outils": ("📦", "Autres outils"),
    "hors_perimetre": ("📰", "Autres actualités (hors périmètre)"),
}
# Ordre d'affichage des sections "dans le périmètre" — hors_perimetre n'y
# figure jamais : cette section est toujours rendue à part, repliée, en tout
# dernier (voir build_html).
CATEGORY_ORDER = [c for c in ALLOWED_CATEGORIES if c != "hors_perimetre"]

# ─────────────────────────────────────────────────────────────────────────
# Reclassification par produit réellement utilisé chez PMIT (liste confirmée
# par Pierre le 16/09/2026). La catégorie envoyée par la tâche Cowork dans le
# JSON n'est qu'indicative : c'est CE mapping, déterministe et basé sur le nom
# du produit, qui décide de la catégorie finale affichée — un article sur un
# outil non listé ici part automatiquement dans "hors_perimetre", quelle que
# soit la catégorie d'origine. Prembattu keyword gagne (ordre de la liste).
# ─────────────────────────────────────────────────────────────────────────
IN_SCOPE_VENDOR_KEYWORDS: list[tuple[str, str]] = [
    # Pare-feu / routeur / switch
    ("fortianalyzer", "reseau_securite"), ("fortimanager", "reseau_securite"),
    ("fortiproxy", "reseau_securite"), ("fortisiem", "reseau_securite"),
    ("fortisoar", "reseau_securite"), ("fortisandbox", "reseau_securite"),
    ("fortipam", "reseau_securite"), ("fortiswitch", "reseau_securite"),
    ("forticlient", "reseau_securite"), ("fortigate", "reseau_securite"),
    ("fortios", "reseau_securite"), ("fortinet", "reseau_securite"),
    ("pfsense", "reseau_securite"), ("netgate", "reseau_securite"),
    ("unifi", "reseau_securite"), ("ubiquiti", "reseau_securite"),
    # Systèmes d'exploitation
    ("windows server", "systemes"), ("windows", "systemes"),
    ("macos", "systemes"), ("mac os", "systemes"), ("os x", "systemes"),
    ("catalina", "systemes"), ("mojave", "systemes"), ("big sur", "systemes"),
    ("monterey", "systemes"), ("ventura", "systemes"), ("sonoma", "systemes"),
    ("sequoia", "systemes"), ("tahoe", "systemes"),
    # Cloud & Microsoft 365
    ("microsoft 365", "cloud_m365"), ("m365", "cloud_m365"), ("office 365", "cloud_m365"),
    ("suite office", "cloud_m365"), ("entra id", "cloud_m365"), ("azure ad", "cloud_m365"),
    ("azure", "cloud_m365"), ("exchange online", "cloud_m365"), ("outlook", "cloud_m365"),
    ("sharepoint", "cloud_m365"), ("onedrive", "cloud_m365"), ("microsoft teams", "cloud_m365"),
    # Sécurité endpoint
    ("threatdown", "securite_endpoint"), ("malwarebytes", "securite_endpoint"),
    # Sauvegarde
    ("veeam", "sauvegarde"), ("tri-backup", "sauvegarde"), ("tribackup", "sauvegarde"),
    # Gestion de parc
    ("ninjaone", "gestion_parc"),
    # Navigateurs
    ("chrome", "navigateurs"), ("safari", "navigateurs"), ("firefox", "navigateurs"),
    # Stockage / NAS
    ("synology", "stockage_nas"),
    # Transfert de fichiers
    ("filezilla", "transfert_fichiers"), ("rumpus", "transfert_fichiers"),
    # Accès à distance
    ("teamviewer", "acces_distant"), ("anydesk", "acces_distant"),
    # Gestionnaire de mots de passe
    ("1password", "mot_de_passe"),
]


def classify_category(product: str) -> str:
    """Détermine la catégorie finale d'affichage à partir du nom du produit,
    indépendamment de la catégorie fournie par la tâche Cowork. Renvoie
    "hors_perimetre" si aucun outil connu du parc PMIT n'est reconnu."""
    p = product.lower()
    for keyword, category in IN_SCOPE_VENDOR_KEYWORDS:
        if keyword in p:
            return category
    return "hors_perimetre"

ALLOWED_CRITICALITY = {
    "critique": ("🔴", "#dc2626"),
    "important": ("🟠", "#d97706"),
    "info": ("🟢", "#16a34a"),
}
CRITICALITY_ORDER = ["critique", "important", "info"]

MAX_FIELD_LEN = {
    "product": 80,
    "impact": 300,
    "technical_detail": 600,
    "source": 120,
}

GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

FR_WEEKDAYS_SHORT = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"]


def _get_app_only_token() -> str:
    """Authentification application-only (client credentials) via l'app
    Azure AD dédiée. Aucune session utilisateur, aucun mot de passe humain
    — seul un secret client à expiration, limité par Sites.Selected au
    site Veillepublication uniquement (voir README)."""
    import msal

    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            "Impossible d'obtenir un jeton Azure AD (vérifie AZURE_TENANT_ID / "
            f"AZURE_CLIENT_ID / AZURE_CLIENT_SECRET) : "
            f"{result.get('error')}: {result.get('error_description')}"
        )
    return result["access_token"]


def fetch_items_from_sharepoint() -> dict:
    """Télécharge le fichier JSON écrit par la tâche Cowork sur le site
    SharePoint dédié "Veillepublication", via Microsoft Graph en
    authentification application-only. Aucun identifiant utilisateur,
    aucun lien public — l'app dédiée n'a qu'un accès en lecture seule à ce
    site précis (Sites.Selected)."""
    token = _get_app_only_token()
    drive_id = os.environ["SHAREPOINT_DRIVE_ID"]
    file_name = os.environ.get("SHAREPOINT_FILE_NAME", "veille-daily-items.json")

    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{quote(file_name)}:/content"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "User-Agent": "veille-publish-bot/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_bytes = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Erreur HTTP {exc.code} en récupérant le fichier SharePoint (driveId="
            f"{drive_id!r}, fichier={file_name!r}) : {body[:300]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Impossible de télécharger le fichier SharePoint : {exc}") from exc

    raw = raw_bytes.decode("utf-8", errors="replace").strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Le fichier SharePoint ne contient pas du JSON valide : {exc}\n"
            f"Début du contenu reçu : {raw[:300]!r}"
        ) from exc

    if not isinstance(data, dict) or "items" not in data:
        raise RuntimeError(f"JSON reçu mais structure inattendue : {raw[:300]!r}")

    return data


def _truncate(text: str, max_len: int) -> str:
    text = text.strip()
    if len(text) > max_len:
        return text[: max_len - 1].rstrip() + "…"
    return text


def _validate_and_sanitize_url(url: str) -> str | None:
    if not isinstance(url, str):
        return None
    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return url


def _sanitize_items(raw_items: list) -> list[dict]:
    clean = []
    for idx, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict):
            print(f"Item #{idx} ignoré (pas un objet)", file=sys.stderr)
            continue

        category = raw_item.get("category")
        if category not in ALLOWED_CATEGORIES:
            print(f"Item #{idx} ignoré (catégorie inconnue : {category!r})", file=sys.stderr)
            continue

        criticality = raw_item.get("criticality")
        if criticality not in ALLOWED_CRITICALITY:
            print(f"Item #{idx} ignoré (criticité inconnue : {criticality!r})", file=sys.stderr)
            continue

        url = _validate_and_sanitize_url(raw_item.get("url", ""))
        if url is None:
            print(f"Item #{idx} ignoré (URL absente ou non http/https)", file=sys.stderr)
            continue

        impact = raw_item.get("impact")
        if not isinstance(impact, str) or not impact.strip():
            print(f"Item #{idx} ignoré (impact manquant)", file=sys.stderr)
            continue

        clean.append(
            {
                "category": category,
                "product": _truncate(str(raw_item.get("product", "Autre")), MAX_FIELD_LEN["product"]),
                "criticality": criticality,
                "impact": _truncate(impact, MAX_FIELD_LEN["impact"]),
                "technical_detail": _truncate(
                    str(raw_item.get("technical_detail", "")), MAX_FIELD_LEN["technical_detail"]
                ),
                "source": _truncate(str(raw_item.get("source", "")), MAX_FIELD_LEN["source"]),
                "date": _truncate(str(raw_item.get("date", "")), 20),
                "url": url,
            }
        )
    return clean


CRIT_CSS_CLASS = {"critique": "crit", "important": "imp", "info": "info"}
CRIT_BADGE_LABEL = {"critique": "CRITIQUE", "important": "IMPORTANT", "info": "INFO"}


# ─────────────────────────────────────────────────────────────────────────
# Date "aujourd'hui à Paris" — sans dépendance externe (pas de zoneinfo/
# tzdata requis : règle DST de l'UE calculée à la main, cf. README) :
# heure d'été du dernier dimanche de mars 1h UTC au dernier dimanche
# d'octobre 1h UTC (UTC+2), UTC+1 le reste de l'année.
# ─────────────────────────────────────────────────────────────────────────
def _last_sunday(year: int, month: int) -> date:
    last_day = calendar.monthrange(year, month)[1]
    d = date(year, month, last_day)
    return d - timedelta(days=(d.weekday() - 6) % 7)


def paris_today(now_utc: datetime | None = None) -> date:
    now_utc = now_utc or datetime.now(timezone.utc)
    year = now_utc.year
    dst_start = datetime(year, 3, _last_sunday(year, 3).day, 1, tzinfo=timezone.utc)
    dst_end = datetime(year, 10, _last_sunday(year, 10).day, 1, tzinfo=timezone.utc)
    offset_hours = 2 if dst_start <= now_utc < dst_end else 1
    return (now_utc + timedelta(hours=offset_hours)).date()


def week_monday(d: date) -> date:
    return d - timedelta(days=d.weekday())


# ─────────────────────────────────────────────────────────────────────────
# Archivage quotidien (dossier data/, committé par le workflow via git —
# pas par ce script) et historique de la semaine en cours.
# ─────────────────────────────────────────────────────────────────────────
def _archive_path(archive_dir: str, d: date) -> str:
    return os.path.join(archive_dir, f"{d.isoformat()}.json")


def save_archive(archive_dir: str, d: date, page_date: str, items: list[dict]) -> None:
    os.makedirs(archive_dir, exist_ok=True)
    payload = {"schema": 1, "date_key": d.isoformat(), "page_date": page_date, "items": items}
    with open(_archive_path(archive_dir, d), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def load_archive(archive_dir: str, d: date) -> dict | None:
    """Relit un rapport archivé. Re-valide les items comme s'ils venaient
    de SharePoint (défense en profondeur : un fichier archivé n'est pas
    plus digne de confiance a priori qu'un fichier fraîchement récupéré)."""
    path = _archive_path(archive_dir, d)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Archive {path} illisible, ignorée : {exc}", file=sys.stderr)
        return None
    if not isinstance(payload, dict):
        return None
    page_date = _truncate(str(payload.get("page_date", "")), 40)
    items = _sanitize_items(payload.get("items", []) if isinstance(payload.get("items"), list) else [])
    return {"page_date": page_date, "items": items}


def available_week_dates(archive_dir: str, today: date) -> list[date]:
    """Jours (avec archive existante) entre le lundi de la semaine en cours
    et aujourd'hui inclus, triés du plus ancien au plus récent."""
    monday = week_monday(today)
    dates = []
    d = monday
    while d <= today:
        if os.path.isfile(_archive_path(archive_dir, d)):
            dates.append(d)
        d += timedelta(days=1)
    return dates


def build_sidebar(week_dates: list[date], active_date: date, location: str) -> str:
    """location : "root" (page à la racine, index.html) ou "archive"
    (pages dans public/archive/), pour calculer les bons liens relatifs."""
    if not week_dates:
        return ""
    today = max(week_dates)
    entries = []
    for d in week_dates:
        is_active = d == active_date
        is_today = d == today
        dot = '<span class="day-dot" title="Aujourd’hui"></span>' if is_today and not is_active else ""
        inner = f'<span class="day-name">{FR_WEEKDAYS_SHORT[d.weekday()]}</span><span class="day-num">{d.day:02d}</span>{dot}'
        if is_active:
            entries.append(f'<span class="day-item active">{inner}</span>')
        else:
            if location == "root":
                href = f"archive/{d.isoformat()}.html"
            else:
                href = "../index.html" if is_today else f"{d.isoformat()}.html"
            entries.append(f'<a class="day-item" href="{href}">{inner}</a>')
    return f'''<aside class="sidebar">
  <div class="sidebar-label">Cette semaine</div>
  <nav class="day-list">
    {"".join(entries)}
  </nav>
</aside>'''


def _render_cards(product_items: list[dict], esc) -> str:
    cards_html = []
    for item in sorted(product_items, key=lambda i: CRITICALITY_ORDER.index(i["criticality"])):
        crit_class = CRIT_CSS_CLASS[item["criticality"]]
        crit_icon, _ = ALLOWED_CRITICALITY[item["criticality"]]
        crit_label = CRIT_BADGE_LABEL[item["criticality"]]
        tech_detail_html = (
            f'''<div class="level2">
      <div class="level2-label">Détail technique</div>
      <div class="meta">{esc(item["source"])} · {esc(item["date"])}</div>
      <p class="tech">{esc(item["technical_detail"])}</p>
    </div>'''
            if item["technical_detail"]
            else f'''<div class="level2">
      <div class="meta">{esc(item["source"])} · {esc(item["date"])}</div>
    </div>'''
        )
        cards_html.append(
            f'''<a class="card {crit_class}" href="{esc(item["url"])}" target="_blank" rel="noopener noreferrer">
    <div class="card-top">
      <span class="badge {crit_class}">{crit_icon} {crit_label}</span>
    </div>
    <div class="level1">{esc(item["impact"])}</div>
    {tech_detail_html}
  </a>'''
        )
    return "".join(cards_html)


def _render_product_groups(items: list[dict], esc) -> str:
    """Regroupe une liste d'items par produit et rend les sous-groupes +
    cartes correspondants (réutilisé pour les sections du périmètre et pour
    le bloc "hors périmètre")."""
    products: dict[str, list[dict]] = {}
    for item in items:
        products.setdefault(item["product"], []).append(item)
    subgroups_html = []
    for product_name, product_items in products.items():
        subgroups_html.append(
            f'''<div class="subgroup">
    <div class="subgroup-title">→ {esc(product_name)}</div>
    <div class="cards">
      {_render_cards(product_items, esc)}
    </div>
  </div>'''
        )
    return "".join(subgroups_html)


def build_html(page_date: str, items: list[dict], sidebar_html: str) -> str:
    def esc(value: str) -> str:
        return html_lib.escape(value, quote=True)

    # Reclassification déterministe par produit réellement utilisé chez PMIT
    # — la catégorie d'origine du JSON n'est qu'indicative (voir
    # classify_category). Un item non reconnu part en "hors_perimetre".
    items = [dict(item, category=classify_category(item["product"])) for item in items]

    in_scope_items = [i for i in items if i["category"] != "hors_perimetre"]
    out_of_scope_items = [i for i in items if i["category"] == "hors_perimetre"]

    # Les compteurs en tête de page ne reflètent que ce qui concerne
    # vraiment le parc PMIT — pas le "hors périmètre" replié plus bas.
    counts = {c: 0 for c in CRITICALITY_ORDER}
    for item in in_scope_items:
        counts[item["criticality"]] += 1

    by_category: dict[str, list[dict]] = {c: [] for c in CATEGORY_ORDER}
    for item in in_scope_items:
        by_category[item["category"]].append(item)

    # Liste des sources consultées, dérivée de TOUS les items réellement
    # présents ce jour-là (périmètre + hors périmètre), dédupliquée par nom
    # de source — pas une liste statique, uniquement ce qui a vraiment servi.
    seen_sources: dict[str, str] = {}
    for item in items:
        if item["source"] and item["source"] not in seen_sources:
            seen_sources[item["source"]] = item["url"]

    sections_html = []
    for cat_key in CATEGORY_ORDER:
        cat_items = by_category[cat_key]
        if not cat_items:
            continue
        icon, label = ALLOWED_CATEGORIES[cat_key]
        sections_html.append(
            f'''<section class="category">
  <div class="cat-head">
    <span class="cat-icon">{icon}</span>
    <h2>{esc(label)}</h2>
  </div>
  {_render_product_groups(cat_items, esc)}
</section>'''
        )

    body_content = (
        "".join(sections_html)
        if sections_html
        else '<p class="empty">Aucune actualité critique aujourd\'hui dans ton périmètre.</p>'
    )

    out_of_scope_html = ""
    if out_of_scope_items:
        icon, label = ALLOWED_CATEGORIES["hors_perimetre"]
        out_of_scope_html = f'''<details class="out-of-scope">
  <summary>
    <span class="cat-icon">{icon}</span>
    <span class="oos-label">{esc(label)}</span>
    <span class="oos-count">{len(out_of_scope_items)}</span>
  </summary>
  <div class="oos-body">
    {_render_product_groups(out_of_scope_items, esc)}
  </div>
</details>'''

    sources_html = "".join(
        f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(name)}</a>'
        for name, url in seen_sources.items()
    )
    footer_html = (
        f'''<footer>
  <div class="sources">
    <span class="sources-label">Sources consultées&nbsp;:</span>
    {sources_html}
  </div>
</footer>'''
        if seen_sources
        else ""
    )

    sidebar_block = sidebar_html or ""

    return f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veille IT du {esc(page_date)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;650;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
  :root {{
    color-scheme: light;
    --bg: #f5f6f8;
    --surface: #ffffff;
    --surface-2: #fafbfc;
    --border: #e2e5ea;
    --text: #14181f;
    --text-muted: #4b5563;
    --text-faint: #8a93a3;
    --accent: #2f5fd6;
    --accent-soft: #eaf0fd;
    --crit: #e02424;
    --crit-bg: #fbebe9;
    --crit-border: #f0c4bd;
    --imp: #b5730f;
    --imp-bg: #fbf1e1;
    --imp-border: #f0d6a8;
    --info: #2f7a4f;
    --info-bg: #e9f5ee;
    --info-border: #c3e3d1;
    --shadow: 0 2px 10px rgba(20,24,31,.06);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .layout {{
    display: grid;
    grid-template-columns: 190px 1fr;
    grid-template-areas: "side head" "side main";
    gap: 8px 40px;
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 20px 64px;
  }}
  header.page {{ grid-area: head; margin-bottom: 32px; }}
  .content {{ grid-area: main; }}
  aside.sidebar {{ grid-area: side; }}
  .sidebar-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: var(--text-faint);
    margin-bottom: 10px;
    padding-left: 10px;
  }}
  .day-list {{ display: flex; flex-direction: column; gap: 4px; position: sticky; top: 24px; }}
  .day-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 8px;
    text-decoration: none;
    color: var(--text-muted);
    font-size: .85rem;
    border: 1px solid transparent;
  }}
  .day-item .day-name {{
    text-transform: uppercase;
    font-size: .72rem;
    letter-spacing: .03em;
    width: 2.4em;
    color: inherit;
  }}
  .day-item .day-num {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-weight: 600; color: var(--text); }}
  .day-item:hover {{ background: var(--surface-2); }}
  .day-item.active {{ background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }}
  .day-item.active .day-num {{ color: var(--accent); }}
  .day-dot {{ width: 6px; height: 6px; border-radius: 50%; background: var(--accent); margin-left: auto; }}
  .eyebrow {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .78rem;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--accent);
    font-weight: 600;
    margin-bottom: 10px;
  }}
  h1 {{ font-size: 1.9rem; font-weight: 650; margin: 0 0 10px; letter-spacing: -.01em; }}
  .scope-note {{ color: var(--text-muted); font-size: .95rem; line-height: 1.55; max-width: 720px; margin: 0; }}
  .scope-note strong {{ color: var(--text); }}
  .counters {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 28px 0 36px; }}
  .counter {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--text-faint);
    border-radius: 10px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
  }}
  .counter .n {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 1.7rem;
    font-weight: 600;
    display: block;
  }}
  .counter .l {{
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-muted);
  }}
  .counter.crit {{ border-left-color: var(--crit); }}
  .counter.imp {{ border-left-color: var(--imp); }}
  .counter.info {{ border-left-color: var(--info); }}
  section.category {{ margin-bottom: 36px; }}
  .cat-head {{
    display: flex;
    align-items: center;
    gap: 10px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 16px;
  }}
  .cat-icon {{ font-size: 1.2rem; }}
  .cat-head h2 {{ font-size: 1.15rem; font-weight: 600; margin: 0; }}
  .subgroup {{ margin-bottom: 18px; }}
  .subgroup-title {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .78rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
    margin-bottom: 8px;
  }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }}
  .card {{
    display: block;
    text-decoration: none;
    color: inherit;
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--text-faint);
    border-radius: 10px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
    transition: transform .12s ease, box-shadow .12s ease;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 6px 18px rgba(20,24,31,.12); }}
  .card.crit {{ border-left-color: var(--crit); }}
  .card.imp {{ border-left-color: var(--imp); }}
  .card.info {{ border-left-color: var(--info); }}
  .card-top {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .7rem;
    font-weight: 600;
    letter-spacing: .03em;
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid;
  }}
  .badge.crit {{ background: var(--crit-bg); border-color: var(--crit-border); color: var(--crit); }}
  .badge.imp {{ background: var(--imp-bg); border-color: var(--imp-border); color: var(--imp); }}
  .badge.info {{ background: var(--info-bg); border-color: var(--info-border); color: var(--info); }}
  .level1 {{ font-size: 1rem; font-weight: 600; line-height: 1.4; }}
  .card:hover .level1 {{ color: var(--accent); text-decoration: underline; }}
  .level2 {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); }}
  .level2-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .68rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
    margin-bottom: 4px;
  }}
  .meta {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .72rem;
    color: var(--text-faint);
    margin-bottom: 4px;
  }}
  .tech {{ margin: 0; font-size: .85rem; color: var(--text-muted); line-height: 1.5; }}
  .empty {{ color: var(--text-muted); font-style: italic; }}
  details.out-of-scope {{
    margin: 40px 0 8px;
    border-top: 1px solid var(--border);
    padding-top: 20px;
  }}
  details.out-of-scope summary {{
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    list-style: none;
    color: var(--text-faint);
    user-select: none;
  }}
  details.out-of-scope summary::-webkit-details-marker {{ display: none; }}
  details.out-of-scope summary::before {{
    content: "▸";
    font-size: .8rem;
    transition: transform .12s ease;
  }}
  details.out-of-scope[open] summary::before {{ transform: rotate(90deg); }}
  details.out-of-scope .oos-label {{
    font-size: .85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .03em;
  }}
  details.out-of-scope .oos-count {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .75rem;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 8px;
  }}
  details.out-of-scope .oos-body {{ margin-top: 20px; opacity: .85; }}
  footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); }}
  .sources {{ display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; }}
  .sources-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
  }}
  .sources a {{ font-size: .82rem; color: var(--accent); text-decoration: none; }}
  .sources a:hover {{ text-decoration: underline; }}
  @media (max-width: 860px) {{
    .layout {{
      grid-template-columns: 1fr;
      grid-template-areas: "head" "side" "main";
      gap: 16px 0;
      padding: 24px 16px 48px;
    }}
    .sidebar-label {{ padding-left: 2px; }}
    .day-list {{
      flex-direction: row;
      overflow-x: auto;
      gap: 8px;
      position: static;
      padding-bottom: 4px;
      -webkit-overflow-scrolling: touch;
    }}
    .day-item {{ flex: 0 0 auto; flex-direction: column; text-align: center; padding: 8px 14px; gap: 2px; }}
    .day-item .day-name {{ width: auto; }}
    .day-dot {{ margin: 0 auto; }}
  }}
</style>
</head>
<body>
<div class="layout">
{sidebar_block}
<header class="page">
  <div class="eyebrow">Agent de veille informatique · {esc(page_date)}</div>
  <h1>Veille cybersécurité &amp; IT</h1>
  <p class="scope-note">Actualités et alertes touchant <strong>le périmètre PMIT</strong> (Fortinet, pfSense, Microsoft 365, NinjaOne et les autres outils du parc), classées par catégorie et par produit.</p>
  <div class="counters">
    <div class="counter crit"><span class="n">{counts["critique"]}</span><span class="l">🔴 Critique</span></div>
    <div class="counter imp"><span class="n">{counts["important"]}</span><span class="l">🟠 Important</span></div>
    <div class="counter info"><span class="n">{counts["info"]}</span><span class="l">🟢 Info</span></div>
  </div>
</header>
<div class="content">
{body_content}
{out_of_scope_html}
{footer_html}
</div>
</div>
</body>
</html>'''


def sanity_check(rendered_html: str) -> None:
    lowered = rendered_html.lower()
    if "<!doctype html" not in lowered:
        raise RuntimeError("Page générée invalide — publication annulée.")
    if len(rendered_html) < 400:
        raise RuntimeError(
            f"Page générée trop courte ({len(rendered_html)} caractères) — publication annulée par précaution."
        )


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    output_dir = os.environ.get("OUTPUT_DIR", "public")
    archive_dir = os.environ.get("ARCHIVE_DIR", "data")

    try:
        data = fetch_items_from_sharepoint()
        raw_date = data.get("date", "")
        page_date_today = _truncate(str(raw_date), 40) if raw_date else ""
        items_today = _sanitize_items(data.get("items", []))
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR pendant la récupération/génération du rapport : {exc}", file=sys.stderr)
        return 1

    today = paris_today()

    try:
        # 1. Archiver le rapport du jour (le workflow committe data/ ensuite).
        save_archive(archive_dir, today, page_date_today, items_today)

        # 2. Reconstituer l'historique de la semaine (lundi → aujourd'hui).
        week_dates = available_week_dates(archive_dir, today)

        # 3. Page du jour à la racine du site.
        sidebar_root = build_sidebar(week_dates, active_date=today, location="root")
        index_html = build_html(page_date_today, items_today, sidebar_root)
        sanity_check(index_html)
        _write_file(os.path.join(output_dir, "index.html"), index_html)

        # 4. Une page par jour archivé de la semaine, dans archive/.
        for d in week_dates:
            archived = load_archive(archive_dir, d)
            if archived is None:
                continue
            sidebar_arch = build_sidebar(week_dates, active_date=d, location="archive")
            page_html = build_html(archived["page_date"], archived["items"], sidebar_arch)
            _write_file(os.path.join(output_dir, "archive", f"{d.isoformat()}.html"), page_html)
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR en générant/écrivant les pages : {exc}", file=sys.stderr)
        return 1

    print(f"Page du jour générée : {os.path.join(output_dir, 'index.html')}")
    print(f"Historique de la semaine ({len(week_dates)} jour(s)) régénéré dans {os.path.join(output_dir, 'archive')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
