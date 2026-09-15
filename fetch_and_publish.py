#!/usr/bin/env python3
"""
Récupère le rapport quotidien de veille (déjà généré gratuitement par la
tâche planifiée Cowork "Daily report", qui l'écrit dans un fichier JSON sur
le site SharePoint dédié "Veillepublication") et génère la page HTML
publiée sur GitHub Pages, en écrasant la version précédente.

AUCUN appel à l'API Anthropic ici — ce script ne fait que lire un fichier
JSON déjà produit ailleurs et le transformer en page HTML. Objectif :
coût récurrent nul (GitHub Actions + GitHub Pages, gratuits pour un dépôt
privé dans ce volume d'usage).

Pas d'hébergement web tiers, pas de SFTP : GitHub héberge directement la
page générée. Ça réduit aussi la surface — un système en moins avec des
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
  OUTPUT_DIR            (optionnel, défaut : public) dossier où écrire la
                        page générée (index.html), repris ensuite par
                        actions/upload-pages-artifact dans le workflow
"""

import html as html_lib
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

ALLOWED_CATEGORIES = {
    "reseau_securite": ("📡", "Réseau & sécurité périmétrique"),
    "systemes": ("💻", "Systèmes d'exploitation"),
    "cloud_m365": ("☁️", "Cloud & M365"),
    "securite_endpoint": ("🛡️", "Sécurité endpoint"),
    "sauvegarde": ("💾", "Sauvegarde"),
    "gestion_parc": ("🔧", "Gestion de parc"),
    "autres_outils": ("📦", "Autres outils"),
}
CATEGORY_ORDER = list(ALLOWED_CATEGORIES.keys())

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


def build_html(data: dict) -> str:
    raw_date = data.get("date", "")
    page_date = _truncate(str(raw_date), 40) if raw_date else ""
    items = _sanitize_items(data.get("items", []))

    counts = {c: 0 for c in CRITICALITY_ORDER}
    for item in items:
        counts[item["criticality"]] += 1

    by_category: dict[str, dict[str, list[dict]]] = {c: {} for c in CATEGORY_ORDER}
    for item in items:
        by_category[item["category"]].setdefault(item["product"], []).append(item)

    # Liste des sources consultées, dérivée des items réellement présents ce
    # jour-là (dédupliquée par nom de source, première URL rencontrée
    # conservée) — pas de liste statique : uniquement ce qui a vraiment servi.
    seen_sources: dict[str, str] = {}
    for item in items:
        if item["source"] and item["source"] not in seen_sources:
            seen_sources[item["source"]] = item["url"]

    def esc(value: str) -> str:
        return html_lib.escape(value, quote=True)

    sections_html = []
    for cat_key in CATEGORY_ORDER:
        products = by_category[cat_key]
        if not products:
            continue
        icon, label = ALLOWED_CATEGORIES[cat_key]

        subgroups_html = []
        for product_name, product_items in products.items():
            cards_html = []
            for item in sorted(
                product_items, key=lambda i: CRITICALITY_ORDER.index(i["criticality"])
            ):
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
            subgroups_html.append(
                f'''<div class="subgroup">
    <div class="subgroup-title">→ {esc(product_name)}</div>
    <div class="cards">
      {"".join(cards_html)}
    </div>
  </div>'''
            )

        sections_html.append(
            f'''<section class="category">
  <div class="cat-head">
    <span class="cat-icon">{icon}</span>
    <h2>{esc(label)}</h2>
  </div>
  {"".join(subgroups_html)}
</section>'''
        )

    body_content = (
        "".join(sections_html)
        if sections_html
        else '<p class="empty">Aucune actualité critique aujourd\'hui dans ton périmètre.</p>'
    )

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
    color-scheme: light dark;
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
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg: #14161a;
      --surface: #1c1f25;
      --surface-2: #20232a;
      --border: #2d3138;
      --text: #e7e9ec;
      --text-muted: #a6acb8;
      --text-faint: #6d7480;
      --accent: #7fa0f5;
      --accent-soft: #212d47;
      --crit: #f18f8a;
      --crit-bg: #3a1f1e;
      --crit-border: #5c2b28;
      --imp: #e3b567;
      --imp-bg: #3a2f1a;
      --imp-border: #5c4a26;
      --info: #7fceA0;
      --info-bg: #1c3327;
      --info-border: #2c4f3b;
      --shadow: 0 2px 10px rgba(0,0,0,.35);
    }}
  }}
  :root[data-theme="dark"] {{
    --bg: #14161a;
    --surface: #1c1f25;
    --surface-2: #20232a;
    --border: #2d3138;
    --text: #e7e9ec;
    --text-muted: #a6acb8;
    --text-faint: #6d7480;
    --accent: #7fa0f5;
    --accent-soft: #212d47;
    --crit: #f18f8a;
    --crit-bg: #3a1f1e;
    --crit-border: #5c2b28;
    --imp: #e3b567;
    --imp-bg: #3a2f1a;
    --imp-border: #5c4a26;
    --info: #7fceA0;
    --info-bg: #1c3327;
    --info-border: #2c4f3b;
    --shadow: 0 2px 10px rgba(0,0,0,.35);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; padding: 40px 20px 64px; }}
  header.page {{ margin-bottom: 32px; }}
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
</style>
</head>
<body>
<div class="wrap">
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
{body_content}
{footer_html}
</div>
</body>
</html>'''


def sanity_check(html: str) -> None:
    lowered = html.lower()
    if "<!doctype html" not in lowered:
        raise RuntimeError("Page générée invalide — publication annulée.")
    if len(html) < 400:
        raise RuntimeError(
            f"Page générée trop courte ({len(html)} caractères) — publication annulée par précaution."
        )


def write_output(rendered_html: str) -> str:
    """Écrit la page générée dans le dossier de sortie (par défaut
    "public/index.html"), qui sera ensuite publié tel quel sur GitHub Pages
    par le workflow (actions/upload-pages-artifact + actions/deploy-pages).
    Pas de FTP/SFTP, pas d'identifiant d'hébergement tiers."""
    output_dir = os.environ.get("OUTPUT_DIR", "public")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "index.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    return output_path


def main() -> int:
    try:
        data = fetch_items_from_sharepoint()
        rendered_html = build_html(data)
        sanity_check(rendered_html)
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR pendant la récupération/génération du rapport : {exc}", file=sys.stderr)
        return 1

    try:
        output_path = write_output(rendered_html)
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR en écrivant la page générée : {exc}", file=sys.stderr)
        return 1

    print(f"Page générée avec succès : {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
