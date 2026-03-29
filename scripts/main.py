import asyncio
import os
import re

import aiohttp
from bs4 import BeautifulSoup
from markdownify import markdownify as md

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APPLE_SECURITY_UPDATES_URL = "https://support.apple.com/en-us/HT201222"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTENT_DIR = os.path.join(BASE_DIR, "content")
CHANGELOGS_DIR = os.path.join(CONTENT_DIR, "changelogs")

SEVERITY_MAPPING = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
DEFAULT_SEVERITY = "Medium"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 6.5  # seconds between NVD requests (no API key limit)

SEVERITY_WEIGHT = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
SEVERITY_BADGE_HTML = {
    "Critical": '<span style="background:#b91c1c;color:#fff;padding:1px 8px;border-radius:4px;font-size:0.8em;font-weight:700;letter-spacing:0.05em">CRITICAL</span>',
    "High": '<span style="background:#c2410c;color:#fff;padding:1px 8px;border-radius:4px;font-size:0.8em;font-weight:700;letter-spacing:0.05em">HIGH</span>',
    "Medium": '<span style="background:#b45309;color:#fff;padding:1px 8px;border-radius:4px;font-size:0.8em;font-weight:700;letter-spacing:0.05em">MEDIUM</span>',
    "Low": '<span style="background:#15803d;color:#fff;padding:1px 8px;border-radius:4px;font-size:0.8em;font-weight:700;letter-spacing:0.05em">LOW</span>',
}

PLATFORM_ORDER = [
    "iOS",
    "iPadOS",
    "macOS",
    "watchOS",
    "tvOS",
    "visionOS",
    "Safari",
    "Xcode",
    "Other",
]
PLATFORM_WEIGHT = {p: i + 1 for i, p in enumerate(PLATFORM_ORDER)}

# NVD in-process cache and rate-limit semaphore (initialised inside main())
_NVD_CACHE: dict = {}
_NVD_SEMAPHORE: asyncio.Semaphore | None = None


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _yaml_str(value: str) -> str:
    """Escape a value for use inside a YAML double-quoted scalar."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _url_id(url: str) -> str:
    """Return the last path segment of a URL (Apple advisory identifier)."""
    return url.rstrip("/").split("/")[-1]


def detect_platforms(title: str) -> list[str]:
    tl = title.lower()
    platforms: list[str] = []
    if "ios" in tl:
        platforms.append("iOS")
    if "ipados" in tl:
        platforms.append("iPadOS")
    if "macos" in tl or "os x" in tl:
        platforms.append("macOS")
    if "watchos" in tl:
        platforms.append("watchOS")
    if "tvos" in tl:
        platforms.append("tvOS")
    if "visionos" in tl:
        platforms.append("visionOS")
    if "safari" in tl:
        platforms.append("Safari")
    if "xcode" in tl:
        platforms.append("Xcode")
    if not platforms:
        platforms.append("Other")
    return platforms


# ---------------------------------------------------------------------------
# Hugo content helpers
# ---------------------------------------------------------------------------


def _make_cve_page(
    item: dict, cve: str, severity: str, nvd_data: dict | None = None
) -> str:
    """Build the full Hugo page for a single CVE / platform combination."""
    platform = item["platform"]
    url = item["url"]
    title = item["title"]
    advisory_id = item.get("advisory_id", _url_id(url))

    weight = SEVERITY_WEIGHT.get(severity, 5)
    badge = SEVERITY_BADGE_HTML.get(
        severity,
        f'<span style="background:#6b7280;color:#fff;padding:1px 8px;border-radius:4px;font-size:0.8em;font-weight:700">{severity.upper()}</span>',
    )

    front_matter = (
        "---\n"
        f'title: "{_yaml_str(cve)}"\n'
        f"weight: {weight}\n"
        "params:\n"
        f'  severity: "{_yaml_str(severity)}"\n'
        f'  platform: "{_yaml_str(platform)}"\n'
        f'  url: "{_yaml_str(url)}"\n'
        f'  advisoryTitle: "{_yaml_str(title)}"\n'
        f'  changelogId: "{_yaml_str(advisory_id)}"\n'
        "---\n"
    )

    header = (
        f"{badge} &nbsp;|&nbsp; "
        f"**Platform:** {platform} &nbsp;|&nbsp; "
        f"[Changelog](/changelogs/{advisory_id}/)"
    )

    # CVE Details accordion — content sourced from NVD, not the Apple changelog
    details_content = _format_nvd_details(nvd_data, cve, url)
    details_open = '{{% details title="CVE Details" %}}'
    details_close = "{{% /details %}}"

    body = "\n".join(
        [
            header,
            "",
            details_open,
            "",
            details_content,
            "",
            details_close,
            "",
        ]
    )

    return front_matter + "\n" + body


def _make_changelog_page(
    advisory_id: str, title: str, url: str, platforms: list[str], markdown_body: str
) -> str:
    """Build the Hugo page for a full Apple security advisory (changelog)."""
    platforms_list = ", ".join(f'"{p}"' for p in platforms)

    front_matter = (
        "---\n"
        f'title: "{_yaml_str(title)}"\n'
        "params:\n"
        f'  url: "{_yaml_str(url)}"\n'
        f'  canonicalURL: "{_yaml_str(url)}"\n'
        f"  platforms: [{platforms_list}]\n"
        "---\n"
    )

    header = f"[Original Advisory]({url})\n"

    return front_matter + "\n" + header + "\n" + markdown_body + "\n"


# ---------------------------------------------------------------------------
# Hugo section-index helpers  (called lazily so we never overwrite user edits)
# ---------------------------------------------------------------------------


def _ensure_home_index() -> None:
    os.makedirs(CONTENT_DIR, exist_ok=True)
    path = os.path.join(CONTENT_DIR, "_index.md")
    if os.path.exists(path):
        return
    content = """\
---
title: Dissecting Apple
toc: false
---

{{< cards >}}
  {{< card link="iOS"       title="iOS"       icon="device-mobile"    subtitle="iPhone vulnerabilities" >}}
  {{< card link="iPadOS"    title="iPadOS"    icon="device-tablet"    subtitle="iPad vulnerabilities" >}}
  {{< card link="macOS"     title="macOS"     icon="desktop-computer" subtitle="Mac vulnerabilities" >}}
  {{< card link="watchOS"   title="watchOS"   icon="clock"            subtitle="Apple Watch vulnerabilities" >}}
  {{< card link="tvOS"      title="tvOS"      icon="film"             subtitle="Apple TV vulnerabilities" >}}
  {{< card link="visionOS"  title="visionOS"  icon="eye"              subtitle="Vision Pro vulnerabilities" >}}
  {{< card link="Safari"    title="Safari"    icon="globe-alt"        subtitle="Browser vulnerabilities" >}}
  {{< card link="Xcode"     title="Xcode"     icon="code"             subtitle="Developer tool vulnerabilities" >}}
  {{< card link="changelogs" title="Changelogs" icon="document-text"  subtitle="Apple security release notes" >}}
{{< /cards >}}
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _ensure_changelogs_index() -> None:
    os.makedirs(CHANGELOGS_DIR, exist_ok=True)
    path = os.path.join(CHANGELOGS_DIR, "_index.md")
    if os.path.exists(path):
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write("---\ntitle: Changelogs\nweight: 99\nsidebar:\n  open: false\n---\n")


def _ensure_platform_index(platform: str) -> None:
    platform_dir = os.path.join(CONTENT_DIR, platform)
    os.makedirs(platform_dir, exist_ok=True)
    path = os.path.join(platform_dir, "_index.md")
    if os.path.exists(path):
        return
    weight = PLATFORM_WEIGHT.get(platform, 50)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"---\ntitle: {platform}\nweight: {weight}\n---\n")


def _ensure_severity_index(platform: str, severity: str) -> None:
    sev_dir = os.path.join(CONTENT_DIR, platform, severity)
    os.makedirs(sev_dir, exist_ok=True)
    path = os.path.join(sev_dir, "_index.md")
    if os.path.exists(path):
        return
    weight = SEVERITY_WEIGHT.get(severity, 5)
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            f"---\ntitle: {severity}\nweight: {weight}\nsidebar:\n  open: false\n---\n"
        )


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


async def get_soup(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            content = await response.text()
            return BeautifulSoup(content, "html.parser")
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


async def get_nvd_data(session, cve_id: str) -> dict | None:
    """Fetch full CVE data from NVD API and return a structured dict."""
    params = {"cveId": cve_id}
    try:
        async with session.get(NVD_API_URL, params=params) as response:
            if response.status in (403, 429):
                print(
                    f"Rate limited by NVD for {cve_id} (status {response.status}). Waiting…"
                )
                await asyncio.sleep(30)
                return await get_nvd_data(session, cve_id)

            if response.status != 200:
                print(f"NVD API error {response.status} for {cve_id}")
                return None

            data = await response.json()
            if not data.get("vulnerabilities"):
                return None

            cve_obj = data["vulnerabilities"][0]["cve"]
            metrics = cve_obj.get("metrics", {})

            # English description
            description = next(
                (
                    d["value"]
                    for d in cve_obj.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                "",
            )

            # CVSS — prefer v3.1 > v3.0 > v2
            cvss_data = None
            severity = None
            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]
                severity = m["cvssData"]["baseSeverity"].title()
                cvss_data = m["cvssData"]
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]
                severity = m["cvssData"]["baseSeverity"].title()
                cvss_data = m["cvssData"]
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]
                severity = m["baseMetricV2"]["severity"].title()
                cvss_data = m["cvssData"]

            # CWEs (deduplicated, skip catch-all entries)
            cwes: list[str] = []
            for w in cve_obj.get("weaknesses", []):
                for d in w.get("description", []):
                    val = d.get("value", "")
                    if (
                        d.get("lang") == "en"
                        and val.startswith("CWE-")
                        and val not in cwes
                    ):
                        cwes.append(val)

            # References
            references = [
                {"url": r["url"], "tags": r.get("tags", [])}
                for r in cve_obj.get("references", [])
                if r.get("url")
            ]

            return {
                "severity": severity,
                "description": description,
                "cvss": cvss_data,
                "cwes": cwes,
                "references": references,
            }

    except Exception as e:
        print(f"Failed to fetch NVD data for {cve_id}: {e}")

    return None


async def _get_nvd_data_cached(session, cve_id: str) -> dict | None:
    """
    Fetch NVD data with in-process caching and strict rate limiting.
    Only one NVD request runs at a time to stay within the 5 req/30 s limit.
    """
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    async with _NVD_SEMAPHORE:
        # Re-check after acquiring the semaphore
        if cve_id in _NVD_CACHE:
            return _NVD_CACHE[cve_id]
        data = await get_nvd_data(session, cve_id)
        await asyncio.sleep(NVD_DELAY)
        _NVD_CACHE[cve_id] = data
        return data


def _format_nvd_details(nvd_data: dict | None, cve_id: str, apple_url: str) -> str:
    """Format NVD CVE data as Markdown for the CVE Details accordion."""
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    if not nvd_data:
        return (
            f"No NVD data available for this CVE.\n\n"
            f"- [Apple Security Advisory]({apple_url})\n"
            f"- [NVD Entry]({nvd_url})\n"
        )

    lines: list[str] = []

    # Description
    desc = nvd_data.get("description", "")
    if desc:
        lines += ["**Description**", "", desc, ""]

    # CVSS score table
    cvss = nvd_data.get("cvss")
    if cvss:
        score = cvss.get("baseScore", "N/A")
        sev = cvss.get("baseSeverity", "")
        vector = cvss.get("vectorString", "")
        ver = cvss.get("version", "")
        lines += [
            f"**CVSS {ver} Score**",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Base Score | **{score}** ({sev}) |",
        ]
        if vector:
            lines.append(f"| Vector | `{vector}` |")
        lines.append("")

    # CWE weaknesses
    cwes = nvd_data.get("cwes", [])
    if cwes:
        lines += ["**Weakness**", ""]
        for cwe in cwes:
            cwe_num = cwe.replace("CWE-", "")
            lines.append(
                f"- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
            )
        lines.append("")

    # References
    lines += ["**References**", ""]
    lines.append(f"- [Apple Security Advisory]({apple_url})")
    lines.append(f"- [NVD Entry]({nvd_url})")
    seen = {apple_url, nvd_url}
    for ref in nvd_data.get("references", [])[:8]:
        ref_url = ref.get("url", "")
        tags = ref.get("tags", [])
        if ref_url and ref_url not in seen:
            seen.add(ref_url)
            tag_str = f" *({', '.join(tags)})*" if tags else ""
            lines.append(f"- [{ref_url}]({ref_url}){tag_str}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Changelog writer  (one file per Apple advisory URL, written once)
# ---------------------------------------------------------------------------


def _save_changelog(
    advisory_id: str, title: str, url: str, platforms: list[str], markdown_body: str
) -> None:
    _ensure_changelogs_index()
    path = os.path.join(CHANGELOGS_DIR, f"{advisory_id}.md")
    page = _make_changelog_page(advisory_id, title, url, platforms, markdown_body)
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"Saved changelog {path}")


# ---------------------------------------------------------------------------
# Advisory scraper
# ---------------------------------------------------------------------------


async def process_advisory(session, url, title, nvd_queue):
    print(f"Scraping advisory: {title}")
    soup = await get_soup(session, url)
    if not soup:
        return

    content_div = soup.find("div", {"id": "sections"}) or soup.find(
        "div", {"class": "main"}
    )
    markdown_content = md(str(content_div) if content_div else str(soup))

    platforms = detect_platforms(title)
    advisory_id = _url_id(url)
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cves = set(re.findall(cve_pattern, markdown_content))

    if not cves:
        return

    # Persist the full Apple advisory page as a changelog (idempotent)
    _save_changelog(advisory_id, title, url, platforms, markdown_content)

    for cve in cves:
        for platform in platforms:
            await nvd_queue.put(
                {
                    "cve": cve,
                    "platform": platform,
                    "title": title,
                    "url": url,
                    "advisory_id": advisory_id,
                    "markdown": markdown_content,
                    "date": "Unknown Date",
                }
            )


# ---------------------------------------------------------------------------
# NVD worker  (severity resolution + Hugo CVE page writer)
# ---------------------------------------------------------------------------


async def nvd_worker(session, queue):
    while True:
        item = await queue.get()
        cve = item["cve"]
        platform = item["platform"]

        # ── Step 1: fetch full NVD data (cached + rate-limited per CVE) ──────
        nvd_data = await _get_nvd_data_cached(session, cve)
        nvd_severity = (nvd_data or {}).get("severity")

        # ── Step 2: resolve severity ──────────────────────────────────────────
        if nvd_severity and nvd_severity.upper() in SEVERITY_MAPPING:
            severity = SEVERITY_MAPPING[nvd_severity.upper()]
        else:
            # Fallback: old advisory directory structure still present in repo
            severity = DEFAULT_SEVERITY
            for s in SEVERITY_MAPPING.values():
                if os.path.isdir(os.path.join(BASE_DIR, s, cve)):
                    severity = s
                    break

        print(f"{cve} ({platform}) → {severity}")

        # ── Step 3: always write Hugo CVE page (picks up template changes) ────
        _ensure_platform_index(platform)
        _ensure_severity_index(platform, severity)

        out_dir = os.path.join(CONTENT_DIR, platform, severity)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{cve}.md")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(_make_cve_page(item, cve, severity, nvd_data))
        print(f"Saved {out_path}")

        queue.task_done()


# ---------------------------------------------------------------------------
# README generator
# ---------------------------------------------------------------------------


def update_readme():
    print("Updating README.md…")
    readme_path = os.path.join(BASE_DIR, "README.md")

    tech_columns = [
        "iOS",
        "iPadOS",
        "macOS",
        "tvOS",
        "watchOS",
        "visionOS",
        "Safari",
        "Xcode",
    ]
    severity_counts = {
        s: {t: 0 for t in tech_columns} for s in SEVERITY_MAPPING.values()
    }

    # Count from new Hugo content structure
    if os.path.exists(CONTENT_DIR):
        for platform in os.listdir(CONTENT_DIR):
            if platform not in tech_columns:
                continue
            for severity in SEVERITY_MAPPING.values():
                sev_dir = os.path.join(CONTENT_DIR, platform, severity)
                if not os.path.isdir(sev_dir):
                    continue
                count = sum(
                    1
                    for f in os.listdir(sev_dir)
                    if f.startswith("CVE-") and f.endswith(".md")
                )
                severity_counts[severity][platform] += count

    # Fallback: also tally old advisory directories not yet migrated
    for severity in SEVERITY_MAPPING.values():
        old_sev_dir = os.path.join(BASE_DIR, severity)
        if not os.path.isdir(old_sev_dir):
            continue
        for cve in os.listdir(old_sev_dir):
            if not cve.startswith("CVE-"):
                continue
            cve_dir = os.path.join(old_sev_dir, cve)
            if not os.path.isdir(cve_dir):
                continue
            for platform in os.listdir(cve_dir):
                if platform not in tech_columns:
                    continue
                # Skip if already represented in new structure
                if os.path.exists(
                    os.path.join(CONTENT_DIR, platform, severity, f"{cve}.md")
                ):
                    continue
                severity_counts[severity][platform] += 1

    content = (
        "# Apple CVEs\n\n"
        "Automated tracking of Apple platform security advisories and CVEs.\n\n"
        "## CVE counts by severity and platform\n\n"
    )
    header = "| Severity | " + " | ".join(tech_columns) + " |\n"
    separator = "| :--- | " + " | ".join([":---:"] * len(tech_columns)) + " |\n"
    content += header + separator
    for severity, counts in severity_counts.items():
        row = (
            f"| [{severity}](content/{severity}/) | "
            + " | ".join(str(counts[p]) for p in tech_columns)
            + " |\n"
        )
        content += row

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("README.md updated.")


# ---------------------------------------------------------------------------
# Link extraction helpers (unchanged logic, refactored)
# ---------------------------------------------------------------------------


async def extract_links_from_soup(soup, session, nvd_queue, tasks, processed_urls):
    ADVISORY_KEYWORDS = [
        "iOS",
        "iPadOS",
        "macOS",
        "watchOS",
        "tvOS",
        "Safari",
        "Xcode",
        "visionOS",
    ]
    archive_tasks = []

    for link in soup.find_all("a", href=True):
        text = link.get_text().strip()
        href = link["href"]
        if href.startswith("/"):
            href = "https://support.apple.com" + href

        # Discover archive pages (2020+)
        if "Apple security updates" in text:
            years = re.findall(r"\d{4}", text)
            if years and any(int(y) >= 2020 for y in years):
                if href not in processed_urls:
                    print(f"Found archive: {text} — {href}")
                    processed_urls.add(href)
                    tasks.append(
                        process_archive(session, href, nvd_queue, processed_urls)
                    )
            continue

        if "archive" in text.lower():
            continue

        if any(kw in text for kw in ADVISORY_KEYWORDS):
            if href not in processed_urls:
                processed_urls.add(href)
                archive_tasks.append(process_advisory(session, href, text, nvd_queue))

    if archive_tasks:
        print(f"Main page: processing {len(archive_tasks)} advisories concurrently…")
        await asyncio.gather(*archive_tasks)


async def process_archive(session, url, nvd_queue, processed_urls):
    print(f"Processing archive page: {url}")
    soup = await get_soup(session, url)
    if not soup:
        return

    ADVISORY_KEYWORDS = [
        "iOS",
        "iPadOS",
        "macOS",
        "watchOS",
        "tvOS",
        "Safari",
        "Xcode",
        "visionOS",
    ]
    archive_tasks = []

    for link in soup.find_all("a", href=True):
        text = link.get_text().strip()
        href = link["href"]
        if href.startswith("/"):
            href = "https://support.apple.com" + href

        if "Apple security updates" in text or "archive" in text.lower():
            continue

        if any(kw in text for kw in ADVISORY_KEYWORDS):
            if href not in processed_urls:
                processed_urls.add(href)
                archive_tasks.append(process_advisory(session, href, text, nvd_queue))

    if archive_tasks:
        print(
            f"Archive {url}: processing {len(archive_tasks)} advisories concurrently…"
        )
        await asyncio.gather(*archive_tasks)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main():
    global _NVD_SEMAPHORE
    _NVD_SEMAPHORE = asyncio.Semaphore(1)
    print("Starting async scraper…")

    # Ensure top-level Hugo content skeleton exists
    _ensure_home_index()
    _ensure_changelogs_index()

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.2 Safari/605.1.15"
        )
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        soup = await get_soup(session, APPLE_SECURITY_UPDATES_URL)
        if not soup:
            return

        nvd_queue = asyncio.Queue()
        workers = [
            asyncio.create_task(nvd_worker(session, nvd_queue)) for _ in range(3)
        ]

        tasks = []
        processed_urls = set()

        await extract_links_from_soup(soup, session, nvd_queue, tasks, processed_urls)
        await asyncio.gather(*tasks)
        await nvd_queue.join()

        for w in workers:
            w.cancel()

    update_readme()


if __name__ == "__main__":
    asyncio.run(main())
