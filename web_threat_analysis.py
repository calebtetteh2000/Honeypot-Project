#!/usr/bin/env python3
"""
web_threat_analysis.py
Reads http_audits.log and rebuilds every data-driven section of
web_attack_dashboard_v31.html with REAL attack data — replacing
all hardcoded sample data (stat cards, attack origins, top
usernames/passwords, pages visited, most active attackers,
live login feed, post-login activity, the map, and the OSINT
investigator's IP list).

Usage:
    python web_threat_analysis.py
Output:
    web_attack_dashboard.html  (opens automatically in browser)
"""

import re, json, time, os, webbrowser, requests
from collections import Counter
from datetime import datetime

LOG_FILE      = 'http_audits.log'
TEMPLATE_FILE = 'web_dashboard_template.html'   # never overwrite this file — it's the master design
OUTPUT_FILE   = 'web_attack_dashboard.html'     # this is what gets rebuilt fresh on every run
MAX_GEO       = 200

COUNTRY_FLAGS_FALLBACK = 'xx'

# ── SAMPLE DATA (used only if log is completely empty) ──────────────────────
SAMPLE_LOGINS = [
    {'ts':'2026-06-18 09:00:01','ip':'218.92.0.115',  'username':'admin',         'password':'123456'},
    {'ts':'2026-06-18 09:00:05','ip':'218.92.0.115',  'username':'admin',         'password':'password'},
    {'ts':'2026-06-18 09:00:09','ip':'218.92.0.115',  'username':'administrator', 'password':'admin'},
    {'ts':'2026-06-18 09:01:00','ip':'185.234.219.45','username':'admin',         'password':'admin123'},
    {'ts':'2026-06-18 09:01:30','ip':'77.23.145.67',  'username':'wp-admin',      'password':'wordpress'},
    {'ts':'2026-06-18 09:02:00','ip':'103.56.78.9',   'username':'admin',         'password':'letmein'},
    {'ts':'2026-06-18 09:02:45','ip':'42.114.145.21', 'username':'root',          'password':'toor'},
]
SAMPLE_SUCCESS = [
    {'ts':'2026-06-18 09:05:00','ip':'218.92.0.115',  'username':'admin'},
    {'ts':'2026-06-18 09:12:00','ip':'185.234.219.45','username':'admin'},
]
SAMPLE_ACTIONS = [
    {'ts':'2026-06-18 09:05:10','ip':'218.92.0.115',  'action':'page_loaded_dashboard'},
    {'ts':'2026-06-18 09:05:22','ip':'218.92.0.115',  'action':'open_post_credentials'},
    {'ts':'2026-06-18 09:05:45','ip':'218.92.0.115',  'action':'open_post_backup'},
    {'ts':'2026-06-18 09:06:01','ip':'218.92.0.115',  'action':'menu_plugins'},
    {'ts':'2026-06-18 09:12:10','ip':'185.234.219.45','action':'page_loaded_dashboard'},
    {'ts':'2026-06-18 09:12:33','ip':'185.234.219.45','action':'menu_users'},
]
SAMPLE_GEO = {
    '218.92.0.115':   {'country':'China',      'countryCode':'CN','city':'Shanghai', 'isp':'ChinaNet', 'lat':31.2, 'lon':121.5},
    '185.234.219.45': {'country':'Russia',     'countryCode':'RU','city':'Moscow',   'isp':'Selectel', 'lat':55.75,'lon':37.6},
    '77.23.145.67':   {'country':'Netherlands','countryCode':'NL','city':'Amsterdam','isp':'M247',     'lat':52.37,'lon':4.9},
    '103.56.78.9':    {'country':'India',      'countryCode':'IN','city':'Mumbai',   'isp':'Jio',      'lat':19.07,'lon':72.88},
    '42.114.145.21':  {'country':'Vietnam',    'countryCode':'VN','city':'Hanoi',    'isp':'VNPT',     'lat':21.03,'lon':105.85},
}
# ─────────────────────────────────────────────────────────────────────────────

def parse_log(filepath):
    """Every real login click writes TWO lines to http_audits.log — a raw
    'user | pass' credential line, immediately followed by a same-timestamp
    LOGIN_SUCCESS/LOGIN_FAILED status line. Counting both as separate
    attempts is what made the dashboard show 18 for 9 real submissions.
    This merges each pair into one attempt record."""
    logins, actions, session_times = [], [], []
    pending = None  # holds a raw credential line awaiting its status companion

    def flush(entry):
        if entry is not None:
            logins.append(entry)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or '|' not in line:
                    continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) < 4:
                    continue
                ts, ip, event, detail = parts[0], parts[1], parts[2], parts[3]

                if event in ('LOGIN_SUCCESS', 'LOGIN_FAILED'):
                    if pending and pending['ts'] == ts and pending['ip'] == ip:
                        pending['success'] = (event == 'LOGIN_SUCCESS')
                        flush(pending)
                        pending = None
                    else:
                        # status line with no matching raw line (older log format)
                        flush({'ts': ts, 'ip': ip, 'username': detail, 'password': '',
                               'success': event == 'LOGIN_SUCCESS'})
                elif event == 'POST-LOGIN':
                    actions.append({'ts': ts, 'ip': ip, 'action': detail})
                elif event == 'SESSION_TIME':
                    try:
                        session_times.append(int(detail.replace('s', '')))
                    except:
                        pass
                elif event not in ('LOGOUT',) and len(event) < 40 and '@' not in event:
                    flush(pending)  # an unresolved previous raw line — keep it, don't drop data
                    pending = {'ts': ts, 'ip': ip, 'username': event, 'password': detail, 'success': None}
    except FileNotFoundError:
        pass

    flush(pending)  # trailing raw line with no status line yet
    successes = [l for l in logins if l.get('success')]
    return logins, successes, actions, session_times

def geoip_lookup(ip):
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon',
            timeout=5)
        d = r.json()
        if d.get('status') == 'success':
            return d
    except:
        pass
    return {'country': 'Unknown', 'countryCode': 'XX', 'city': 'Unknown',
            'isp': 'Unknown', 'lat': 0, 'lon': 0}

def build_geo(entries):
    unique = list({e['ip'] for e in entries if e['ip'] not in ('127.0.0.1', '::1', '')})[:MAX_GEO]
    geo = {}
    print(f"[*] Looking up {len(unique)} IP(s)...")
    for i, ip in enumerate(unique, 1):
        print(f"    [{i}/{len(unique)}] {ip}", end=' ')
        geo[ip] = geoip_lookup(ip)
        print(f"→ {geo[ip].get('country', '?')}")
        time.sleep(0.3)
    return geo

def avg_session(times):
    if not times:
        return 0
    return sum(times) // len(times)

def esc(s):
    """Escape for safe HTML insertion."""
    return (str(s).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))

def build_bar_rows(items, value_class='', label_is_mono=False):
    """Build .bar-row HTML blocks matching v31's exact structure."""
    if not items:
        return '<div style="color:#3a6a8a;font-size:12px;padding:8px 0;">No data captured yet — awaiting attacker traffic.</div>'
    max_v = items[0][1] or 1
    rows = []
    for i, (label, count) in enumerate(items[:8], 1):
        pct = max(8, int(count / max_v * 100))
        label_html = f'<span class="mono">{esc(label)}</span>' if label_is_mono else esc(label)
        rows.append(f'''      <div class="bar-row">
        <div class="rank-num">{i:02d}</div>
        <div class="bar-label{(' ' + 'mono') if label_is_mono else ''}">{label_html}</div>
        <div class="bar-track"><div class="bar-fill{value_class}" style="width:{pct}%"></div></div>
        <div class="bar-value">{count}</div>
      </div>''')
    return '\n'.join(rows)

def build_country_rows(country_counts, country_to_code):
    if not country_counts:
        return '<div style="color:#3a6a8a;font-size:12px;padding:8px 0;">No data captured yet.</div>'
    max_v = country_counts[0][1] or 1
    rows = []
    for i, (country, count) in enumerate(country_counts[:8], 1):
        code = country_to_code.get(country, 'xx')
        pct = max(8, int(count / max_v * 100))
        rows.append(f'''      <div class="bar-row">
        <div class="rank-num">{i:02d}</div>
        <div class="bar-label"><img class="flag" src="https://flagcdn.com/w20/{code}.png" onerror="this.style.display='none'"> {esc(country)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
        <div class="bar-value">{count}</div>
      </div>''')
    return '\n'.join(rows)

def build_attacker_rows(attackers):
    if not attackers:
        return '<div style="color:#3a6a8a;font-size:12px;padding:8px 0;">No attackers detected yet.</div>'
    rows = []
    for i, a in enumerate(attackers[:6]):
        border = ' style="border-bottom:none;"' if i == len(attackers[:6]) - 1 else ''
        rows.append(f'''        <div class="ip-row"{border}>
          <div class="ip-main"><img class="flag" src="https://flagcdn.com/w20/{a['code']}.png" onerror="this.style.display='none'"> <span class="mono">{a['ip']}</span></div>
          <div class="ip-sub">{esc(a['country'])} · {esc(a['city'])} · {a['count']} attempts</div>
        </div>''')
    return '\n'.join(rows)

def build_login_feed(logins, geo):
    if not logins:
        return '<div style="color:#3a6a8a;font-size:12px;padding:8px 0;">No login attempts captured yet.</div>'
    rows = []
    for e in logins[-15:][::-1]:
        info = geo.get(e['ip'], {})
        code = info.get('countryCode', 'XX').lower()
        cred = f"{e['username']}:{e.get('password','') or '(empty)'}"
        rows.append(f'''      <div class="feed-row">
        <span class="feed-time">{esc(e['ts'])}</span>
        <img class="flag" src="https://flagcdn.com/w20/{code}.png" onerror="this.style.display='none'">
        <span class="mono">{esc(e['ip'])}</span>
        <span class="feed-arrow">&rarr;</span>
        <span class="feed-cred">{esc(cred)}</span>
      </div>''')
    return '\n'.join(rows)

def build_activity_feed(actions, geo):
    if not actions:
        return '<div style="color:#3a6a8a;font-size:12px;padding:8px 0;">No post-login activity captured yet.</div>'
    danger_words = ['credential', 'backup', 'password', 'db', 'upload', 'keystore', 'export']
    rows = []
    for e in actions[-20:][::-1]:
        info = geo.get(e['ip'], {})
        code = info.get('countryCode', 'XX').lower()
        action = e['action']
        is_danger = any(w in action.lower() for w in danger_words)
        row_class = 'activity-row danger' if is_danger else 'activity-row'
        if action.startswith('/'):
            icon, span = '📄', f'<span class="action-nav">{esc(action)}</span>'
        elif 'login' in action.lower():
            icon, span = '🚪', f'<span class="action-login">Logged In</span>'
        elif 'click' in action.lower() or is_danger:
            icon, span = '⚠️', f'<span class="action-click">{esc(action)}</span>'
        else:
            icon, span = '🖱️', f'<span class="action-nav">{esc(action)}</span>'
        rows.append(f'''      <div class="{row_class}">
        <span class="feed-time">{esc(e['ts'])}</span>
        <img class="flag" src="https://flagcdn.com/w20/{code}.png" onerror="this.style.display='none'">
        <span class="mono">{esc(e['ip'])}</span>
        <span class="activity-icon">{icon}</span>
        <span>{span}</span>
      </div>''')
    return '\n'.join(rows)

def analyse(logins, successes, actions, geo):
    # attempt counts are credential attempts only — nav clicks (actions) are a
    # different signal and used to inflate the "attempts" badge (e.g. 58 for
    # an IP that only actually submitted the login form a handful of times)
    ip_counts = Counter(e['ip'] for e in logins)
    usernames = Counter(e['username'] for e in logins)
    passwords = Counter(e.get('password', '') for e in logins if e.get('password', '').strip())
    # real action names are like 'menu_posts' / 'page_load_dashboard' — never
    # start with '/', so the old filter here left this panel permanently empty
    pages = Counter(e['action'] for e in actions)

    country_counts = Counter()
    country_to_code = {}
    for ip, count in ip_counts.items():
        info = geo.get(ip, {})
        country = info.get('country', 'Unknown')
        country_counts[country] += count
        country_to_code[country] = info.get('countryCode', 'XX').lower()

    attackers = []
    for ip, count in ip_counts.most_common(10):
        info = geo.get(ip, {})
        attackers.append({
            'ip': ip, 'count': count,
            'country': info.get('country', 'Unknown'),
            'code': info.get('countryCode', 'XX').lower(),
            'city': info.get('city', ''),
            'isp': info.get('isp', ''),
            'lat': info.get('lat', 0),
            'lon': info.get('lon', 0),
        })

    confidential_clicks = sum(1 for e in actions
                               if any(w in e['action'].lower() for w in ('credential', 'backup', 'password')))

    return {
        'total_attempts': len(logins),
        'unique_attackers': len(ip_counts),
        'countries': len(country_counts),
        'confidential_clicks': confidential_clicks,
        'usernames': usernames.most_common(8),
        'passwords': passwords.most_common(8),
        'pages': pages.most_common(8),
        'countries_list': country_counts.most_common(8),
        'country_to_code': country_to_code,
        'attackers': attackers,
    }

def replace_block(html, marker_name, fallback_pattern, new_statement):
    """Replace a JS data-array declaration. Prefers the exact
    /* NAME_START */ ... /* NAME_END */ marker pair (can't accidentally
    match too much or too little). Falls back to the old non-greedy regex
    for any template copy that doesn't have the markers yet."""
    start, end = f'/* {marker_name}_START */', f'/* {marker_name}_END */'
    marker_pattern = re.escape(start) + r'.*?' + re.escape(end)
    if re.search(marker_pattern, html, flags=re.DOTALL):
        return re.sub(marker_pattern, f'{start}\n{new_statement}\n{end}', html, count=1, flags=re.DOTALL)
    return re.sub(fallback_pattern, new_statement, html, count=1, flags=re.DOTALL)


def inject_into_v31(stats, geo, session_avg, logins_all, actions_all, template_path, output_path):
    with open(template_path, 'r', encoding='utf-8', errors='ignore') as f:
        html = f.read()

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # build_*_rows() renders this exact placeholder when a panel has zero
    # data. Every panel regex below must match EITHER the placeholder OR
    # real row divs — matching only real rows means a panel that was ever
    # empty (like Pages Visited was, before the startswith('/') fix) can
    # never be refilled on a later run, because the regex has nothing to
    # grab onto once the placeholder is what's actually in the file.
    NODATA = r'\s*<div style="color:#3a6a8a;[^"]*">[^<]*</div>\s*'

    # ── 1. Stat cards (data-count attributes) ─────────────────────────────────
    stat_replacements = [
        (r'(<div class="num" data-count=")\d+(">0</div><div class="lbl">Login Attempts</div>)',
         rf'\g<1>{stats["total_attempts"]}\2'),
        (r'(<div class="num" data-count=")\d+(">0</div><div class="lbl">Unique Attackers</div>)',
         rf'\g<1>{stats["unique_attackers"]}\2'),
        (r'(<div class="num" data-count=")\d+(">0</div><div class="lbl">Countries Detected</div>)',
         rf'\g<1>{stats["countries"]}\2'),
        (r'(<div class="num" data-count=")\d+(">0</div><div class="lbl">Confidential Clicks</div>)',
         rf'\g<1>{stats["confidential_clicks"]}\2'),
        (r'(<div class="num" data-count=")\d+(" data-suffix="s">0</div>)',
         rf'\g<1>{session_avg}\2'),
    ]
    for pattern, repl in stat_replacements:
        html = re.sub(pattern, repl, html)

    # ── 2. Attack Origins panel ────────────────────────────────────────────────
    origins_html = build_country_rows(stats['countries_list'], stats['country_to_code'])
    html = re.sub(
        r'(<h2>Attack Origins</h2>\s*)(?:(?:\s*<div class="bar-row">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*<div class="panel" style="margin-bottom:18px;">\s*<h2>Top Usernames)',
        rf'\g<1>\n{origins_html}\n    ', html, flags=re.DOTALL
    )

    # ── 3. Top Usernames panel ─────────────────────────────────────────────────
    usernames_html = build_bar_rows(stats['usernames'], value_class=' alt', label_is_mono=True)
    html = re.sub(
        r'(<h2>Top Usernames</h2>\s*)(?:(?:\s*<div class="bar-row">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*<div class="panel">\s*<h2>Top Passwords)',
        rf'\g<1>\n{usernames_html}\n    ', html, flags=re.DOTALL
    )

    # ── 4. Top Passwords panel ─────────────────────────────────────────────────
    passwords_html = build_bar_rows(stats['passwords'], value_class=' alt', label_is_mono=True)
    html = re.sub(
        r'(<h2>Top Passwords</h2>\s*)(?:(?:\s*<div class="bar-row">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*</div>\s*<div>\s*<div class="panel">\s*<h2>Global Attack Map)',
        rf'\g<1>\n{passwords_html}\n    ', html, flags=re.DOTALL
    )

    # ── 5. Pages Visited Post-Login panel ──────────────────────────────────────
    pages_html = build_bar_rows(stats['pages'], value_class=' alt')
    if stats['pages']:
        max_v = stats['pages'][0][1] or 1
        rows = []
        for i, (label, count) in enumerate(stats['pages'][:8], 1):
            pct = max(8, int(count / max_v * 100))
            rows.append(f'''      <div class="bar-row">
        <div class="rank-num">{i:02d}</div>
        <div class="bar-label mono"><span class="action-nav">{esc(label)}</span></div>
        <div class="bar-track"><div class="bar-fill alt" style="width:{pct}%"></div></div>
        <div class="bar-value">{count}</div>
      </div>''')
        pages_html = '\n'.join(rows)
    html = re.sub(
        r'(<h2>Pages Visited Post-Login</h2>\s*)(?:(?:\s*<div class="bar-row">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*</div>\s*<div>)',
        rf'\g<1>\n{pages_html}\n    ', html, flags=re.DOTALL
    )

    # ── 6. Most Active Attackers panel ─────────────────────────────────────────
    attackers_html = build_attacker_rows(stats['attackers'])
    html = re.sub(
        r'(<div id="attacker-list">\s*)(?:(?:\s*<div class="ip-row".*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*</div>\s*<!-- ── PANEL 2)',
        rf'\g<1>\n{attackers_html}\n        ', html, flags=re.DOTALL
    )

    # ── 7. Live Login Feed panel ───────────────────────────────────────────────
    feed_html = build_login_feed(logins_all, geo)
    html = re.sub(
        r'(<div class="scroll-box" style="max-height:220px;" id="login-feed">\s*)(?:(?:\s*<div class="feed-row">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*</div>\s*<!-- ── PANEL 3)',
        rf'\g<1>\n{feed_html}\n      ', html, flags=re.DOTALL
    )

    # ── 8. Post-Login Activity panel ───────────────────────────────────────────
    activity_html = build_activity_feed(actions_all, geo)
    html = re.sub(
        r'(<div class="scroll-box" style="max-height:300px;" id="activity-feed">\s*)(?:(?:\s*<div class="activity-row[^"]*">.*?</div>\s*)+|' + NODATA + r')(?=\s*</div>\s*</div>\s*</div>)',
        rf'\g<1>\n{activity_html}\n        ', html, flags=re.DOTALL
    )

    # ── 9. mapPoints JS array (drives the globe) ───────────────────────────────
    map_points = []
    seen_codes = set()
    for a in stats['attackers']:
        if a['lat'] == 0 and a['lon'] == 0:
            continue
        if a['code'] in seen_codes:
            continue
        seen_codes.add(a['code'])
        total = sum(x['count'] for x in stats['attackers'] if x['code'] == a['code'])
        map_points.append({
            'ip': a['ip'], 'country': a['country'], 'city': a['city'],
            'isp': a['isp'] or 'Unknown ISP', 'lat': a['lat'], 'lon': a['lon'],
            'flag': a['code'], 'attempts': total,
        })

    # Note: mapPoints stays empty when every hit so far is from 127.0.0.1 —
    # that's correct, not a bug. The template already has a permanent static
    # "HONEYPOT · Accra, Ghana" pin (see the `honeypot` const above) that
    # renders regardless, so the globe is never actually blank; attacker
    # arcs simply appear the moment a real external IP hits the honeypot.
    new_map_points = f"const mapPoints = {json.dumps(map_points)};"
    html = replace_block(html, 'DATA_MAPPOINTS', r'const mapPoints\s*=\s*\[.*?\];', new_map_points)

    # ── 10. ATTACKER_IPS JS array (drives the OSINT investigator page) ─────────
    attacker_ips_js = []
    for a in stats['attackers'][:8]:
        attacker_ips_js.append(
            f"  {{ ip:'{a['ip']}', flag:'{a['code']}', country:'{esc(a['country'])}', "
            f"city:'{esc(a['city'])}', attempts:{a['count']} }},"
        )
    new_attacker_ips = "const ATTACKER_IPS = [\n" + "\n".join(attacker_ips_js) + "\n];"
    html = replace_block(html, 'DATA_ATTACKERIPS', r'const ATTACKER_IPS\s*=\s*\[.*?\];', new_attacker_ips)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

def main():
    print("=" * 55)
    print("  WEB HONEYPOT THREAT ANALYSER (v31 injector)")
    print("=" * 55)

    if not os.path.exists(TEMPLATE_FILE):
        print(f"[!] Template not found at: {TEMPLATE_FILE}")
        print(f"    Make sure {TEMPLATE_FILE} is in the same folder as this script.")
        return

    logins, successes, actions, times = parse_log(LOG_FILE)
    using_sample = False

    if not logins and not actions:
        print("[!] No data in log yet. Using SAMPLE data so you can preview the design.")
        logins, successes, actions = SAMPLE_LOGINS, SAMPLE_SUCCESS, SAMPLE_ACTIONS
        geo = SAMPLE_GEO
        using_sample = True
    else:
        print(f"[*] Found {len(logins)} login attempts, {len(successes)} successful logins, {len(actions)} post-login actions.")
        geo = build_geo(logins + actions)

    session_avg = avg_session(times)
    print("[*] Analysing real attack data...")
    stats = analyse(logins, successes, actions, geo)

    print(f"\n[*] Results:")
    print(f"    Total attempts    : {stats['total_attempts']}")
    print(f"    Unique attackers  : {stats['unique_attackers']}")
    print(f"    Countries         : {stats['countries']}")
    print(f"    Confidential clicks: {stats['confidential_clicks']}")

    if using_sample:
        print("\n[!] NOTE: Dashboard currently shows SAMPLE data.")
        print("    Once your honeypot is deployed and collects real traffic,")
        print("    re-run this script to inject real attacker data.")

    print(f"\n[*] Rebuilding dashboard with real data → {OUTPUT_FILE}")
    inject_into_v31(stats, geo, session_avg, logins, actions, TEMPLATE_FILE, OUTPUT_FILE)

    print(f"[✓] Done! Opening dashboard...")
    print("=" * 55)
    webbrowser.open('file:///' + os.path.abspath(OUTPUT_FILE).replace('\\', '/'))

if __name__ == '__main__':
    main()
