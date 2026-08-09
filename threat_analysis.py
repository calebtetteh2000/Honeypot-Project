#!/usr/bin/env python3
"""
threat_analysis.py — SSH Honeypot Dashboard Generator
Reads audits.log + cmd_audits.log, geocodes real IPs via ip-api.com,
then injects live data into ssh_attack_dashboard_v15.html and opens it.

Usage:
    python threat_analysis.py

Requirements:
    pip install requests
    ssh_attack_dashboard_v15.html must be in the same folder as this script.
"""

import os, re, json, time, webbrowser
from datetime import datetime
from collections import Counter

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] 'requests' not installed — GeoIP lookup disabled. Run: pip install requests")

# ── CONFIG ───────────────────────────────────────────────────────────────────
AUDITS_LOG    = 'audits.log'
CMD_LOG       = 'cmd_audits.log'
TEMPLATE_FILE = 'ssh_attack_dashboard_v15.html'
OUTPUT_FILE   = 'attack_dashboard.html'
MAX_GEO       = 100
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS = {'cat /etc/passwd', 'wget', 'curl', 'id', 'uname -a',
             'ps aux', 'ifconfig', 'ip a', 'cat jumpbox1.conf'}

def is_dangerous(cmd):
    cmd = cmd.lower().strip()
    return any(d in cmd for d in DANGEROUS)

# ── LOG PARSERS ───────────────────────────────────────────────────────────────

def parse_audits(path):
    """Parse audits.log → [{timestamp, ip, username, password}]"""
    entries = []
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or '|' not in line:
                    continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 4:
                    entries.append({
                        'timestamp': parts[0],
                        'ip':        parts[1],
                        'username':  parts[2],
                        'password':  parts[3],
                    })
    except FileNotFoundError:
        print(f"[!] {path} not found.")
    return entries


def parse_cmd_log(path):
    """
    Parse cmd_audits.log into sessions.
    A session begins at each login line (4 pipe fields, username not b'...').
    Commands appear as:
      New:  2026-06-10 10:22:51 | 127.0.0.1 | b'pwd'
      Old:  Command b'ls' executed by 127.0.0.1
    """
    sessions = []
    current  = None
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    # Login line: ts | ip | user | password
                    if len(parts) == 4 and not parts[2].startswith("b'"):
                        if current:
                            sessions.append(current)
                        current = {
                            'ip':      parts[1],
                            'start':   parts[0],
                            'country': 'Unknown',
                            'code':    'un',
                            'cmds':    [],
                        }
                    # Command line: ts | ip | b'cmd'
                    elif len(parts) == 3 and current:
                        raw = parts[2].strip("b'\" ")
                        ts  = parts[0][11:19] if len(parts[0]) > 11 else ''
                        current['cmds'].append({
                            'ts':     ts,
                            'cmd':    raw,
                            'danger': is_dangerous(raw),
                        })
                # Old format: Command b'ls' executed by 127.0.0.1
                elif line.startswith('Command ') and 'executed by' in line:
                    m = re.match(r"Command b'(.+?)' executed by .+", line)
                    if m and current:
                        cmd = m.group(1)
                        current['cmds'].append({
                            'ts':     '',
                            'cmd':    cmd,
                            'danger': is_dangerous(cmd),
                        })
        if current:
            sessions.append(current)
    except FileNotFoundError:
        print(f"[!] {path} not found.")
    return sessions


# ── GEOIP ─────────────────────────────────────────────────────────────────────

def geoip(ip):
    if not HAS_REQUESTS:
        return {}
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon',
            timeout=5)
        d = r.json()
        if d.get('status') == 'success':
            return d
    except Exception:
        pass
    return {}


def geocode_all(ips):
    cache = {}
    ips = [ip for ip in dict.fromkeys(ips)
           if ip not in ('127.0.0.1', '::1', 'localhost', '')][:MAX_GEO]
    if not ips:
        return cache
    for i, ip in enumerate(ips, 1):
        print(f'    [{i}/{len(ips)}] {ip}', end=' ', flush=True)
        cache[ip] = geoip(ip)
        print(f"→ {cache[ip].get('country', 'Unknown')}")
        time.sleep(0.35)
    return cache


# ── ANALYSIS ──────────────────────────────────────────────────────────────────

COUNTRY_CODES = {
    'China':'cn','Russia':'ru','Netherlands':'nl','Vietnam':'vn','India':'in',
    'United States':'us','Tunisia':'tn','Brazil':'br','Ukraine':'ua','Nigeria':'ng',
    'Taiwan':'tw','Germany':'de','United Kingdom':'gb','France':'fr','Japan':'jp',
    'South Korea':'kr','Australia':'au','Canada':'ca','Singapore':'sg',
    'Hong Kong':'hk','Turkey':'tr','Poland':'pl','Romania':'ro','Italy':'it',
    'Spain':'es','Indonesia':'id','Pakistan':'pk','Egypt':'eg','Ghana':'gh',
}

def geo_of(ip, cache):
    return cache.get(ip, {
        'country': 'Unknown', 'countryCode': 'XX', 'city': 'Unknown',
        'isp': 'Unknown', 'lat': 0, 'lon': 0,
    })


def analyse(entries, sessions, geo):
    ip_counts  = Counter(e['ip'] for e in entries)
    usernames  = Counter(e['username'] for e in entries)
    passwords  = Counter(e['password'] for e in entries)

    country_cnt = Counter()
    for ip, cnt in ip_counts.items():
        country_cnt[geo_of(ip, geo).get('country', 'Unknown')] += cnt

    # attackers list
    attackers = []
    for ip, cnt in ip_counts.most_common(20):
        g = geo_of(ip, geo)
        attackers.append({
            'ip':      ip,
            'count':   cnt,
            'country': g.get('country', 'Unknown'),
            'code':    g.get('countryCode', 'XX').lower(),
            'city':    g.get('city', ''),
            'isp':     g.get('isp', ''),
            'lat':     g.get('lat', 0),
            'lon':     g.get('lon', 0),
        })

    # attack dots for the map
    seen = set()
    attack_dots = []
    for a in attackers:
        if a['lat'] == 0 and a['lon'] == 0:
            continue
        if a['code'] in seen:
            continue
        seen.add(a['code'])
        attack_dots.append({
            'lat':     a['lat'],  'lon':     a['lon'],
            'country': a['country'], 'city':    a['city'],
            'count':   a['count'],   'ip':      a['ip'],
            'isp':     a['isp'],     'code':    a['code'].upper(),
        })

    # enrich sessions with geo
    for s in sessions:
        g = geo_of(s['ip'], geo)
        s['country'] = g.get('country', 'Unknown')
        s['code']    = g.get('countryCode', 'XX').lower()

    # login feed (most recent 20)
    feed = []
    for e in entries[-20:][::-1]:
        g = geo_of(e['ip'], geo)
        feed.append({
            'ts':     e['timestamp'][11:19] if len(e['timestamp']) > 11 else '',
            'ip':     e['ip'],
            'code':   g.get('countryCode', 'XX').lower(),
            'user':   e['username'],
            'pw':     e['password'],
            'danger': e['username'] in ('root', 'admin'),
        })

    # OSINT IP list
    osint_ips = [
        {'ip': a['ip'], 'country': a['country'], 'code': a['code'], 'count': a['count']}
        for a in attackers[:10]
    ]

    return {
        'total':         len(entries),
        'unique_ips':    len(ip_counts),
        'countries':     len(country_cnt),
        'cred_variants': len(passwords),
        'usernames':     usernames.most_common(8),
        'passwords':     passwords.most_common(8),
        'countries_top': country_cnt.most_common(12),
        'attackers':     attackers,
        'attack_dots':   attack_dots,
        'sessions':      sessions[:20],
        'feed':          feed,
        'osint_ips':     osint_ips,
    }


# ── JS ARRAY INJECTION ────────────────────────────────────────────────────────

def replace_js_array(html, var_name, new_data):
    """Replace: const varName = [...]; with real data"""
    new_json = json.dumps(new_data, indent=2, ensure_ascii=False)
    pattern = rf'(const {re.escape(var_name)}\s*=\s*)\[[\s\S]*?\];'
    replacement = rf'\g<1>{new_json};'
    result = re.sub(pattern, replacement, html, count=1)
    if result == html:
        print(f"    [!] Could not find JS array: {var_name}")
    return result


def replace_marked_block(html, start_marker, end_marker, new_content):
    """Replace HTML between <!-- START --> and <!-- END --> markers"""
    pattern = rf'{re.escape(start_marker)}[\s\S]*?{re.escape(end_marker)}'
    replacement = f'{start_marker}\n{new_content}\n{end_marker}'
    return re.sub(pattern, replacement, html, count=1)


def replace_js_block(html, start_marker, end_marker, new_content):
    """Replace JS between /* START */ and /* END */ markers"""
    pattern = rf'{re.escape(start_marker)}[\s\S]*?{re.escape(end_marker)}'
    replacement = f'{start_marker}\n{new_content}\n{end_marker}'
    return re.sub(pattern, replacement, html, count=1)


def flag_img(code, size=20):
    code = (code or 'xx').lower()
    return (f'<img class="flagimg" src="https://flagcdn.com/w{size}/{code}.png" '
            f'alt="{code.upper()}" onerror="this.style.display=\'none\'">')


def inject(template, stats):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1 ── Stat cards (SSH Threat Map page)
    def scard(v, label, sc):
        return (f'<div class="stat-card" style="--sc:{sc}">'
                f'<div class="num" data-count="{v}">{v}</div>'
                f'<div class="lbl">{label}</div>'
                f'<div class="pbar"></div></div>')

    stat_html = (
        scard(stats['total'],         'TOTAL ATTEMPTS',      'var(--c-prime)') +
        scard(stats['unique_ips'],    'UNIQUE ATTACKERS',    'var(--c-danger)') +
        scard(stats['countries'],     'COUNTRIES DETECTED',  'var(--c-gold)') +
        scard(stats['cred_variants'], 'CREDENTIAL VARIANTS', 'var(--c-cyan)')
    )
    template = replace_marked_block(template, '<!--STATS_START-->', '<!--STATS_END-->', stat_html)

    # 2 ── JS data arrays (these feed all the panels via renderBarList etc.)
    def to_username_arr(data):
        top = data[0][1] if data else 1
        return [{'rank':i+1,'name':n,'count':c,'pct':round(c/top*100)}
                for i,(n,c) in enumerate(data)]

    def to_country_arr(data):
        top = data[0][1] if data else 1
        return [{'rank':i+1,'country':c,'code':COUNTRY_CODES.get(c,'xx'),
                 'count':cnt,'pct':round(cnt/top*100)}
                for i,(c,cnt) in enumerate(data)]

    def to_attackers_arr(attackers):
        return [{'ip':a['ip'],'country':a['country'],'code':a['code'],'count':a['count']}
                for a in attackers[:8]]

    def to_feed_arr(feed):
        return [{'ts':e['ts'],'ip':e['ip'],'code':e['code'],
                 'user':e['user'],'pw':e['pw'],'danger':e['danger']}
                for e in feed]

    template = replace_js_array(template, 'usernamesData',  to_username_arr(stats['usernames']))
    template = replace_js_array(template, 'passwordsData',  to_username_arr(stats['passwords']))
    template = replace_js_array(template, 'originsData',    to_country_arr(stats['countries_top']))
    template = replace_js_array(template, 'attackersData',  to_attackers_arr(stats['attackers']))
    template = replace_js_array(template, 'loginFeedData',  to_feed_arr(stats['feed']))

    # 3 ── Attack dots (map markers)
    dots_js = 'const attackDots=' + json.dumps(stats['attack_dots'], indent=2, ensure_ascii=False) + ';'
    template = replace_js_block(template, '/* DATA_ATTACKDOTS_START */', '/* DATA_ATTACKDOTS_END */', dots_js)

    # 4 ── Sessions (Command Log tab)
    sess_arr = []
    for s in stats['sessions']:
        sess_arr.append({
            'ip':      s['ip'],
            'country': s['country'],
            'code':    s['code'],
            'start':   s['start'][11:19] if len(s['start']) > 11 else s['start'],
            'cmds':    [{'ts':c['ts'],'cmd':c['cmd'],'danger':c.get('danger',False)}
                        for c in s['cmds']],
        })
    sessions_js = 'const sessionsData = ' + json.dumps(sess_arr, indent=2, ensure_ascii=False) + ';'
    template = replace_js_block(template, '/* DATA_SESSIONS_START */', '/* DATA_SESSIONS_END */', sessions_js)

    # 5 ── OSINT IP list
    osint_js = 'const osintIPs = ' + json.dumps(stats['osint_ips'], indent=2, ensure_ascii=False) + ';'
    template = replace_js_block(template, '/* DATA_OSINT_START */', '/* DATA_OSINT_END */', osint_js)

    # 6 ── Command Log stat cards
    all_cmds     = [c for s in stats['sessions'] for c in s['cmds']]
    danger_count = sum(1 for c in all_cmds if c.get('danger'))
    cmd_counts   = Counter(c['cmd'] for c in all_cmds)
    top_cmd      = cmd_counts.most_common(1)[0] if cmd_counts else ('—', 0)
    cmd_stat_html = (
        scard(len(all_cmds),         'COMMANDS LOGGED',          'var(--c-prime)') +
        scard(len(stats['sessions']), 'SHELL SESSIONS',           'var(--c-cyan)') +
        f'<div class="stat-card" style="--sc:var(--c-gold)">'
        f'<div class="num" id="cmd-top-num" data-count="{top_cmd[1]}">{top_cmd[1]}</div>'
        f'<div class="lbl" id="cmd-top-lbl">TOP: {top_cmd[0].upper()[:12]}</div>'
        f'<div class="pbar"></div></div>' +
        scard(danger_count, 'RECON / DANGEROUS CMDS', 'var(--c-danger)')
    )
    template = replace_marked_block(template, '<!--CMDSTATS_START-->', '<!--CMDSTATS_END-->', cmd_stat_html)

    # 7 ── Session list HTML (Command Log left panel)
    sess_html = ''
    for idx, s in enumerate(stats['sessions'][:20]):
        danger_c = sum(1 for c in s['cmds'] if c.get('danger'))
        border   = 'var(--c-danger)' if danger_c else 'var(--c-prime-dim)'
        ts_disp  = s['start'][11:19] if len(s['start']) > 11 else s['start']
        sess_html += f'''<div class="sess-row" data-idx="{idx}" onclick="loadSession({idx})"
  style="background:#020f08;border:1px solid var(--c-line);border-left:3px solid {border};
  padding:9px 10px;cursor:pointer;margin-bottom:6px;transition:background .15s;"
  onmouseover="this.style.background='#021a0e'" onmouseout="this.style.background='#020f08'">
  <div style="display:flex;justify-content:space-between;align-items:center;">
    <span style="font-family:'Share Tech Mono',monospace;font-size:10.5px;color:#ff5577;">{s['ip']}</span>
    <span style="font-size:9px;color:var(--c-text-dim);">{ts_disp}</span>
  </div>
  <div style="display:flex;align-items:center;gap:5px;margin-top:4px;font-size:9.5px;color:var(--c-text-dim);">
    {flag_img(s['code'], 16)}<span>{s['country']}</span>
    <span style="margin-left:auto;color:var(--c-gold);">{len(s['cmds'])} cmd{"s" if len(s["cmds"])!=1 else ""}</span>
  </div>
</div>'''
    template = replace_marked_block(template, '<!--SESSIONS_START-->', '<!--SESSIONS_END-->', sess_html)

    # 8 ── OSINT registry HTML
    osint_html = ''
    max_c = max((a['count'] for a in stats['attackers']), default=1)
    for a in stats['attackers'][:8]:
        rid   = a['ip'].replace('.', '-')
        bars  = ''.join(
            f'<i style="height:{3+n*1.7}px;'
            f'{"background:var(--c-prime);box-shadow:0 0 4px var(--c-prime);" if a["count"]/max_c >= n/5 else "opacity:.25;"}'
            f'"></i>'
            for n in range(1, 6)
        )
        osint_html += f'''<div class="osint-row" id="osint-row-{rid}" onclick="investigate('{a['ip']}')">
  <div class="oaddr mono">{flag_img(a['code'], 16)}{a['ip']}</div>
  <div class="osint-sig">{bars}</div>
</div>'''
    template = replace_marked_block(template, '<!--OSINTLIST_START-->', '<!--OSINTLIST_END-->', osint_html)

    # 9 ── Generation timestamp
    template = re.sub(r'id="gen-time">[^<]+<', f'id="gen-time">{now}<', template)

    return template


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print('=' * 55)
    print('  SSH HONEYPOT DASHBOARD GENERATOR')
    print('=' * 55)

    base = os.path.dirname(os.path.abspath(__file__))

    # Parse logs
    entries  = parse_audits(os.path.join(base, AUDITS_LOG))
    sessions = parse_cmd_log(os.path.join(base, CMD_LOG))
    print(f'[*] Parsed {len(entries)} login attempts, {len(sessions)} shell session(s).')

    # GeoIP
    all_ips  = list({e['ip'] for e in entries} | {s['ip'] for s in sessions})
    real_ips = [ip for ip in all_ips if ip not in ('127.0.0.1', '::1', '')]
    geo = {}
    if real_ips and HAS_REQUESTS:
        print(f'[*] Geocoding {len(real_ips)} unique IP(s)...')
        geo = geocode_all(real_ips)
    elif not real_ips:
        print('[!] All IPs are 127.0.0.1 (local test). Deploy to a server for real attacker data.')

    # Analyse
    stats = analyse(entries, sessions, geo)
    print(f'[*] Totals → attempts:{stats["total"]}  attackers:{stats["unique_ips"]}  '
          f'countries:{stats["countries"]}  sessions:{len(sessions)}')

    # Load template
    tpl_path = os.path.join(base, TEMPLATE_FILE)
    if not os.path.exists(tpl_path):
        print(f'\n[!] ERROR: Template not found: {TEMPLATE_FILE}')
        print(f'    Make sure ssh_attack_dashboard_v15.html is in your project folder.')
        print(f'    Expected location: {tpl_path}')
        return

    with open(tpl_path, encoding='utf-8') as f:
        template = f.read()
    print(f'[*] Loaded template: {TEMPLATE_FILE}')

    # Inject & write
    print('[*] Injecting real data...')
    html = inject(template, stats)

    out_path = os.path.join(base, OUTPUT_FILE)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f'[✓] Dashboard saved → {OUTPUT_FILE}')
    print('[✓] Opening in browser...')
    print('=' * 55)
    webbrowser.open('file:///' + out_path.replace('\\', '/'))


if __name__ == '__main__':
    main()
