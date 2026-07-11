#!/usr/bin/env python3
"""
analyse_attacks.py
SSH Honeypot Attack Analysis Script
Reads audits.log, looks up each IP address country via ip-api.com,
and generates a hacker-themed HTML dashboard with real attack data.

Usage:
    python analyse_attacks.py
Output:
    attack_dashboard.html  (open in any browser)
"""

import re
import json
import time
import requests
from collections import Counter
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────────────────────────
LOG_FILE      = 'audits.log'
OUTPUT_FILE   = 'attack_dashboard.html'
MAX_GEO_LOOKUPS = 200   # stop after this many IP lookups (free API limit)
# ─────────────────────────────────────────────────────────────────────────────

COUNTRY_FLAGS = {
    'CN':'🇨🇳','RU':'🇷🇺','US':'🇺🇸','NL':'🇳🇱','DE':'🇩🇪','BR':'🇧🇷',
    'IN':'🇮🇳','VN':'🇻🇳','TW':'🇹🇼','UA':'🇺🇦','TN':'🇹🇳','FR':'🇫🇷',
    'GB':'🇬🇧','KR':'🇰🇷','JP':'🇯🇵','SG':'🇸🇬','HK':'🇭🇰','TR':'🇹🇷',
    'PL':'🇵🇱','RO':'🇷🇴','IT':'🇮🇹','ES':'🇪🇸','CA':'🇨🇦','AU':'🇦🇺',
    'NG':'🇳🇬','GH':'🇬🇭','ZA':'🇿🇦','EG':'🇪🇬','PK':'🇵🇰','ID':'🇮🇩',
}

def flag_img(code):
    """Return an <img> tag for a country flag."""
    code = (code or 'XX').upper()
    return (
        f'<img src="https://flagcdn.com/w20/{code.lower()}.png" '
        f'width="20" height="14" style="vertical-align:middle;margin-right:6px;'
        f'border:1px solid #1a4d1a;image-rendering:pixelated;" '
        f'onerror="this.style.display=\'none\'">'
    )

def parse_log(filepath):
    """
    Parse lines in two formats:
      New:  2026-06-10 09:08:45 | 127.0.0.1 | root | qwerty
      Old:  127.0.0.1, root, qwerty
    Returns list of dicts with keys: ip, username, password, timestamp
    """
    entries = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # New timestamped format
                if '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 4:
                        entries.append({
                            'timestamp': parts[0],
                            'ip':        parts[1],
                            'username':  parts[2],
                            'password':  parts[3],
                        })
                # Old format
                elif ',' in line and 'Command' not in line and 'Client' not in line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 3:
                        entries.append({
                            'timestamp': '',
                            'ip':        parts[0],
                            'username':  parts[1],
                            'password':  parts[2],
                        })
    except FileNotFoundError:
        print(f"[!] Log file '{filepath}' not found. Using sample data.")
    return entries

def geoip_lookup(ip):
    """Look up country/city for an IP using the free ip-api.com service."""
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon',
                         timeout=5)
        data = r.json()
        if data.get('status') == 'success':
            return data
    except Exception:
        pass
    return {'country': 'Unknown', 'countryCode': 'XX', 'city': 'Unknown',
            'isp': 'Unknown', 'lat': 0, 'lon': 0}

def build_geo_data(entries):
    """Geocode each unique IP (with rate limiting to be nice to the free API)."""
    unique_ips = list({e['ip'] for e in entries
                       if e['ip'] not in ('127.0.0.1', '::1', '')})
    unique_ips = unique_ips[:MAX_GEO_LOOKUPS]

    geo_cache = {}
    total = len(unique_ips)
    print(f"[*] Looking up {total} unique IP address(es)...")

    for i, ip in enumerate(unique_ips, 1):
        print(f"    [{i}/{total}] {ip}", end=' ')
        geo_cache[ip] = geoip_lookup(ip)
        print(f"→ {geo_cache[ip].get('country','?')}")
        time.sleep(0.35)   # ip-api.com free tier: max ~45 req/min

    return geo_cache

def analyse(entries, geo_cache):
    """Crunch the numbers."""
    usernames  = Counter(e['username'] for e in entries)
    passwords  = Counter(e['password'] for e in entries)
    ip_counts  = Counter(e['ip'] for e in entries)

    country_counts = Counter()
    for ip, count in ip_counts.items():
        info = geo_cache.get(ip, {})
        country = info.get('country', 'Unknown')
        country_counts[country] += count

    # Build attacker list with geo info
    attackers = []
    for ip, count in ip_counts.most_common(20):
        info = geo_cache.get(ip, {})
        attackers.append({
            'ip':      ip,
            'count':   count,
            'country': info.get('country', 'Unknown'),
            'code':    info.get('countryCode', 'XX'),
            'city':    info.get('city', ''),
            'isp':     info.get('isp', ''),
            'lat':     info.get('lat', 0),
            'lon':     info.get('lon', 0),
        })

    return {
        'total':          len(entries),
        'unique_ips':     len(ip_counts),
        'countries':      len(country_counts),
        'cred_variants':  len({(e['username'], e['password']) for e in entries}),
        'top_usernames':  usernames.most_common(10),
        'top_passwords':  passwords.most_common(10),
        'top_countries':  country_counts.most_common(10),
        'attackers':      attackers,
        'recent':         entries[-20:][::-1],
    }

# ── SAMPLE DATA (used when log file is empty or missing) ────────────────────
SAMPLE_ENTRIES = [
    {'timestamp':'2026-06-10 09:00:01','ip':'218.92.0.115',  'username':'root',   'password':'123456'},
    {'timestamp':'2026-06-10 09:00:05','ip':'218.92.0.115',  'username':'root',   'password':'password'},
    {'timestamp':'2026-06-10 09:00:09','ip':'61.177.172.12', 'username':'admin',  'password':'admin'},
    {'timestamp':'2026-06-10 09:01:00','ip':'185.234.219.45','username':'root',   'password':'toor'},
    {'timestamp':'2026-06-10 09:01:30','ip':'77.23.145.67',  'username':'ubuntu', 'password':'ubuntu'},
    {'timestamp':'2026-06-10 09:02:00','ip':'103.56.78.9',   'username':'pi',     'password':'raspberry'},
    {'timestamp':'2026-06-10 09:02:45','ip':'42.114.145.21', 'username':'admin',  'password':'1234'},
    {'timestamp':'2026-06-10 09:03:10','ip':'141.98.10.1',   'username':'root',   'password':'qwerty'},
]

SAMPLE_GEO = {
    '218.92.0.115':   {'country':'China',       'countryCode':'CN','city':'Shanghai', 'isp':'ChinaNet','lat':31.2,'lon':121.5},
    '61.177.172.12':  {'country':'China',       'countryCode':'CN','city':'Beijing',  'isp':'ChinaNet','lat':39.9,'lon':116.4},
    '185.234.219.45': {'country':'Russia',      'countryCode':'RU','city':'Moscow',   'isp':'Selectel','lat':55.75,'lon':37.6},
    '77.23.145.67':   {'country':'Netherlands', 'countryCode':'NL','city':'Amsterdam','isp':'Surfshark','lat':52.37,'lon':4.9},
    '103.56.78.9':    {'country':'India',       'countryCode':'IN','city':'Mumbai',   'isp':'Jio',     'lat':19.07,'lon':72.88},
    '42.114.145.21':  {'country':'Vietnam',     'countryCode':'VN','city':'Hanoi',    'isp':'VNPT',    'lat':21.03,'lon':105.85},
    '141.98.10.1':    {'country':'Netherlands', 'countryCode':'NL','city':'Amsterdam','isp':'M247',    'lat':52.37,'lon':4.9},
}
# ─────────────────────────────────────────────────────────────────────────────

def generate_html(stats, geo_cache):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── map attack data for D3 ───────────────────────────────────────────────
    seen = set()
    map_attacks = []
    for a in stats['attackers']:
        if a['lat'] == 0 and a['lon'] == 0:
            continue
        key = a['code']
        if key in seen:
            continue
        seen.add(key)
        map_attacks.append({
            'country': a['country'],
            'code':    a['code'],
            'lat':     a['lat'],
            'lon':     a['lon'],
            'count':   sum(x['count'] for x in stats['attackers'] if x['code'] == a['code']),
        })

    map_attacks_json = json.dumps(map_attacks)

    # ── helper: bar rows ────────────────────────────────────────────────────
    def bar_rows(items, color):
        if not items:
            return '<div style="color:#1a5a1a;font-size:11px;">No data yet</div>'
        max_v = items[0][1] or 1
        rows = []
        for i, (label, count) in enumerate(items, 1):
            pct = int(count / max_v * 100)
            rows.append(f'''
            <div style="margin-bottom:8px;">
              <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">
                <span><span style="color:#1a5a1a;">#{i:02d}</span> {label}</span>
                <span style="color:{color};">{count}x</span>
              </div>
              <div style="background:#051205;height:3px;border-radius:2px;">
                <div style="width:{pct}%;height:3px;background:{color};border-radius:2px;
                  box-shadow:0 0 6px {color};"></div>
              </div>
            </div>''')
        return ''.join(rows)

    # ── helper: country rows ────────────────────────────────────────────────
    def country_rows(items):
        if not items:
            return '<div style="color:#1a5a1a;font-size:11px;">No data yet</div>'
        max_v = items[0][1] or 1
        rows = []
        for i, (country, count) in enumerate(items, 1):
            code = next((a['code'] for a in stats['attackers'] if a['country'] == country), 'XX')
            pct = int(count / max_v * 100)
            rows.append(f'''
            <div style="margin-bottom:8px;">
              <div style="display:flex;justify-content:space-between;align-items:center;
                font-size:11px;margin-bottom:3px;">
                <span style="display:flex;align-items:center;">
                  <span style="color:#1a5a1a;margin-right:6px;">#{i:02d}</span>
                  {flag_img(code)}{country}
                </span>
                <span style="color:#ffcc00;">{count}x</span>
              </div>
              <div style="background:#051205;height:3px;border-radius:2px;">
                <div style="width:{pct}%;height:3px;background:#ffcc00;border-radius:2px;
                  box-shadow:0 0 6px #ffcc00;"></div>
              </div>
            </div>''')
        return ''.join(rows)

    # ── helper: attacker rows ───────────────────────────────────────────────
    def attacker_rows():
        rows = []
        for a in stats['attackers'][:10]:
            rows.append(f'''
            <div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #051205;">
              <div style="display:flex;align-items:center;justify-content:space-between;">
                <span style="color:#ff4060;font-size:12px;">{a['ip']}</span>
                <span style="color:#ff0040;font-size:11px;">{a['count']}x</span>
              </div>
              <div style="font-size:10px;color:#1a5a1a;margin-top:3px;display:flex;align-items:center;">
                {flag_img(a['code'])}{a['country']}
              </div>
            </div>''')
        return ''.join(rows) if rows else '<div style="color:#1a5a1a;font-size:11px;">No data yet</div>'

    # ── helper: recent feed ─────────────────────────────────────────────────
    def feed_rows():
        rows = []
        for e in stats['recent'][:12]:
            code = next((a['code'] for a in stats['attackers'] if a['ip'] == e['ip']), 'XX')
            ts   = e['timestamp'] or '—'
            rows.append(f'''
            <div style="margin-bottom:6px;padding:5px 6px;background:#010d01;
              border-left:2px solid #00ff41;font-size:10px;line-height:1.7;">
              <span style="color:#1a5a1a;">{ts}</span><br>
              {flag_img(code)}
              <span style="color:#ff4060;">{e['ip']}</span> —
              <span style="color:#00ff41;">{e['username']}</span> /
              <span style="color:#ff9900;">{e['password']}</span>
            </div>''')
        return ''.join(rows) if rows else '<div style="color:#1a5a1a;font-size:11px;">No attempts logged yet</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SSH HONEYPOT // THREAT MAP</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#020c02;color:#00ff41;font-family:'Share Tech Mono',monospace;overflow:hidden;height:100vh;display:flex;flex-direction:column;}}
body::before{{content:"";position:fixed;inset:0;pointer-events:none;z-index:9000;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,255,65,0.007) 3px,rgba(0,255,65,0.007) 4px);}}
::-webkit-scrollbar{{width:3px;}}::-webkit-scrollbar-thumb{{background:#00ff41;}}
.blink{{animation:blink 1s step-end infinite;}}
@keyframes blink{{50%{{opacity:0;}}}}
@keyframes scanline{{0%{{transform:translateX(-100%);}}100%{{transform:translateX(100%);}}}}
#tooltip{{position:fixed;background:#010801f0;border:1px solid #00ff41;color:#00ff41;
  font-family:'Share Tech Mono',monospace;font-size:11px;padding:10px 14px;
  pointer-events:none;display:none;z-index:9999;line-height:1.9;min-width:200px;
  box-shadow:0 0 20px #00ff4122;}}
#tooltip b{{color:#ff0040;font-size:12px;}}
.ptitle{{font-family:'Orbitron',monospace;font-size:9px;letter-spacing:2px;color:#00ff41;
  border-bottom:1px solid #051205;padding-bottom:6px;margin-bottom:10px;}}
</style>
</head>
<body>
<div id="tooltip"></div>

<!-- HEADER -->
<div style="background:linear-gradient(90deg,#000,#001800,#000);border-bottom:1px solid #00ff41;
  padding:10px 20px;display:flex;align-items:center;justify-content:space-between;
  flex-shrink:0;position:relative;overflow:hidden;">
  <div style="position:absolute;bottom:0;left:0;width:50%;height:1px;
    background:linear-gradient(90deg,transparent,#00ff41,transparent);animation:scanline 4s linear infinite;"></div>
  <div>
    <div style="font-family:'Orbitron',monospace;font-size:18px;font-weight:900;letter-spacing:4px;
      color:#00ff41;text-shadow:0 0 15px #00ff41;">
      SSH<span style="color:#ff0040;text-shadow:0 0 15px #ff0040;">//</span>HONEYPOT &nbsp; THREAT MAP
    </div>
    <div style="font-size:9px;color:#1a5a1a;letter-spacing:2px;margin-top:3px;">
      REAL-TIME ATTACK GEOLOCATION &amp; CREDENTIAL ANALYSIS — ACADEMIC RESEARCH
    </div>
  </div>
  <div style="text-align:right;font-size:9px;color:#1a5a1a;line-height:1.9;">
    <div>GENERATED: {now}</div>
    <div style="color:#ff0040;">● <span class="blink">MONITORING ACTIVE</span></div>
    <div style="display:flex;align-items:center;justify-content:flex-end;gap:5px;">
      {flag_img('gh')} SERVER: Accra, Ghana
    </div>
  </div>
</div>

<!-- STAT CARDS -->
<div style="display:flex;gap:1px;background:#001800;border-bottom:1px solid #00ff41;flex-shrink:0;">
  {"".join(f'''<div style="flex:1;text-align:center;padding:12px 5px;background:#020c02;">
    <div style="font-family:'Orbitron',monospace;font-size:28px;font-weight:900;
      color:{c};text-shadow:0 0 20px {c};">{v}</div>
    <div style="font-size:8px;letter-spacing:2px;color:#1a5a1a;margin-top:4px;">{lbl}</div>
  </div>''' for v,c,lbl in [
      (stats['total'],       '#00ff41', 'TOTAL ATTEMPTS'),
      (stats['unique_ips'],  '#ff0040', 'UNIQUE ATTACKERS'),
      (stats['countries'],   '#ffcc00', 'COUNTRIES DETECTED'),
      (stats['cred_variants'],'#00ccff','CREDENTIAL VARIANTS'),
  ])}
</div>

<!-- MAIN BODY -->
<div style="display:flex;flex:1;overflow:hidden;gap:1px;background:#001800;">

  <!-- LEFT PANEL -->
  <div style="width:230px;flex-shrink:0;background:#020c02;overflow-y:auto;padding:14px 12px;border-right:1px solid #051205;">
    <div class="ptitle">▶ TOP USERNAMES</div>
    {bar_rows(stats['top_usernames'], '#00ff41')}
    <div class="ptitle" style="margin-top:16px;">▶ TOP PASSWORDS</div>
    {bar_rows(stats['top_passwords'], '#ff0040')}
  </div>

  <!-- MAP -->
  <div style="flex:1;position:relative;background:#010d01;overflow:hidden;">
    <svg id="map" style="width:100%;height:100%;"></svg>
  </div>

  <!-- RIGHT PANEL -->
  <div style="width:230px;flex-shrink:0;background:#020c02;overflow-y:auto;padding:14px 12px;border-left:1px solid #051205;">
    <div class="ptitle">▶ ATTACK ORIGINS</div>
    {country_rows(stats['top_countries'])}
    <div class="ptitle" style="margin-top:16px;">▶ TOP ATTACKERS</div>
    {attacker_rows()}
    <div class="ptitle" style="margin-top:16px;">▶ LIVE FEED</div>
    {feed_rows()}
  </div>

</div>

<!-- FOOTER -->
<div style="background:#000;border-top:1px solid #051205;padding:5px 20px;
  display:flex;justify-content:space-between;font-size:9px;color:#1a5a1a;flex-shrink:0;">
  <span>SSH HONEYPOT // FINAL YEAR CYBERSECURITY PROJECT</span>
  <span>github.com/calebtetteh2000/Honeypot-Project</span>
  <span>{now}</span>
</div>

<script>
const attacks = {map_attacks_json};
const svg = d3.select("#map");
const width  = () => svg.node().clientWidth  || 800;
const height = () => svg.node().clientHeight || 500;
const SERVER = {{lat:5.6037, lon:-0.1870}};

function flagUrl(code){{return "https://flagcdn.com/w20/"+code.toLowerCase()+".png";}}

let path, projection;

function render(){{
  svg.selectAll("*").remove();
  const W = width(), H = height();
  projection = d3.geoNaturalEarth1()
    .scale(W/6.2).translate([W/2, H/2]);
  path = d3.geoPath().projection(projection);

  const defs = svg.append("defs");
  const glow = defs.append("filter").attr("id","glow");
  glow.append("feGaussianBlur").attr("stdDeviation","3").attr("result","blur");
  const merge = glow.append("feMerge");
  merge.append("feMergeNode").attr("in","blur");
  merge.append("feMergeNode").attr("in","SourceGraphic");

  svg.append("rect").attr("width",W).attr("height",H).attr("fill","#010d01");

  d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(world=>{{
    svg.append("g").selectAll("path")
      .data(topojson.feature(world, world.objects.countries).features)
      .join("path").attr("d",path)
      .attr("fill","#021202").attr("stroke","#00ff4133").attr("stroke-width",0.4);

    const maxCount = d3.max(attacks, d=>d.count) || 1;
    const colour = d3.scaleLinear().domain([0,maxCount/2,maxCount])
      .range(["#ffcc00","#ff6600","#ff0040"]);

    attacks.forEach(a=>{{
      const src = projection([a.lon, a.lat]);
      const dst = projection([SERVER.lon, SERVER.lat]);
      if (!src || !dst) return;

      const mx = (src[0]+dst[0])/2, my = (src[1]+dst[1])/2 - 60;
      const pathStr = `M${{src[0]}},${{src[1]}} Q${{mx}},${{my}} ${{dst[0]}},${{dst[1]}}`;

      // arc
      svg.append("path").attr("d",pathStr)
        .attr("fill","none").attr("stroke",colour(a.count))
        .attr("stroke-width",0.6).attr("opacity",0.35)
        .attr("filter","url(#glow)");

      // animated laser
      const laser = svg.append("path").attr("d",pathStr)
        .attr("fill","none").attr("stroke","white")
        .attr("stroke-width",2).attr("opacity",0);
      const total = laser.node().getTotalLength();
      laser.attr("stroke-dasharray",`20 ${{total}}`)
        .attr("stroke-dashoffset", total)
        .attr("opacity",0.9)
        .transition().duration(1800)
        .delay(Math.random()*2000)
        .ease(d3.easeLinear)
        .attr("stroke-dashoffset",-total)
        .on("end", function repeat(){{
          d3.select(this).attr("stroke-dashoffset",total)
            .transition().duration(1800)
            .delay(Math.random()*1500)
            .ease(d3.easeLinear)
            .attr("stroke-dashoffset",-total)
            .on("end",repeat);
        }});

      // attacker dot
      svg.append("circle").attr("cx",src[0]).attr("cy",src[1])
        .attr("r", 3 + Math.sqrt(a.count)*1.5).attr("fill",colour(a.count))
        .attr("opacity",0.85).attr("filter","url(#glow)")
        .on("mouseover", function(event){{
          d3.select("#tooltip").style("display","block")
            .html(`<b>${{a.country}}</b><br>
              <img src="${{flagUrl(a.code)}}" width="20" height="14"
                style="vertical-align:middle;margin-right:4px;">${{a.country}}<br>
              Attempts: ${{a.count}}`);
        }})
        .on("mousemove", e=>d3.select("#tooltip")
          .style("left",(e.pageX+12)+"px").style("top",(e.pageY-10)+"px"))
        .on("mouseout", ()=>d3.select("#tooltip").style("display","none"));

      // pulse ring
      (function pulse(){{
        svg.append("circle").attr("cx",src[0]).attr("cy",src[1]).attr("r",4)
          .attr("fill","none").attr("stroke",colour(a.count)).attr("stroke-width",1.5)
          .attr("opacity",0.8)
          .transition().duration(1500).ease(d3.easeCubicOut)
          .attr("r",20).attr("opacity",0)
          .on("end", function(){{ d3.select(this).remove(); pulse(); }});
      }})();
    }});

    // server dot (Accra)
    const sp = projection([SERVER.lon, SERVER.lat]);
    if (sp) {{
      for (let i=0;i<3;i++) {{
        (function ripple(n){{
          svg.append("circle").attr("cx",sp[0]).attr("cy",sp[1]).attr("r",6)
            .attr("fill","none").attr("stroke","#00ff41").attr("stroke-width",1.5)
            .attr("opacity",0.9)
            .transition().duration(2000).delay(n*600).ease(d3.easeCubicOut)
            .attr("r",30).attr("opacity",0)
            .on("end",function(){{d3.select(this).remove();ripple(0);}});
        }})(i);
      }}
      svg.append("circle").attr("cx",sp[0]).attr("cy",sp[1]).attr("r",6)
        .attr("fill","#00ff41").attr("filter","url(#glow)")
        .on("mouseover",e=>d3.select("#tooltip").style("display","block")
          .html(`<b>YOUR HONEYPOT</b><br>
            <img src="${{flagUrl('gh')}}" width="20" height="14"
              style="vertical-align:middle;margin-right:4px;">Accra, Ghana<br>
            Total attacks received: {stats['total']}`))
        .on("mousemove",e=>d3.select("#tooltip")
          .style("left",(e.pageX+12)+"px").style("top",(e.pageY-10)+"px"))
        .on("mouseout",()=>d3.select("#tooltip").style("display","none"));
      svg.append("text").attr("x",sp[0]+9).attr("y",sp[1]+4)
        .attr("fill","#00ff41").attr("font-size","9px")
        .attr("font-family","Share Tech Mono,monospace").text("HONEYPOT");
    }}
  }}).catch(()=>{{
    svg.append("text").attr("x","50%").attr("y","50%")
      .attr("text-anchor","middle").attr("fill","#1a5a1a")
      .attr("font-family","Share Tech Mono,monospace")
      .text("Map requires internet connection");
  }});
}}

render();
window.addEventListener("resize", render);
</script>
</body>
</html>"""
    return html

def main():
    print("=" * 50)
    print("  SSH HONEYPOT ATTACK ANALYSER")
    print("=" * 50)

    entries = parse_log(LOG_FILE)

    if not entries:
        print("[!] No valid entries found in log. Using sample data for demo.")
        entries  = SAMPLE_ENTRIES
        geo_cache = SAMPLE_GEO
    else:
        print(f"[*] Parsed {len(entries)} log entries.")
        geo_cache = build_geo_data(entries)

    print("[*] Analysing data...")
    stats = analyse(entries, geo_cache)

    print(f"\n[*] Results:")
    print(f"    Total attempts  : {stats['total']}")
    print(f"    Unique attackers: {stats['unique_ips']}")
    print(f"    Countries       : {stats['countries']}")
    print(f"    Top username    : {stats['top_usernames'][0][0] if stats['top_usernames'] else 'N/A'}")
    print(f"    Top password    : {stats['top_passwords'][0][0] if stats['top_passwords'] else 'N/A'}")

    print(f"\n[*] Generating dashboard → {OUTPUT_FILE}")
    html = generate_html(stats, geo_cache)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[✓] Done! Opening '{OUTPUT_FILE}' in your browser...")
    print("=" * 50)
    import webbrowser, os
    webbrowser.open('file:///' + os.path.abspath(OUTPUT_FILE).replace('\\', '/'))
    

if __name__ == '__main__':
    main()
