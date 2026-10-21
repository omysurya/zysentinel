# ZySentinel Sweeper: mesin analisis webshell (referensi Python, juga cadangan bila biner C tidak ada).
#
# Logika berasal dari keluarga ShellSweep (https://github.com/splunk/ShellSweep, Apache-2.0, (c) Splunk):
#   - entropi Shannon per berkas dan ambang per jenis berkas (ShellSweep.py);
#   - daftar abai berbasis hash SHA-256 dan pengecualian path (ShellSweep.py);
#   - analisis heuristik berlapis dan skor keyakinan (ShellSweepPlus.py).
# Perbedaan yang disengaja (alasan: ambang entropi ShellSweep asli menandai 95% berkas PHP yang sah):
#   - entropi hanya indikator pendukung, memakai z-score terhadap prior berkas sah, bukan ambang tetap;
#   - kata kunci generik ShellSweepPlus diganti analisis token PHP (lexer, taint sederhana, pelipatan konstanta);
#   - hash dibandingkan dalam huruf kecil (versi asli membandingkan HEX huruf besar dengan hexdigest huruf kecil);
#   - pengecualian path benar-benar dipakai (variabel `exclude` versi Plus tidak pernah dibaca).
# Mesin C (sentinel-sweeper.c) memberi putusan yang sama persis; keduanya diuji paritas pada korpus nyata.
import math, re, collections

# ------------------------------------------------------------------ konfigurasi bawaan
PHP_EXTS = {'.php', '.phtml', '.phar', '.pht', '.php3', '.php4', '.php5', '.php7', '.php8', '.phps', '.inc'}
JSP_EXTS = {'.jsp', '.jspx', '.jsw', '.jsv'}
ASP_EXTS = {'.asp', '.aspx', '.ashx', '.asax', '.asmx', '.cer'}
OTHER_EXTS = {'.pl', '.cgi', '.py', '.sh'}
MAX_FILE = 2 * 1024 * 1024
ENT_MEAN, ENT_SD = 4.664, 0.325     # prior PHP (diukur dari 42.566 berkas sah); z >= Z_FLAG = tanda ShellSweep dinamis
Z_FLAG, Z_STRONG = 3.2, 4.2

def _B(*xs):
    return {x.encode() if isinstance(x, str) else x for x in xs}
EXEC_SINKS = _B('system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec')
EVAL_SINKS = _B('eval', 'assert', 'create_function')
INCLUDE_SINKS = _B('include', 'include_once', 'require', 'require_once')
# nama fungsi -> posisi argumen yang berupa callback
CALLBACK_SINKS = {k.encode(): v for k, v in {'call_user_func': 0, 'call_user_func_array': 0, 'array_map': 0, 'array_filter': 1, 'array_walk': 1,
                  'array_walk_recursive': 1, 'usort': 1, 'uasort': 1, 'uksort': 1, 'array_reduce': 1,
                  'register_shutdown_function': 0, 'preg_replace_callback': 1, 'iterator_apply': 1,
                  'forward_static_call': 0, 'forward_static_call_array': 0, 'register_tick_function': 0}.items()}
DECODERS_STRICT = _B('base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13', 'rawurldecode', 'urldecode',
                   'convert_uudecode', 'hex2bin', 'zlib_decode', 'bzdecompress', 'strrev')
FOLD_DECODERS = _B('base64_decode', 'str_rot13', 'strrev', 'hex2bin', 'rawurldecode', 'urldecode', 'strtolower', 'strtoupper', 'trim', 'ucfirst')
FN_NAME_DANGER = EXEC_SINKS | _B('eval', 'assert', 'create_function')
SUPERGLOBALS = _B('_get', '_post', '_request', '_cookie', '_files', '_server', '_env')
SERVER_TAINT_KEYS = (b'http_', b'query_string', b'request_uri', b'path_info')
KNOWN_NAMES = [b'c99shell', b'r57shell', b'b374k', b'filesman', b'indoxploit', b'mini shell', b'china chopper', b'priv8 shell',
               b'webshell by', b'weevely', b'safe mode bypass', b'safe_mode bypass', b'alfa team', b'wso shell', b'wso web', b'wso 2', b'c100 shell',
               b'sh3ll', b'phpspy', b'webadmin.php', b'antichat shell', b'r57 shell', b'hacked by', b'shell by', b'ani-shell', b'zehir', b'1n73ct10n', b'dhanush']

# ------------------------------------------------------------------ entropi
def entropy_bytes(b):
    n = len(b)
    if not n:
        return 0.0
    c = collections.Counter(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

# ------------------------------------------------------------------ lexer PHP
ID0 = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\\') | set(range(128, 256))
IDN = ID0 | set(b'0123456789')
WS = set(b' \t\r\n\x0b\x0c')

class Tok:
    __slots__ = ('t', 'v', 'pos', 'interp', 'n')
    def __init__(self, t, v, pos, interp=None, n=0):
        self.t = t; self.v = v; self.pos = pos; self.interp = interp; self.n = n

def _decode_dq(s):
    """Dekode escape string petik-dua. Return (bytes, daftar variabel yang diinterpolasi)."""
    out = bytearray(); vars_ = []; i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c == 0x5c and i + 1 < n:
            d = s[i + 1]
            m = {0x6e: 10, 0x74: 9, 0x72: 13, 0x76: 11, 0x65: 27, 0x66: 12, 0x5c: 0x5c, 0x24: 0x24, 0x22: 0x22}
            if d in m:
                out.append(m[d]); i += 2; continue
            if d == 0x78 and i + 2 < n and chr(s[i + 2]) in '0123456789abcdefABCDEF':
                j = i + 2; k = j
                while k < n and k < j + 2 and chr(s[k]) in '0123456789abcdefABCDEF': k += 1
                out.append(int(s[j:k], 16)); i = k; continue
            if 0x30 <= d <= 0x37:
                j = i + 1; k = j
                while k < n and k < j + 3 and 0x30 <= s[k] <= 0x37: k += 1
                out.append(int(s[j:k], 8) & 255); i = k; continue
            out.append(c); out.append(d); i += 2; continue
        if c == 0x24 and i + 1 < n and (s[i + 1] in ID0 or s[i + 1] == 0x7b):
            j = i + 1
            if s[j] == 0x7b:
                k = s.find(b'}', j)
                k = n if k < 0 else k
                vars_.append(s[j + 1:k].lstrip(b'$').split(b'[')[0].split(b'-')[0].strip().lower()); i = k + 1; out.append(0x3f); continue
            k = j
            while k < n and s[k] in IDN: k += 1
            vars_.append(s[j:k].lower()); i = k; out.append(0x3f); continue
        if c == 0x7b and i + 1 < n and s[i + 1] == 0x24:
            k = s.find(b'}', i)
            k = n if k < 0 else k
            inner = s[i + 2:k]
            m2 = re.match(rb'[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*', inner)
            if m2: vars_.append(m2.group(0).lower())
            out.append(0x3f); i = k + 1; continue
        out.append(c); i += 1
    return bytes(out), vars_

def lex_php(b):
    """Daftar token kode PHP. Komentar dibuang, string didekode (<=512 bita disimpan), HTML di luar tag dilewati."""
    toks = []; n = len(b); i = 0; in_code = False
    n_hex_esc = 0
    while i < n:
        if not in_code:
            j = b.find(b'<?', i)
            if j < 0: break
            k = j + 2
            if b[k:k + 3].lower() == b'php' and (k + 3 >= n or b[k + 3] in WS):
                i = k + 3; in_code = True
            elif b[k:k + 1] == b'=':
                i = k + 1; in_code = True; toks.append(Tok('ID', b'echo', j))
            elif k < n and b[k] in WS:
                i = k; in_code = True
            else:
                i = k
            continue
        c = b[i]
        if c in WS:
            i += 1; continue
        if c == 0x3f and b[i + 1:i + 2] == b'>':
            in_code = False; i += 2
            if i < n and b[i] == 0x0a: i += 1
            toks.append(Tok('OP', b';', i)); continue
        if c == 0x23 and b[i + 1:i + 2] == b'[':
            toks.append(Tok('OP', b'#', i)); i += 1; continue
        if c == 0x23 or (c == 0x2f and b[i + 1:i + 2] == b'/'):
            j = i
            while j < n and b[j] != 0x0a:
                if b[j] == 0x3f and b[j + 1:j + 2] == b'>': break
                j += 1
            i = j; continue
        if c == 0x2f and b[i + 1:i + 2] == b'*':
            j = b.find(b'*/', i + 2)
            i = n if j < 0 else j + 2; continue
        if c == 0x27:
            j = i + 1
            while j < n and b[j] != 0x27:
                j += 2 if b[j] == 0x5c else 1
            raw = b[i + 1:j]
            s = raw.replace(b"\\\\", b"\\").replace(b"\\'", b"'") if b'\\' in raw else raw
            toks.append(Tok('STR', s[:512], i, [], len(s)))
            i = j + 1; continue
        if c == 0x22:
            j = i + 1
            while j < n and b[j] != 0x22:
                j += 2 if b[j] == 0x5c else 1
            raw = b[i + 1:j]
            s, vs = _decode_dq(raw)
            n_hex_esc += len(re.findall(rb'\\x[0-9a-fA-F]{2}', raw))
            toks.append(Tok('STR', s[:512], i, vs, len(s)))
            i = j + 1; continue
        if c == 0x60:
            j = i + 1
            while j < n and b[j] != 0x60:
                j += 2 if b[j] == 0x5c else 1
            s, vs = _decode_dq(b[i + 1:j])
            toks.append(Tok('BT', s[:512], i, vs)); i = j + 1; continue
        if c == 0x3c and b[i:i + 3] == b'<<<':
            m = re.match(rb'<<<[ \t]*([\'"]?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n', b[i:i + 80])
            if m:
                ident = m.group(2); now = (m.group(1) == b"'")
                start = i + m.end()
                mm = re.compile(rb'^[ \t]*' + re.escape(ident) + rb'\b', re.M).search(b, start)
                end = mm.start() if mm else n
                body = b[start:end]
                if now: s, vs = body, []
                else: s, vs = _decode_dq(body)
                toks.append(Tok('STR', s[:512], i, vs, len(s)))
                i = mm.end() if mm else n; continue
        if c == 0x24:
            j = i + 1
            if j < n and b[j] == 0x24:
                toks.append(Tok('VARVAR', b'$', i)); i += 1; continue
            if j < n and b[j] == 0x7b:
                toks.append(Tok('VARVAR', b'${', i)); i += 2; continue
            k = j
            while k < n and b[k] in IDN: k += 1
            toks.append(Tok('VAR', b[j:k].lower(), i)); i = k; continue
        if c in ID0:
            k = i
            while k < n and b[k] in IDN: k += 1
            v = b[i:k].lower().lstrip(b'\\')
            toks.append(Tok('ID', v, i)); i = k; continue
        if 0x30 <= c <= 0x39:
            k = i
            while k < n and (b[k] in IDN or b[k] == 0x2e): k += 1
            toks.append(Tok('NUM', b[i:k], i)); i = k; continue
        two = b[i:i + 2]
        if two in (b'.=', b'=>', b'->', b'::', b'==', b'!=', b'&&', b'||', b'??', b'+=', b'-=', b'<=', b'>=', b'++', b'--'):
            toks.append(Tok('OP', two, i)); i += 2; continue
        toks.append(Tok('OP', bytes([c]), i)); i += 1
    return toks, n_hex_esc

# ------------------------------------------------------------------ analisis token PHP
def _fold_const(expr, st=None):
    """Lipat ekspresi konstanta sederhana: 'sy'.'stem', chr(1).chr(2), strrev('x'), base64_decode('..'). None bila bukan konstanta."""
    n = len(expr)
    def parse_atom(i):
        t = expr[i]
        if t.t == 'STR' and not t.interp:
            return bytes(t.v), i + 1
        if t.t == 'VAR' and st is not None and t.v in st.fold and st.cls.get(t.v) not in ('T', 'S'):
            return bytes(st.fold[t.v]), i + 1
        if t.t == 'ID' and i + 1 < n and expr[i + 1].t == 'OP' and expr[i + 1].v == b'(':
            # fungsi konstan: ambil argumen sampai ')' yang seimbang
            depth = 0; j = i + 1; args = []
            while j < n:
                if expr[j].t == 'OP' and expr[j].v == b'(': depth += 1
                elif expr[j].t == 'OP' and expr[j].v == b')':
                    depth -= 1
                    if depth == 0: break
                j += 1
            if j >= n: return None, i
            inner = expr[i + 2:j]
            name = t.v
            if name == b'chr' and len(inner) == 1 and inner[0].t == 'NUM':
                try: return bytes([int(inner[0].v, 0) & 255]), j + 1
                except ValueError: return None, i
            if name in FOLD_DECODERS:
                val = _fold_const(inner, st)
                if val is None: return None, i
                return _apply(name, val), j + 1
            return None, i
        return None, i
    pos = 0
    res = bytearray()
    while pos < n:
        v, pos2 = parse_atom(pos)
        if v is None: return None
        res += v; pos = pos2
        if pos < n:
            if expr[pos].t == 'OP' and expr[pos].v == b'.': pos += 1
            else: return None
    return bytes(res)

def _apply(name, v):
    import base64, codecs, urllib.parse
    try:
        if name == b'base64_decode': return base64.b64decode(v + b'=' * (-len(v) % 4), validate=False)
        if name == b'str_rot13': return codecs.encode(v.decode('latin1'), 'rot13').encode('latin1')
        if name == b'strrev': return v[::-1]
        if name == b'hex2bin': return bytes.fromhex(v.decode('latin1'))
        if name in (b'rawurldecode', b'urldecode'): return urllib.parse.unquote_to_bytes(v)
        if name == b'strtolower': return v.lower()
        if name == b'strtoupper': return v.upper()
        if name == b'trim': return v.strip()
        if name == b'ucfirst': return v[:1].upper() + v[1:]
    except Exception:
        return b''
    return v

def _match_paren(toks, i):
    """toks[i] adalah '('. Kembalikan indeks ')' yang seimbang atau len(toks)."""
    depth = 0; n = len(toks)
    for j in range(i, min(n, i + 3000)):
        t = toks[j]
        if t.t == 'OP':
            if t.v == b'(': depth += 1
            elif t.v == b')':
                depth -= 1
                if depth == 0: return j
    return min(n, i + 3000)

def _split_args(toks, a, b_):
    """Pisahkan toks[a:b_] pada koma tingkat atas."""
    args = []; cur = []; depth = 0
    for t in toks[a:b_]:
        if t.t == 'OP':
            if t.v in (b'(', b'['): depth += 1
            elif t.v in (b')', b']'): depth -= 1
            elif t.v == b',' and depth == 0:
                args.append(cur); cur = []; continue
        cur.append(t)
    args.append(cur)
    return args

class State:
    def __init__(self):
        self.cls = {}      # var -> 'T' tercemar masukan | 'O' hasil dekode konstanta | 'D' nama fungsi berbahaya | 'F' fungsi konstan
        self.fold = {}     # var -> bytes konstan
        self.extract = False   # extract($_REQUEST) dipanggil: variabel yang tak pernah diberi nilai dianggap tercemar

FS_WRITE = _B('file_put_contents', 'fwrite', 'fputs', 'move_uploaded_file', 'copy', 'rename', 'symlink', 'link')
FS_READ = _B('readfile', 'file_get_contents', 'file', 'highlight_file', 'show_source', 'fopen', 'unlink', 'rmdir', 'mkdir', 'chmod', 'scandir', 'opendir', 'glob', 'touch')
READERS = _B('file_get_contents', 'fopen', 'fgets', 'fread', 'stream_get_contents', 'readfile', 'file')

def _expr_taint(expr, st):
    """Klasifikasi ekspresi: himpunan bagian {'T' tercemar masukan, 'O' hasil dekode konstanta, 'D' nama fungsi berbahaya, 'dec', 'vv'}."""
    r = set(); n = len(expr)
    for i, t in enumerate(expr):
        if t.t == 'VAR':
            if t.v in SUPERGLOBALS:
                if t.v == b'_server':
                    if i + 2 < n and expr[i + 1].t == 'OP' and expr[i + 1].v == b'[' and expr[i + 2].t == 'STR':
                        if expr[i + 2].v.lower().startswith(SERVER_TAINT_KEYS): r.add('S')
                elif t.v != b'_env':
                    r.add('T')
            else:
                c = st.cls.get(t.v)
                if c == 'F': r.add('dec'); r.add('F')
                elif c: r.add(c)
                elif st.extract and t.v not in st.fold and t.v != b'this': r.add('T')
        elif t.t == 'STR':
            lv = t.v.lower()
            if (b'php://input' in lv or b'php://stdin' in lv) and i >= 2 and expr[i - 1].t == 'OP' and expr[i - 1].v == b'(' and expr[i - 2].t == 'ID' and expr[i - 2].v in READERS:
                r.add('T')
            for vn in (t.interp or []):
                if vn in SUPERGLOBALS and vn not in (b'_env', b'_server'): r.add('T')
                elif vn in st.cls: r.add(st.cls[vn])
        elif t.t == 'BT':
            for vn in (t.interp or []):
                if vn in SUPERGLOBALS or st.cls.get(vn) == 'T': r.add('T')
        elif t.t == 'ID':
            if t.v in DECODERS_STRICT: r.add('dec')
            if t.v in (b'getallheaders', b'apache_request_headers'): r.add('T')
        elif t.t == 'VARVAR':
            r.add('vv')
    return r

_FN_AFTER = (b'function', b'new', b'class', b'const', b'namespace', b'use', b'extends', b'implements', b'trait', b'interface', b'instanceof', b'catch', b'insteadof')

def analyze_php(b, F):
    """Satu lintasan berurutan dengan lingkup fungsi. Isi F dan kembalikan daftar temuan (id, bobot, detail)."""
    toks, n_hex = lex_php(b)
    n = len(toks)
    F['tokens'] = n; F['hex_esc'] = n_hex
    fnd = []
    scopes = [State()]; braces = []
    pending = None
    code_has = set()
    fs_kinds = set(); sock_has = False; has_input = False
    i = 0
    while i < n:
        t = toks[i]
        st = scopes[-1]
        prev = toks[i - 1] if i else None
        nxt = toks[i + 1] if i + 1 < n else None
        if t.t == 'OP':
            if t.v == b'{':
                if pending:
                    ns = State()
                    if pending == 'anon': ns.cls = dict(st.cls); ns.fold = dict(st.fold)
                    scopes.append(ns); braces.append(True); pending = None
                else: braces.append(False)
            elif t.v == b'}':
                if braces and braces.pop() and len(scopes) > 1: scopes.pop()
            elif t.v == b';': pending = None
            i += 1; continue
        if t.t == 'ID':
            name = t.v
            member = prev is not None and prev.t == 'OP' and prev.v in (b'->', b'::')
            if member:
                i += 1; continue
            if name == b'function':
                j = i + 1
                if j < n and toks[j].t == 'OP' and toks[j].v == b'&': j += 1
                pending = 'anon' if (j < n and toks[j].t == 'OP' and toks[j].v == b'(') else 'named'
                i += 1; continue
            if prev is not None and prev.t == 'ID' and prev.v in _FN_AFTER:
                i += 1; continue
            is_call = nxt is not None and nxt.t == 'OP' and nxt.v == b'('
            if name == b'foreach' and is_call:
                e = _match_paren(toks, i + 1)
                k = i + 2
                while k < e and not (toks[k].t == 'ID' and toks[k].v == b'as'): k += 1
                if k < e and 'T' in _expr_taint(toks[i + 2:k], st):
                    for u in toks[k + 1:e]:
                        if u.t == 'VAR': st.cls[u.v] = 'T'
                    # $$k = $v pada badan foreach masukan
                    F['foreach_input'] = True
                i += 1; continue
            if name == b'extract' and is_call:
                e = _match_paren(toks, i + 1)
                if 'T' in _expr_taint(toks[i + 2:e], st):
                    fnd.append(('extract-input', 40, '')); st.extract = True
            if name in EVAL_SINKS or name in EXEC_SINKS or name in INCLUDE_SINKS:
                if is_call:
                    e = _match_paren(toks, i + 1); arg_all = toks[i + 2:e]
                elif name in INCLUDE_SINKS or name == b'eval':
                    e = i + 1
                    while e < n and not (toks[e].t == 'OP' and toks[e].v == b';'): e += 1
                    arg_all = toks[i + 1:e]
                else:
                    i += 1; continue
                cl = _expr_taint(arg_all, st)
                if 'S' in cl and name not in INCLUDE_SINKS: cl.add('T')
                if name in EVAL_SINKS:
                    code_has.add('eval')
                    if 'T' in cl: fnd.append(('eval-input', 98, name.decode()))
                    elif 'O' in cl or 'dec' in cl: fnd.append(('eval-decode', 95, name.decode()))
                    elif 'D' in cl: fnd.append(('eval-dynname', 90, name.decode()))
                    elif name == b'create_function' and arg_all and not any(u.t == 'STR' and not u.interp for u in arg_all): fnd.append(('eval-dynamic', 40, name.decode()))
                    elif name == b'eval' and 'vv' in cl: fnd.append(('eval-varvar', 50, ''))
                    elif name == b'eval' and any(u.t == 'VAR' for u in arg_all): fnd.append(('eval-var', 20, ''))
                elif name in EXEC_SINKS:
                    code_has.add('exec')
                    if 'T' in cl: fnd.append(('exec-input', 98, name.decode()))
                    elif 'O' in cl: fnd.append(('exec-decode', 95, name.decode()))
                    elif any(u.t == 'VAR' for u in arg_all): fnd.append(('exec-var', 12, name.decode()))
                else:
                    if 'T' in cl: fnd.append(('include-input', 85, name.decode()))
                    elif 'O' in cl: fnd.append(('include-decode', 90, name.decode()))
            elif name in CALLBACK_SINKS and is_call:
                e = _match_paren(toks, i + 1); args = _split_args(toks, i + 2, e)
                pos = CALLBACK_SINKS[name]
                if pos < len(args):
                    cl = _expr_taint(args[pos], st)
                    if 'S' in cl: cl.add('T')
                    if 'T' in cl or 'D' in cl or 'O' in cl: fnd.append(('callback-input', 97, name.decode()))
                    elif len(args[pos]) == 1 and args[pos][0].t == 'STR' and args[pos][0].v.lower() in (EXEC_SINKS | _B('eval', 'assert', 'create_function')) and any('T' in _expr_taint(a, st) for a in args[pos + 1:] + args[:pos]):
                        fnd.append(('callback-dangerous-const', 96, args[pos][0].v.decode('latin1')))
            elif name == b'preg_replace' and is_call:
                e = _match_paren(toks, i + 1); args = _split_args(toks, i + 2, e)
                if args and len(args[0]) >= 1 and args[0][0].t == 'STR':
                    m = re.match(rb'^(.)(?:.*)\1([a-zA-Z]*)$', args[0][0].v, re.S)
                    if m and b'e' in m.group(2):
                        rest = [u for a in args[1:] for u in a]
                        fnd.append(('preg-e-input', 96, '') if 'T' in _expr_taint(rest, st) else ('preg-e', 45, ''))
            elif name in FS_WRITE and is_call:
                e = _match_paren(toks, i + 1); args = _split_args(toks, i + 2, e)
                if args:
                    c0 = _expr_taint(args[0], st); c0.discard('S')
                    first_tainted = args[0] and ((args[0][0].t == 'VAR' and (args[0][0].v in SUPERGLOBALS or st.cls.get(args[0][0].v) == 'T')))
                    rest_t = any(('T' in _expr_taint(a, st) or 'dec' in _expr_taint(a, st)) for a in args[1:])
                    if name == b'move_uploaded_file':
                        if len(args) > 1 and args[1] and args[1][0].t == 'VAR' and (args[1][0].v in SUPERGLOBALS or st.cls.get(args[1][0].v) == 'T'): fnd.append(('upload-input-path', 92, name.decode()))
                    elif first_tainted and rest_t: fnd.append(('write-input', 95, name.decode()))
                    elif first_tainted: fnd.append(('fs-input', 45, name.decode()))
            elif name in FS_READ and is_call:
                e = _match_paren(toks, i + 1); args = _split_args(toks, i + 2, e)
                if args and args[0] and args[0][0].t == 'VAR' and (args[0][0].v in SUPERGLOBALS or st.cls.get(args[0][0].v) == 'T'):
                    fs_kinds.add(name)
            elif name in (b'fsockopen', b'stream_socket_client', b'socket_create', b'pfsockopen', b'socket_connect'):
                sock_has = True
            elif name in DECODERS_STRICT and is_call:
                e = _match_paren(toks, i + 1)
                if any(u.t == 'STR' and u.n >= 300 and _b64ish(u.v, u.n) for u in toks[i + 2:e]):
                    fnd.append(('decode-blob', 25, name.decode()))
            i += 1; continue
        if t.t == 'BT':
            if any(v in SUPERGLOBALS or st.cls.get(v) == 'T' for v in (t.interp or [])): fnd.append(('backtick-input', 98, ''))
            elif t.interp: fnd.append(('backtick-var', 12, ''))
            i += 1; continue
        if t.t == 'VAR':
            if t.v in (b'_post', b'_get', b'_request', b'_cookie'): has_input = True
            # penyebaran taint: $x = ekspresi;
            if nxt is not None and nxt.t == 'OP' and nxt.v in (b'=', b'.='):
                k = i + 2; depth = 0
                while k < n:
                    u = toks[k]
                    if u.t == 'OP':
                        if u.v in (b'(', b'['): depth += 1
                        elif u.v in (b')', b']'): depth -= 1
                        elif u.v == b';' and depth <= 0: break
                        elif u.v in (b'{', b'}') and depth <= 0: break
                    k += 1
                expr = toks[i + 2:k]
                cl = _expr_taint(expr, st); name = t.v
                if 'T' in cl or 'S' in cl: st.cls[name] = 'T' if 'T' in cl else 'S'
                elif ('O' in cl or 'D' in cl) and name not in st.cls: st.cls[name] = 'O' if 'O' in cl else 'D'
                folded = _fold_const(expr, st) if expr else None
                if folded is not None:
                    prevf = st.fold.get(name)
                    st.fold[name] = (prevf + folded) if (nxt.v == b'.=' and prevf is not None) else folded
                    if st.fold[name].lower().strip() in FN_NAME_DANGER and st.cls.get(name) != 'T': st.cls[name] = 'D'
                    elif st.fold[name].lower().strip() in DECODERS_STRICT and st.cls.get(name) != 'T': st.cls[name] = 'F'
                    elif name not in st.cls and any(u.t == 'ID' and u.v in DECODERS_STRICT for u in expr) and len(folded) > 8: st.cls[name] = 'O'
                elif 'dec' in cl and 'T' not in cl and name not in st.cls and any(u.t == 'STR' and u.n > 40 for u in expr):
                    st.cls[name] = 'O'
            # pemanggilan fungsi variabel
            if nxt is not None and nxt.t == 'OP' and nxt.v == b'(' and not (prev is not None and prev.t == 'OP' and prev.v in (b'->', b'::')):
                c = 'T' if t.v in SUPERGLOBALS and t.v not in (b'_env', b'_server') else st.cls.get(t.v)
                if c == 'S': c = 'T'
                if c == 'T': fnd.append(('varcall-input', 97, t.v.decode()))
                elif c == 'D': fnd.append(('varcall-dynname', 96, st.fold.get(t.v, b'').decode('latin1')))
                elif c == 'O': fnd.append(('varcall-decoded', 92, ''))
                elif c == 'F': fnd.append(('varcall-decoder-name', 15, st.fold.get(t.v, b'').decode('latin1')))
                elif c is None and st.extract and t.v not in st.fold and t.v != b'this': fnd.append(('varcall-input', 97, t.v.decode()))
            elif t.v in SUPERGLOBALS and t.v not in (b'_env', b'_server') and nxt is not None and nxt.t == 'OP' and nxt.v == b'[':
                e = i + 1; depth = 0
                while e < n:
                    if toks[e].t == 'OP':
                        if toks[e].v == b'[': depth += 1
                        elif toks[e].v == b']':
                            depth -= 1
                            if depth == 0: break
                    e += 1
                if e + 1 < n and toks[e + 1].t == 'OP' and toks[e + 1].v == b'(': fnd.append(('varcall-input', 97, t.v.decode()))
            i += 1; continue
        if t.t == 'VARVAR' and F.get('foreach_input'):
            fnd.append(('varvar-input', 45, '')); F['foreach_input'] = False
        i += 1
    # nama fungsi konstan yang dipanggil langsung: ('sys'.'tem')(...)
    for i in range(n - 3):
        if toks[i].t == 'OP' and toks[i].v == b'(' and (i == 0 or toks[i - 1].t not in ('ID', 'VAR')):
            e = _match_paren(toks, i)
            if e + 1 < n and toks[e + 1].t == 'OP' and toks[e + 1].v == b'(':
                fv = _fold_const(toks[i + 1:e], scopes[0])
                if fv is not None and fv.lower() in FN_NAME_DANGER: fnd.append(('callconst-dynname', 96, fv.decode('latin1')))
    ids_found = {f[0] for f in fnd}
    if has_input and 'eval-var' in ids_found:
        dec_any = any(t.t == 'ID' and t.v in (DECODERS_STRICT | _B('openssl_decrypt', 'mcrypt_decrypt', 'gzinflate')) for t in toks)
        fnd.append(('input-eval-decode', 92, '') if dec_any else ('input-eval', 70, ''))
    run = 0; best = 0
    for k in range(n - 2):
        if toks[k].t == 'VAR' and toks[k + 1].t == 'OP' and toks[k + 1].v == b'++' and toks[k + 2].t == 'OP' and toks[k + 2].v == b';':
            run += 1
            if run > best: best = run
        elif toks[k].t == 'OP' and toks[k].v == b';': pass
        elif not (toks[k].t == 'OP' and toks[k].v in (b'++', b';')) and toks[k].t != 'VAR': run = 0
    if best >= 8:
        vv = any(t.t == 'VARVAR' for t in toks)
        fnd.append(('inc-chain-dynamic', 92, str(best)) if (vv or has_input) else ('inc-chain', 75, str(best)))
    if b'registerphpfunctions' in {t.v for t in toks if t.t == 'ID'}:
        danger = any(t.t == 'STR' and b'function' in t.v.lower() and any(d in t.v.lower() for d in (b'assert', b'system', b'exec', b'passthru', b'shell_exec', b'eval')) for t in toks)
        fnd.append(('xslt-php', 92 if danger else 40, ''))
    if len(fs_kinds) >= 3: fnd.append(('fs-input-multi', 60, ','.join(sorted(k.decode() for k in fs_kinds))))
    elif fs_kinds: fnd.append(('fs-input-read', 20, ''))
    ids = {t.v for t in toks if t.t == 'ID'}
    if sock_has and (ids & (EXEC_SINKS)) and any(t.t == 'STR' and re.search(rb'(?:/bin/(?:ba)?sh|\bbash|\bsh)\s+-i\b|[<>]&\s*[345]\b', t.v) for t in toks):
        fnd.append(('revshell-php', 92, ''))
    # ${"\x47\x4c..."} : variabel dinamis yang namanya dilipat jadi GLOBALS
    for i in range(n - 2):
        if toks[i].t == 'VARVAR' and toks[i].v == b'${' and toks[i + 1].t == 'STR' and toks[i + 1].v.lower() == b'globals': fnd.append(('obf-globals', 45, ''))
    if F['hex_esc'] >= 100 and F['hex_esc'] * 4 >= 0.25 * len(b): fnd.append(('hex-escape-heavy', 35, str(F['hex_esc'])))
    F['sinks'] = sorted(code_has)
    return fnd

def _b64ish(v, n):
    if not v: return False
    ok = sum(1 for c in v if c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    return ok / len(v) > 0.97

# ------------------------------------------------------------------ JSP / ASP / lain-lain (berbasis teks)
def _norm_script(b):
    """Lepas komentar blok dan penyambung string ("e"+"v"+"al") agar pola tersembunyi terlihat."""
    s = re.sub(rb'/\*.*?\*/', b'', b, flags=re.S)
    s = re.sub(rb'"\s*\+\s*"', b'', s)
    s = re.sub(rb"'\s*\+\s*'", b'', s)
    return s.lower()

def analyze_jsp(b):
    s = _norm_script(b); f = []
    req = any(k in s for k in (b'request.getparameter', b'request.getheader', b'request.getinputstream', b'request.getreader', b'getparametermap', b'request.getcookies'))
    if b'runtime.getruntime()' in s and b'.exec' in s and req: f.append(('jsp-exec-input', 97, ''))
    elif b'processbuilder' in s and req: f.append(('jsp-exec-input', 97, 'ProcessBuilder'))
    if b'defineclass' in s and (req or b'base64' in s): f.append(('jsp-defineclass', 96, ''))
    if (b'scriptengine' in s or b'javax.script' in s) and b'.eval(' in s and req: f.append(('jsp-script-eval', 95, ''))
    if b'class.forname' in s and b'getmethod' in s and b'invoke' in s and req and (b'base64' in s or b'cipher' in s): f.append(('jsp-reflect-input', 94, ''))
    if re.search(rb'(?:fileoutputstream|filewriter|randomaccessfile)\s*\([^;]{0,160}request\.getparameter', s): f.append(('jsp-write-input', 94, ''))
    if b'runtime.getruntime()' in s and b'.exec' in s and not req: f.append(('jsp-exec', 15, ''))
    return f

def analyze_asp(b):
    s = _norm_script(b); f = []
    req = any(k in s for k in (b'request.form', b'request.querystring', b'request(', b'request.item', b'request.binaryread', b'request["', b'request.params', b'request.files', b'.text'))
    if re.search(rb'\b(?:eval|execute|executeglobal)\s*\(?\s*(?:request|unescape)\b', s): f.append(('asp-eval-input', 98, ''))
    if re.search(rb'\b(?:eval|execute)\s*\(?\s*(?:morfi|decode|rev|str)', s) and b'request' in s: f.append(('asp-eval-input', 96, 'indirect'))
    if b'process.start' in s and req: f.append(('asp-exec-input', 97, ''))
    if re.search(rb'\.arguments\s*=\s*[^\n;]{0,100}(?:\.text|request)', s) and (b'processstartinfo' in s or b'process' in s): f.append(('aspx-exec-input', 94, ''))
    if (b'wscript.shell' in s) and (b'.exec' in s or b'.run' in s) and req: f.append(('asp-wscript-input', 96, ''))
    if b'assembly.load' in s and (b'frombase64string' in s or req): f.append(('asp-assembly-load', 96, ''))
    if b'processstartinfo' in s and req and b'cmd' in s: f.append(('asp-exec-input', 96, 'ProcessStartInfo'))
    if re.search(rb'(?:adodb\.stream|scripting\.filesystemobject)', s) and re.search(rb'(?:savetofile|createtextfile|opentextfile)\s*\(?[^\n]{0,120}request', s): f.append(('asp-write-input', 94, ''))
    if b'scripting.filesystemobject' in s and req and (b'savetofile' in s or b'binaryread' in s or b'.write' in s): f.append(('asp-filemanager', 50, ''))
    return f

def analyze_script(b, ext_=''):
    s = b.lower(); f = []
    if ext_ != '.py' and re.search(rb'bash\s+-i\s*>&?\s*/dev/tcp/\d|/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|nc(?:at)?\s+-[a-z]*e\s+/bin/(?:ba)?sh', s): f.append(('revshell', 96, ''))
    if re.search(rb'pty\.spawn\s*\(\s*["\']/bin/(?:ba)?sh', s) and b'socket' in s: f.append(('revshell', 96, 'pty'))
    if re.search(rb'socket\.socket\([^)]*\)[\s\S]{0,300}(?:os\.dup2|subprocess\.(?:call|popen))[\s\S]{0,200}(?:/bin/(?:ba)?sh|cmd\.exe)', s): f.append(('revshell', 95, 'python'))
    return f

# ------------------------------------------------------------------ penilaian
def known_markers(b):
    low = b[:MAX_FILE].lower()
    return [k.decode() for k in KNOWN_NAMES if k in low]

def analyze(path, data, ext, baseline=None, entropy_mode=True):
    """Putusan satu berkas. Return dict: score, verdict ('webshell'|'suspicious'|'clean'), rules, entropy."""
    F = {}
    ext = ext.lower()
    rules = []
    if ext in PHP_EXTS or (ext in ('.html', '.htm') and b'<?php' in data[:MAX_FILE].lower()):
        rules += analyze_php(data[:MAX_FILE], F)
    elif ext in JSP_EXTS: rules += analyze_jsp(data[:MAX_FILE])
    elif ext in ASP_EXTS: rules += analyze_asp(data[:MAX_FILE])
    elif ext in OTHER_EXTS: rules += analyze_script(data[:MAX_FILE], ext)
    H = entropy_bytes(data[:MAX_FILE]) if entropy_mode else 0.0
    if entropy_mode and ext in PHP_EXTS and len(data) >= 256:
        mean, sd = (baseline or (ENT_MEAN, ENT_SD))
        z = (H - mean) / sd
        if z >= Z_STRONG: rules.append(('entropy-high', 40, '%.2f' % H))
        elif z >= Z_FLAG: rules.append(('entropy-high', 30, '%.2f' % H))
    uniq = {}
    for r in rules:
        if r[0] not in uniq or r[1] > uniq[r[0]][1]: uniq[r[0]] = r
    rules = list(uniq.values())
    strong = [r for r in rules if r[1] >= 90]
    mark = known_markers(data) if (ext in PHP_EXTS or ext in JSP_EXTS or ext in ASP_EXTS) else []
    weak = sum(r[1] for r in rules if r[1] < 30)
    mid = sum(r[1] for r in rules if 30 <= r[1] < 90)
    if strong: score = max(r[1] for r in strong)
    else: score = min(89, min(weak, 40) + mid)
    if mark and rules and score < 90: score = min(89, score + 30)
    score = min(100, score)
    verdict = 'webshell' if score >= 90 else ('suspicious' if score >= 50 else 'clean')
    return {'score': score, 'verdict': verdict, 'rules': rules, 'entropy': round(H, 4), 'markers': mark}
