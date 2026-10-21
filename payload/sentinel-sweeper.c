/*
 * sentinel-sweeper.c : mesin pemindai webshell ZySentinel Sweeper (native, hemat sumber daya).
 *
 * Logika berasal dari keluarga ShellSweep (Splunk, Apache-2.0): entropi Shannon per berkas, ambang per jenis
 * berkas, daftar abai berbasis hash SHA-256, pengecualian path, dan analisis heuristik ShellSweepPlus. Mesin ini
 * menambahkan analisis token PHP (lexer, taint sederhana, pelipatan konstanta) agar tidak menandai kode sah.
 * Pustaka referensi Python (sweeplib.py di sentinel-sweeper.py) harus memberi putusan yang sama persis.
 *
 * Keluaran: satu baris JSON per temuan, lalu satu baris ringkasan. Tanpa efek samping pada berkas yang dipindai
 * (karantina dilakukan pemanggil).
 *
 * Bangun: cc -O2 -std=gnu11 -o sentinel-sweeper sentinel-sweeper.c -lm
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <math.h>
#include <regex.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <fts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

#define VERSION "1.0"
#define MAX_FILE (2 * 1024 * 1024)
#define STR_KEEP 512

/* ------------------------------------------------------------------ pengaturan */
static double ENT_MEAN = 4.664, ENT_SD = 0.325, Z_FLAG = 3.2, Z_STRONG = 4.2;
static long max_size = MAX_FILE;
static int min_score = 50;
static bool opt_all = false, opt_compat = false, opt_stats = false, opt_quiet = false;
static long since_epoch = 0;
static int throttle_ms = 0;
static char **excludes = NULL; static int n_excludes = 0;
static char **allow = NULL; static int n_allow = 0;       /* sha256 huruf kecil, terurut tidak diwajibkan */
static const char *list_file = NULL;
static int progress_sec = 0; static time_t last_progress = 0;

/* ------------------------------------------------------------------ memori */
static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) { fprintf(stderr, "memori habis\n"); exit(3); } return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n ? n : 1); if (!p) { fprintf(stderr, "memori habis\n"); exit(3); } return p; }

typedef struct Arena { char *buf; size_t cap, used; } Arena;
static Arena AR;
/* catatan: pointer arena dibatalkan bila buffer tumbuh; karena itu arena diperlakukan sebagai blok offset */
typedef struct { uint32_t off, len; } Span;
static Span ar_put(const unsigned char *s, size_t n) {
    size_t need = n + 1;
    if (AR.used + need > AR.cap) { size_t nc = AR.cap ? AR.cap : 1 << 20; while (nc < AR.used + need) nc *= 2; AR.buf = xrealloc(AR.buf, nc); AR.cap = nc; }
    Span sp = { (uint32_t)AR.used, (uint32_t)n };
    memcpy(AR.buf + AR.used, s, n); AR.buf[AR.used + n] = 0; AR.used += need; return sp;
}
#define SP(sp) ((const unsigned char *)(AR.buf + (sp).off))

/* ------------------------------------------------------------------ simbol */
enum {
    SF_EXEC = 1u << 0, SF_EVAL = 1u << 1, SF_INCLUDE = 1u << 2, SF_CB = 1u << 3, SF_DECS = 1u << 4, SF_FOLDDEC = 1u << 5,
    SF_SG_T = 1u << 6,      /* _get _post _request _cookie _files */
    SF_SG_SRV = 1u << 7, SF_SG_ENV = 1u << 8, SF_HASIN = 1u << 9, /* _get _post _request _cookie */
    SF_FSW = 1u << 10, SF_FSR = 1u << 11, SF_READER = 1u << 12, SF_FNAFTER = 1u << 13, SF_SOCK = 1u << 14, SF_HDRFN = 1u << 15,
    SF_DEC2 = 1u << 16,     /* DECODERS_STRICT + openssl_decrypt, mcrypt_decrypt */
};
typedef struct { char *name; uint32_t len, flags; int cbpos; } Sym;
static Sym *syms = NULL; static int nsyms = 0, capsyms = 0;
static int *symtab = NULL; static int symtab_cap = 0;
static int S_FUNCTION, S_FOREACH, S_AS, S_EXTRACT, S_THIS, S_PREG_REPLACE, S_ECHO, S_EVAL, S_ASSERT, S_CREATE_FUNCTION, S_REGISTERPHP;

static uint32_t hash_bytes(const unsigned char *s, size_t n) { uint32_t h = 2166136261u; for (size_t i = 0; i < n; i++) { h ^= s[i]; h *= 16777619u; } return h; }
static int sym_find(const unsigned char *s, size_t n) {
    if (!symtab_cap) return -1;
    uint32_t h = hash_bytes(s, n) & (symtab_cap - 1);
    while (symtab[h] >= 0) { Sym *y = &syms[symtab[h]]; if (y->len == n && memcmp(y->name, s, n) == 0) return symtab[h]; h = (h + 1) & (symtab_cap - 1); }
    return -1;
}
static void symtab_rehash(void) {
    int nc = symtab_cap ? symtab_cap * 2 : 4096;
    free(symtab); symtab = xmalloc(sizeof(int) * nc); for (int i = 0; i < nc; i++) symtab[i] = -1; symtab_cap = nc;
    for (int i = 0; i < nsyms; i++) { uint32_t h = hash_bytes((unsigned char *)syms[i].name, syms[i].len) & (nc - 1); while (symtab[h] >= 0) h = (h + 1) & (nc - 1); symtab[h] = i; }
}
static int sym_intern(const unsigned char *s, size_t n) {
    int id = sym_find(s, n); if (id >= 0) return id;
    if (nsyms + 1 > symtab_cap / 2) symtab_rehash();
    if (nsyms == capsyms) { capsyms = capsyms ? capsyms * 2 : 1024; syms = xrealloc(syms, sizeof(Sym) * capsyms); }
    Sym *y = &syms[nsyms]; y->name = xmalloc(n + 1); memcpy(y->name, s, n); y->name[n] = 0; y->len = (uint32_t)n; y->flags = 0; y->cbpos = 0;
    uint32_t h = hash_bytes(s, n) & (symtab_cap - 1); while (symtab[h] >= 0) h = (h + 1) & (symtab_cap - 1); symtab[h] = nsyms;
    return nsyms++;
}
static int sym_flag(const char *name, uint32_t f) { int id = sym_intern((const unsigned char *)name, strlen(name)); syms[id].flags |= f; return id; }
static void symbols_reset(void);
static void symbols_init(void) {
    const char *ex[] = { "system", "exec", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec", NULL };
    for (int i = 0; ex[i]; i++) sym_flag(ex[i], SF_EXEC);
    sym_flag("eval", SF_EVAL); sym_flag("assert", SF_EVAL); sym_flag("create_function", SF_EVAL);
    const char *inc[] = { "include", "include_once", "require", "require_once", NULL };
    for (int i = 0; inc[i]; i++) sym_flag(inc[i], SF_INCLUDE);
    struct { const char *n; int p; } cb[] = { {"call_user_func", 0}, {"call_user_func_array", 0}, {"array_map", 0}, {"array_filter", 1}, {"array_walk", 1},
        {"array_walk_recursive", 1}, {"usort", 1}, {"uasort", 1}, {"uksort", 1}, {"array_reduce", 1}, {"register_shutdown_function", 0},
        {"preg_replace_callback", 1}, {"iterator_apply", 1}, {"forward_static_call", 0}, {"forward_static_call_array", 0}, {"register_tick_function", 0}, {NULL, 0} };
    for (int i = 0; cb[i].n; i++) { int id = sym_flag(cb[i].n, SF_CB); syms[id].cbpos = cb[i].p; }
    const char *ds[] = { "base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "rawurldecode", "urldecode", "convert_uudecode", "hex2bin", "zlib_decode", "bzdecompress", "strrev", NULL };
    for (int i = 0; ds[i]; i++) sym_flag(ds[i], SF_DECS | SF_DEC2);
    sym_flag("openssl_decrypt", SF_DEC2); sym_flag("mcrypt_decrypt", SF_DEC2);
    const char *fd[] = { "base64_decode", "str_rot13", "strrev", "hex2bin", "rawurldecode", "urldecode", "strtolower", "strtoupper", "trim", "ucfirst", NULL };
    for (int i = 0; fd[i]; i++) sym_flag(fd[i], SF_FOLDDEC);
    sym_flag("_get", SF_SG_T | SF_HASIN); sym_flag("_post", SF_SG_T | SF_HASIN); sym_flag("_request", SF_SG_T | SF_HASIN); sym_flag("_cookie", SF_SG_T | SF_HASIN);
    sym_flag("_files", SF_SG_T); sym_flag("_server", SF_SG_SRV); sym_flag("_env", SF_SG_ENV);
    const char *fw[] = { "file_put_contents", "fwrite", "fputs", "move_uploaded_file", "copy", "rename", "symlink", "link", NULL };
    for (int i = 0; fw[i]; i++) sym_flag(fw[i], SF_FSW);
    const char *fr[] = { "readfile", "file_get_contents", "file", "highlight_file", "show_source", "fopen", "unlink", "rmdir", "mkdir", "chmod", "scandir", "opendir", "glob", "touch", NULL };
    for (int i = 0; fr[i]; i++) sym_flag(fr[i], SF_FSR);
    const char *rd[] = { "file_get_contents", "fopen", "fgets", "fread", "stream_get_contents", "readfile", "file", NULL };
    for (int i = 0; rd[i]; i++) sym_flag(rd[i], SF_READER);
    const char *fa[] = { "function", "new", "class", "const", "namespace", "use", "extends", "implements", "trait", "interface", "instanceof", "catch", "insteadof", NULL };
    for (int i = 0; fa[i]; i++) sym_flag(fa[i], SF_FNAFTER);
    const char *sk[] = { "fsockopen", "stream_socket_client", "socket_create", "pfsockopen", "socket_connect", NULL };
    for (int i = 0; sk[i]; i++) sym_flag(sk[i], SF_SOCK);
    sym_flag("getallheaders", SF_HDRFN); sym_flag("apache_request_headers", SF_HDRFN);
    S_FUNCTION = sym_intern((const unsigned char *)"function", 8); S_FOREACH = sym_intern((const unsigned char *)"foreach", 7);
    S_AS = sym_intern((const unsigned char *)"as", 2); S_EXTRACT = sym_intern((const unsigned char *)"extract", 7);
    S_THIS = sym_intern((const unsigned char *)"this", 4); S_PREG_REPLACE = sym_intern((const unsigned char *)"preg_replace", 12);
    S_ECHO = sym_intern((const unsigned char *)"echo", 4); S_EVAL = sym_intern((const unsigned char *)"eval", 4);
    S_ASSERT = sym_intern((const unsigned char *)"assert", 6); S_CREATE_FUNCTION = sym_intern((const unsigned char *)"create_function", 15);
    S_REGISTERPHP = sym_intern((const unsigned char *)"registerphpfunctions", 20);
}

static void symbols_reset(void) { for (int i = 0; i < nsyms; i++) free(syms[i].name); nsyms = 0; free(symtab); symtab = NULL; symtab_cap = 0; symbols_init(); }

/* ------------------------------------------------------------------ token */
enum { T_ID = 1, T_VAR, T_VARVAR, T_STR, T_BT, T_NUM, T_OP };
typedef struct {
    uint8_t t; uint16_t op;        /* op: char1 | char2 << 8 */
    int32_t sym;                   /* ID / VAR */
    Span val;                      /* STR / BT / NUM / VARVAR: nilai terdekode (maks STR_KEEP) */
    uint32_t n;                    /* panjang sebenarnya string */
    int32_t *interp; uint16_t ni;  /* variabel yang diinterpolasi (sym) */
} Tok;
static Tok *toks; static int ntok, captok;
static long hex_esc;
static void tok_push(Tok t) { if (ntok == captok) { captok = captok ? captok * 2 : 4096; toks = xrealloc(toks, sizeof(Tok) * captok); } toks[ntok++] = t; }
static Tok mk(uint8_t t) { Tok k; memset(&k, 0, sizeof k); k.t = t; return k; }
static Tok mkop(unsigned char c1, unsigned char c2) { Tok k = mk(T_OP); k.op = c1 | (c2 << 8); return k; }
#define OP1(p, ch) ((p)->t == T_OP && (p)->op == (ch))

static inline bool is_id0(unsigned c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '\\' || c >= 128; }
static inline bool is_idn(unsigned c) { return is_id0(c) || (c >= '0' && c <= '9'); }
static inline bool is_ws(unsigned c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0b || c == 0x0c; }
static inline int hexv(unsigned c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }

/* dekode string petik-dua. out harus berkapasitas >= n; vars = daftar sym yang diinterpolasi (di-malloc). */
static size_t decode_dq(const unsigned char *s, size_t n, unsigned char *out, int32_t **vars, uint16_t *nvars) {
    size_t o = 0, i = 0; int32_t *v = NULL; int nv = 0, cv = 0;
#define PUSHV(p, l) do { unsigned char tmp[256]; size_t ll = (l) > 255 ? 255 : (l); for (size_t q = 0; q < ll; q++) tmp[q] = (unsigned char)tolower((p)[q]); \
        if (nv == cv) { cv = cv ? cv * 2 : 4; v = xrealloc(v, sizeof(int32_t) * cv); } v[nv++] = sym_intern(tmp, ll); } while (0)
    while (i < n) {
        unsigned c = s[i];
        if (c == '\\' && i + 1 < n) {
            unsigned d = s[i + 1];
            switch (d) {
            case 'n': out[o++] = 10; i += 2; continue; case 't': out[o++] = 9; i += 2; continue; case 'r': out[o++] = 13; i += 2; continue;
            case 'v': out[o++] = 11; i += 2; continue; case 'e': out[o++] = 27; i += 2; continue; case 'f': out[o++] = 12; i += 2; continue;
            case '\\': out[o++] = '\\'; i += 2; continue; case '$': out[o++] = '$'; i += 2; continue; case '"': out[o++] = '"'; i += 2; continue;
            }
            if (d == 'x' && i + 2 < n && hexv(s[i + 2]) >= 0) {
                size_t j = i + 2, k = j; int val = 0;
                while (k < n && k < j + 2 && hexv(s[k]) >= 0) { val = val * 16 + hexv(s[k]); k++; }
                out[o++] = (unsigned char)val; i = k; continue;
            }
            if (d >= '0' && d <= '7') {
                size_t j = i + 1, k = j; int val = 0;
                while (k < n && k < j + 3 && s[k] >= '0' && s[k] <= '7') { val = val * 8 + (s[k] - '0'); k++; }
                out[o++] = (unsigned char)(val & 255); i = k; continue;
            }
            out[o++] = (unsigned char)c; out[o++] = (unsigned char)d; i += 2; continue;
        }
        if (c == '$' && i + 1 < n && (is_id0(s[i + 1]) || s[i + 1] == '{')) {
            size_t j = i + 1;
            if (s[j] == '{') {
                const unsigned char *e = memchr(s + j, '}', n - j); size_t k = e ? (size_t)(e - s) : n;
                /* isi: lstrip('$'), potong di '[' lalu di '-', strip spasi, huruf kecil */
                size_t a = j + 1, b = k; while (a < b && s[a] == '$') a++;
                size_t z = a; while (z < b && s[z] != '[') z++; b = z; z = a; while (z < b && s[z] != '-') z++; b = z;
                while (a < b && is_ws(s[a])) a++;
                while (b > a && is_ws(s[b - 1])) b--;
                PUSHV(s + a, b - a); i = k + 1; out[o++] = '?'; continue;
            }
            size_t k = j; while (k < n && is_idn(s[k])) k++;
            PUSHV(s + j, k - j); i = k; out[o++] = '?'; continue;
        }
        if (c == '{' && i + 1 < n && s[i + 1] == '$') {
            const unsigned char *e = memchr(s + i, '}', n - i); size_t k = e ? (size_t)(e - s) : n;
            size_t a = i + 2; if (a < k && (isalpha(s[a]) || s[a] == '_' || s[a] >= 0x80)) { size_t z = a; while (z < k && (isalnum(s[z]) || s[z] == '_' || s[z] >= 0x80)) z++; PUSHV(s + a, z - a); }
            out[o++] = '?'; i = k + 1; continue;
        }
        out[o++] = (unsigned char)c; i++;
    }
    *vars = v; *nvars = (uint16_t)nv; return o;
}

/* konversi string petik-tunggal: ganti "\\\\" -> "\\" lalu "\\'" -> "'" (berurutan, sama dengan referensi) */
static size_t decode_sq(const unsigned char *raw, size_t n, unsigned char *out) {
    unsigned char *tmp = xmalloc(n + 1); size_t t = 0;
    for (size_t i = 0; i < n; i++) { if (raw[i] == '\\' && i + 1 < n && raw[i + 1] == '\\') { tmp[t++] = '\\'; i++; } else tmp[t++] = raw[i]; }
    size_t o = 0;
    for (size_t i = 0; i < t; i++) { if (tmp[i] == '\\' && i + 1 < t && tmp[i + 1] == '\'') { out[o++] = '\''; i++; } else out[o++] = tmp[i]; }
    free(tmp); return o;
}

static void free_tokens(void) { for (int i = 0; i < ntok; i++) if (toks[i].interp) { free(toks[i].interp); toks[i].interp = NULL; } ntok = 0; }
static void lex_php(const unsigned char *b, size_t n) {
    free_tokens(); AR.used = 0; hex_esc = 0;
    size_t i = 0; bool in_code = false;
    unsigned char *tmp = xmalloc(n + 8);
    while (i < n) {
        if (!in_code) {
            const unsigned char *p = memmem(b + i, n - i, "<?", 2);
            if (!p) break;
            size_t j = (size_t)(p - b), k = j + 2;
            if (k + 3 <= n && strncasecmp((const char *)b + k, "php", 3) == 0 && (k + 3 >= n || is_ws(b[k + 3]))) { i = k + 3; in_code = true; }
            else if (k < n && b[k] == '=') { i = k + 1; in_code = true; Tok t = mk(T_ID); t.sym = S_ECHO; tok_push(t); }
            else if (k < n && is_ws(b[k])) { i = k; in_code = true; }
            else i = k;
            continue;
        }
        unsigned c = b[i];
        if (is_ws(c)) { i++; continue; }
        if (c == '?' && i + 1 < n && b[i + 1] == '>') {
            in_code = false; i += 2; if (i < n && b[i] == '\n') i++;
            tok_push(mkop(';', 0)); continue;
        }
        if (c == '#' && i + 1 < n && b[i + 1] == '[') { tok_push(mkop('#', 0)); i++; continue; }
        if (c == '#' || (c == '/' && i + 1 < n && b[i + 1] == '/')) {
            size_t j = i; while (j < n && b[j] != '\n') { if (b[j] == '?' && j + 1 < n && b[j + 1] == '>') break; j++; }
            i = j; continue;
        }
        if (c == '/' && i + 1 < n && b[i + 1] == '*') {
            const unsigned char *e = (i + 2 <= n) ? memmem(b + i + 2, n - i - 2, "*/", 2) : NULL;
            i = e ? (size_t)(e - b) + 2 : n; continue;
        }
        if (c == '\'') {
            size_t j = i + 1; while (j < n && b[j] != '\'') j += (b[j] == '\\') ? 2 : 1;
            size_t rl = (j <= n ? j : n) - (i + 1);
            size_t ol = decode_sq(b + i + 1, rl, tmp);
            Tok t = mk(T_STR); t.val = ar_put(tmp, ol > STR_KEEP ? STR_KEEP : ol); t.n = (uint32_t)ol; tok_push(t);
            i = j + 1; continue;
        }
        if (c == '"') {
            size_t j = i + 1; while (j < n && b[j] != '"') j += (b[j] == '\\') ? 2 : 1;
            size_t rl = (j <= n ? j : n) - (i + 1); const unsigned char *raw = b + i + 1;
            for (size_t q = 0; q + 3 < rl; ) { if (raw[q] == '\\' && raw[q + 1] == 'x' && hexv(raw[q + 2]) >= 0 && hexv(raw[q + 3]) >= 0) { hex_esc++; q += 4; } else q++; }
            int32_t *vs; uint16_t nv; size_t ol = decode_dq(raw, rl, tmp, &vs, &nv);
            Tok t = mk(T_STR); t.val = ar_put(tmp, ol > STR_KEEP ? STR_KEEP : ol); t.n = (uint32_t)ol; t.interp = vs; t.ni = nv; tok_push(t);
            i = j + 1; continue;
        }
        if (c == '`') {
            size_t j = i + 1; while (j < n && b[j] != '`') j += (b[j] == '\\') ? 2 : 1;
            size_t rl = (j <= n ? j : n) - (i + 1);
            int32_t *vs; uint16_t nv; size_t ol = decode_dq(b + i + 1, rl, tmp, &vs, &nv);
            Tok t = mk(T_BT); t.val = ar_put(tmp, ol > STR_KEEP ? STR_KEEP : ol); t.n = (uint32_t)ol; t.interp = vs; t.ni = nv; tok_push(t);
            i = j + 1; continue;
        }
        if (c == '<' && i + 2 < n && b[i + 1] == '<' && b[i + 2] == '<') {
            /* heredoc / nowdoc */
            size_t p = i + 3; while (p < n && (b[p] == ' ' || b[p] == '\t')) p++;
            unsigned q = 0; if (p < n && (b[p] == '\'' || b[p] == '"')) { q = b[p]; p++; }
            size_t a = p; if (p < n && ((b[p] >= 'A' && b[p] <= 'Z') || (b[p] >= 'a' && b[p] <= 'z') || b[p] == '_')) { p++; while (p < n && (isalnum(b[p]) || b[p] == '_')) p++; } else a = p;
            size_t idlen = p - a; bool ok = idlen > 0;
            if (ok && q) { if (p < n && b[p] == q) p++; else ok = false; }
            if (ok && p < n && b[p] == '\r') p++;
            if (ok && p < n && b[p] == '\n') p++; else ok = false;
            if (ok && (p - i) <= 80) {
                size_t start = p, ls = start, end = n, after = n; bool found = false;
                while (ls <= n) {
                    size_t x = ls; while (x < n && (b[x] == ' ' || b[x] == '\t')) x++;
                    if (x + idlen <= n && memcmp(b + x, b + a, idlen) == 0 && (x + idlen >= n || !(isalnum(b[x + idlen]) || b[x + idlen] == '_'))) { end = ls; after = x + idlen; found = true; break; }
                    const unsigned char *nl = (ls < n) ? memchr(b + ls, '\n', n - ls) : NULL; if (!nl) break; ls = (size_t)(nl - b) + 1;
                }
                size_t bl = end - start; const unsigned char *body = b + start;
                Tok t = mk(T_STR);
                if (q == '\'') { memcpy(tmp, body, bl); t.val = ar_put(tmp, bl > STR_KEEP ? STR_KEEP : bl); t.n = (uint32_t)bl; }
                else { int32_t *vs; uint16_t nv; size_t ol = decode_dq(body, bl, tmp, &vs, &nv); t.val = ar_put(tmp, ol > STR_KEEP ? STR_KEEP : ol); t.n = (uint32_t)ol; t.interp = vs; t.ni = nv; }
                tok_push(t); i = found ? after : n; continue;
            }
        }
        if (c == '$') {
            size_t j = i + 1;
            if (j < n && b[j] == '$') { Tok t = mk(T_VARVAR); t.val = ar_put((const unsigned char *)"$", 1); tok_push(t); i++; continue; }
            if (j < n && b[j] == '{') { Tok t = mk(T_VARVAR); t.val = ar_put((const unsigned char *)"${", 2); tok_push(t); i += 2; continue; }
            size_t k = j; while (k < n && is_idn(b[k])) k++;
            unsigned char nm[256]; size_t l = k - j; if (l > 255) l = 255; for (size_t q = 0; q < l; q++) nm[q] = (unsigned char)tolower(b[j + q]);
            Tok t = mk(T_VAR); t.sym = sym_intern(nm, l); tok_push(t); i = k; continue;
        }
        if (is_id0(c)) {
            size_t k = i; while (k < n && is_idn(b[k])) k++;
            size_t a = i; while (a < k && b[a] == '\\') a++;       /* lstrip('\\') setelah lower */
            unsigned char nm[256]; size_t l = k - a; if (l > 255) l = 255; for (size_t q = 0; q < l; q++) nm[q] = (unsigned char)tolower(b[a + q]);
            Tok t = mk(T_ID); t.sym = sym_intern(nm, l); tok_push(t); i = k; continue;
        }
        if (c >= '0' && c <= '9') {
            size_t k = i; while (k < n && (is_idn(b[k]) || b[k] == '.')) k++;
            Tok t = mk(T_NUM); size_t l = k - i; t.val = ar_put(b + i, l > STR_KEEP ? STR_KEEP : l); t.n = (uint32_t)l; tok_push(t); i = k; continue;
        }
        if (i + 1 < n) {
            unsigned d = b[i + 1]; unsigned pr = c | (d << 8);
            if (pr == ('.' | ('=' << 8)) || pr == ('=' | ('>' << 8)) || pr == ('-' | ('>' << 8)) || pr == (':' | (':' << 8)) || pr == ('=' | ('=' << 8)) ||
                pr == ('!' | ('=' << 8)) || pr == ('&' | ('&' << 8)) || pr == ('|' | ('|' << 8)) || pr == ('?' | ('?' << 8)) || pr == ('+' | ('=' << 8)) ||
                pr == ('-' | ('=' << 8)) || pr == ('<' | ('=' << 8)) || pr == ('>' | ('=' << 8)) || pr == ('+' | ('+' << 8)) || pr == ('-' | ('-' << 8))) {
                tok_push(mkop((unsigned char)c, (unsigned char)d)); i += 2; continue;
            }
        }
        tok_push(mkop((unsigned char)c, 0)); i++;
    }
    free(tmp);
}

/* ------------------------------------------------------------------ keadaan variabel (lingkup) */
typedef struct { int32_t sym; char cls; bool hasfold; Span fold; } Ent;
typedef struct { Ent *tab; int cap, n; bool extract; } Scope;
static Scope *scope_new(void) { Scope *s = xmalloc(sizeof *s); s->cap = 16; s->n = 0; s->extract = false; s->tab = xmalloc(sizeof(Ent) * 16); for (int i = 0; i < 16; i++) s->tab[i].sym = -1; return s; }
static void scope_free(Scope *s) { free(s->tab); free(s); }
static Ent *scope_find(Scope *s, int32_t sym) {
    uint32_t h = ((uint32_t)sym * 2654435761u) & (s->cap - 1);
    while (s->tab[h].sym >= 0) { if (s->tab[h].sym == sym) return &s->tab[h]; h = (h + 1) & (s->cap - 1); }
    return NULL;
}
static Ent *scope_get(Scope *s, int32_t sym) {
    Ent *e = scope_find(s, sym); if (e) return e;
    if ((s->n + 1) * 2 > s->cap) {
        int nc = s->cap * 2; Ent *nt = xmalloc(sizeof(Ent) * nc); for (int i = 0; i < nc; i++) nt[i].sym = -1;
        for (int i = 0; i < s->cap; i++) if (s->tab[i].sym >= 0) { uint32_t h = ((uint32_t)s->tab[i].sym * 2654435761u) & (nc - 1); while (nt[h].sym >= 0) h = (h + 1) & (nc - 1); nt[h] = s->tab[i]; }
        free(s->tab); s->tab = nt; s->cap = nc;
    }
    uint32_t h = ((uint32_t)sym * 2654435761u) & (s->cap - 1);
    while (s->tab[h].sym >= 0) h = (h + 1) & (s->cap - 1);
    s->tab[h].sym = sym; s->tab[h].cls = 0; s->tab[h].hasfold = false; s->n++; return &s->tab[h];
}
static Scope *scope_clone(Scope *o) { Scope *s = xmalloc(sizeof *s); s->cap = o->cap; s->n = o->n; s->extract = false; s->tab = xmalloc(sizeof(Ent) * o->cap); memcpy(s->tab, o->tab, sizeof(Ent) * o->cap); return s; }
static inline char cls_of(Scope *s, int32_t sym) { Ent *e = scope_find(s, sym); return e ? e->cls : 0; }

/* himpunan kelas ekspresi */
enum { C_T = 1, C_S = 2, C_O = 4, C_D = 8, C_F = 16, C_DEC = 32, C_VV = 64 };
static inline int cbit(char c) { switch (c) { case 'T': return C_T; case 'S': return C_S; case 'O': return C_O; case 'D': return C_D; case 'F': return C_F; } return 0; }

static int expr_taint(int a, int b, Scope *st) {   /* token [a, b) */
    int r = 0;
    for (int i = a; i < b; i++) {
        Tok *t = &toks[i];
        if (t->t == T_VAR) {
            uint32_t f = syms[t->sym].flags;
            if (f & (SF_SG_T | SF_SG_SRV | SF_SG_ENV)) {
                if (f & SF_SG_SRV) {
                    if (i + 2 < b && OP1(&toks[i + 1], '[') && toks[i + 2].t == T_STR) {
                        const unsigned char *v = SP(toks[i + 2].val); size_t l = toks[i + 2].val.len;
                        if ((l >= 5 && strncasecmp((const char *)v, "http_", 5) == 0) || (l >= 12 && strncasecmp((const char *)v, "query_string", 12) == 0) ||
                            (l >= 11 && strncasecmp((const char *)v, "request_uri", 11) == 0) || (l >= 9 && strncasecmp((const char *)v, "path_info", 9) == 0)) r |= C_S;
                    }
                } else if (!(f & SF_SG_ENV)) r |= C_T;
            } else {
                char c = cls_of(st, t->sym);
                if (c == 'F') r |= C_DEC | C_F;
                else if (c) r |= cbit(c);
                else if (st->extract && !(scope_find(st, t->sym) && scope_find(st, t->sym)->hasfold) && t->sym != S_THIS) r |= C_T;
            }
        } else if (t->t == T_STR) {
            const unsigned char *v = SP(t->val); size_t l = t->val.len;
            if (i >= a + 2 && OP1(&toks[i - 1], '(') && toks[i - 2].t == T_ID && (syms[toks[i - 2].sym].flags & SF_READER)) {
                bool in = false;
                for (size_t q = 0; q + 11 <= l; q++) if (strncasecmp((const char *)v + q, "php://input", 11) == 0) { in = true; break; }
                if (!in) for (size_t q = 0; q + 11 <= l; q++) if (strncasecmp((const char *)v + q, "php://stdin", 11) == 0) { in = true; break; }
                if (in) r |= C_T;
            }
            for (int q = 0; q < t->ni; q++) {
                int32_t vn = t->interp[q]; uint32_t f = syms[vn].flags;
                if ((f & SF_SG_T)) r |= C_T;
                else { char c = cls_of(st, vn); if (c) r |= cbit(c); }
            }
        } else if (t->t == T_BT) {
            for (int q = 0; q < t->ni; q++) { int32_t vn = t->interp[q]; if ((syms[vn].flags & (SF_SG_T | SF_SG_SRV | SF_SG_ENV)) || cls_of(st, vn) == 'T') r |= C_T; }
        } else if (t->t == T_ID) {
            uint32_t f = syms[t->sym].flags;
            if (f & SF_DECS) r |= C_DEC;
            if (f & SF_HDRFN) r |= C_T;
        } else if (t->t == T_VARVAR) r |= C_VV;
    }
    return r;
}

/* ------------------------------------------------------------------ pelipatan konstanta */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char *apply_decoder(const char *name, const unsigned char *v, size_t n, size_t *ol) {
    unsigned char *o = xmalloc(n * 2 + 8);
    if (strcmp(name, "base64_decode") == 0) {
        /* sama dengan b64decode non-ketat: abaikan karakter di luar alfabet; bersihkan padding dulu */
        unsigned char *cl = xmalloc(n + 1); size_t cn = 0;
        for (size_t i = 0; i < n; i++) if (strchr(B64, v[i]) && v[i]) cl[cn++] = v[i];
        size_t oo = 0; uint32_t acc = 0; int bits = 0;
        for (size_t i = 0; i < cn; i++) { acc = (acc << 6) | (uint32_t)(strchr(B64, cl[i]) - B64); bits += 6; if (bits >= 8) { bits -= 8; o[oo++] = (acc >> bits) & 255; } }
        free(cl); *ol = oo; return o;
    }
    if (strcmp(name, "str_rot13") == 0) { for (size_t i = 0; i < n; i++) { unsigned c = v[i]; if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + 13) % 26; else if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + 13) % 26; o[i] = (unsigned char)c; } *ol = n; return o; }
    if (strcmp(name, "strrev") == 0) { for (size_t i = 0; i < n; i++) o[i] = v[n - 1 - i]; *ol = n; return o; }
    if (strcmp(name, "hex2bin") == 0) {
        size_t oo = 0; bool bad = (n % 2) != 0;
        for (size_t i = 0; !bad && i + 1 < n; i += 2) { int h = hexv(v[i]), l = hexv(v[i + 1]); if (h < 0 || l < 0) { bad = true; break; } o[oo++] = (unsigned char)(h * 16 + l); }
        *ol = bad ? 0 : oo; return o;
    }
    if (strcmp(name, "rawurldecode") == 0 || strcmp(name, "urldecode") == 0) {
        size_t oo = 0; for (size_t i = 0; i < n; i++) { if (v[i] == '%' && i + 2 < n + 0 && hexv(v[i + 1]) >= 0 && hexv(v[i + 2]) >= 0) { o[oo++] = (unsigned char)(hexv(v[i + 1]) * 16 + hexv(v[i + 2])); i += 2; } else o[oo++] = v[i]; }
        *ol = oo; return o;
    }
    if (strcmp(name, "strtolower") == 0) { for (size_t i = 0; i < n; i++) o[i] = (unsigned char)((v[i] >= 'A' && v[i] <= 'Z') ? v[i] + 32 : v[i]); *ol = n; return o; }
    if (strcmp(name, "strtoupper") == 0) { for (size_t i = 0; i < n; i++) o[i] = (unsigned char)((v[i] >= 'a' && v[i] <= 'z') ? v[i] - 32 : v[i]); *ol = n; return o; }
    if (strcmp(name, "trim") == 0) { size_t a = 0, b = n; while (a < b && is_ws(v[a])) a++; while (b > a && is_ws(v[b - 1])) b--; memcpy(o, v + a, b - a); *ol = b - a; return o; }
    if (strcmp(name, "ucfirst") == 0) { memcpy(o, v, n); if (n && o[0] >= 'a' && o[0] <= 'z') o[0] -= 32; *ol = n; return o; }
    memcpy(o, v, n); *ol = n; return o;
}
#define FOLD_MAX 4096
/* kembalikan buffer malloc atau NULL. [a, b) token. */
static unsigned char *fold_const(int a, int b, Scope *st, size_t *outlen, int depth) {
    if (depth > 8) return NULL;
    unsigned char *res = xmalloc(FOLD_MAX + 1); size_t rl = 0; int pos = a;
    while (pos < b) {
        Tok *t = &toks[pos];
        unsigned char *piece = NULL; size_t pl = 0; int npos = pos;
        if (t->t == T_STR && t->ni == 0) { pl = t->val.len; piece = xmalloc(pl + 1); memcpy(piece, SP(t->val), pl); npos = pos + 1; }
        else if (t->t == T_VAR && st) {
            Ent *e = scope_find(st, t->sym);
            if (e && e->hasfold && e->cls != 'T' && e->cls != 'S') { pl = e->fold.len; piece = xmalloc(pl + 1); memcpy(piece, SP(e->fold), pl); npos = pos + 1; }
        } else if (t->t == T_ID && pos + 1 < b && OP1(&toks[pos + 1], '(')) {
            int dpt = 0, j = pos + 1;
            while (j < b) { if (OP1(&toks[j], '(')) dpt++; else if (OP1(&toks[j], ')')) { dpt--; if (dpt == 0) break; } j++; }
            if (j < b) {
                const char *nm = syms[t->sym].name;
                if (strcmp(nm, "chr") == 0 && j - (pos + 2) == 1 && toks[pos + 2].t == T_NUM) {
                    char nb[64]; size_t l = toks[pos + 2].val.len; if (l > 60) l = 60; memcpy(nb, SP(toks[pos + 2].val), l); nb[l] = 0;
                    char *end; long v = strtol(nb, &end, 0);
                    bool lead0 = (l > 1 && nb[0] == '0' && isdigit((unsigned char)nb[1]));
                    if (*end == 0 && l > 0 && !lead0) { piece = xmalloc(2); piece[0] = (unsigned char)(v & 255); pl = 1; npos = j + 1; }
                } else if (syms[t->sym].flags & SF_FOLDDEC) {
                    size_t il; unsigned char *inner = fold_const(pos + 2, j, st, &il, depth + 1);
                    if (inner) { piece = apply_decoder(nm, inner, il, &pl); free(inner); npos = j + 1; }
                }
            }
        }
        if (!piece) { free(res); return NULL; }
        if (rl + pl > FOLD_MAX) pl = FOLD_MAX - rl;
        memcpy(res + rl, piece, pl); rl += pl; free(piece); pos = npos;
        if (pos < b) { if (OP1(&toks[pos], '.')) pos++; else { free(res); return NULL; } }
    }
    *outlen = rl; return res;
}

/* nama (huruf kecil, dipangkas) apakah sink / dekoder */
static uint32_t flags_of_bytes_x(const unsigned char *v, size_t n, bool strip) {
    size_t a = 0, b = n; if (strip) { while (a < b && is_ws(v[a])) a++; while (b > a && is_ws(v[b - 1])) b--; }
    if (b - a > 64) return 0;
    unsigned char tmp[64]; for (size_t i = a; i < b; i++) tmp[i - a] = (unsigned char)tolower(v[i]);
    int id = sym_find(tmp, b - a); return id < 0 ? 0 : syms[id].flags;
}
static uint32_t flags_of_bytes(const unsigned char *v, size_t n) { return flags_of_bytes_x(v, n, true); }

/* ------------------------------------------------------------------ temuan */
typedef struct { char id[40]; int w; char detail[72]; } Fnd;
typedef struct { Fnd *a; int n, cap; } FndList;
static FndList FL;
static void fnd_add(const char *id, int w, const char *detail) {
    if (FL.n == FL.cap) { FL.cap = FL.cap ? FL.cap * 2 : 32; FL.a = xrealloc(FL.a, sizeof(Fnd) * FL.cap); }
    Fnd *f = &FL.a[FL.n++]; snprintf(f->id, sizeof f->id, "%s", id); f->w = w; snprintf(f->detail, sizeof f->detail, "%s", detail ? detail : "");
}
static bool fnd_has(const char *id) { for (int i = 0; i < FL.n; i++) if (strcmp(FL.a[i].id, id) == 0) return true; return false; }

static int match_paren(int i) {                       /* toks[i] == '(' ; sama dengan _match_paren */
    int depth = 0, lim = i + 3000 < ntok ? i + 3000 : ntok;
    for (int j = i; j < lim; j++) { if (OP1(&toks[j], '(')) depth++; else if (OP1(&toks[j], ')')) { depth--; if (depth == 0) return j; } }
    return lim;
}
typedef struct { int a, b; } Rng;
static int split_args(int a, int b, Rng *out, int maxn) {
    int n = 0, depth = 0, cur = a;
    for (int i = a; i < b; i++) {
        Tok *t = &toks[i];
        if (t->t == T_OP) {
            if (t->op == '(' || t->op == '[') depth++;
            else if (t->op == ')' || t->op == ']') depth--;
            else if (t->op == ',' && depth == 0) { if (n < maxn) { out[n].a = cur; out[n].b = i; } n++; cur = i + 1; }
        }
    }
    if (n < maxn) { out[n].a = cur; out[n].b = b; } n++;
    return n < maxn ? n : maxn;
}
static bool tainted_first(Rng r, Scope *st) {         /* args[0][0] VAR dan (superglobal apa pun atau kelas T) */
    if (r.a >= r.b) return false;
    Tok *t = &toks[r.a]; if (t->t != T_VAR) return false;
    return (syms[t->sym].flags & (SF_SG_T | SF_SG_SRV | SF_SG_ENV)) || cls_of(st, t->sym) == 'T';
}
static bool b64ish(const unsigned char *v, size_t n) {
    if (!n) return false;
    size_t ok = 0;
    for (size_t i = 0; i < n; i++) if (strchr(B64, v[i]) ? v[i] != 0 : v[i] == '=') ok++;
    return (double)ok / (double)n > 0.97;
}
static bool regex_php_e(const unsigned char *s, size_t n) {   /* ^(.)(?:.*)\1([a-zA-Z]*)$ dengan 'e' pada pengubah */
    if (n < 2) return false;
    unsigned char d = s[0];
    for (size_t j = n - 1; j >= 1; j--) {
        if (s[j] == d) {
            size_t k = j + 1; bool letters = true, hase = false;
            size_t e = n; if (e > 0 && s[e - 1] == '\n') e--;          /* '$' cocok sebelum newline akhir */
            for (; k < e; k++) { if (!isalpha(s[k])) { letters = false; break; } if (s[k] == 'e') hase = true; }
            if (letters && (e == n || k == e)) return hase;
        }
        if (j == 1) break;
    }
    return false;
}
static bool revshell_str(const unsigned char *s, size_t n) {   /* (?:/bin/(?:ba)?sh|\bbash|\bsh)\s+-i\b | [<>]&\s*[345]\b */
    for (size_t i = 0; i < n; i++) {
        size_t p = i; bool m = false;
        if (n - i >= 7 && memcmp(s + i, "/bin/sh", 7) == 0) { p = i + 7; m = true; }
        else if (n - i >= 9 && memcmp(s + i, "/bin/bash", 9) == 0) { p = i + 9; m = true; }
        else if (n - i >= 4 && memcmp(s + i, "bash", 4) == 0 && (i == 0 || !(isalnum(s[i - 1]) || s[i - 1] == '_'))) { p = i + 4; m = true; }
        else if (n - i >= 2 && memcmp(s + i, "sh", 2) == 0 && (i == 0 || !(isalnum(s[i - 1]) || s[i - 1] == '_'))) { p = i + 2; m = true; }
        if (m) {
            size_t q = p; while (q < n && is_ws(s[q])) q++;
            if (q > p && q + 1 < n && s[q] == '-' && s[q + 1] == 'i' && (q + 2 >= n || !(isalnum(s[q + 2]) || s[q + 2] == '_'))) return true;
        }
        if ((s[i] == '<' || s[i] == '>') && i + 1 < n && s[i + 1] == '&') {
            size_t q = i + 2; while (q < n && is_ws(s[q])) q++;
            if (q < n && (s[q] == '3' || s[q] == '4' || s[q] == '5') && (q + 1 >= n || !(isalnum(s[q + 1]) || s[q + 1] == '_'))) return true;
        }
    }
    return false;
}

static bool foreach_input;
static void analyze_php(const unsigned char *b, size_t n, long *ntoks_out) {
    lex_php(b, n);
    if (ntoks_out) *ntoks_out = ntok;
    FL.n = 0; foreach_input = false;
    Scope *scopes[64]; int nsc = 0; scopes[nsc++] = scope_new();
    unsigned char *brs = xmalloc(ntok + 16); int nbs = 0;
    int pending = 0;                 /* 0 none, 1 named, 2 anon */
    bool eval_seen = false, exec_seen = false, sock_has = false, has_input = false;
    uint32_t fs_mask = 0; int fs_count = 0; char fs_names[16][24]; int fs_nn = 0;
    int i = 0;
    while (i < ntok) {
        Tok *t = &toks[i]; Scope *st = scopes[nsc - 1];
        Tok *prev = i ? &toks[i - 1] : NULL; Tok *nxt = i + 1 < ntok ? &toks[i + 1] : NULL;
        if (t->t == T_OP) {
            if (t->op == '{') {
                if (pending && nsc < 63) {
                    Scope *ns = (pending == 2) ? scope_clone(st) : scope_new();
                    scopes[nsc++] = ns; brs[nbs++] = 1; pending = 0;
                } else { brs[nbs++] = 0; if (pending) pending = 0; }
            } else if (t->op == '}') {
                if (nbs > 0) { if (brs[--nbs] && nsc > 1) { scope_free(scopes[--nsc]); } }
            } else if (t->op == ';') pending = 0;
            i++; continue;
        }
        if (t->t == T_ID) {
            int name = t->sym; uint32_t fl = syms[name].flags;
            bool member = prev && prev->t == T_OP && (prev->op == ('-' | ('>' << 8)) || prev->op == (':' | (':' << 8)));
            if (member) { i++; continue; }
            if (name == S_FUNCTION) {
                int j = i + 1; if (j < ntok && OP1(&toks[j], '&')) j++;
                pending = (j < ntok && OP1(&toks[j], '(')) ? 2 : 1; i++; continue;
            }
            if (prev && prev->t == T_ID && (syms[prev->sym].flags & SF_FNAFTER)) { i++; continue; }
            bool is_call = nxt && OP1(nxt, '(');
            if (name == S_FOREACH && is_call) {
                int e = match_paren(i + 1), k = i + 2;
                while (k < e && !(toks[k].t == T_ID && toks[k].sym == S_AS)) k++;
                if (k < e && (expr_taint(i + 2, k, st) & C_T)) {
                    for (int u = k + 1; u < e; u++) if (toks[u].t == T_VAR) { Ent *en = scope_get(st, toks[u].sym); en->cls = 'T'; }
                    foreach_input = true;
                }
                i++; continue;
            }
            if (name == S_EXTRACT && is_call) {
                int e = match_paren(i + 1);
                if (expr_taint(i + 2, e, st) & C_T) { fnd_add("extract-input", 40, ""); st->extract = true; }
            }
            if (fl & (SF_EVAL | SF_EXEC | SF_INCLUDE)) {
                int a, e;
                if (is_call) { e = match_paren(i + 1); a = i + 2; }
                else if ((fl & SF_INCLUDE) || name == S_EVAL) { e = i + 1; while (e < ntok && !OP1(&toks[e], ';')) e++; a = i + 1; }
                else { i++; continue; }
                int cl = expr_taint(a, e, st);
                if ((cl & C_S) && !(fl & SF_INCLUDE)) cl |= C_T;
                const char *nm = syms[name].name;
                if (fl & SF_EVAL) {
                    eval_seen = true;
                    if (cl & C_T) fnd_add("eval-input", 98, nm);
                    else if (cl & (C_O | C_DEC)) fnd_add("eval-decode", 95, nm);
                    else if (cl & C_D) fnd_add("eval-dynname", 90, nm);
                    else {
                        bool anyvar = false, anyconst = false;
                        for (int u = a; u < e; u++) { if (toks[u].t == T_VAR) anyvar = true; if (toks[u].t == T_STR && toks[u].ni == 0) anyconst = true; }
                        if (name == S_CREATE_FUNCTION && e > a && !anyconst) fnd_add("eval-dynamic", 40, nm);
                        else if (name == S_EVAL && (cl & C_VV)) fnd_add("eval-varvar", 50, "");
                        else if (name == S_EVAL && anyvar) fnd_add("eval-var", 20, "");
                    }
                } else if (fl & SF_EXEC) {
                    exec_seen = true;
                    if (cl & C_T) fnd_add("exec-input", 98, nm);
                    else if (cl & C_O) fnd_add("exec-decode", 95, nm);
                    else { bool anyvar = false; for (int u = a; u < e; u++) if (toks[u].t == T_VAR) { anyvar = true; break; } if (anyvar) fnd_add("exec-var", 12, nm); }
                } else {
                    if (cl & C_T) fnd_add("include-input", 85, nm);
                    else if (cl & C_O) fnd_add("include-decode", 90, nm);
                }
            } else if ((fl & SF_CB) && is_call) {
                int e = match_paren(i + 1); Rng ar[64]; int na = split_args(i + 2, e, ar, 64);
                int pos = syms[name].cbpos;
                if (pos < na) {
                    int cl = expr_taint(ar[pos].a, ar[pos].b, st);
                    if (cl & C_S) cl |= C_T;
                    if (cl & (C_T | C_D | C_O)) fnd_add("callback-input", 97, syms[name].name);
                    else if (ar[pos].b - ar[pos].a == 1 && toks[ar[pos].a].t == T_STR && ((flags_of_bytes_x(SP(toks[ar[pos].a].val), toks[ar[pos].a].val.len, false)) & (SF_EXEC | SF_EVAL))) {
                        bool anyt = false;
                        for (int q = 0; q < na && !anyt; q++) if (q != pos && (expr_taint(ar[q].a, ar[q].b, st) & C_T)) anyt = true;
                        if (anyt) { char d[72]; size_t l = toks[ar[pos].a].val.len; if (l > 60) l = 60; memcpy(d, SP(toks[ar[pos].a].val), l); d[l] = 0; fnd_add("callback-dangerous-const", 96, d); }
                    }
                }
            } else if (name == S_PREG_REPLACE && is_call) {
                int e = match_paren(i + 1); Rng ar[64]; int na = split_args(i + 2, e, ar, 64);
                if (na > 0 && ar[0].b > ar[0].a && toks[ar[0].a].t == T_STR) {
                    if (regex_php_e(SP(toks[ar[0].a].val), toks[ar[0].a].val.len)) {
                        int rest = 0; for (int q = 1; q < na; q++) rest |= expr_taint(ar[q].a, ar[q].b, st);
                        if (rest & C_T) fnd_add("preg-e-input", 96, ""); else fnd_add("preg-e", 45, "");
                    }
                }
            } else if ((fl & SF_FSW) && is_call) {
                int e = match_paren(i + 1); Rng ar[64]; int na = split_args(i + 2, e, ar, 64);
                if (na > 0) {
                    bool first_t = tainted_first(ar[0], st);
                    bool rest_t = false;
                    for (int q = 1; q < na && !rest_t; q++) { int c2 = expr_taint(ar[q].a, ar[q].b, st); if (c2 & (C_T | C_DEC)) rest_t = true; }
                    if (strcmp(syms[name].name, "move_uploaded_file") == 0) { if (na > 1 && tainted_first(ar[1], st)) fnd_add("upload-input-path", 92, syms[name].name); }
                    else if (first_t && rest_t) fnd_add("write-input", 95, syms[name].name);
                    else if (first_t) fnd_add("fs-input", 45, syms[name].name);
                }
            } else if ((fl & SF_FSR) && is_call) {
                int e = match_paren(i + 1); Rng ar[64]; int na = split_args(i + 2, e, ar, 64);
                if (na > 0 && tainted_first(ar[0], st)) {
                    bool have = false; for (int q = 0; q < fs_nn; q++) if (strcmp(fs_names[q], syms[name].name) == 0) have = true;
                    if (!have && fs_nn < 16) { snprintf(fs_names[fs_nn++], 24, "%s", syms[name].name); }
                }
            } else if (fl & SF_SOCK) {
                sock_has = true;
            } else if ((fl & SF_DECS) && is_call) {
                int e = match_paren(i + 1);
                for (int u = i + 2; u < e; u++) if (toks[u].t == T_STR && toks[u].n >= 300 && b64ish(SP(toks[u].val), toks[u].val.len)) { fnd_add("decode-blob", 25, syms[name].name); break; }
            }
            i++; continue;
        }
        if (t->t == T_BT) {
            bool inp = false; for (int q = 0; q < t->ni; q++) { int32_t vn = t->interp[q]; if ((syms[vn].flags & (SF_SG_T | SF_SG_SRV | SF_SG_ENV)) || cls_of(st, vn) == 'T') inp = true; }
            if (inp) fnd_add("backtick-input", 98, ""); else if (t->ni) fnd_add("backtick-var", 12, "");
            i++; continue;
        }
        if (t->t == T_VAR) {
            uint32_t f = syms[t->sym].flags;
            if (f & SF_HASIN) has_input = true;
            if (nxt && nxt->t == T_OP && (nxt->op == '=' || nxt->op == ('.' | ('=' << 8)))) {
                int k = i + 2, depth = 0;
                while (k < ntok) {
                    Tok *u = &toks[k];
                    if (u->t == T_OP) {
                        if (u->op == '(' || u->op == '[') depth++;
                        else if (u->op == ')' || u->op == ']') depth--;
                        else if (u->op == ';' && depth <= 0) break;
                        else if ((u->op == '{' || u->op == '}') && depth <= 0) break;
                    }
                    k++;
                }
                int cl = expr_taint(i + 2, k, st); int32_t name = t->sym;
                Ent *en = scope_get(st, name);
                if (cl & (C_T | C_S)) en->cls = (cl & C_T) ? 'T' : 'S';
                else if ((cl & (C_O | C_D)) && en->cls == 0) en->cls = (cl & C_O) ? 'O' : 'D';
                size_t fl2 = 0; unsigned char *folded = (k > i + 2) ? fold_const(i + 2, k, st, &fl2, 0) : NULL;
                if (folded) {
                    bool concat = (nxt->op == ('.' | ('=' << 8)));
                    if (concat && en->hasfold) {
                        size_t pl = en->fold.len; size_t tl = pl + fl2; if (tl > FOLD_MAX) tl = FOLD_MAX;
                        unsigned char *nb = xmalloc(tl + 1); memcpy(nb, SP(en->fold), pl); if (tl > pl) memcpy(nb + pl, folded, tl - pl);
                        en->fold = ar_put(nb, tl); free(nb);
                    } else en->fold = ar_put(folded, fl2);
                    en->hasfold = true;
                    uint32_t ff = flags_of_bytes(SP(en->fold), en->fold.len);
                    if ((ff & (SF_EXEC | SF_EVAL)) && en->cls != 'T') en->cls = 'D';
                    else if ((ff & SF_DECS) && en->cls != 'T') en->cls = 'F';
                    else if (en->cls == 0) {
                        bool anydec = false; for (int u = i + 2; u < k; u++) if (toks[u].t == T_ID && (syms[toks[u].sym].flags & SF_DECS)) anydec = true;
                        if (anydec && fl2 > 8) en->cls = 'O';
                    }
                    free(folded);
                } else if ((cl & C_DEC) && !(cl & C_T) && en->cls == 0) {
                    bool longstr = false; for (int u = i + 2; u < k; u++) if (toks[u].t == T_STR && toks[u].n > 40) longstr = true;
                    if (longstr) en->cls = 'O';
                }
            }
            bool member = prev && prev->t == T_OP && (prev->op == ('-' | ('>' << 8)) || prev->op == (':' | (':' << 8)));
            if (nxt && OP1(nxt, '(') && !member) {
                char c = ((f & (SF_SG_T | SF_SG_SRV | SF_SG_ENV)) && !(f & (SF_SG_SRV | SF_SG_ENV))) ? 'T' : cls_of(st, t->sym);
                if (c == 'S') c = 'T';
                Ent *en = scope_find(st, t->sym);
                char d[72]; d[0] = 0;
                if (c == 'T') fnd_add("varcall-input", 97, syms[t->sym].name);
                else if (c == 'D') { if (en && en->hasfold) { size_t l = en->fold.len > 60 ? 60 : en->fold.len; memcpy(d, SP(en->fold), l); d[l] = 0; } fnd_add("varcall-dynname", 96, d); }
                else if (c == 'O') fnd_add("varcall-decoded", 92, "");
                else if (c == 'F') { if (en && en->hasfold) { size_t l = en->fold.len > 60 ? 60 : en->fold.len; memcpy(d, SP(en->fold), l); d[l] = 0; } fnd_add("varcall-decoder-name", 15, d); }
                else if (c == 0 && st->extract && !(en && en->hasfold) && t->sym != S_THIS) fnd_add("varcall-input", 97, syms[t->sym].name);
            } else if ((f & SF_SG_T) && nxt && OP1(nxt, '[')) {
                int e = i + 1, depth = 0;
                while (e < ntok) {
                    if (toks[e].t == T_OP) { if (toks[e].op == '[') depth++; else if (toks[e].op == ']') { depth--; if (depth == 0) break; } }
                    e++;
                }
                if (e + 1 < ntok && OP1(&toks[e + 1], '(')) fnd_add("varcall-input", 97, syms[t->sym].name);
            }
            i++; continue;
        }
        if (t->t == T_VARVAR && foreach_input) { fnd_add("varvar-input", 45, ""); foreach_input = false; }
        i++;
    }
    /* nama fungsi konstan yang dipanggil langsung: ('sys'.'tem')(...) */
    for (int k = 0; k < ntok - 3; k++) {
        if (OP1(&toks[k], '(') && (k == 0 || (toks[k - 1].t != T_ID && toks[k - 1].t != T_VAR))) {
            int e = match_paren(k);
            if (e + 1 < ntok && OP1(&toks[e + 1], '(')) {
                size_t fl2; unsigned char *fv = fold_const(k + 1, e, scopes[0], &fl2, 0);
                if (fv) { uint32_t ff = flags_of_bytes(fv, fl2); /* Python: fv.lower() sama persis (tanpa strip) */
                    bool exact = true; for (size_t q = 0; q < fl2; q++) if (is_ws(fv[q])) exact = false;
                    if ((ff & (SF_EXEC | SF_EVAL)) && exact) { char d[72]; size_t l = fl2 > 60 ? 60 : fl2; memcpy(d, fv, l); d[l] = 0; fnd_add("callconst-dynname", 96, d); }
                    free(fv); }
            }
        }
    }
    if (has_input && fnd_has("eval-var")) {
        bool dec_any = false; for (int k = 0; k < ntok; k++) if (toks[k].t == T_ID && (syms[toks[k].sym].flags & SF_DEC2)) { dec_any = true; break; }
        if (dec_any) fnd_add("input-eval-decode", 92, ""); else fnd_add("input-eval", 70, "");
    }
    {
        int run = 0, best = 0;
        for (int k = 0; k < ntok - 2; k++) {
            if (toks[k].t == T_VAR && toks[k + 1].t == T_OP && toks[k + 1].op == ('+' | ('+' << 8)) && OP1(&toks[k + 2], ';')) { run++; if (run > best) best = run; }
            else if (OP1(&toks[k], ';')) { }
            else if (!(toks[k].t == T_OP && (toks[k].op == ('+' | ('+' << 8)) || toks[k].op == ';')) && toks[k].t != T_VAR) run = 0;
        }
        if (best >= 8) {
            bool vv = false; for (int k = 0; k < ntok; k++) if (toks[k].t == T_VARVAR) { vv = true; break; }
            char d[16]; snprintf(d, sizeof d, "%d", best);
            fnd_add((vv || has_input) ? "inc-chain-dynamic" : "inc-chain", (vv || has_input) ? 92 : 75, d);
        }
    }
    {
        bool reg = false; for (int k = 0; k < ntok; k++) if (toks[k].t == T_ID && toks[k].sym == S_REGISTERPHP) { reg = true; break; }
        if (reg) {
            bool danger = false;
            for (int k = 0; k < ntok && !danger; k++) if (toks[k].t == T_STR) {
                const unsigned char *v = SP(toks[k].val); size_t l = toks[k].val.len; char *lc = xmalloc(l + 1); for (size_t q = 0; q < l; q++) lc[q] = (char)tolower(v[q]); lc[l] = 0;
                if (strstr(lc, "function") && (strstr(lc, "assert") || strstr(lc, "system") || strstr(lc, "exec") || strstr(lc, "passthru") || strstr(lc, "shell_exec") || strstr(lc, "eval"))) danger = true;
                free(lc);
            }
            fnd_add("xslt-php", danger ? 92 : 40, "");
        }
    }
    if (fs_nn >= 3) {
        /* nama diurutkan seperti sorted() di referensi */
        for (int x = 0; x < fs_nn; x++) for (int y = x + 1; y < fs_nn; y++) if (strcmp(fs_names[x], fs_names[y]) > 0) { char t2[24]; strcpy(t2, fs_names[x]); strcpy(fs_names[x], fs_names[y]); strcpy(fs_names[y], t2); }
        char d[72] = ""; size_t dl = 0;
        for (int x = 0; x < fs_nn && dl < sizeof d - 1; x++) { int w = snprintf(d + dl, sizeof d - dl, "%s%s", x ? "," : "", fs_names[x]); if (w < 0) break; dl += (size_t)w; if (dl >= sizeof d) { dl = sizeof d - 1; break; } }
        fnd_add("fs-input-multi", 60, d);
    } else if (fs_nn > 0) fnd_add("fs-input-read", 20, "");
    if (sock_has) {
        bool ex = false; for (int k = 0; k < ntok && !ex; k++) if (toks[k].t == T_ID && (syms[toks[k].sym].flags & SF_EXEC)) ex = true;
        if (ex) { bool rs = false; for (int k = 0; k < ntok && !rs; k++) if (toks[k].t == T_STR && revshell_str(SP(toks[k].val), toks[k].val.len)) rs = true; if (rs) fnd_add("revshell-php", 92, ""); }
    }
    for (int k = 0; k + 2 < ntok + 0 && k < ntok - 2; k++)
        if (toks[k].t == T_VARVAR && toks[k].val.len == 2 && SP(toks[k].val)[1] == '{' && toks[k + 1].t == T_STR && toks[k + 1].val.len == 7 && strncasecmp((const char *)SP(toks[k + 1].val), "globals", 7) == 0) fnd_add("obf-globals", 45, "");
    if (hex_esc >= 100 && hex_esc * 4 >= 0.25 * (double)n) { char d[24]; snprintf(d, sizeof d, "%ld", hex_esc); fnd_add("hex-escape-heavy", 35, d); }
    (void)eval_seen; (void)exec_seen; (void)fs_mask; (void)fs_count;
    free(brs);
    for (int s = 0; s < nsc; s++) scope_free(scopes[s]);
    free_tokens();
}

/* ------------------------------------------------------------------ JSP / ASP / skrip (teks) */
static regex_t RX_JSP_WRITE, RX_ASP_EVAL, RX_ASP_EVAL2, RX_ASP_ARGS, RX_ASP_FS, RX_ASP_FSOP, RX_SH_REV, RX_PY_REV, RX_PTY;
static bool rx_ready = false;
static void rx_init(void) {
    if (rx_ready) return;
    int fl = REG_EXTENDED | REG_NOSUB;
    regcomp(&RX_JSP_WRITE, "(fileoutputstream|filewriter|randomaccessfile)[[:space:]]*\\([^;]{0,160}request\\.getparameter", fl);
    regcomp(&RX_ASP_EVAL, "\\b(eval|execute|executeglobal)[[:space:]]*\\(?[[:space:]]*(request|unescape)\\b", fl);
    regcomp(&RX_ASP_EVAL2, "\\b(eval|execute)[[:space:]]*\\(?[[:space:]]*(morfi|decode|rev|str)", fl);
    regcomp(&RX_ASP_ARGS, "\\.arguments[[:space:]]*=[[:space:]]*[^\n;]{0,100}(\\.text|request)", fl);
    regcomp(&RX_ASP_FS, "(adodb\\.stream|scripting\\.filesystemobject)", fl);
    regcomp(&RX_ASP_FSOP, "(savetofile|createtextfile|opentextfile)[[:space:]]*\\(?[^\n]{0,120}request", fl);
    regcomp(&RX_SH_REV, "bash[[:space:]]+-i[[:space:]]*>&?[[:space:]]*/dev/tcp/[0-9]|/dev/tcp/[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]+|nc(at)?[[:space:]]+-[a-z]*e[[:space:]]+/bin/(ba)?sh", fl);
    regcomp(&RX_PY_REV, "socket\\.socket\\([^)]*\\).{0,300}(os\\.dup2|subprocess\\.(call|popen)).{0,200}(/bin/(ba)?sh|cmd\\.exe)", fl);
    regcomp(&RX_PTY, "pty\\.spawn[[:space:]]*\\([[:space:]]*[\"']/bin/(ba)?sh", fl);
    rx_ready = true;
}
/* normalisasi: buang komentar blok, penyambung string, huruf kecil. Hasil malloc, NUL-terminated. */
static unsigned char *norm_script(const unsigned char *b, size_t n, size_t *ol) {
    unsigned char *t1 = xmalloc(n + 1); size_t a = 0;
    for (size_t i = 0; i < n; ) {
        if (b[i] == '/' && i + 1 < n && b[i + 1] == '*') { const unsigned char *e = (i + 2 <= n) ? memmem(b + i + 2, n - i - 2, "*/", 2) : NULL; if (!e) { /* komentar tidak tertutup tidak dibuang (re non-greedy tidak cocok) */ t1[a++] = b[i++]; continue; } i = (size_t)(e - b) + 2; continue; }
        t1[a++] = b[i++];
    }
    unsigned char *t2 = xmalloc(a + 1); size_t o = 0;
    for (int pass = 0; pass < 2; pass++) {
        unsigned char *src = pass == 0 ? t1 : t2; size_t sl = pass == 0 ? a : o; unsigned char *dst = pass == 0 ? t2 : t1; size_t d = 0; unsigned q = pass == 0 ? '"' : '\'';
        for (size_t i = 0; i < sl; ) {
            if (src[i] == q) {
                size_t j = i + 1; while (j < sl && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r' || src[j] == '\f' || src[j] == '\v')) j++;
                if (j < sl && src[j] == '+') { size_t k = j + 1; while (k < sl && (src[k] == ' ' || src[k] == '\t' || src[k] == '\n' || src[k] == '\r' || src[k] == '\f' || src[k] == '\v')) k++; if (k < sl && src[k] == q) { i = k + 1; continue; } }
            }
            dst[d++] = src[i++];
        }
        if (pass == 0) o = d; else { a = d; }
    }
    for (size_t i = 0; i < a; i++) if (t1[i] >= 'A' && t1[i] <= 'Z') t1[i] += 32;
    t1[a] = 0; free(t2); *ol = a; return t1;
}
static bool has(const unsigned char *s, size_t n, const char *lit) { return memmem(s, n, lit, strlen(lit)) != NULL; }
static bool rx(regex_t *r, const unsigned char *s) { return regexec(r, (const char *)s, 0, NULL, 0) == 0; }
static void nul_to_soh(unsigned char *s, size_t n) { for (size_t i = 0; i < n; i++) if (s[i] == 0) s[i] = 1; }
static void analyze_jsp(const unsigned char *b, size_t n) {
    rx_init(); size_t l; unsigned char *s = norm_script(b, n, &l); nul_to_soh(s, l);
    bool req = has(s, l, "request.getparameter") || has(s, l, "request.getheader") || has(s, l, "request.getinputstream") || has(s, l, "request.getreader") || has(s, l, "getparametermap") || has(s, l, "request.getcookies");
    bool rt = has(s, l, "runtime.getruntime()") && has(s, l, ".exec");
    if (rt && req) fnd_add("jsp-exec-input", 97, "");
    else if (has(s, l, "processbuilder") && req) fnd_add("jsp-exec-input", 97, "ProcessBuilder");
    if (has(s, l, "defineclass") && (req || has(s, l, "base64"))) fnd_add("jsp-defineclass", 96, "");
    if ((has(s, l, "scriptengine") || has(s, l, "javax.script")) && has(s, l, ".eval(") && req) fnd_add("jsp-script-eval", 95, "");
    if (has(s, l, "class.forname") && has(s, l, "getmethod") && has(s, l, "invoke") && req && (has(s, l, "base64") || has(s, l, "cipher"))) fnd_add("jsp-reflect-input", 94, "");
    if (rx(&RX_JSP_WRITE, s)) fnd_add("jsp-write-input", 94, "");
    if (rt && !req) fnd_add("jsp-exec", 15, "");
    free(s);
}
static void analyze_asp(const unsigned char *b, size_t n) {
    rx_init(); size_t l; unsigned char *s = norm_script(b, n, &l); nul_to_soh(s, l);
    bool req = has(s, l, "request.form") || has(s, l, "request.querystring") || has(s, l, "request(") || has(s, l, "request.item") || has(s, l, "request.binaryread") || has(s, l, "request[\"") || has(s, l, "request.params") || has(s, l, "request.files") || has(s, l, ".text");
    if (rx(&RX_ASP_EVAL, s)) fnd_add("asp-eval-input", 98, "");
    if (rx(&RX_ASP_EVAL2, s) && has(s, l, "request")) fnd_add("asp-eval-input", 96, "indirect");
    if (has(s, l, "process.start") && req) fnd_add("asp-exec-input", 97, "");
    if (rx(&RX_ASP_ARGS, s) && (has(s, l, "processstartinfo") || has(s, l, "process"))) fnd_add("aspx-exec-input", 94, "");
    if (has(s, l, "wscript.shell") && (has(s, l, ".exec") || has(s, l, ".run")) && req) fnd_add("asp-wscript-input", 96, "");
    if (has(s, l, "assembly.load") && (has(s, l, "frombase64string") || req)) fnd_add("asp-assembly-load", 96, "");
    if (has(s, l, "processstartinfo") && req && has(s, l, "cmd")) fnd_add("asp-exec-input", 96, "ProcessStartInfo");
    if (rx(&RX_ASP_FS, s) && rx(&RX_ASP_FSOP, s)) fnd_add("asp-write-input", 94, "");
    if (has(s, l, "scripting.filesystemobject") && req && (has(s, l, "savetofile") || has(s, l, "binaryread") || has(s, l, ".write"))) fnd_add("asp-filemanager", 50, "");
    free(s);
}
static void analyze_script(const unsigned char *b, size_t n, bool is_py) {
    rx_init(); unsigned char *s = xmalloc(n + 1); for (size_t i = 0; i < n; i++) s[i] = (b[i] >= 'A' && b[i] <= 'Z') ? b[i] + 32 : b[i]; s[n] = 0; nul_to_soh(s, n);
    if (!is_py && rx(&RX_SH_REV, s)) fnd_add("revshell", 96, "");
    if (rx(&RX_PTY, s) && has(s, n, "socket")) fnd_add("revshell", 96, "pty");
    if (rx(&RX_PY_REV, s)) fnd_add("revshell", 95, "python");
    free(s);
}

/* ------------------------------------------------------------------ penanda dan penilaian */
static const char *KNOWN[] = { "c99shell", "r57shell", "b374k", "filesman", "indoxploit", "mini shell", "china chopper", "priv8 shell", "webshell by", "weevely",
    "safe mode bypass", "safe_mode bypass", "alfa team", "wso shell", "wso web", "wso 2", "c100 shell", "sh3ll", "phpspy", "webadmin.php", "antichat shell",
    "r57 shell", "hacked by", "shell by", "ani-shell", "zehir", "1n73ct10n", "dhanush", NULL };
typedef struct { int score; const char *verdict; double entropy; char markers[4][32]; int nmark; } Result;
enum { K_NONE, K_PHP, K_JSP, K_ASP, K_OTHER };
static int kind_of_ext(const char *ext, bool *is_html, bool *is_py) {
    *is_html = false; *is_py = false;
    static const char *php[] = { ".php", ".phtml", ".phar", ".pht", ".php3", ".php4", ".php5", ".php7", ".php8", ".phps", ".inc", NULL };
    static const char *jsp[] = { ".jsp", ".jspx", ".jsw", ".jsv", NULL };
    static const char *asp[] = { ".asp", ".aspx", ".ashx", ".asax", ".asmx", ".cer", NULL };
    static const char *oth[] = { ".pl", ".cgi", ".py", ".sh", NULL };
    for (int i = 0; php[i]; i++) if (!strcmp(ext, php[i])) return K_PHP;
    for (int i = 0; jsp[i]; i++) if (!strcmp(ext, jsp[i])) return K_JSP;
    for (int i = 0; asp[i]; i++) if (!strcmp(ext, asp[i])) return K_ASP;
    for (int i = 0; oth[i]; i++) if (!strcmp(ext, oth[i])) { *is_py = !strcmp(ext, ".py"); return K_OTHER; }
    if (!strcmp(ext, ".html") || !strcmp(ext, ".htm")) { *is_html = true; return K_PHP; }
    return K_NONE;
}
static double entropy_of(const unsigned char *b, size_t n) {
    if (!n) return 0.0;
    size_t cnt[256]; memset(cnt, 0, sizeof cnt);
    for (size_t i = 0; i < n; i++) cnt[b[i]]++;
    double h = 0.0; for (int i = 0; i < 256; i++) if (cnt[i]) { double p = (double)cnt[i] / (double)n; h -= p * log2(p); } return h;
}
static Result analyze_file(const unsigned char *data, size_t len, const char *ext, int kind, bool is_html, bool is_py) {
    Result R; memset(&R, 0, sizeof R); FL.n = 0;
    size_t n = len > MAX_FILE ? MAX_FILE : len;
    bool php_ext = (kind == K_PHP && !is_html);
    if (kind == K_PHP) {
        bool run = php_ext;
        if (is_html) { /* b'<?php' in data.lower() */ for (size_t i = 0; i + 5 <= n; i++) if (strncasecmp((const char *)data + i, "<?php", 5) == 0) { run = true; break; } }
        if (run) analyze_php(data, n, NULL);
    } else if (kind == K_JSP) analyze_jsp(data, n);
    else if (kind == K_ASP) analyze_asp(data, n);
    else if (kind == K_OTHER) analyze_script(data, n, is_py);
    double H = entropy_of(data, n);
    if (php_ext && len >= 256) {
        double z = (H - ENT_MEAN) / ENT_SD; char d[16]; snprintf(d, sizeof d, "%.2f", H);
        if (z >= Z_STRONG) fnd_add("entropy-high", 40, d); else if (z >= Z_FLAG) fnd_add("entropy-high", 30, d);
    }
    /* dedup per id (bobot tertinggi) */
    int uw[256]; int un = 0; Fnd *uf[256];
    for (int i = 0; i < FL.n && un < 256; i++) {
        int j; for (j = 0; j < un; j++) if (!strcmp(uf[j]->id, FL.a[i].id)) break;
        if (j == un) { uf[un] = &FL.a[i]; uw[un] = FL.a[i].w; un++; } else if (FL.a[i].w > uf[j]->w) uf[j] = &FL.a[i];
    }
    int weak = 0, mid = 0, strong = 0;
    for (int j = 0; j < un; j++) { int w = uf[j]->w; if (w >= 90) { if (w > strong) strong = w; } else if (w < 30) weak += w; else mid += w; }
    int score;
    if (strong) score = strong; else { int wk = weak < 40 ? weak : 40; score = wk + mid; if (score > 89) score = 89; }
    /* penanda */
    if (php_ext || kind == K_JSP || kind == K_ASP) {
        unsigned char *lc = xmalloc(n + 1); for (size_t i = 0; i < n; i++) lc[i] = (data[i] >= 'A' && data[i] <= 'Z') ? data[i] + 32 : data[i];
        for (int k = 0; KNOWN[k]; k++) if (memmem(lc, n, KNOWN[k], strlen(KNOWN[k])) && R.nmark < 4) snprintf(R.markers[R.nmark++], 32, "%s", KNOWN[k]);
        free(lc);
    }
    if (R.nmark && un > 0 && score < 90) { score += 30; if (score > 89) score = 89; }
    if (score > 100) score = 100;
    R.score = score; R.verdict = score >= 90 ? "webshell" : (score >= 50 ? "suspicious" : "clean"); R.entropy = H;
    /* salin temuan unik ke akhir daftar agar pemanggil mencetak */
    static Fnd keep[256]; for (int j = 0; j < un; j++) keep[j] = *uf[j];
    FL.n = 0; for (int j = 0; j < un; j++) { if (FL.n == FL.cap) { FL.cap = FL.cap ? FL.cap * 2 : 32; FL.a = xrealloc(FL.a, sizeof(Fnd) * FL.cap); } FL.a[FL.n++] = keep[j]; }
    (void)uw; (void)ext;
    return R;
}

/* ------------------------------------------------------------------ SHA-256 */
typedef struct { uint32_t s[8]; uint64_t len; unsigned char buf[64]; size_t bl; } Sha;
static const uint32_t K256[64] = { 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(Sha *h, const unsigned char *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 | (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) { uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3), s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10); w[i] = w[i - 16] + s0 + w[i - 7] + s1; }
    a = h->s[0]; b = h->s[1]; c = h->s[2]; d = h->s[3]; e = h->s[4]; f = h->s[5]; g = h->s[6]; hh = h->s[7];
    for (int i = 0; i < 64; i++) { uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25), ch = (e & f) ^ (~e & g), t1 = hh + S1 + ch + K256[i] + w[i], S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = S0 + mj; hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    h->s[0] += a; h->s[1] += b; h->s[2] += c; h->s[3] += d; h->s[4] += e; h->s[5] += f; h->s[6] += g; h->s[7] += hh;
}
static void sha256_hex(const unsigned char *data, size_t n, char *out) {
    Sha h = { { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 }, 0, {0}, 0 };
    size_t i = 0; for (; i + 64 <= n; i += 64) sha_block(&h, data + i);
    unsigned char blk[128]; size_t rem = n - i; memcpy(blk, data + i, rem); blk[rem++] = 0x80;
    size_t tot = (rem + 8 <= 64) ? 64 : 128; memset(blk + rem, 0, tot - rem); uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) blk[tot - 1 - k] = (unsigned char)(bits >> (8 * k));
    sha_block(&h, blk); if (tot == 128) sha_block(&h, blk + 64);
    for (int k = 0; k < 8; k++) sprintf(out + k * 8, "%08x", h.s[k]);
    out[64] = 0;
}
static bool in_allow(const char *hex) { for (int i = 0; i < n_allow; i++) if (strcmp(allow[i], hex) == 0) return true; return false; }

/* ------------------------------------------------------------------ keluaran JSON */
static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; ) {
        unsigned c = *p;
        if (c == '"') { fputs("\\\"", f); p++; } else if (c == '\\') { fputs("\\\\", f); p++; }
        else if (c < 0x20) { fprintf(f, "\\u%04x", c); p++; }
        else if (c < 0x80) { fputc((int)c, f); p++; }
        else {
            int len = (c >= 0xf0 && c <= 0xf4) ? 4 : (c >= 0xe0) ? 3 : (c >= 0xc2 && c < 0xe0) ? 2 : 0; bool ok = len > 0 && c < 0xf5;
            for (int k = 1; ok && k < len; k++) if ((p[k] & 0xc0) != 0x80) ok = false;
            if (ok && len == 3 && c == 0xe0 && p[1] < 0xa0) ok = false;
            if (ok && len == 3 && c == 0xed && p[1] >= 0xa0) ok = false;
            if (ok && len == 4 && c == 0xf0 && p[1] < 0x90) ok = false;
            if (ok && len == 4 && c == 0xf4 && p[1] >= 0x90) ok = false;
            if (ok) { for (int k = 0; k < len; k++) fputc(p[k], f); p += len; } else { fprintf(f, "\\udc%02x", c); p++; }
        }
    }
    fputc('"', f);
}

/* ------------------------------------------------------------------ pemindaian */
static long st_files = 0, st_scanned = 0, st_skipped_large = 0, st_skipped_unread = 0, st_hits = 0, st_web = 0, st_susp = 0, st_allowed = 0, st_excl = 0;
static double ent_sum[8], ent_sq[8]; static long ent_n[8];
static unsigned char *fbuf = NULL; static size_t fcap = 0;

static bool excluded(const char *path) { for (int i = 0; i < n_excludes; i++) if (strstr(path, excludes[i])) return true; return false; }
static const char *ext_of(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/'); const char *base = slash ? slash + 1 : path; const char *dot = strrchr(base, '.');
    if (!dot || dot == base) { out[0] = 0; return out; }
    size_t l = strlen(dot); if (l >= cap) l = cap - 1; for (size_t i = 0; i < l; i++) out[i] = (char)tolower((unsigned char)dot[i]); out[l] = 0; return out;
}
/* ambang asli ShellSweep (mode --compat) */
static bool compat_hit(const char *ext, double H) {
    if (!strcmp(ext, ".asp")) return H < 0.805376867704514 || H > 5.51268104400858;
    if (!strcmp(ext, ".ashx")) return H > 3.75840459657413;
    if (!strcmp(ext, ".asax")) return H > 3.7288741494524;
    if (!strcmp(ext, ".jspx")) return H > 4.87651397975203;
    if (!strcmp(ext, ".html")) return H > 4.8738392644771;
    if (!strcmp(ext, ".aspx")) return H < 0.805376867704514 || H > 4.15186444439319;
    if (!strcmp(ext, ".php")) return H > 4.23015141285636;
    if (!strcmp(ext, ".jsp")) return H > 4.40958415652662;
    if (!strcmp(ext, ".js")) return H > 4.25868439013462;
    return false;
}
static void scan_path(const char *path, const struct stat *sb) {
    char ext[16]; ext_of(path, ext, sizeof ext);
    bool is_html, is_py; int kind = kind_of_ext(ext, &is_html, &is_py);
    if (opt_compat) { if (kind == K_NONE && strcmp(ext, ".js") && strcmp(ext, ".lua")) return; } else if (kind == K_NONE) return;
    st_files++;
    if (progress_sec && (st_files & 127) == 0) { time_t nw = time(NULL); if (nw - last_progress >= progress_sec) { last_progress = nw; fprintf(stderr, "{\"progress\":{\"files\":%ld,\"scanned\":%ld,\"flagged\":%ld,\"path\":", st_files, st_scanned, st_hits); json_str(stderr, path); fprintf(stderr, "}}\n"); } }
    if (sb->st_size == 0) return;
    if (since_epoch && sb->st_mtime < since_epoch && sb->st_ctime < since_epoch) return;
    if (sb->st_size > max_size) { st_skipped_large++; return; }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); if (fd < 0) { st_skipped_unread++; return; }
    size_t sz = (size_t)sb->st_size; if (sz + 1 > fcap) { fcap = sz + 4096; fbuf = xrealloc(fbuf, fcap); }
    size_t got = 0; while (got < sz) { ssize_t r = read(fd, fbuf + got, sz - got); if (r <= 0) break; got += (size_t)r; }
    close(fd); if (got == 0) return;
    st_scanned++;
    Result R;
    if (opt_compat) {
        double H = entropy_of(fbuf, got > MAX_FILE ? MAX_FILE : got); R.entropy = H; R.nmark = 0; FL.n = 0;
        if (compat_hit(ext, H)) { R.score = 50; R.verdict = "suspicious"; fnd_add("shellsweep-entropy", 50, ext); } else { R.score = 0; R.verdict = "clean"; }
    } else R = analyze_file(fbuf, got, ext, kind, is_html, is_py);
    if (kind == K_PHP && !is_html && got >= 256) { ent_sum[0] += R.entropy; ent_sq[0] += R.entropy * R.entropy; ent_n[0]++; }
    if (!opt_all && R.score < min_score) { if (throttle_ms && (st_scanned % 50) == 0) usleep(throttle_ms * 1000); return; }
    bool is_clean = (R.score < 50);
    char sha[65]; sha[0] = 0;
    if (!is_clean || opt_all) sha256_hex(fbuf, got, sha);
    bool allowed = sha[0] && in_allow(sha);
    if (allowed && !opt_all) { st_allowed++; return; }
    if (!is_clean) { st_hits++; if (!strcmp(R.verdict, "webshell")) st_web++; else st_susp++; }
    if (opt_quiet) return;
    printf("{\"path\":"); json_str(stdout, path);
    printf(",\"verdict\":\"%s\",\"score\":%d,\"entropy\":%.4f,\"size\":%zu,\"mtime\":%ld,\"sha256\":\"%s\",\"allowed\":%s,\"rules\":[", R.verdict, R.score, R.entropy, got, (long)sb->st_mtime, sha, allowed ? "true" : "false");
    for (int i = 0; i < FL.n; i++) { printf("%s[", i ? "," : ""); json_str(stdout, FL.a[i].id); printf(",%d,", FL.a[i].w); json_str(stdout, FL.a[i].detail); printf("]"); }
    printf("],\"markers\":["); for (int i = 0; i < R.nmark; i++) { printf("%s", i ? "," : ""); json_str(stdout, R.markers[i]); } printf("]}\n");
    if (throttle_ms && (st_scanned % 50) == 0) { fflush(stdout); usleep(throttle_ms * 1000); }
    if (nsyms > 400000) symbols_reset();
}

static void walk(const char *root) {
    char *paths[2] = { (char *)root, NULL };
    FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, NULL);
    if (!fts) { fprintf(stderr, "tidak bisa membuka %s: %s\n", root, strerror(errno)); return; }
    FTSENT *e;
    while ((e = fts_read(fts))) {
        if (e->fts_info == FTS_D) { if (excluded(e->fts_path)) { st_excl++; fts_set(fts, e, FTS_SKIP); } continue; }
        if (e->fts_info != FTS_F) continue;
        if (excluded(e->fts_path)) { st_excl++; continue; }
        scan_path(e->fts_path, e->fts_statp);
    }
    fts_close(fts);
}

static void load_lines(const char *file, char ***out, int *n, bool lower) {
    FILE *f = fopen(file, "r"); if (!f) return; char line[4096];
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line); while (l && (line[l - 1] == '\n' || line[l - 1] == '\r' || line[l - 1] == ' ')) line[--l] = 0;
        char *p = line; while (*p == ' ') p++; if (!*p || *p == '#') continue;
        for (char *q = p; *q; q++) if (*q == '#' || *q == ' ' || *q == '\t') { *q = 0; break; }      /* abaikan komentar di akhir baris */
        if (lower) for (char *q = p; *q; q++) *q = (char)tolower((unsigned char)*q);
        *out = xrealloc(*out, sizeof(char *) * (*n + 1)); (*out)[(*n)++] = strdup(p);
    }
    fclose(f);
}

static void usage(void) {
    fprintf(stderr, "sentinel-sweeper %s\nPemakaian: sentinel-sweeper [opsi] <direktori|berkas>...\n"
        "  --exclude STR      lewati path yang memuat STR (boleh berulang)\n"
        "  --allow-file F     daftar sha256 (huruf besar/kecil) yang diabaikan\n"
        "  --list-file F      baca daftar path dari F (satu per baris) alih-alih menelusuri\n"
        "  --min-score N      ambang cetak (bawaan 50)   --all  cetak semua berkas\n"
        "  --max-size BYTES   lewati berkas lebih besar (bawaan 2097152)\n"
        "  --since EPOCH      hanya berkas dengan mtime/ctime >= EPOCH\n"
        "  --throttle-ms N    jeda N ms tiap 50 berkas (hemat CPU)\n"
        "  --progress-sec N   cetak kemajuan JSON ke stderr tiap N detik\n"
        "  --nice N           prioritas CPU (0..19)\n"
        "  --entropy M,S,Z1,Z2 prior entropi PHP (rata-rata, simpangan baku, z tanda, z kuat)\n"
        "  --compat           mode ShellSweep asli: hanya ambang entropi per ekstensi\n"
        "  --stats            cetak statistik entropi PHP (kalibrasi)   --quiet  hanya ringkasan\n", VERSION);
}

int main(int argc, char **argv) {
    symbols_init();
    char **roots = NULL; int nroots = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--exclude") && i + 1 < argc) { excludes = xrealloc(excludes, sizeof(char *) * (n_excludes + 1)); excludes[n_excludes++] = argv[++i]; }
        else if (!strcmp(a, "--allow-file") && i + 1 < argc) load_lines(argv[++i], &allow, &n_allow, true);
        else if (!strcmp(a, "--list-file") && i + 1 < argc) list_file = argv[++i];
        else if (!strcmp(a, "--min-score") && i + 1 < argc) min_score = atoi(argv[++i]);
        else if (!strcmp(a, "--max-size") && i + 1 < argc) max_size = atol(argv[++i]);
        else if (!strcmp(a, "--since") && i + 1 < argc) since_epoch = atol(argv[++i]);
        else if (!strcmp(a, "--throttle-ms") && i + 1 < argc) throttle_ms = atoi(argv[++i]);
        else if (!strcmp(a, "--progress-sec") && i + 1 < argc) progress_sec = atoi(argv[++i]);
        else if (!strcmp(a, "--version")) { printf("sentinel-sweeper %s\n", VERSION); return 0; }
        else if (!strcmp(a, "--nice") && i + 1 < argc) { setpriority(PRIO_PROCESS, 0, atoi(argv[++i])); }
        else if (!strcmp(a, "--entropy") && i + 1 < argc) sscanf(argv[++i], "%lf,%lf,%lf,%lf", &ENT_MEAN, &ENT_SD, &Z_FLAG, &Z_STRONG);
        else if (!strcmp(a, "--all")) opt_all = true;
        else if (!strcmp(a, "--compat")) opt_compat = true;
        else if (!strcmp(a, "--stats")) opt_stats = true;
        else if (!strcmp(a, "--quiet")) opt_quiet = true;
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else if (a[0] == '-' && a[1]) { fprintf(stderr, "opsi tidak dikenal: %s\n", a); usage(); return 2; }
        else { roots = xrealloc(roots, sizeof(char *) * (nroots + 1)); roots[nroots++] = (char *)a; }
    }
    if (!nroots && !list_file) { usage(); return 2; }
    if (ENT_SD <= 0) ENT_SD = 0.325;
    time_t t0 = time(NULL); struct timespec c0, c1; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
    if (list_file) {
        FILE *f = fopen(list_file, "r"); if (f) { char line[8192];
            while (fgets(line, sizeof line, f)) { size_t l = strlen(line); while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0; if (!l) continue;
                struct stat sb; if (lstat(line, &sb) == 0 && S_ISREG(sb.st_mode) && !excluded(line)) scan_path(line, &sb); }
            fclose(f); }
    }
    for (int i = 0; i < nroots; i++) {
        struct stat sb; if (lstat(roots[i], &sb) != 0) { fprintf(stderr, "tidak ada: %s\n", roots[i]); continue; }
        if (S_ISREG(sb.st_mode)) { if (!excluded(roots[i])) scan_path(roots[i], &sb); } else walk(roots[i]);
        fflush(stdout);
        AR.used = 0;
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
    double cpu = (double)(c1.tv_sec - c0.tv_sec) + (double)(c1.tv_nsec - c0.tv_nsec) / 1e9;
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    double mean = ent_n[0] ? ent_sum[0] / (double)ent_n[0] : 0, sd = ent_n[0] ? sqrt(fmax(0, ent_sq[0] / (double)ent_n[0] - mean * mean)) : 0;
    printf("{\"summary\":{\"files\":%ld,\"scanned\":%ld,\"skipped_large\":%ld,\"skipped_unreadable\":%ld,\"excluded\":%ld,\"flagged\":%ld,\"webshell\":%ld,\"suspicious\":%ld,\"allowed\":%ld,"
           "\"seconds\":%ld,\"cpu_seconds\":%.3f,\"max_rss_kb\":%ld,\"engine\":\"c %s\",\"php_entropy_mean\":%.4f,\"php_entropy_sd\":%.4f,\"php_entropy_n\":%ld}}\n",
           st_files, st_scanned, st_skipped_large, st_skipped_unread, st_excl, st_hits, st_web, st_susp, st_allowed, (long)(time(NULL) - t0), cpu, ru.ru_maxrss, VERSION, mean, sd, ent_n[0]);
    (void)opt_stats;
    return 0;
}
