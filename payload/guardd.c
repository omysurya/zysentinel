/*
 * guardd.c -- Sentinel: daemon pertahanan & statistik untuk aaPanel/nginx
 *
 * Peran:
 *   1. Men-tail SELURUH access log nginx secara DINAMIS (tidak ada daftar
 *      vhost yang di-hardcode). Sumber daftar log:
 *        a. rekursif memindai directive `access_log` di semua *.conf nginx
 *        b. jaring pengaman: berkas *.log di /www/wwwlogs yang validasi
 *           pertama barisnya sebagai access log format "combined"
 *      Disinkronkan ulang tiap rescan_interval detik + saat SIGHUP, jadi
 *      menambah/menghapus vhost tidak perlu menyentuh kode.
 *   2. Menghitung statistik (request, byte, kelas status, per situs, per IP).
 *   3. Mengklasifikasikan serangan: scanner, bruteforce, flood, bot/UA palsu,
 *      404-storm, lalu memberi skor.
 *   4. Menerjemahkan skor menjadi tindakan di ipset:
 *        watch    -> hanya dicatat di dasbor
 *        throttle -> ipset sentinel_throttle (dibatasi rps oleh iptables)
 *        ban      -> ipset sentinel_ban (DROP, ada timeout)
 *
 * Prinsip anti-crash (WAJIB dijaga saat mengubah berkas ini):
 *   - Tidak ada pekerjaan berat di jalur request nginx. Semua analisis
 *     terjadi di luar nginx, di proses terpisah.
 *   - Tidak ada alokasi dinamis tak terbatas. Semua tabel punya batas atas
 *     keras dan entry yang tidak aktif di-evict.
 *   - Tak ada regex pada jalur panas; pencocokan memakai strstr/memcmp.
 *   - SQLite hanya menulis secara batch; kegagalan stats TIDAK boleh
 *     menjatuhkan daemon (setiap panggilan dibungkus saverr()).
 *   - Tidak ada makro yang bisa keluar tanpa dibersihkan; tidak ada
 *     rekursi; semua indeks dibatasi.
 *   -/action memblokir SELALU preceded oleh cek allowlist.
 *
 * Build:  gcc -O2 -Wall -Wextra -o guardd guardd.c -lsqlite3 -lm
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#define VERSION "v1.6.1"

/* ------------------------------------------------------------------ *
 * Batas keras. Semua angka di sini adalah pagu memori/CPU, bukan saran.
 * ------------------------------------------------------------------ */
#define CFG_PATH        320     /* panjang maksimal jalur di config */
#define MAX_TAILERS      256     /* jumlah access log yang ditail */
#define MAX_CONF_DEPTH    8      /* kedalaman rekursi pemindaian conf */
#define MAX_IP           16384   /* entri IP yang dilacak */
#define IP_BUCKETS       65536   /* bucket hash */
#define RATE_SLOTS        16     /* 16 x 4s = jendela 64 detik */
#define RATE_SLOT_SEC      4
#define MAX_DISTINCT_PATHS  8
#define MAX_BAN_ENTRIES   4096   /* pagu ban aktif */
#define MAX_EVENTS_BATCH  256
#define MAX_IPMIN_BATCH   512
#define MAX_MIN_BATCH      64
#define SENT_LINE_MAX        4096   /* panjang maksimum satu baris log */
#define SENT_READ_CHUNK      2048   /* ukuran blok read() per pemanggilan */
#define STATUS_JSON_MAX (48 * 1024)

/* Levelemporarily */
enum { LVL_NORMAL = 0, LVL_WATCH = 1, LVL_THROTTLE = 2, LVL_BAN = 3 };

/* ------------------------------------------------------------------ *
 * Util
 * ------------------------------------------------------------------ */
static const char *g_prog = "guardd";
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_rescan = 0;

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    struct timespec ts;
    struct tm tm;
    char tbuf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "[%s] %s ", tbuf, g_prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

__attribute__((noreturn)) static void die(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[%s] FATAL: ", g_prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    exit(1);
}

static void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) die("OOM alokasi %zu x %zu byte", n, sz);
    return p;
}

static time_t now_t(void) { return time(NULL); }

static uint32_t ip2u(const char *s)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static void u2ip(uint32_t ip, char *out, size_t n)
{
    struct in_addr a;
    a.s_addr = htonl(ip);
    if (!inet_ntop(AF_INET, &a, out, (socklen_t)n)) snprintf(out, n, "0.0.0.0");
}

static uint64_t fnv1a(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    return h;
}

/* ------------------------------------------------------------------ *
 * Konfigurasi (format key = value, tanpa pustaka eksternal)
 * ------------------------------------------------------------------ */
typedef struct {
    /* jalur */
    char conf_dirs[8][CFG_PATH];
    int  n_conf_dirs;
    char log_dirs[8][CFG_PATH];
    int  n_log_dirs;
    char db_path[CFG_PATH];
    char run_dir[CFG_PATH];
    char log_file[CFG_PATH];
    char allow_file[CFG_PATH];

    /* penemuan dinamis */
    int  rescan_interval;
    int  startup_backfill;   /* detik log lama yang dipindai saat start (0=skip) */

    /* classify */
    int  win_ban;
    int  win_ban_max;
    int  ban_step_seconds;

    /* aksi */
    int  enforce;
    /* Notifikasi. URL kosong berarti notifikasi dimatikan. */
    char notify_url[256];
    char notify_token[96];
    /* Ambang antrian review. IP yang mencapai skor ini MASIH
       diberi tanda masuk antrian, bukan diblokir. 0 mematikan antrian. */
    int  review_score;            /* 1 = benar-benar pasang ban/throttle */
    int  watch_score;
    int  throttle_score;
    int  ban_score;

    /* pagu */
    int  max_ips;
    int  max_lines_per_tick;
    int  max_bytes_per_tick;

    /* telemetri */
    int  flush_interval;
    int  prune_interval;

    /* Bobot skor per kategori. Dapat diubah lewat berkas konfigurasi
     * supaya kalibrasi tidak memerlukan kompilasi ulang.
     *
     * Kenapa "distinct" (path 4xx berbeda) punya bobot paling rendah:
     * pengukuran terhadap log produksi menunjukkan crawler sah seperti
     * GrokBot dan TelegramBot menjelajah puluhan path berbeda dan
     * mencapai skor 137 dengan bobot lama -- hanya 13 poin di bawah
     * ambang ban. while scanner dan brute force hampir tidak pernah
     * muncul pada trafik sah. Kategori yang "mahal" (scanner) tetap
     * punya bobot terbesar. */
    int  w_scan;
    int  w_brute;
    int  w_badua;
    int  w_distinct;
    int  cap_scan;
    int  cap_brute;
    int  cap_badua;
    int  cap_distinct;
} cfg_t;

static cfg_t cfg = {
    /* Daftar direktori TIDAK dipixelai di sini. Nilai bawaan dipasang
     * di dalam cfg_load, dan langsung digantikan begitu berkas konfigurasi
     * menyebut conf_dir/log_dir. Ini penting: kalauconfig cuma menambah,
     * mengubahnya di uji tidak akan benar-benar mengisolasi daemon. */
    .n_conf_dirs = 0,
    .n_log_dirs = 0,
    .db_path = "/www/server/sentinel/data/guardd.db",
    .run_dir = "/www/server/sentinel/run",
    .log_file = "/www/server/sentinel/log/guardd.log",
    .allow_file = "/www/server/sentinel/etc/allowlist.txt",
    .rescan_interval = 30,
    .startup_backfill = 0,
    .win_ban = 3600,
    .win_ban_max = 86400,
    .ban_step_seconds = 3600,
    .enforce = 0,
    /* Di antara throttle (60) dan ban (150): cukup tinggi untuk
       menyaring kebisingan, cukup rendah untuk tidak menahan
       setiap perbedaan path yang aneh. */
    .review_score = 100,
    .watch_score = 20,
    .throttle_score = 60,
    .ban_score = 150,
    .w_scan = 8,
    .w_brute = 6,
    .w_badua = 1,
    .w_distinct = 1,
    .cap_scan = 10,
    .cap_brute = 20,
    .cap_badua = 20,
    .cap_distinct = 20,
    .max_ips = MAX_IP,
    .max_lines_per_tick = 20000,
    .max_bytes_per_tick = 64 * 1024 * 1024,
    .flush_interval = 5,
    .prune_interval = 3600,
};

static void cfg_load(const char *path)
{
    FILE *f = fopen(path, "re");
    char line[1024];
    int ln = 0;

    if (!f) logmsg("config %s tidak terbaca, memakai seluruh bawaan", path);
    while (f && fgets(line, sizeof(line), f)) {
        char *eq, *k, *v, *end;
        ++ln;
        k = line;
        while (*k == ' ' || *k == '\t') k++;
        if (*k == '#' || *k == ';' || *k == '\n' || *k == '\0') continue;
        eq = strchr(k, '=');
        if (!eq) continue;
        *eq = '\0';
        v = eq + 1;
        end = k + strlen(k);
        while (end > k && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
        while (*v == ' ' || *v == '\t') v++;
        end = v + strlen(v);
        while (end > v && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';

        if      (!strcmp(k, "enforce"))            cfg.enforce = atoi(v);
        else if (!strcmp(k, "notify_url"))
            snprintf(cfg.notify_url, sizeof(cfg.notify_url), "%s", v);
        else if (!strcmp(k, "notify_token"))
            snprintf(cfg.notify_token, sizeof(cfg.notify_token), "%s", v);
        else if (!strcmp(k, "review_score"))      cfg.review_score = atoi(v);
        else if (!strcmp(k, "watch_score"))        cfg.watch_score = atoi(v);
        else if (!strcmp(k, "throttle_score"))     cfg.throttle_score = atoi(v);
        else if (!strcmp(k, "ban_score"))          cfg.ban_score = atoi(v);
        else if (!strcmp(k, "ban_seconds"))        cfg.win_ban = atoi(v);
        else if (!strcmp(k, "ban_seconds_max"))    cfg.win_ban_max = atoi(v);
        else if (!strcmp(k, "rescan_interval"))    cfg.rescan_interval = atoi(v);
        else if (!strcmp(k, "startup_backfill"))   cfg.startup_backfill = atoi(v);
        else if (!strcmp(k, "max_ips"))            cfg.max_ips = atoi(v);
        else if (!strcmp(k, "max_lines_per_tick")) cfg.max_lines_per_tick = atoi(v);
        else if (!strcmp(k, "flush_interval"))     cfg.flush_interval = atoi(v);
        else if (!strcmp(k, "weight_scan"))        cfg.w_scan = atoi(v);
        else if (!strcmp(k, "weight_brute"))       cfg.w_brute = atoi(v);
        else if (!strcmp(k, "weight_badua"))       cfg.w_badua = atoi(v);
        else if (!strcmp(k, "weight_distinct"))    cfg.w_distinct = atoi(v);
        else if (!strcmp(k, "cap_scan"))           cfg.cap_scan = atoi(v);
        else if (!strcmp(k, "cap_brute"))          cfg.cap_brute = atoi(v);
        else if (!strcmp(k, "cap_badua"))          cfg.cap_badua = atoi(v);
        else if (!strcmp(k, "cap_distinct"))       cfg.cap_distinct = atoi(v);
        else if (!strcmp(k, "db_path"))            snprintf(cfg.db_path, CFG_PATH, "%s", v);
        else if (!strcmp(k, "run_dir"))            snprintf(cfg.run_dir, CFG_PATH, "%s", v);
        else if (!strcmp(k, "log_file"))           snprintf(cfg.log_file, CFG_PATH, "%s", v);
        else if (!strcmp(k, "allow_file"))          snprintf(cfg.allow_file, CFG_PATH, "%s", v);
        else if (!strcmp(k, "conf_dir")) {
            /* entri PERTAMA menggeser daftar bawaan, entri berikutnya
             * menambah. Kalau hanya menambah, mengubah conf_dir di
             * pengujian tidak akan benar-benar mengisolasi daemon dari
             * log produksi. */
            if (cfg.n_conf_dirs == 0) logmsg("conf_dir bawaan digantikan oleh config");
            if (cfg.n_conf_dirs < 8) snprintf(cfg.conf_dirs[cfg.n_conf_dirs++], CFG_PATH, "%s", v);
        } else if (!strcmp(k, "log_dir")) {
            if (cfg.n_log_dirs == 0) logmsg("log_dir bawaan digantikan oleh config");
            if (cfg.n_log_dirs < 8) snprintf(cfg.log_dirs[cfg.n_log_dirs++], CFG_PATH, "%s", v);
        }
    }
    if (f) fclose(f);

    if (cfg.w_scan < 0) cfg.w_scan = 0;
    if (cfg.w_brute < 0) cfg.w_brute = 0;
    if (cfg.w_badua < 0) cfg.w_badua = 0;
    if (cfg.w_distinct < 0) cfg.w_distinct = 0;
    if (cfg.cap_scan < 1) cfg.cap_scan = 1;
    if (cfg.cap_brute < 1) cfg.cap_brute = 1;
    if (cfg.cap_badua < 1) cfg.cap_badua = 1;
    if (cfg.cap_distinct < 1) cfg.cap_distinct = 1;

    if (cfg.max_ips < 1024) cfg.max_ips = 1024;
    if (cfg.max_ips > MAX_IP) cfg.max_ips = MAX_IP;
    if (cfg.rescan_interval < 5) cfg.rescan_interval = 5;
    if (cfg.max_lines_per_tick < 100) cfg.max_lines_per_tick = 100;
    if (cfg.win_ban < 60) cfg.win_ban = 60;
    if (cfg.win_ban_max < cfg.win_ban) cfg.win_ban_max = cfg.win_ban;
    if (cfg.watch_score <= 0) cfg.watch_score = 20;
    if (cfg.throttle_score <= cfg.watch_score) cfg.throttle_score = cfg.watch_score + 40;
    if (cfg.ban_score <= cfg.throttle_score) cfg.ban_score = cfg.throttle_score + 90;

    /* Bawaan hanya dipakai bila config tidak menyebut sama sekali. */
    if (cfg.n_conf_dirs == 0) {
        snprintf(cfg.conf_dirs[0], CFG_PATH, "%s", "/www/server/panel/vhost/nginx");
        snprintf(cfg.conf_dirs[1], CFG_PATH, "%s", "/www/server/nginx/conf");
        cfg.n_conf_dirs = 2;
    }
    if (cfg.n_log_dirs == 0) {
        snprintf(cfg.log_dirs[0], CFG_PATH, "%s", "/www/wwwlogs");
        cfg.n_log_dirs = 1;
    }
}

/* ------------------------------------------------------------------ *
 * Allowlist: tidak boleh pernah diblokir.
 * ------------------------------------------------------------------ */
static uint32_t allow_net[256];
static int      allow_n = 0;
static uint32_t *allow_hash = NULL;   /* hash berisi ip persis (self IP) */

/* Salinan IP persis yang berasal dari allow_init (alamat server sendiri dan
 * whitelist panel). Daftar ini harus dipisah dari allow_hash, sama seperti
 * allow_base[] untuk daftar jaringan. Tanpa pemisahan ini, muat ulang
 * allowlist.txt hanya bisa menambah IP dan tidak pernah bisa mencabut:
 * IP yang sudah dihapus dari berkas tetap dianggap putih selamanya. */
static uint32_t allow_base_exact[512];
static int      allow_base_exact_n = 0;
static int      allow_sedang_builtin = 0;

static int net_contains(const uint32_t *net, int n, uint32_t ip)
{
    for (int i = 0; i < n; i++) {
        uint32_t base = net[i] & 0xffffff00u;
        if ((ip & 0xffffff00u) == base) return 1;
    }
    return 0;
}

static void allow_add_exact(uint32_t ip);
static void allow_add(const char *cidr);
static void allow_load_file(const char *path);

/* Baca daftar putih persisten. IP yang ada di sini tidak akan pernah
 * diblokir, berapa pun skornya.
 *
 * Berkas boleh dimuat ulang berkali-kali: daftar builtin (jaringan
 * internal dan alamat milik server sendiri) disimpan terpisah di
 * allow_base[], sehingga allow_n bisa dianggarkan ulang ke allow_base_n
 * setiap kali berkas dibaca ulang. Tanpa pemisahan ini,muat ulang
 * akan menumpuk entri dan membuat allow_n sooner or later penuh.
 * Gunanya: operator bisa menambah IP lewat panel atau edit berkas
 * tanpa perlu me-restart daemon. */
static void allow_load_file(const char *path)
{
    static uint32_t allow_base[256];
    static int      allow_base_n = 0;
    static int      first = 1;

    if (first) {
        /* salinan builtin saat allow_init sudah selesai bekerja */
        memcpy(allow_base, allow_net, sizeof(allow_net));
        allow_base_n = allow_n;
        first = 0;
    }
    allow_n = allow_base_n;
    /* Bangun ulang tabel IP persis dari nol. Tanpa langkah ini, IP yang
     * dihapus dari allowlist.txt tetap terbaca sebagai putih selamanya,
     * karena allow_add_exact hanya pernah menambah dan tidak pernah
     * mengurangi. */
    if (allow_hash) memset(allow_hash, 0, IP_BUCKETS * sizeof(uint32_t));
    allow_sedang_builtin = 0;
    for (int i = 0; i < allow_base_exact_n; i++)
        allow_add_exact(allow_base_exact[i]);

    FILE *f = fopen(path, "re");
    if (!f) {
        if (errno == ENOENT) return;
        logmsg("allowlist %s tidak terbaca, memakai daftar builtin", path);
        return;
    }
    char line[256];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line, *e;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        e = p + strlen(p);
        while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = '\0';
        if (!*p) continue;
        if (strchr(p, '/')) { allow_add(p); added++; }
        else {
            uint32_t ip = ip2u(p);
            if (ip) { allow_add_exact(ip); added++; }
        }
    }
    fclose(f);
    if (added) logmsg("whitelist persisten: %d entri dari %s", added, path);
}

static int allow_exact(uint32_t ip)
{
    if (!allow_hash) return 0;
    uint32_t h = (ip * 2654435761u) & (IP_BUCKETS - 1);
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t v = allow_hash[(h + i) & (IP_BUCKETS - 1)];
        if (v == 0) return 0;
        if (v == ip) return 1;
    }
    return 0;
}

/* Tambahkan satu CIDR ke daftar putih jaringan (disimpan per /24). */
static void allow_add(const char *cidr)
{
    char buf[64];
    char *slash;
    snprintf(buf, sizeof(buf), "%s", cidr);
    slash = strchr(buf, '/');
    if (slash) *slash = '\0';
    uint32_t ip = ip2u(buf);
    if (!ip) return;
    if (allow_n < 256) allow_net[allow_n++] = ip;
}

static void allow_add_exact(uint32_t ip)
{
    if (!ip) return;
    if (allow_sedang_builtin && allow_base_exact_n < (int)(sizeof(allow_base_exact) / sizeof(allow_base_exact[0]))) {
        for (int i = 0; i < allow_base_exact_n; i++)
            if (allow_base_exact[i] == ip) return;
        allow_base_exact[allow_base_exact_n++] = ip;
    }
    if (!allow_hash) return;
    uint32_t h = (ip * 2654435761u) & (IP_BUCKETS - 1);
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t *slot = &allow_hash[(h + i) & (IP_BUCKETS - 1)];
        if (*slot == 0 || *slot == ip) { *slot = ip; return; }
    }
}

/* Minggirkan juga jaringan internal & link-local; hanya /24 yang dipakai
 * untuk efficiency, cukup untuk 10/8, 172.16/12, 192.168/16, loopback. */
static void allow_init(void)
{
    allow_hash = xcalloc(IP_BUCKETS, sizeof(uint32_t));
    allow_base_exact_n = 0;
    allow_sedang_builtin = 1;

    /* jaringan internal selalu aman: 127/8, 10/8, 172.16/12, 192.168/16 */
    allow_net[allow_n++] = 0x7f000000u;   /* 127.0.0.0 */
    allow_net[allow_n++] = 0x0a000000u;   /* 10.0.0.0   */
    allow_net[allow_n++] = 0xac100000u;  /* 172.16.0.0 */
    allow_net[allow_n++] = 0xc0a80000u;  /* 192.168.0.0 */
    allow_net[allow_n++] = 0xa9fe0000u;  /* 169.254.0.0 */
    allow_net[allow_n++] = 0x64400000u;  /* 100.64.0.0 */

    /* alamat publik milik server ini sendiri */
    struct ifaddrs *ifa = NULL, *p;
    if (getifaddrs(&ifa) == 0) {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
            uint32_t ip = ntohl(sin->sin_addr.s_addr);
            if (ip == 0 || (ip >> 24) == 127) continue;
            allow_add_exact(ip);
            char b[32];
            u2ip(ip, b, sizeof(b));
            logmsg("allowlist: alamat publik sendiri %s", b);
        }
        freeifaddrs(ifa);
    }

    /* whitelist yang sudah dikelola panel aaPanel */
    const char *pcmd[] = { "/usr/sbin/ipset", "list", "aapanel.ipv4.whitelist", NULL };
    int fds[2];
    pid_t pid;
    if (pipe(fds) != 0) return;
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
        execv(pcmd[0], (char *const *)pcmd);
        _exit(127);
    }
    close(fds[1]);
    if (pid > 0) {
        char b[512];
        ssize_t n;
        FILE *r = fdopen(fds[0], "r");
        if (r) {
            while ((n = fread(b, 1, sizeof(b) - 1, r)) > 0) {
                b[n] = '\0';
                char *save = NULL;
                for (char *ln = strtok_r(b, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                    while (*ln == ' ' || *ln == '\t') ln++;
                    if (!strchr(ln, '.') || strchr(ln, '/')) continue;
                    uint32_t ip = ip2u(ln);
                    if (ip) {
                        allow_add_exact(ip);
                        char t[32]; u2ip(ip, t, sizeof(t));
                        logmsg("allowlist: dari panel %s", t);
                    }
                }
            }
            fclose(r);
        }
        waitpid(pid, NULL, 0);
    }
    allow_sedang_builtin = 0;
}

static int is_allowed(uint32_t ip)
{
    if (!ip) return 1;
    if (net_contains(allow_net, allow_n, ip)) return 1;
    if (allow_exact(ip)) return 1;
    return 0;
}

/* ------------------------------------------------------------------ *
 * Klasifikasi serangan.
 *
 * Semua daftar di bawah adalah POLA PATH/UA yang punya konfirmasi empiris
 * pada log server ini (lihat docs/). Tidak ada satu pun daftar ini yang
 * menabrak endpoint aplikasi yang sah.
 * ------------------------------------------------------------------ */
static const char *PAT_SCANNER[] = {
    /* WordPress */
    "/wp-login", "/wp-admin", "/wp-content", "/wp-includes", "/wp-json",
    "/wp-cron", "/wp-config", "/wp-login.php", "/xmlrpc.php", "/wordpress/",
    /* config & secret bocor */
    "/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "/.docker",
    "/.vscode", "/.idea", "/.zsh_history", "/.bash_history", "/.DS_Store",
    "/config.json", "/config.yaml", "/config.php.bak", "/web.config",
    "/database.yml", "/.htpasswd", "/.npmrc", "/.netrc",
    /* webshell & RCE marker */
    "/shell.php", "/shell/", "/c99.php", "/r57.php", "/b374k.php", "/cgi-bin/",
    "/.ssh/authorized_keys", "/vendor/phpunit", "/eval-stdin", "/base64_decode",
    "/boaform", "/HNAP1", "/favicon.ico.bak", "/.php5", "/.php7",
    /* app server & infra generik */
    "/manager/html", "/jmx-console", "/solr/", "/actuator", "/druid/",
    "/server-status", "/server-info", "/elmah.axd", "/web-console",
    "/console/", "/admin-console", "/hudson/", "/jenkins/", "/gitlab/",
    "/phpmyadmin", "/pma/", "/myadmin", "/mysqladmin", "/sqladmin",
    "/adminer", "/adminer.php",
    /* path sensitif */
    "/etc/passwd", "/etc/shadow", "/proc/self/environ", "/proc/self/cmdline",
    "/boot.ini", "/win.ini", "/id_rsa", "/.aws/credentials",
    /* Laravel & framework debug */
    "/_ignition", "/telescope", "/artisan", "/laravel.log", "/storage/logs",
    "/vendor/autoload", "/elmah.axd.axd", "/error_log",
    /* reverse proxy & infra */
    "/zremotescheduler", "/invoker/JMXInvokerServlet", "/cluster/domain",
    "/solr/admin", "/api/v1/../", "/%2e%2e/", "/boa", "/HNAP",
    NULL
};

static const char *PATH_BRUTE[] = {
    "/login", "/signin", "/log-in", "/sign-in", "/auth", "/authenticate",
    "/wp-login", "/password", "/passwd", "/user/login", "/api/login",
    "/api/auth", "/api/v1/login", "/api/v1/auth", "/oauth/token", "/session",
    "/member/login", "/account/login", "/users/sign_in", "/do/login",
    NULL
};

/* UA yang hanya dipakai alat, bukan peramban pengguna.
 * PENTING: daftar ini hanya menaikkan skor, tidak pernah menyebabkan ban
 * secara tunggal -- harus digabung dengan kategori lain. */
static const char *UA_TOOL[] = {
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "zmap", "dirbuster",
    "gobuster", "dirb", "wpscan", "joomscan", "nuclei", "xsstrike",
    "havij", "acunetix", "nessus", "openvas", "arachni", "w3af",
    "python-requests", "python-urllib", "go-http-client", "curl/", "wget",
    "libwww-perl", "lwp::simple", "apachebench", "siege", "ab -", "jMeter",
    "Apache-HttpClient", "Java/", "okhttp", "axios/", "node-fetch",
    "got (", "puppeteer", "playwright", "phantomjs", "headlesschrome",
    "scrapy", "http_request", "ruby", "dart:io", "lua-resty-http",
    "aiohttp", "urllib3", "httpie", "postmanruntime", "insomnia",
    "cf-facebook", "meta-webindexer", "applebot", "bytespider", "gptbot",
    "claudebot", "anthropic-ai", "perplexitybot", "ccbot", "youbot",
    NULL
};

static int in_list(const char *const *list, const char *needle, size_t nlen)
{
    for (int i = 0; list[i]; i++) {
        size_t l = strlen(list[i]);
        if (l <= nlen && !memcmp(list[i], needle, l)) return 1;
    }
    return 0;
}

static int path_is_scanner(const char *path, size_t len)
{
    /* normalisasi sedikit: buang garis miring di akhir */
    size_t n = len;
    while (n > 1 && path[n - 1] == '/') n--;
    return in_list(PAT_SCANNER, path, n);
}

static int path_is_brute(const char *path, size_t len)
{
    return in_list(PATH_BRUTE, path, len);
}

static int ua_is_tool(const char *ua, size_t len)
{
    if (len == 0) return 0;
    if (len < 5) return 1;                     /* UA sangat pendek = bukan browser */
    return in_list(UA_TOOL, ua, len);
}

/* ------------------------------------------------------------------ *
 * Tabel IP
 * ------------------------------------------------------------------ */
typedef struct ip_ent {
    struct ip_ent *next;      /* rantai dalam bucket hash */
    struct ip_ent *lru_prev;  /* daftar umur: kepala = paling lama tidak terlihat */
    struct ip_ent *lru_next;
    uint32_t ip;
    uint32_t score;
    uint16_t peak;
    uint16_t req_window;              /* total request dalam jendela */
    uint32_t slot_ts[RATE_SLOTS];     /* epoch penanda slot */
    uint16_t slot_cnt[RATE_SLOTS];    /* request per slot */
    uint32_t first_seen, last_seen;
    uint64_t bytes;
    uint16_t s2, s3, s4, s5, s429;
    uint16_t scan, brute, badua, e404, distinct;
    uint8_t  path_hash[MAX_DISTINCT_PATHS];
    uint8_t  npath;
    uint8_t  level;
    uint32_t last_ev;                 /* pembatas spam event */
    /* Konteks request terakhir dari IP ini. Tanpa tiga field ini,
       event yang dibuat dari agregat per-IP tidak tahu mengenai
       vhost/path mana serangan itu terjadi, sehingga kolom host dan
       path di tabel events selalu kosong dan analisis per-vhost
       mustahil. Diisi setiap kali baris log untuk IP ini diproses. */
    char     last_host[64];
    char     last_path[160];
    char     last_ua[120];
    uint32_t last_ctx;                /* tick terakhir konteks diisi */
} ip_ent;

static ip_ent **g_buckets;
static int      g_ip_used = 0;
static uint32_t g_self_ip = 0;

/* agregat agregat per menit */
typedef struct {
    uint64_t req, bytes, s2, s3, s4, s5, s429;
} agg_t;

#define MAX_HOSTS 256
static agg_t g_host[MAX_HOSTS];
static char  *g_hostname[MAX_HOSTS];
static int    g_nhost = 0;

/* agregat per IP per menit (untuk "top talker" & grafik) */
typedef struct {
    uint32_t ip;
    uint32_t ts;
    uint32_t req;
    uint16_t score;
} ipmin_t;
static ipmin_t g_ipmin[MAX_IPMIN_BATCH];
static int      g_ipmin_n = 0;

static agg_t g_cur;
static uint32_t g_cur_min = 0;

/* event serangan */
typedef struct {
    uint32_t ts;
    uint32_t ip;
    uint16_t score;
    uint8_t  level;
    uint8_t  kind;
    char     host[64];
    char     path[160];
    char     ua[120];
} ev_t;

static ev_t g_ev[MAX_EVENTS_BATCH];
static int  g_ev_n = 0;

/* event "informasi" supaya dasbor tetap punya isi */
static uint64_t g_stat_total = 0;
static uint64_t g_stat_bytes = 0;
static uint64_t g_stat_flood = 0;      /* tick yang mengalami throttle */
static uint64_t g_stat_parse_fail = 0;
static uint64_t g_stat_lines = 0;
static uint64_t g_stat_dropped_cap = 0;  /* line dilewati karena pagu tick */
static uint64_t g_stat_bans_total = 0;
static uint64_t g_stat_throttles_total = 0;

/* daftar ban */
typedef struct {
    uint32_t ip;
    time_t   until;
    time_t   start;
    uint32_t score;
    uint32_t offenses;
    uint8_t  kind;
    char     reason[120];
    int      active;
} ban_t;

static ban_t g_ban[MAX_BAN_ENTRIES];
static int   g_ban_n = 0;

/* Prototipe agar ban_remove (bagian ban) boleh memanggil ipset_del yang
 * didefinisikan jauh di bawah pada bagian ipset. */
static void ipset_del(const char *set, uint32_t ip);

/* Definisi tailer_release ada di bawah tailer_open. */
static void tailer_release(int idx);

static ban_t *ban_find(uint32_t ip)
{
    for (int i = 0; i < g_ban_n; i++) if (g_ban[i].ip == ip) return &g_ban[i];
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Tabel IP: hash + daftar umur (LRU) dalam dua arah.
 *
 * Kenapa dua struktur? Karena syarat "buang yang paling lama tidak
 * terlihat" tidak bisa dijawab dari hash bucket tanpa memindai
 * SELURUH tabel. Versi pertama memakai pemindaian seluruh 65536 bucket
 * setiap kali tabel penuh; hasil pengujian ulang log produksi
 * menunjukkan tabel itu gagal dikosongkan dan 34 persen baris log
 * terbuang. Dengan daftar LRU dua arah, pembuangan jadi O(1).
 *
 * Daftar umur disusun dari kepala (paling lama) ke ekor (paling baru).
 * Setiap kali sebuah IP terlihat, entri digeser ke ekor.
 * ------------------------------------------------------------------ */
static ip_ent  *g_lru_head = NULL;   /* paling lama tidak terlihat */
static ip_ent  *g_lru_tail = NULL;   /* paling baru terlihat */
#define EVICT_MIN_IDLE 60           /* detik minimal tak terlihat agar aman dibuang */

static void lru_unlink(ip_ent *e)
{
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             g_lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             g_lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void lru_push_tail(ip_ent *e)
{
    e->lru_prev = g_lru_tail;
    e->lru_next = NULL;
    if (g_lru_tail) g_lru_tail->lru_next = e;
    else            g_lru_head = e;
    g_lru_tail = e;
}

static void ip_unlink_bucket(uint32_t ip)
{
    uint32_t h = (ip * 2654435761u) & (IP_BUCKETS - 1);
    ip_ent **pp = &g_buckets[h];
    while (*pp) {
        if ((*pp)->ip == ip) {
            ip_ent *dead = *pp;
            *pp = dead->next;
            lru_unlink(dead);
            free(dead);
            g_ip_used--;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Buang satu entri. Dua lapis:
 *   1. dari kepala daftar umur, ambil yang sudah lama tidak terlihat
 *      (>= EVICT_MIN_IDLE detik), skor 0, level NORMAL
 *   2. kalau tidak ada yang cukup lama, ambil entri NORMAL paling tua
 *      yang ada. Lapis kedua menjaga tabel tetap bisa menerima IP baru
 *      walau semuanya aktif, tanpa perlu menolak.
 * Return 1 kalau ada yang dibuang. */
static int ip_evict_one(uint32_t now)
{
    /* Lapis 1 */
    int scanned = 0;
    for (ip_ent *e = g_lru_head; e && scanned < 4096; e = e->lru_next, scanned++) {
        if (e->level != LVL_NORMAL || e->score != 0) continue;
        if ((uint32_t)(now - e->last_seen) < EVICT_MIN_IDLE) continue;
        ip_unlink_bucket(e->ip);
        return 1;
    }

    /* Lapis 2: entri NORMAL paling tua, dengan batas pindai supaya
     * tidak pernah berjalan lama saat semua entri bertingkat. */
    ip_ent *best = NULL;
    scanned = 0;
    for (ip_ent *e = g_lru_head; e && scanned < 4096; e = e->lru_next, scanned++) {
        if (e->level != LVL_NORMAL) continue;
        if (!best || e->last_seen < best->last_seen) best = e;
    }
    if (best) { ip_unlink_bucket(best->ip); return 1; }

    return 0;
}

static ip_ent *ip_get(uint32_t ip, time_t t)
{
    uint32_t h = (ip * 2654435761u) & (IP_BUCKETS - 1);
    ip_ent *e;
    for (e = g_buckets[h]; e; e = e->next) {
        if (e->ip != ip) continue;
        e->last_seen = (uint32_t)t;
        /* geser ke ekor daftar umur: paling baru terlihat */
        if (g_lru_tail != e) { lru_unlink(e); lru_push_tail(e); }
        return e;
    }
    if (g_ip_used >= cfg.max_ips && !ip_evict_one((uint32_t)t))
        return NULL;

    e = xcalloc(1, sizeof(ip_ent));
    e->ip = ip;
    e->first_seen = e->last_seen = (uint32_t)t;
    e->next = g_buckets[h];
    g_buckets[h] = e;
    lru_push_tail(e);
    g_ip_used++;
    return e;
}

/* ------------------------------------------------------------------ *
 * Tailer log DINAMIS
 * ------------------------------------------------------------------ */
typedef struct {
    char     path[PATH_MAX];
    char     host[64];
    int      fd;
    ino_t    ino;
    dev_t    dev;     /* perangkat penyimpan, ikut dibandingkan saat rotasi */
    off_t    off;
    uint64_t lines;
    time_t   added;
    int      in_use;
    int      degraded;      /* tidak bisa dibuka / stat gagal */
    /* Sisa baris yang belum lengkap. WAJIB ada: read() mengembalikan
     * potongan byte, bukan baris. Tanpa buffer ini, baris yang terpotong
     * di batas read akan dihitung sebagai baris utuh, lalu bagian
     * sisanya dibaca lagi sebagai "baris baru" pada siklus berikutnya.
     * Gejalanya: jumlah baris terproses melebihi jumlah baris sebenarnya
     * dan ribuan parse gagal palsu. */
    char     carry[SENT_LINE_MAX];
    size_t   carry_len;
} tailer_t;

static tailer_t g_tail[MAX_TAILERS];
static int      g_tail_n = 0;

/* ------------------------------------------------------------------ *
 * Kumpulan log yang INGIN ditail, dibangun ulang setiap siklus
 * penemuan. Dipisahkan dari daftar tailer yang aktif supaya vhost yang
 * dihapus lalu dibuatkan lagi tetap terdeteksi.
 * ------------------------------------------------------------------ */
static char *g_want[MAX_TAILERS];
static int   g_want_n = 0;

static void want_reset(void)
{
    for (int i = 0; i < g_want_n; i++) free(g_want[i]);
    g_want_n = 0;
}

static int want_add(const char *p)
{
    for (int i = 0; i < g_want_n; i++) if (!strcmp(g_want[i], p)) return 0;
    if (g_want_n >= MAX_TAILERS) return 0;
    char *d = strdup(p);
    if (!d) return 0;
    g_want[g_want_n++] = d;
    return 1;
}

static int want_has(const char *p)
{
    for (int i = 0; i < g_want_n; i++) if (!strcmp(g_want[i], p)) return 1;
    return 0;
}

/* Nama host diturunkan dari nama berkas agar situs baru langsung muncul
 * di dasbor tanpa perlu disentuh kode. */
static void host_from_path(const char *path, char *out, size_t n)
{
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    snprintf(out, n, "%s", b);
    size_t l = strlen(out);
    if (l > 4 && !strcmp(out + l - 4, ".log")) out[l - 4] = '\0';
    /* buang sufiks tanggal ala aaPanel: nama_YYYY-MM-DD.log / nama.2026-10-02.log */
    char *us = strrchr(out, '_');
    char *dot = strrchr(out, '.');
    if (us && us != out && dot && dot > us + 1) {
        int ok = 1;
        for (const char *p = us + 1; *p; p++) {
            if (*p >= '0' && *p <= '9') continue;
            if (*p == '-') continue;
            ok = 0; break;
        }
        if (ok && strlen(us + 1) >= 8) *us = '\0';
    }
    if (!*out) snprintf(out, n, "-");
}

static int host_index(const char *host)
{
    for (int i = 0; i < g_nhost; i++) if (!strcmp(g_hostname[i], host)) return i;
    if (g_nhost >= MAX_HOSTS) return -1;
    g_hostname[g_nhost] = strdup(host);
    if (!g_hostname[g_nhost]) return -1;
    memset(&g_host[g_nhost], 0, sizeof(agg_t));
    return g_nhost++;
}

/* Apakah baris log terlihat seperti access log format "combined"?
 * Dipakai untuk jaring pengaman saat memindai direktori log. */
static int looks_like_access_log(const char *path)
{
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    char line[SENT_LINE_MAX];
    int found = 0;
    for (int i = 0; i < 20 && !found; i++) {
        if (!fgets(line, sizeof(line), f)) break;
        if (line[0] == '\0' || line[0] == '\n') continue;
        /* harus diawali IP v4 */
        int dots = 0, ok = 1;
        for (const char *p = line; *p == '.' || isdigit((unsigned char)*p); p++) {
            if (*p == '.') dots++;
            if (!isdigit((unsigned char)*p) && *p != '.') { ok = 0; break; }
            if (p - line > 40) { ok = 0; break; }
        }
        if (!ok || dots < 3) continue;
        /* harus ada field requestMODE " dan status 3 digit */
        if (strchr(line, '"') && strstr(line, "HTTP/")) { found = 1; }
    }
    fclose(f);
    return found;
}

/* Buka log dan mulai tail. Log yang masih kosong TETAP didaftarkan:
 * vhost baru bisa sahi log kosong selama beberapa detik. */
static int tailer_open(const char *path, const char *src)
{
    for (int i = 0; i < g_tail_n; i++)
        if (g_tail[i].in_use && !strcmp(g_tail[i].path, path)) return 0;
    if (g_tail_n >= MAX_TAILERS) {
        logmsg("pagu tailer penuh (%d), log %s diabaikan", MAX_TAILERS, path);
        return -1;
    }

    tailer_t *t = &g_tail[g_tail_n];
    memset(t, 0, sizeof(*t));
    snprintf(t->path, PATH_MAX, "%s", path);
    host_from_path(path, t->host, sizeof(t->host));
    t->added = now_t();
    t->fd = -1;
    t->in_use = 1;
    g_tail_n++;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        logmsg("gagal buka %s (%s), akan dicoba lagi tiap detik", path, strerror(errno));
        t->degraded = 1;
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        t->fd = fd;
        t->ino = st.st_ino;
        t->dev = st.st_dev;
        t->off = 0;
        logmsg("tail + %-50s (host=%s, sumber=%s, ukuran=%lld)",
               path, t->host, src, (long long)st.st_size);
        return 1;
    }
    close(fd);
    logmsg("%s bukan berkas biasa, dilewati", path);
    tailer_release(g_tail_n - 1);
    return -1;
}

static void tailer_release(int idx)
{
    tailer_t *t = &g_tail[idx];
    if (!t->in_use) return;
    if (t->fd >= 0) close(t->fd);
    t->fd = -1;
    t->in_use = 0;
    t->path[0] = '\0';
    t->ino = 0;
    t->dev = 0;
    t->off = 0;
    t->lines = 0;
    t->carry_len = 0;
}

/* Coba buka ulang tailer yang sebelumnya gagal (mis. log belum ada
 * saat penemuan, lalu panel baru membuatnya). */
static void tailer_retry(void)
{
    for (int i = 0; i < g_tail_n; i++) {
        tailer_t *t = &g_tail[i];
        if (!t->in_use || t->fd >= 0) continue;
        int fd = open(t->path, O_RDONLY);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); continue; }
        t->fd = fd;
        t->ino = st.st_ino;
        t->dev = st.st_dev;
        t->off = 0;
        t->degraded = 0;
        logmsg("tail pulih: %s", t->path);
    }
}

/* Direktori yang isinya BUKAN access log server (dilewati). */
static const char *SKIP_DIR[] = { "free_waf_log", "waf", "go", "python", "load_balancing", NULL };

static int dir_should_skip(const char *name)
{
    for (int i = 0; SKIP_DIR[i]; i++) if (!strcmp(SKIP_DIR[i], name)) return 1;
    return 0;
}

/* Baca satu directive access_log dari sebuah berkas conf.
 * Mengembalikan jumlah target valid yang ditemukan. */
static int scan_one_conf(const char *path)
{
    int found = 0;
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    char line[SENT_LINE_MAX];

    while (fgets(line, sizeof(line), f)) {
        /* Abaikan baris komentar dan directive di dalam blok include
         * yang di-komentari. Directive harus di awal baris (setelah
         * spasi), supaya "# access_log /x.log;" tidak ikut terbaca. */
        char *q = line;
        while (*q == ' ' || *q == '\t') q++;
        if (*q == '#' || *q == '\n' || *q == '\0') continue;
        if (strncmp(q, "access_log", 10) != 0) continue;
        q += 10;
        if (*q != ' ' && *q != '\t') continue;

        while (*q == ' ' || *q == '\t') q++;
        if (*q == '\0' || *q == '\n' || *q == '#') continue;

        /* token pertama = target */
        char target[PATH_MAX];
        size_t i = 0;
        while (*q && *q != ' ' && *q != '\t' && *q != ';' && *q != '\n' && i < PATH_MAX - 1)
            target[i++] = *q++;
        target[i] = '\0';
        if (!i) continue;

        /* Buang bentuk yang bukan berkas nyata:
         *   off            -> matikan log
         *   syslog:...     -> lewat soket, bukan berkas
         *   $pipe / $var   -> variabel, tidak bisa dibuka
         *   /dev/null      -> buang
         *   stderr         -> stream
         */
        if (target[0] != '/') continue;
        if (!strncmp(target, "/dev/", 5)) continue;
        if (strchr(target, '$')) continue;
        if (!strstr(target, ".log")) continue;

        if (want_add(target)) found++;
    }
    fclose(f);
    return found;
}

static void scan_conf_recursive(const char *dir, int depth, int *found)
{
    if (depth > MAX_CONF_DEPTH) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", dir, de->d_name) >= PATH_MAX) continue;
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { scan_conf_recursive(path, depth + 1, found); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        size_t ln = strlen(de->d_name);
        if (ln < 6 || strcmp(de->d_name + ln - 5, ".conf") != 0) continue;
        *found += scan_one_conf(path);
    }
    closedir(d);
}

/* Jaring pengaman: pindai direktori log, ambil *.log yang memverifikasi
 * dirinya sebagai access log. Menutup kemungkinan ada access log yang
 * tidak tertulis eksplisit di conf (mis. dibuat manual oleh pemilik). */
static void scan_logdir(const char *dir, int depth, int *found)
{
    if (depth > 2) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (dir_should_skip(de->d_name)) continue;
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", dir, de->d_name) >= PATH_MAX) continue;
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { scan_logdir(path, depth + 1, found); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        size_t ln = strlen(de->d_name);
        if (ln < 5 || strcmp(de->d_name + ln - 4, ".log") != 0) continue;
        /* jangan ikut error log */
        if (strstr(de->d_name, "error")) continue;
        if (want_has(path)) continue;
        if (!looks_like_access_log(path)) continue;
        if (want_add(path)) (*found)++;
    }
    closedir(d);
}

static int g_logs_seen = 0;

/* Siklus penemuan. Dipanggil berkala dan setiap SIGHUP.
 * Tidak ada daftar vhost yang disimpan di kode: seluruhnya berasal dari
 * pembacaan berkas conf dan direktori log saat runtime. */
static void rediscover(void)
{
    int found = 0;
    want_reset();
    for (int i = 0; i < cfg.n_conf_dirs; i++)
        scan_conf_recursive(cfg.conf_dirs[i], 0, &found);
    for (int i = 0; i < cfg.n_log_dirs; i++)
        scan_logdir(cfg.log_dirs[i], 0, &found);

    /* Buka yang baru */
    for (int i = 0; i < g_want_n; i++)
        tailer_open(g_want[i], "penemuan");

    /* Lepas yang sudah tidak ada (vhost dihapus di panel) */
    for (int i = 0; i < g_tail_n; i++) {
        if (!g_tail[i].in_use) continue;
        if (!want_has(g_tail[i].path)) {
            logmsg("tail - %s (vhost atau berkas log sudah dihapus)", g_tail[i].path);
            tailer_release(i);
        }
    }

    g_logs_seen = 0;
    for (int i = 0; i < g_tail_n; i++) if (g_tail[i].in_use) g_logs_seen++;
    if (found || g_logs_seen)
        logmsg("penemuan dinamis: %d log ditail, %d kandidat baru siklus ini",
               g_logs_seen, found);
}

/* ------------------------------------------------------------------ *
 * Pemrosesan
 * ------------------------------------------------------------------ */
enum { K_NONE = 0, K_SCANNER = 1, K_BRUTE = 2, K_FLOOD = 3, K_BADUA = 4,
       K_MIXED = 5, K_PROBE = 6 };

static const char *KIND_NAME[] = { "-", "scanner", "bruteforce", "flood",
                                   "bad-ua", "campuran", "probe-paths" };

/* Apakah path ini TIDAK ada di daftar aset/health check yang sah?
 * Kalau iya dan statusnya 4xx, request itu dicurigai enumerasi direktori. */
static int path_unlisted(const char *p, size_t n)
{
    static const char *OKP[] = {
        "/favicon.ico", "/robots.txt", "/sitemap", "/app-ads.txt", "/ads.txt",
        "/apple-touch-icon", "/manifest.json", "/service-worker", "/sw.js",
        "/health", "/ping", "/pong", "/up", "/readyz", "/livez",
        "/uploads/", "/assets/", "/storage/", "/images/", "/img/", "/css/",
        "/js/", "/fonts/", "/media/", "/uploads", "/assets", "/api/pong",
        NULL
    };
    return !in_list(OKP, p, n);
}

/* parser format "combined" tanpa regex. Return 0 kalau tidak cocok. */
typedef struct {
    uint32_t ip;
    int      status;
    uint64_t bytes;
    char     method[8];
    const char *path;
    size_t   path_len;
    const char *ua;
    size_t   ua_len;
} parsed_t;

static int parse_line(const char *s, size_t len, parsed_t *r)
{
    const char *p = s, *end = s + len;

    /* --- IP --- */
    const char *ipb = p;
    while (p < end && (isdigit((unsigned char)*p) || *p == '.')) p++;
    if (p - ipb < 7 || p == ipb) return 0;
    char ipbuf[24];
    size_t iplen = (size_t)(p - ipb);
    if (iplen >= sizeof(ipbuf)) return 0;
    memcpy(ipbuf, ipb, iplen); ipbuf[iplen] = '\0';
    r->ip = ip2u(ipbuf);
    if (!r->ip) return 0;

    /* lewati sampai tanda kutip pertama */
    while (p < end && *p != '"') p++;
    if (p >= end) return 0;
    p++;
    const char *reqb = p;
    while (p < end && *p != '"') p++;
    if (p >= end) return 0;
    const char *reqe = p;
    p++;
    if (reqe - reqb < 4) return 0;

    /* --- method --- */
    const char *msp = reqb;
    while (msp < reqe && *msp != ' ') msp++;
    size_t ml = (size_t)(msp - reqb);
    if (ml == 0 || ml >= sizeof(r->method)) return 0;
    memcpy(r->method, reqb, ml); r->method[ml] = '\0';
    for (size_t k = 0; k < ml; k++)
        if (!isupper((unsigned char)r->method[k]) && r->method[k] != '-') return 0;

    /* --- URI (tanpa query string) --- */
    const char *up = msp < reqe ? msp + 1 : reqe;
    const char *qe = up;
    while (qe < reqe && *qe != '?' && *qe != ' ' && *qe != '#') qe++;
    r->path = up;
    r->path_len = (size_t)(qe - up);
    if (r->path_len == 0) return 0;

    /* --- status --- */
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (end - p < 3) return 0;
    for (int k = 0; k < 3; k++) if (!isdigit((unsigned char)p[k])) return 0;
    r->status = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    p += 3;

    /* --- bytes --- */
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    uint64_t b = 0;
    int digits = 0;
    while (p < end && isdigit((unsigned char)*p)) { b = b * 10 + (uint64_t)(*p - '0'); p++; digits++; }
    if (!digits) b = 0;
    r->bytes = b;

    /* --- UA: bagian kutip terakhir di baris --- */
    r->ua = "";
    r->ua_len = 0;
    const char *lastq = NULL;
    for (const char *q = end; q > s; q--) {
        if (*q == '"') { lastq = q; break; }
    }
    if (lastq && lastq > s) {
        const char *ub = lastq - 1;
        while (ub > s && *ub != '"') ub--;
        if (ub < lastq - 1) {
            r->ua = ub + 1;
            r->ua_len = (size_t)(lastq - ub - 1);
            while (r->ua_len && (r->ua[r->ua_len - 1] == '"')) r->ua_len--;
            if (r->ua_len > 240) r->ua_len = 240;
        }
    }
    return 1;
}

static int g_ua_lower_buf[256];

static int ua_is_tool_copy(const char *ua, size_t n)
{
    if (n >= sizeof(g_ua_lower_buf)) n = sizeof(g_ua_lower_buf) - 1;
    for (size_t i = 0; i < n; i++)
        g_ua_lower_buf[i] = tolower((unsigned char)ua[i]);
    g_ua_lower_buf[n] = '\0';
    return ua_is_tool((const char *)g_ua_lower_buf, n);
}

static void ev_push(uint32_t ts, uint32_t ip, uint16_t score, uint8_t level,
                    uint8_t kind, const char *host, const char *path,
                    size_t plen, const char *ua, size_t ulen)
{
    if (g_ev_n >= MAX_EVENTS_BATCH) return;
    ev_t *e = &g_ev[g_ev_n++];
    memset(e, 0, sizeof(*e));
    e->ts = ts; e->ip = ip; e->score = score; e->level = level; e->kind = kind;
    /* Konteks boleh kosong: log terakhir untuk IP itu bisa saja belum
       pernah terisi (mis. IP baru saja dibuat oleh ban, bukan log).
       Nilai kosong diganti "-" supaya kolom database tidak pernah
       berisi string kosong dan supaya UI bisa membedakan "tidak ada
       konteks" dari "konteks kosong". */
    snprintf(e->host, sizeof(e->host), "%s",
             (host && *host) ? host : "-");
    snprintf(e->path, sizeof(e->path), "%.*s",
             (int)(plen > 150 ? 150 : plen), (path && plen) ? path : "-");
    if (!path || !plen) snprintf(e->path, sizeof(e->path), "%s", "-");
    snprintf(e->ua, sizeof(e->ua), "%.*s",
             (int)(ulen > 110 ? 110 : ulen), (ua && ulen) ? ua : "-");
    if (!ua || !ulen) snprintf(e->ua, sizeof(e->ua), "%s", "-");
}

static int score_of(ip_ent *e)
{
    uint32_t cap;
    uint32_t s = 0;

    cap = (uint32_t)cfg.cap_scan;    s += ((uint32_t)e->scan    > cap ? cap : (uint32_t)e->scan)    * (uint32_t)cfg.w_scan;
    cap = (uint32_t)cfg.cap_brute;   s += ((uint32_t)e->brute   > cap ? cap : (uint32_t)e->brute)   * (uint32_t)cfg.w_brute;
    cap = (uint32_t)cfg.cap_badua;   s += ((uint32_t)e->badua   > cap ? cap : (uint32_t)e->badua)   * (uint32_t)cfg.w_badua;
    cap = (uint32_t)cfg.cap_distinct; s += ((uint32_t)e->distinct > cap ? cap : (uint32_t)e->distinct) * (uint32_t)cfg.w_distinct;
    if (e->s429) s += 5;
    return (s > 60000) ? 60000 : (int)s;
}

static uint8_t kind_of(ip_ent *e)
{
    int n = 0, k = K_NONE;
    if (e->scan)  { k = K_SCANNER; n++; }
    if (e->brute) { k = n ? K_MIXED : K_BRUTE; n++; }
    if (e->badua >= 5) { k = n ? K_MIXED : K_BADUA; n++; }
    if (n == 0 && e->req_window > 0) k = K_NONE;
    return (uint8_t)k;
}

/* ------------------------------------------------------------------ *
 * SQLite
 * ------------------------------------------------------------------ */
static sqlite3 *g_db = NULL;

static void saverr(sqlite3 *db, const char *what)
{
    logmsg("sqlite %s gagal: %s", what, sqlite3_errmsg(db));
}

static void db_open(void)
{
    int rc = sqlite3_open_v2(cfg.db_path, &g_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) die("gagal membuka %s: %s", cfg.db_path,
                             g_db ? sqlite3_errmsg(g_db) : sqlite3_errstr(rc));
    sqlite3_busy_timeout(g_db, 3000);
    char *err = NULL;
    /* WAL + synchronous=NORMAL: tulis statistik TIDAK boleh memblokir
     * saat proses lain (dasbor) sedang membaca. */
    const char *pragmas[] = {
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA temp_store=MEMORY",
        "PRAGMA cache_size=-8000",
    };
    for (size_t i = 0; i < sizeof(pragmas) / sizeof(pragmas[0]); i++)
        sqlite3_exec(g_db, pragmas[i], NULL, NULL, &err);
    sqlite3_free(err); err = NULL;

    const char *ddl =
        "CREATE TABLE IF NOT EXISTS minute("
        " ts INTEGER, host TEXT, req INTEGER, bytes INTEGER,"
        " s2 INTEGER, s3 INTEGER, s4 INTEGER, s5 INTEGER, s429 INTEGER,"
        " PRIMARY KEY(ts,host));"
        "CREATE TABLE IF NOT EXISTS ip_minute("
        " ts INTEGER, ip INTEGER, req INTEGER, score INTEGER,"
        " PRIMARY KEY(ts,ip));"
        "CREATE TABLE IF NOT EXISTS events("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER,"
        " kind TEXT, score INTEGER, level INTEGER, host TEXT, path TEXT, ua TEXT);"
        "CREATE TABLE IF NOT EXISTS bans("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ip INTEGER, kind TEXT,"
        " score INTEGER, start INTEGER, until INTEGER, offenses INTEGER, reason TEXT);"
        "CREATE TABLE IF NOT EXISTS verdict("
        " ip INTEGER PRIMARY KEY, offenses INTEGER DEFAULT 0, last_kill INTEGER DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);"
        "CREATE INDEX IF NOT EXISTS ix_minute_ts ON minute(ts);"
        "CREATE INDEX IF NOT EXISTS ix_ban_until ON bans(until);"
        "CREATE TABLE IF NOT EXISTS watch("
        " ts INTEGER, ip INTEGER, host TEXT, score INTEGER, kind TEXT);"
        /* Jejak audit. Tanpa tabel ini tidak ada cara membuktikan
           tindakan apa yang sudah dilakukan terhadap sebuah IP: kapan,
           oleh siapa atau sistem apa, dan dengan alasan apa. Yang
           terlihat hanya status akhir, itu tidak cukup untuk
           rekonsiliasi. */
        "CREATE TABLE IF NOT EXISTS aksi("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER,"
        " aksi TEXT, sumber TEXT, alasan TEXT, detik INTEGER);"
        "CREATE INDEX IF NOT EXISTS ix_aksi_ts ON aksi(ts);"
        "CREATE INDEX IF NOT EXISTS ix_aksi_ip ON aksi(ip);"
        /* Cache negara untuk IP. diisi dari sisi panel (Python) karena
           berkas GeoLite2 berformat MMDB dan daemon tidak punya
           pustaka bacanya. Nilai 'ZZ' berarti tidak diketahui. */
        "CREATE TABLE IF NOT EXISTS geo("
        " ip INTEGER PRIMARY KEY, kode TEXT, nama TEXT, ts INTEGER);"
        /* Antrean review: IP yang mencurigakan tapi menunggu keputusan
           operator. Kepler never_entries() supaya operator bisa
           membedakan "baru masuk antrian" dari "sudah ditolak". */
        "CREATE TABLE IF NOT EXISTS review("
        " ip INTEGER PRIMARY KEY, ts INTEGER, skor INTEGER,"
        " alasan TEXT, status TEXT);"
        "CREATE INDEX IF NOT EXISTS ix_review_status ON review(status);"
        /* Antrean notifikasi. Daemon hanya MENULIS di sini, tidak
           pernah mengirim sendiri. Pengiriman dikerjakan skrip terpisah
           lewat timer, supaya dua hal penting berlaku:

           - Notifikasi tidak memperlambat daemon. Kalau HTTP dikirim
             langsung dari daemon, satu request ke alamat yang tidak
             menjawab akan menahan pemrosesan log seluruhnya.
           - Notifikasi tidak hilang saat jaringan mati. Baris tetap
             tersimpan dan dikirim ulang pada percobaan berikutnya.
           Kolom terkirim menyimpan hasil percobaan terakhir supaya
           masalah bisa dilihat di panel. */
        "CREATE TABLE IF NOT EXISTS notif("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER,"
        " jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0,"
        " coba INTEGER DEFAULT 0, galat TEXT);"
        "CREATE INDEX IF NOT EXISTS ix_notif_kirim ON notif(terkirim);";
    if (sqlite3_exec(g_db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        logmsg("sqlite DDL gagal: %s", err ? err : "?");
        sqlite3_free(err);
    }
}

static uint32_t ban_secs_for(uint32_t ip, time_t t)
{
    sqlite3_stmt *st = NULL;
    uint32_t offenses = 0, last = 0;
    if (sqlite3_prepare_v2(g_db, "SELECT offenses,last_kill FROM verdict WHERE ip=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)ip);
        if (sqlite3_step(st) == SQLITE_ROW) {
            offenses = (uint32_t)sqlite3_column_int64(st, 0);
            last = (uint32_t)sqlite3_column_int64(st, 1);
        }
        sqlite3_finalize(st);
    }
    uint32_t secs = (uint32_t)cfg.win_ban;
    if (last && (t - (time_t)last) < 86400 * 7) {
        if (offenses < 8) secs = (uint32_t)cfg.win_ban << offenses;
        if (secs > (uint32_t)cfg.win_ban_max) secs = (uint32_t)cfg.win_ban_max;
    }
    return secs;
}

/* Setiap IP yang baru masuk allowlist langsung dicabut dari kedua set
 * ipset dan ban aktifnya dimatikan. Tanpa ini, whitelist baru hanya
 * berlaku di sisi guardd sementara aturan kernel masih menolak, sampai
 * sentinel-fw.timer memasang ulang aturannya. */
static void allow_release_ipsets(void)
{
    for (int i = 0; i < g_ban_n; i++) {
        ban_t *b = &g_ban[i];
        if (!b->active) continue;
        if (!is_allowed(b->ip)) continue;
        char buf[32];
        u2ip(b->ip, buf, sizeof(buf));
        ipset_del("sentinel_ban", b->ip);
        ipset_del("sentinel_throttle", b->ip);
        b->active = 0;
        logmsg("IP %s masuk allowlist: ban dan throttle dicabut", buf);
    }
}

static void verdict_bump(uint32_t ip, time_t t)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO verdict(ip,offenses,last_kill) VALUES(?1,1,?2)"
            " ON CONFLICT(ip) DO UPDATE SET offenses=offenses+1, last_kill=?2",
            -1, &st, NULL) != SQLITE_OK) { saverr(g_db, "verdict"); return; }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)ip);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)t);
    if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "verdict step");
    sqlite3_finalize(st);
}

static void ban_upsert(uint32_t ip, uint8_t kind, uint32_t score,
                       const char *reason, time_t t, uint32_t secs)
{
    ban_t *b = ban_find(ip);
    if (!b) {
        if (g_ban_n >= MAX_BAN_ENTRIES) {
            /* Buang ban yang paling cepat berakhir. Pencarian dimulai
             * dari "yang berakhir paling awal", bukan dari nol, sebab
             * until selalu bernilai positif dan perbandingan dengan nol
             * tidak akan pernah cocok. */
            int victim = -1;
            time_t earliest = 0;
            for (int i = 0; i < g_ban_n; i++) {
                if (victim < 0 || g_ban[i].until < earliest) {
                    earliest = g_ban[i].until;
                    victim = i;
                }
            }
            if (victim >= 0) {
                g_ban[victim] = g_ban[g_ban_n - 1];
                g_ban_n--;
            }
        }
        /* Sisakan satu entri di ujung larik. */
        if (g_ban_n >= MAX_BAN_ENTRIES) return;
        b = &g_ban[g_ban_n];
        memset(b, 0, sizeof(*b));
        b->ip = ip;
        b->start = t;
        b->offenses = 1;
        g_ban_n++;
    }
    if (b->start == 0) b->start = t;
    b->until = t + (time_t)secs;
    b->score = score;
    b->kind = kind;
    b->active = 1;
    snprintf(b->reason, sizeof(b->reason), "%s", reason);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO bans(ip,kind,score,start,until,offenses,reason)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7)"
            " ON CONFLICT DO NOTHING", -1, &st, NULL) == SQLITE_OK) {
        char ips[32]; u2ip(ip, ips, sizeof(ips));
        sqlite3_bind_int64(st, 1, (sqlite3_int64)ip);
        sqlite3_bind_text(st, 2, KIND_NAME[kind], -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)score);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)b->start);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)b->until);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)b->offenses);
        sqlite3_bind_text(st, 7, reason, -1, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "ban insert");
        sqlite3_finalize(st);
    } else saverr(g_db, "ban prepare");
}

/* ------------------------------------------------------------------ *
 * JEJAK AUDIT
 * ------------------------------------------------------------------ *
 * Setiap tindakan terhadap sebuah IP dicatat di sini: kapan, oleh
 * sistem atau siapa, dan dengan alasan apa. Tanpa ini, rekonsiliasi
 * tidak mungkin: yang terlihat hanya kondisi sekarang, bukan
 * urutan keputusan yang diambil.
 *
 * Sumber yang dicatat:
 *   auto    - guardd, dari ambang skor (ban atau throttle)
 *   panel   - operator, lewat tombol di dasbor
 *
 * Penulisan gagal tidak boleh menghentikan daemon.
 * jejak audit yang gagal berarti catatan hilang, jadi bukan kegagalan server.
 */
static void aksi_catat(uint32_t ip, const char *aksi, const char *sumber,
                       const char *alasan, uint32_t detik)
{
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO aksi(ts,ip,aksi,sumber,alasan,detik)"
            " VALUES(?1,?2,?3,?4,?5,?6)", -1, &st, NULL) != SQLITE_OK) {
        saverr(g_db, "aksi prepare");
        return;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now_t());
    sqlite3_bind_int64(st, 2, (sqlite3_int64)ip);
    sqlite3_bind_text(st, 3, aksi && *aksi ? aksi : "-", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, sumber && *sumber ? sumber : "-", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, alasan && *alasan ? alasan : "-", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)detik);
    if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "aksi insert");
    sqlite3_finalize(st);
}

static void ban_remove_src(uint32_t ip, int permanent,
                           const char *sumber, const char *alasan);

static void ban_remove(uint32_t ip, int permanent)
{
    ban_remove_src(ip, permanent, "panel", "dicabut manual dari panel");
}

/* Bentuk umum: sumber dan alasan bisa berbeda sesuai pemanggilnya.
   Pemanggil lama memakai ban_remove() yang berarti "panel", supaya
   tidak perlu diubah satu per satu. */
static void ban_remove_src(uint32_t ip, int permanent, const char *sumber,
                           const char *alasan)
{
    ban_t *b = ban_find(ip);
    if (b) { b->active = 0; b->until = now_t(); }
    ipset_del("sentinel_ban", ip);
    ipset_del("sentinel_throttle", ip);
    aksi_catat(ip, "unban", sumber, alasan, 0);
    sqlite3_stmt *st = NULL;
    if (permanent) {
        if (sqlite3_prepare_v2(g_db, "DELETE FROM bans WHERE ip=?1", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)ip);
            if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "ban del");
            sqlite3_finalize(st);
        }
    }
}

/* ------------------------------------------------------------------ *
 * ipset
 * ------------------------------------------------------------------ */
/* Menjalankan perintah dan menangkap keluarannya.
 * Mengembalikan kode keluar, atau -1 bila gagal menjalankan. */
static int run_ps_capture(const char *const argv[], char *keluar,
                          size_t kluar)
{
    if (keluar && kluar) keluar[0] = '\0';
    int fds[2];
    if (pipe(fds) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    size_t ket = 0;
    ssize_t n;
    while ((n = read(fds[0], keluar + ket, kluar - 1 - ket)) > 0) {
        ket += (size_t)n;
        if (ket >= kluar - 1) break;
    }
    keluar[ket] = '\0';
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Apakah IP sedang jadi anggota set? Dipakai untuk membalas jujur ke
 * panel, bukan menebak. */
static int ipset_has(const char *set, uint32_t ip)
{
    char b[32];
    u2ip(ip, b, sizeof(b));
    char out[128];
    /* WAJIB pakai "test", bukan "list SET ENTRI". Pada ipset 7.19
     * bentuk kedua ditolak dengan "Unknown argument" dan keluarannya
     * selalu 2, sehingga pemeriksaan selalu gagal. */
    int n = run_ps_capture(
        (const char *const[]){ "/usr/sbin/ipset", "test", set, b, NULL },
        out, sizeof(out));
    return n == 0;
}

static void run_ps(const char *const argv[], const char *stdin_data, size_t slen)
{
    int fds[2];
    pid_t pid;
    if (pipe(fds) != 0) return;
    pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return; }
    if (pid == 0) {
        close(fds[1]);
        if (slen) {
            dup2(fds[0], STDIN_FILENO);
        }
        close(fds[0]);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDOUT_FILENO); dup2(dn, STDERR_FILENO); close(dn); }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[0]);
    if (slen) {
        size_t off = 0;
        while (off < slen) {
            ssize_t w = write(fds[1], stdin_data + off, slen - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
    close(fds[1]);
    int status = 0;
    waitpid(pid, &status, 0);
}

/* Daftar set yang sudah dicek keberadaannya, supaya tidak memanggil
 * ipset berulang-ulang. */
static int ipset_exists(const char *set)
{
    FILE *f = popen("/usr/sbin/ipset list 2>/dev/null", "re");
    if (!f) return 0;
    char line[512];
    size_t n = strlen(set);
    int found = 0;
    /* PENTING: harus memeriksa SEMUA baris "Name:", bukan berhenti di
     * yang pertama. Output ipset list memuat seluruh set yang ada, jadi
     * berhenti di baris pertama akan selalu salah menjawab. */
    while (fgets(line, sizeof(line), f)) {
        const char *p = strstr(line, "Name:");
        if (!p) continue;
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, set, n) && (p[n] == '\n' || p[n] == '\r' || p[n] == '\0')) {
            found = 1;
            break;
        }
    }
    pclose(f);
    return found;
}

/* Pastikan set ada. Sengaja memakai ipset restore agar creationsama
 * bisa dikirim dalam satu operasi, dan tidak setengah jadi. */
static void ipset_ensure(const char *set, uint32_t def_timeout)
{
    if (ipset_exists(set)) return;
    char cmd[512];
    /* Catatan: opsi "counters" sengaja TIDAK dipakai. Pada ipset 7.19
     * nilai "none" ditolak ("Unknown argument"), sehingga create gagal
     * dengan diam-diam. Set default sudah tanpa counter. */
    snprintf(cmd, sizeof(cmd),
             "create %s hash:net family inet timeout %u hashsize 4096 "
             "maxelem 262144\n", set, def_timeout);
    run_ps((const char *const[]){ "/usr/sbin/ipset", "restore", NULL }, cmd, strlen(cmd));
    if (ipset_exists(set))
        logmsg("ipset %s dibuat (timeout bawaan %u detik)", set, def_timeout);
    else
        logmsg("PERINGATAN: gagal membuat ipset %s", set);
}

/* paksa = 1 dipakai untuk perintah eksplisit dari operator (ban manual
 * dari panel). enforce = 0 mestinya mematikan pemblokiran OTOMATIS
 * berdasarkan skor, bukan membatalkan perintah yang sengaja diketik
 * orang. Tanpa parameternya, tombol "blokir sekarang" di panel akan
 * membalas berhasil padahal ipset tetap kosong. */
static void ipset_add_ex(const char *set, uint32_t ip, uint32_t secs,
                         int paksa)
{
    if (!cfg.enforce && !paksa) return;
    char b[32], secsbuf[16];
    u2ip(ip, b, sizeof(b));
    snprintf(secsbuf, sizeof(secsbuf), "%u", secs);
    /* PENTING: kata "exist" hanya sah untuk ipset add/subtract, TIDAK
     * untuk mode restore. Pada ipset 7.19restore menolaknya dengan
     * "Unknown argument: `exist'", sehingga setiap penambahan ban
     * gagal dengan diam-diam dan tidak pernah masuk ke ipset.
     * Karena itu perintah dijalankan langsung dengan -exist. */
    run_ps((const char *const[]){
        "/usr/sbin/ipset", "add", "-exist", set, b, "timeout", secsbuf, NULL
    }, NULL, 0);
}

static void ipset_add(const char *set, uint32_t ip, uint32_t secs)
{
    ipset_add_ex(set, ip, secs, 0);
}

static void ipset_del(const char *set, uint32_t ip)
{
    char b[32], line[128];
    u2ip(ip, b, sizeof(b));
    snprintf(line, sizeof(line), "del %s %s\n", set, b);
    run_ps((const char *const[]){ "/usr/sbin/ipset", "restore", NULL }, line, strlen(line));
}

/* ------------------------------------------------------------------ *
 * Statistik
 * ------------------------------------------------------------------ */
static void min_roll(time_t t)
{
    uint32_t m = (uint32_t)(t / 60) * 60;
    if (g_cur_min == m) return;
    if (g_cur_min != 0) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(g_db,
            "INSERT INTO minute(ts,host,req,bytes,s2,s3,s4,s5,s429)"
            " VALUES(?1,'-',?2,?3,?4,?5,?6,?7,?8)"
            " ON CONFLICT(ts,host) DO UPDATE SET req=req+excluded.req,"
            " bytes=bytes+excluded.bytes,s2=s2+excluded.s2,s3=s3+excluded.s3,"
            " s4=s4+excluded.s4,s5=s5+excluded.s5,s429=s429+excluded.s429",
            -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)g_cur_min);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)g_cur.req);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)g_cur.bytes);
            sqlite3_bind_int64(st, 4, (sqlite3_int64)g_cur.s2);
            sqlite3_bind_int64(st, 5, (sqlite3_int64)g_cur.s3);
            sqlite3_bind_int64(st, 6, (sqlite3_int64)g_cur.s4);
            sqlite3_bind_int64(st, 7, (sqlite3_int64)g_cur.s5);
            sqlite3_bind_int64(st, 8, (sqlite3_int64)g_cur.s429);
            if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "minute");
            sqlite3_finalize(st);
        } else saverr(g_db, "minute prepare");
        for (int i = 0; i < g_nhost; i++) {
            agg_t *a = &g_host[i];
            if (!a->req) continue;
            if (sqlite3_prepare_v2(g_db,
                "INSERT INTO minute(ts,host,req,bytes,s2,s3,s4,s5,s429)"
                " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)"
                " ON CONFLICT(ts,host) DO UPDATE SET req=req+excluded.req,"
                " bytes=bytes+excluded.bytes,s2=s2+excluded.s2,s3=s3+excluded.s3,"
                " s4=s4+excluded.s4,s5=s5+excluded.s5,s429=s429+excluded.s429",
                -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st, 1, (sqlite3_int64)g_cur_min);
                sqlite3_bind_text(st, 2, g_hostname[i], -1, SQLITE_STATIC);
                sqlite3_bind_int64(st, 3, (sqlite3_int64)a->req);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)a->bytes);
                sqlite3_bind_int64(st, 5, (sqlite3_int64)a->s2);
                sqlite3_bind_int64(st, 6, (sqlite3_int64)a->s3);
                sqlite3_bind_int64(st, 7, (sqlite3_int64)a->s4);
                sqlite3_bind_int64(st, 8, (sqlite3_int64)a->s5);
                sqlite3_bind_int64(st, 9, (sqlite3_int64)a->s429);
                if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "minute host");
                sqlite3_finalize(st);
            } else saverr(g_db, "minute host prepare");
            memset(a, 0, sizeof(agg_t));
        }
    }
    memset(&g_cur, 0, sizeof(g_cur));
    g_cur_min = m;
    g_ipmin_n = 0;
}

static void db_flush(void)
{
    time_t t = now_t();

    /* ban yang sudah lewat dibersihkan dari memori + ipset */
    for (int i = 0; i < g_ban_n; i++) {
        if (g_ban[i].active && g_ban[i].until <= t) {
            ipset_del("sentinel_ban", g_ban[i].ip);
            ipset_del("sentinel_throttle", g_ban[i].ip);
            g_ban[i].active = 0;
        }
    }

    if (!g_db) return;
    sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, NULL);

    if (g_ev_n > 0) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(g_db,
            "INSERT INTO events(ts,ip,kind,score,level,host,path,ua)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", -1, &st, NULL) == SQLITE_OK) {
            for (int i = 0; i < g_ev_n; i++) {
                ev_t *e = &g_ev[i];
                sqlite3_reset(st);
                sqlite3_clear_bindings(st);
                sqlite3_bind_int64(st, 1, (sqlite3_int64)e->ts);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)e->ip);
                sqlite3_bind_text(st, 3, KIND_NAME[e->kind], -1, SQLITE_STATIC);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)e->score);
                sqlite3_bind_int64(st, 5, (sqlite3_int64)e->level);
                sqlite3_bind_text(st, 6, e->host, -1, SQLITE_STATIC);
                sqlite3_bind_text(st, 7, e->path, -1, SQLITE_STATIC);
                sqlite3_bind_text(st, 8, e->ua, -1, SQLITE_STATIC);
                if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "event");
            }
            sqlite3_finalize(st);
        } else saverr(g_db, "event prepare");
        g_ev_n = 0;
    }

    if (g_ipmin_n > 0) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(g_db,
            "INSERT INTO ip_minute(ts,ip,req,score) VALUES(?1,?2,?3,?4)"
            " ON CONFLICT(ts,ip) DO UPDATE SET req=req+excluded.req,"
            " score=max(score,excluded.score)", -1, &st, NULL) == SQLITE_OK) {
            for (int i = 0; i < g_ipmin_n; i++) {
                sqlite3_reset(st);
                sqlite3_clear_bindings(st);
                sqlite3_bind_int64(st, 1, (sqlite3_int64)g_ipmin[i].ts);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)g_ipmin[i].ip);
                sqlite3_bind_int64(st, 3, (sqlite3_int64)g_ipmin[i].req);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)g_ipmin[i].score);
                if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "ip_minute");
            }
            sqlite3_finalize(st);
        } else saverr(g_db, "ip_minute prepare");
        g_ipmin_n = 0;
    }

    sqlite3_exec(g_db, "COMMIT", NULL, NULL, NULL);
}

static void db_prune(void)
{
    time_t t = now_t();
    if (!g_db) return;
    sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    sqlite3_stmt *st = NULL;
    struct { const char *sql; time_t cut; } jobs[] = {
        { "DELETE FROM events WHERE ts < ?1", t - 7 * 86400 },
        { "DELETE FROM minute WHERE ts < ?1", t - 30 * 86400 },
        { "DELETE FROM ip_minute WHERE ts < ?1", t - 3 * 86400 },
        { "DELETE FROM bans WHERE until < ?1 AND until > 0", t - 30 * 86400 },
    };
    for (size_t i = 0; i < sizeof(jobs) / sizeof(jobs[0]); i++) {
        st = NULL;
        if (sqlite3_prepare_v2(g_db, jobs[i].sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)jobs[i].cut);
            if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "prune");
            sqlite3_finalize(st);
        }
    }
    sqlite3_exec(g_db, "COMMIT", NULL, NULL, NULL);
    logmsg("retensi data dijalankan");
}

/* ------------------------------------------------------------------ *
 * status.json untuk dasbor
 * ------------------------------------------------------------------ */
static time_t g_start = 0;
static char g_status[STATUS_JSON_MAX];

static int write_atomic(const char *path, const char *data, size_t len)
{
    char tmp[PATH_MAX + 32];
    /* Panjang nama berkas sering melewati batas PATH_MAX, jadi pakai
     * buffer yang lebih longgar lalu validasi hasilnya. */
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) >= sizeof(tmp))
        return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    fsync(fd);
    close(fd);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int json_escape(char *dst, size_t cap, const char *src, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 8 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
        case '"':  dst[o++] = '\\'; dst[o++] = '"';  break;
        case '\\': dst[o++] = '\\'; dst[o++] = '\\'; break;
        case '\n': dst[o++] = '\\'; dst[o++] = 'n';  break;
        case '\r': dst[o++] = '\\'; dst[o++] = 'r';  break;
        case '\t': dst[o++] = '\\'; dst[o++] = 't';  break;
        default:
            if (c < 0x20) { o += (size_t)snprintf(dst + o, cap - o, "\\u%04x", c); }
            else dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
    return (int)o;
}

/* collect top-N dengan partial selection sort (N kecil, sumber kecil) */
static void top_ips(char *out, size_t cap, int limit)
{
    struct { uint32_t ip; uint32_t req; uint32_t score; uint8_t lvl; } tmp[16];
    int n = 0;
    int limit_c = limit > 16 ? 16 : limit;

    for (int b = 0; b < IP_BUCKETS; b++) {
        ip_ent *e;
        for (e = g_buckets[b]; e; e = e->next) {
            if (e->req_window == 0 && e->score == 0) continue;
            /* sisipkan ke daftar teratas */
            int pos = n < limit_c ? n : -1;
            for (int i = 0; i < (n < limit_c ? n : limit_c); i++) {
                if (e->req_window > tmp[i].req ||
                    (e->req_window == tmp[i].req && e->score > tmp[i].score)) { pos = i; break; }
            }
            if (pos < 0) continue;
            if (n < limit_c) n++;
            for (int i = n - 1; i > pos; i--) tmp[i] = tmp[i - 1];
            tmp[pos].ip = e->ip;
            tmp[pos].req = e->req_window;
            tmp[pos].score = e->score;
            tmp[pos].lvl = e->level;
        }
    }
    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "[");
    for (int i = 0; i < n && o + 160 < cap; i++) {
        char b[32]; u2ip(tmp[i].ip, b, sizeof(b));
        o += (size_t)snprintf(out + o, cap - o,
            "%s{\"ip\":\"%s\",\"req\":%u,\"score\":%u,\"level\":%d}",
            i ? "," : "", b, tmp[i].req, tmp[i].score, tmp[i].lvl);
    }
    if (o < cap) snprintf(out + o, cap - o, "]");
}

static void write_status(time_t t)
{
    char hostbuf[8192];
    size_t o = 0;
    o += (size_t)snprintf(hostbuf + o, sizeof(hostbuf) - o, "[");
    int shown = 0;
    for (int i = 0; i < g_nhost && o + 400 < sizeof(hostbuf); i++) {
        agg_t *a = &g_host[i];
        if (!a->req && !a->bytes) continue;
        o += (size_t)snprintf(hostbuf + o, sizeof(hostbuf) - o,
            "%s{\"host\":\"%s\",\"req\":%llu,\"bytes\":%llu,\"s2\":%llu,\"s3\":%llu,"
            "\"s4\":%llu,\"s5\":%llu,\"s429\":%llu}",
            shown ? "," : "", g_hostname[i],
            (unsigned long long)a->req, (unsigned long long)a->bytes,
            (unsigned long long)a->s2, (unsigned long long)a->s3,
            (unsigned long long)a->s4, (unsigned long long)a->s5,
            (unsigned long long)a->s429);
        shown++;
    }
    snprintf(hostbuf + o, sizeof(hostbuf) - o, "]");

    char banbuf[4096];
    size_t bo = 0;
    int bn = 0;
    bo += (size_t)snprintf(banbuf + bo, sizeof(banbuf) - bo, "[");
    int n_aktif = 0;
    for (int i = 0; i < g_ban_n && bn < 60; i++) {
        if (!g_ban[i].active || g_ban[i].until <= t) continue;
        n_aktif++;
        char b[32]; u2ip(g_ban[i].ip, b, sizeof(b));
        char r[140]; json_escape(r, sizeof(r), g_ban[i].reason, strlen(g_ban[i].reason));
        bo += (size_t)snprintf(banbuf + bo, sizeof(banbuf) - bo,
            "%s{\"ip\":\"%s\",\"kind\":\"%s\",\"score\":%u,\"until\":%lld,"
            "\"offenses\":%u,\"reason\":\"%s\"}",
            bn ? "," : "", b, KIND_NAME[g_ban[i].kind], g_ban[i].score,
            (long long)g_ban[i].until, g_ban[i].offenses, r);
        bn++;
    }
    snprintf(banbuf + bo, sizeof(banbuf) - bo, "]");

    /* Hitung ulang untuk seluruh entri, bukan hanya 60 pertama yang
     * masuk daftar di atas. bans_active harusnya menyebut jumlah ban
     * yang benar-benar masih berlaku, bukan jumlah entri di larik.
     * Kalau tidak, setiap ban yang sudah kedaluwarsa tetap terhitung
     * sehingga angka di panel terus naik padahal ipset sudah kosong. */
    n_aktif = 0;
    for (int i = 0; i < g_ban_n; i++) {
        if (g_ban[i].active && g_ban[i].until > t) n_aktif++;
    }

    char top[4096];
    top_ips(top, sizeof(top), 20);

    char logs[4096];
    size_t lo = 0;
    int ln = 0;
    lo += (size_t)snprintf(logs + lo, sizeof(logs) - lo, "[");
    for (int i = 0; i < g_tail_n; i++) {
        if (!g_tail[i].in_use) continue;
        lo += (size_t)snprintf(logs + lo, sizeof(logs) - lo,
            "%s{\"path\":\"%s\",\"host\":\"%s\",\"lines\":%llu}",
            ln ? "," : "", g_tail[i].path, g_tail[i].host,
            (unsigned long long)g_tail[i].lines);
        ln++;
    }
    snprintf(logs + lo, sizeof(logs) - lo, "]");

    /* RSS dari /proc/self/statm (halaman 4KB) */
    long rss_pages = 0;
    {
        long dummy = 0;
        FILE *f = fopen("/proc/self/statm", "re");
        if (f) {
            if (fscanf(f, "%ld %ld", &dummy, &rss_pages) != 2) rss_pages = 0;
            fclose(f);
        }
    }

    int n = snprintf(g_status, sizeof(g_status),
        "{\"ts\":%lld,\"version\":\"%s\",\"uptime\":%lld,\"pid\":%d,"
        "\"enforce\":%d,\"rss_kb\":%ld,\"ips_tracked\":%d,\"hosts\":%d,"
        "\"total_req\":%llu,\"total_bytes\":%llu,\"window_req\":%llu,"
        "\"window_bytes\":%llu,\"s2\":%llu,\"s3\":%llu,\"s4\":%llu,\"s5\":%llu,"
        "\"s429\":%llu,\"lines\":%llu,\"parse_fail\":%llu,\"cap_dropped\":%llu,"
        "\"bans_total\":%llu,\"throttles_total\":%llu,\"bans_active\":%d,"
        "\"flood_ticks\":%llu,"
        "\"watch_score\":%d,\"throttle_score\":%d,\"ban_score\":%d,"
        "\"ban_seconds\":%d,\"ban_seconds_max\":%d,"
        "\"hosts_detail\":%s,\"top_ips\":%s,\"bans\":%s,\"logs\":%s,"
        "\"rescan_interval\":%d,\"startup_backfill\":%d}\n",
        (long long)t, VERSION, (long long)(t - g_start), (int)getpid(),
        cfg.enforce, rss_pages * 4, g_ip_used, g_nhost,
        (unsigned long long)g_stat_total, (unsigned long long)g_stat_bytes,
        (unsigned long long)g_cur.req, (unsigned long long)g_cur.bytes,
        (unsigned long long)g_cur.s2, (unsigned long long)g_cur.s3,
        (unsigned long long)g_cur.s4, (unsigned long long)g_cur.s5,
        (unsigned long long)g_cur.s429,
        (unsigned long long)g_stat_lines, (unsigned long long)g_stat_parse_fail,
        (unsigned long long)g_stat_dropped_cap,
        (unsigned long long)g_stat_bans_total, (unsigned long long)g_stat_throttles_total,
        n_aktif, (unsigned long long)g_stat_flood,
        cfg.watch_score, cfg.throttle_score, cfg.ban_score,
        cfg.win_ban, cfg.win_ban_max,
        hostbuf, top, banbuf, logs,
        cfg.rescan_interval, cfg.startup_backfill);

    if (n > 0) {
        char path[PATH_MAX + 32];
        snprintf(path, sizeof(path), "%s/status.json", cfg.run_dir);
        write_atomic(path, g_status, (size_t)n);
    }
}

/* ------------------------------------------------------------------ *
 * SOCKET KENDALI (dipakai guardctl & plugin panel)
 * ------------------------------------------------------------------ */
static int g_ctl_fd = -1;

static void ctl_reply(int fd, const char *msg)
{
    size_t l = strlen(msg);
    ssize_t w = write(fd, msg, l);
    (void)w;
}

static void handle_ctl(int cfd)
{
    char buf[512];
    ssize_t n = read(cfd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    char cmd[64] = "", arg[128] = "";
    char *sp = strchr(buf, ' ');
    if (sp) { *sp = '\0'; snprintf(arg, sizeof(arg), "%s", sp + 1); }
    snprintf(cmd, sizeof(cmd), "%.*s", 63, buf);

    /* Argumen kedua opsional untuk perintah ban: "IP" atau "IP detik".
     * Tanpa pemisahan ini, durasi yang diketik pengguna di panel diam-diam
     * dibuang dan ban selalu memakai durasi bawaan. */
    int secs = 0;
    char *sp2 = strchr(arg, ' ');
    if (sp2) {
        *sp2 = '\0';
        secs = atoi(sp2 + 1);
        if (secs <= 0) secs = 0;
    }

    time_t t = now_t();

    if (!strcmp(cmd, "ping")) { ctl_reply(cfd, "{\"ok\":true,\"pong\":true}"); return; }

    if (!strcmp(cmd, "ban")) {
        uint32_t ip = ip2u(arg);
        if (!ip) { ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip tidak valid\"}"); return; }
        if (is_allowed(ip)) {
            ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip ada di allowlist\"}");
            return;
        }
        uint32_t d = (secs > 0) ? (uint32_t)secs : (uint32_t)cfg.win_ban;
        if (secs > 0 && d > (uint32_t)cfg.win_ban_max) d = (uint32_t)cfg.win_ban_max;
        ban_upsert(ip, K_MIXED, cfg.ban_score, "manual-panel", t, d);
        verdict_bump(ip, t);
        /* paksa = 1: perintah operator berlaku juga saat enforce = 0 */
        ipset_add_ex("sentinel_ban", ip, d, 1);
        g_stat_bans_total++;
        aksi_catat(ip, "ban", "panel", "diblokir manual dari panel", d);
        char b[32]; u2ip(ip, b, sizeof(b));
        logmsg("ban manual: %s (%u detik)", b, d);
        /* Balas dengan status sebenarnya yang terjadi, supaya panel
         * tidak menampilkan "berhasil" padahal ipset tetap kosong. */
        int di_ipset = ipset_has("sentinel_ban", ip);
        char bbuf[160];
        snprintf(bbuf, sizeof(bbuf),
                 "{\"ok\":true,\"dalam_ipset\":%s,\"enforce\":%d,"
                 "\"detik\":%u}",
                 di_ipset ? "true" : "false", cfg.enforce, d);
        ctl_reply(cfd, bbuf);
        return;
    }

    if (!strcmp(cmd, "unban")) {
        uint32_t ip = ip2u(arg);
        if (!ip) { ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip tidak valid\"}"); return; }
        int had = ban_find(ip) != NULL;
        ban_remove(ip, 1);
        logmsg("unban manual: %s", arg);
        char r[64];
        snprintf(r, sizeof(r), "{\"ok\":true,\"had\":%s}", had ? "true" : "false");
        ctl_reply(cfd, r);
        return;
    }

    if (!strcmp(cmd, "unreview")) {
        /* Operator menolak IP dari antrian review: lepas dari ipset
           supaya tidak lagi dihitung, dan jangan pernah diblokir. */
        uint32_t ip = ip2u(arg);
        if (!ip) { ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip tidak valid\"}"); return; }
        ipset_del("sentinel_review", ip);
        ctl_reply(cfd, "{\"ok\":true}");
        return;
    }

    if (!strcmp(cmd, "allow")) {
        uint32_t ip = ip2u(arg);
        if (!ip) { ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip tidak valid\"}"); return; }
        allow_add_exact(ip);
        ban_remove_src(ip, 1, "panel",
                       "masuk daftar putih, blokir lama ikut dicabut");
        /* Simpan permanen supaya tetap berlaku setelah daemon restart. */
        FILE *wf = fopen(cfg.allow_file, "ae");
        if (wf) {
            fprintf(wf, "%s\n", arg);
            fclose(wf);
        }
        logmsg("whitelist permanen: %s", arg);
        ctl_reply(cfd, "{\"ok\":true}");
        return;
    }

    if (!strcmp(cmd, "rescan")) { g_rescan = 1; ctl_reply(cfd, "{\"ok\":true}"); return; }
    if (!strcmp(cmd, "flush"))   { db_flush(); min_roll(t); write_status(t); ctl_reply(cfd, "{\"ok\":true}"); return; }
    if (!strcmp(cmd, "stop"))    { g_stop = 1; ctl_reply(cfd, "{\"ok\":true}"); return; }

    ctl_reply(cfd, "{\"ok\":false,\"err\":\"perintah tidak dikenal\"}");
}

static void ctl_setup(void)
{
    char path[CFG_PATH + 32];
    snprintf(path, sizeof(path), "%s/guardd.sock", cfg.run_dir);
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        logmsg("socket kontrol: jalur terlalu panjang, dilewati (%s)", path);
        return;
    }
    unlink(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { logmsg("socket kontrol gagal: %s", strerror(errno)); return; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        logmsg("bind socket kontrol gagal: %s", strerror(errno));
        close(fd); return;
    }
    chmod(path, 0660);
    if (listen(fd, 16) != 0) { logmsg("listen socket kontrol gagal"); close(fd); return; }
    g_ctl_fd = fd;
    logmsg("socket kendali: %s", path);
}

/* ------------------------------------------------------------------ *
 * Sinyal
 * ------------------------------------------------------------------ */
static void on_term(int s) { (void)s; g_stop = 1; }
static void on_hup(int s)  { (void)s; g_rescan = 1; }

/* ------------------------------------------------------------------ *
 * LOOP UTAMA
 * ------------------------------------------------------------------ */
static char g_readbuf[SENT_READ_CHUNK];

static void process_line(tailer_t *t, const char *s, size_t len, time_t now);

static void process_line(tailer_t *t, const char *s, size_t len, time_t now)
{
    parsed_t r;
    if (!parse_line(s, len, &r)) { g_stat_parse_fail++; return; }

    if (r.ip == 0) return;

    ip_ent *e = ip_get(r.ip, now);
    if (!e) { g_stat_dropped_cap++; return; }

    /* --- agregat global & per situs --- */
    g_stat_total++;
    g_stat_bytes += r.bytes;
    g_cur.req++;
    g_cur.bytes += r.bytes;
    g_stat_lines++;

    int hi = host_index(t->host);
    if (hi >= 0) {
        g_host[hi].req++;
        g_host[hi].bytes += r.bytes;
    }

    /* --- konteks terakhir untuk IP ini ---
       Event serangan dibuat dari agregat per-IP di sweep(), bukan dari
       baris log tertentu. Tanpa konteks di sini, event itu tidak punya
       informasi soal vhost, path, dan user-agent, sehingga kolom host
       dan path di tabel events selalu kosong dan mustahil dilakukan
       analisis per-vhost.

       Path dan UA memakai r.path/r.ua yang menunjuk langsung ke dalam
       buffer baca (const char *, bukan char[]), jadi wajib disalin.
       Host juga disalin karena t->host adalah milik tailer dan akan
       berubah ketika log berikutnya diproses. */
    snprintf(e->last_host, sizeof(e->last_host), "%s", t->host);
    snprintf(e->last_path, sizeof(e->last_path), "%.*s",
             (int)(r.path_len > (sizeof(e->last_path) - 1)
                   ? (sizeof(e->last_path) - 1) : r.path_len), r.path);
    snprintf(e->last_ua, sizeof(e->last_ua), "%.*s",
             (int)(r.ua_len > (sizeof(e->last_ua) - 1)
                   ? (sizeof(e->last_ua) - 1) : r.ua_len), r.ua);
    e->last_ctx = (uint32_t)now;

    /* --- jendela laju (16 slot x 4 detik) --- */
    uint32_t slot_epoch = (uint32_t)(now / RATE_SLOT_SEC);
    uint32_t slot = slot_epoch % RATE_SLOTS;
    if (e->slot_ts[slot] != slot_epoch) {
        e->slot_ts[slot] = slot_epoch;
        e->slot_cnt[slot] = 0;
    }
    if (e->slot_cnt[slot] < 65535) e->slot_cnt[slot]++;
    uint32_t req_win = 0;
    for (int i = 0; i < RATE_SLOTS; i++)
        if ((uint32_t)(now / RATE_SLOT_SEC) - e->slot_ts[i] < RATE_SLOTS) req_win += e->slot_cnt[i];
    e->req_window = req_win > 65535 ? 65535 : (uint16_t)req_win;

    /* --- kelas status --- */
    if (r.status >= 200 && r.status < 300)      { g_cur.s2++; if (hi>=0) g_host[hi].s2++; e->s2++; }
    else if (r.status < 400)                     { g_cur.s3++; if (hi>=0) g_host[hi].s3++; e->s3++; }
    else if (r.status < 500)                     { g_cur.s4++; if (hi>=0) g_host[hi].s4++; e->s4++; }
    else                                         { g_cur.s5++; if (hi>=0) g_host[hi].s5++; e->s5++; }
    if (r.status == 429) { g_cur.s429++; if (hi>=0) g_host[hi].s429++; e->s429++; }

    /* --- klasifikasi --- */
    if (r.status == 404 || r.status == 400 || r.status == 401 ||
        r.status == 403 || r.status == 429 || r.status == 499) {
        if (e->e404 < 65535) e->e404++;
        if (path_unlisted(r.path, r.path_len)) {
            /* path berbeda dari yang sudah tercatat -> indikasi enumerasi */
            uint8_t h = (uint8_t)(fnv1a(r.path, r.path_len) & 0xff);
            int seen = 0;
            for (int i = 0; i < e->npath; i++) if (e->path_hash[i] == h) { seen = 1; break; }
            if (!seen) {
                if (e->npath < MAX_DISTINCT_PATHS) e->path_hash[e->npath++] = h;
                if (e->distinct < 65535) e->distinct++;
            }
        }
    }

    if (path_is_scanner(r.path, r.path_len)) {
        if (e->scan < 65535) e->scan++;
    }
    if (path_is_brute(r.path, r.path_len) &&
        (r.status == 401 || r.status == 403 || r.status == 429 ||
         r.status == 400 || r.status == 404 || r.status == 499)) {
        if (e->brute < 65535) e->brute++;
    }
    if (ua_is_tool_copy(r.ua, r.ua_len)) {
        if (e->badua < 65535) e->badua++;
    }

    /* --- ip_minute --- */
    if (g_ipmin_n < MAX_IPMIN_BATCH) {
        ipmin_t *m = &g_ipmin[g_ipmin_n++];
        m->ip = r.ip; m->ts = (uint32_t)now; m->req = 1; m->score = e->score;
    }
}

/* ------------------------------------------------------------------ *
 * ANTREAN REVIEW
 * ------------------------------------------------------------------ *
 * Mode review menjawab masalah yang tidak punya jalan tengah antara
 * "tidak memblokir sama sekali" dan "memblokir semua yang melewati
 * ambang".
 *
 * Saat enforce = 0, daemon tidak pernah memblokir. Operator tidak punya
 * cara melihat siapa yang AKAN diblokir kalau mode itu diaktifkan,
 * sehingga harus ubah-dan-lihat: nyalakan pemblokiran, harapan daftar
 * ban benar, lalu kfortunately ada yang salah. Kalau ternyata ada
 * crawler sah di daftar itu, seluruh mode dimatikan lagi.
 *
 * Antrian review menutup celah itu. IP yang mencapai review_score
 * dicatat di sini dan diberi tanda di ipset, TAPI paketnya tetap lewat.
 * Operator melihat antriannya, lalu memutuskan per IP.
 *
 * Bedanya dengan ban: antrian ini tidak pernah menyentuh kernel
 * selain menambah satu entri ipset. Tidak ada aturan DROP.
 */
/* ------------------------------------------------------------------ *
 * ANTREAN NOTIFIKASI
 * ------------------------------------------------------------------ *
 * Fungsi ini HANYA menulis ke database. Tidak ada jaringan di sini.
 *
 * Alasannya bukan sekadarardown: # Satu HTTP POST ke alamat yang tidak
 * menjawab akan menahan pemrosesan log selama beberapa detik, dan
 * daemon membaca log setiap dua detik. Satu endpoint yang nakal akan
 * membuat Sentinel kehilangan ability untuk melihat serangan sama
 * sekali. Itu tradeoff yang tidak layak.
 *
 * Pengiriman diserahkan ke skrip terpisah yang berjalan dari timer.
 * Dengan begitu ada dua keuntungan sekaligus: daemon tidak pernah
 * menunggu jaringan, dan notifikasi tetap tersimpan kalau jaringan
 * sedang mati sehingga dikirim ulang nanti.
 */
static void notif_tambah(uint32_t ip, const char *jenis, const char *isi)
{
    if (!cfg.notify_url[0]) return;       /* dimatikan di config */
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO notif(ts,ip,jenis,isi) VALUES(?1,?2,?3,?4)",
            -1, &st, NULL) != SQLITE_OK) {
        saverr(g_db, "notif prepare");
        return;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now_t());
    sqlite3_bind_int64(st, 2, (sqlite3_int64)ip);
    sqlite3_bind_text(st, 3, jenis && *jenis ? jenis : "-", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, isi && *isi ? isi : "-", -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "notif insert");
    sqlite3_finalize(st);
}

/* Nama host server diambil dari allowlist milik operator; kalau tidak
   ada, pakai "-". Tidak ada DNS di sini demi alasan yang sama. */
static void notif_ban(uint32_t ip, uint32_t detik, const char *alasan)
{
    char b[32], n[400];
    u2ip(ip, b, sizeof(b));
    snprintf(n, sizeof(n),
             "IP %s diblokir %u detik. Alasan: %s", b, detik, alasan);
    notif_tambah(ip, "ban", n);
}

static void notif_throttle(uint32_t ip, uint32_t detik, uint32_t skor)
{
    char b[32], n[400];
    u2ip(ip, b, sizeof(b));
    snprintf(n, sizeof(n),
             "IP %s diberi batas laju %u detik (skor %u)", b, detik, skor);
    notif_tambah(ip, "throttle", n);
}

/* Panic dibunyikan lewat notifikasi karena dampaknya paling besar:
   seluruh akses web sedang ditutup. */
static void notif_panic(int aktif, const char *port)
{
    char n[300];
    if (aktif)
        snprintf(n, sizeof(n),
                 "PANIC AKTIF. Seluruh akses web diblokir pada port %s. "
                 "Situs tidak dapat diakses sampai panic dicabut.", port);
    else
        snprintf(n, sizeof(n),
                 "Panic dicabut. Akses web sudah normal kembali.");
    notif_tambah(0, aktif ? "panic" : "panic-selesai", n);
}

/* Pemantau panic.
 *
 * Panic dinyalakan/dimatikan oleh sentinel-fw.sh, bukan oleh daemon.
 * Karena itu daemon hanya bisa MENONTON berkas penanda yang ditulis
 * skrip itu, dan memberi tahu operator saat keadaannya berubah. Ditulis
 * di sini, bukan di skrip, karena pengirim notifikasi sudah bekerja
 * dari basis data -- skrip tidak punya cara menaruh baris ke antrean
 * tanpa membuka sqlite sendiri.
 *
 * Keadaan awal dianggap "tidak aktif" dan TIDAK memicu notifikasi,
 * supaya restart daemon tidak mengirim pesan "panic dicabut" palsu
 * setiap kali dijalankan ulang.
 */
static void pantau_panic(void)
{
    static int terakhir = -1;   /* -1 = belum pernah dibaca */
    int sekarang = 0;
    char port[64] = "";
    char path[PATH_MAX];
    /* Ikuti cfg.run_dir, bukan jalur tetap: sejalan dengan pidfile dan
       socket, dan membuat pengujian bisa memakai direktori terpisah
       tanpa menyentuh keadaan produksi. */
    snprintf(path, sizeof(path), "%s/panic.state", cfg.run_dir);
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        char baris[128];
        while (fgets(baris, sizeof(baris), f) != NULL) {
            if (strncmp(baris, "on", 2) == 0) sekarang = 1;
            else if (strncmp(baris, "ports=", 6) == 0) {
                size_t n = strlen(baris + 6);
                while (n > 0 && (baris[6 + n - 1] == '\n' ||
                                 baris[6 + n - 1] == '\r' ||
                                 baris[6 + n - 1] == ' ')) n--;
                if (n >= sizeof(port)) n = sizeof(port) - 1;
                memcpy(port, baris + 6, n);
                port[n] = '\0';
            }
        }
        fclose(f);
    }
    /* Pertama kali dibaca: catat saja sebagai keadaan awal. */
    if (terakhir < 0) { terakhir = sekarang; return; }
    if (sekarang != terakhir) {
        notif_panic(sekarang, port[0] ? port : "80,443");
        terakhir = sekarang;
    }
}

static int review_punya(uint32_t ip)
{
    sqlite3_stmt *st = NULL;
    int ada = 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT 1 FROM review WHERE ip=?1 AND status='tunggu'", -1,
            &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)ip);
        ada = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);
    }
    return ada;
}

static void review_tambah(uint32_t ip, uint32_t skor, const char *alasan)
{
    if (review_punya(ip)) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO review(ts,ip,skor,alasan,status)"
            " VALUES(?1,?2,?3,?4,'tunggu')", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)now_t());
        sqlite3_bind_int64(st, 2, (sqlite3_int64)ip);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)skor);
        sqlite3_bind_text(st, 4, alasan && *alasan ? alasan : "-", -1, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) saverr(g_db, "review insert");
        sqlite3_finalize(st);
    }
    ipset_add_ex("sentinel_review", ip, 43200, 1);
    aksi_catat(ip, "review", "auto", "masuk antrian review", 43200);
    char b[32]; u2ip(ip, b, sizeof(b));
    logmsg("REVIEW %s masuk antrian (skor=%u, belum diblokir) | %s",
           b, skor, alasan ? alasan : "-");
}

static void sweep(time_t now)
{
    /* redam penghitung berkala: setengah setiap 15 detik supaya IP yang
     * sudah berhenti langsung kehilangan skor tanpa perlu dihapus dari tabel */
    static time_t last_decay = 0;
    if (now - last_decay >= 15) {
        int steps = (int)((now - last_decay) / 15);
        if (steps < 1) steps = 1;
        if (steps > 10) steps = 10;
        for (int b = 0; b < IP_BUCKETS; b++) {
            ip_ent *e;
            for (e = g_buckets[b]; e; e = e->next) {
                for (int k = 0; k < steps && k < 8; k++) {
                    e->scan >>= 1; e->brute >>= 1; e->badua >>= 1;
                    e->distinct >>= 1; e->e404 >>= 1;
                }
                e->score = 0;
            }
        }
        last_decay = now;
    }

    uint32_t slot_now = (uint32_t)(now / RATE_SLOT_SEC);
    uint32_t cur_slot = slot_now % RATE_SLOTS;

    for (int b = 0; b < IP_BUCKETS; b++) {
        ip_ent *e = g_buckets[b];
        while (e) {
            ip_ent *next = e->next;
            e->req_window = 0;
            for (int i = 0; i < RATE_SLOTS; i++)
                if (slot_now - e->slot_ts[i] < RATE_SLOTS) e->req_window += e->slot_cnt[i];

            e->score = (uint16_t)score_of(e);
            if (e->score > e->peak) e->peak = e->score;
            uint8_t kind = kind_of(e);

            /* rps Detik */
            uint32_t rps = e->slot_cnt[cur_slot] / RATE_SLOT_SEC;

            /* IP yang ada di allowlist tidak pernah menghasilkan event
             * serangan. Allowlist berarti "dipercaya", jadi mencatatnya
             * sebagai penyerang hanya menghasilkan noise: daemon sendiri
             * dan alamat internal akan muncul sebagai scanner di dasbor.
             * Pemeriksaan dilakukan di sini, sebelum event dibuat,
             * bukan sesudahnya seperti pada blok ban di bawah. */
            int diaperlukannya = is_allowed(e->ip) || e->ip == g_self_ip;

            /* Event dicatat hanya saat level naik, dan dibatasi satu
             * kali per 30 detik per IP supaya flood 100k rps tidak
             * membanjiri tabel events. */
            if (!diaperlukannya
                && e->score >= (uint32_t)cfg.watch_score
                && e->level < LVL_WATCH) {
                e->level = LVL_WATCH;
                e->last_ev = (uint32_t)now;
                ev_push((uint32_t)now, e->ip, e->score, LVL_WATCH, kind,
                        e->last_host, e->last_path, strlen(e->last_path),
                        e->last_ua, strlen(e->last_ua));
            } else if (!diaperlukannya && rps > 40
                       && e->last_ev + 30 <= (uint32_t)now) {
                g_stat_flood++;
                e->last_ev = (uint32_t)now;
                ev_push((uint32_t)now, e->ip, (uint16_t)(e->score + 40), LVL_WATCH,
                        K_FLOOD, e->last_host, e->last_path, strlen(e->last_path),
                        e->last_ua, strlen(e->last_ua));
            }

            int blocked = diaperlukannya;
            if (blocked) {
                e->level = LVL_NORMAL;
            } else if (cfg.review_score > 0
                       && e->score >= (uint32_t)cfg.review_score
                       && !cfg.enforce) {
                /* Hanya saat pemblokiran otomatis dimatikan. Kalau
                   enforce = 1, ambang ban sudah lebih tinggi dan
                   antrian hanya menambah langkah yang tidak perlu. */
                char alasan[140];
                snprintf(alasan, sizeof(alasan),
                         "skor=%u kategori=%s rps=%u request=%u 4xx=%u",
                         e->score, KIND_NAME[kind], rps, e->req_window, e->s4);
                review_tambah(e->ip, e->score, alasan);
                e->level = LVL_WATCH;
            } else if (cfg.enforce && e->score >= (uint32_t)cfg.ban_score) {
                ban_t *ex = ban_find(e->ip);
                if (!ex || ex->until < now) {
                    uint32_t secs = ban_secs_for(e->ip, now);
                    char reason[140];
                    snprintf(reason, sizeof(reason),
                             "skor=%u kategori=%s rps=%u request=%u 4xx=%u",
                             e->score, KIND_NAME[kind], rps, e->req_window, e->s4);
                    ban_upsert(e->ip, kind, e->score, reason, now, secs);
                    verdict_bump(e->ip, now);
                    ipset_add("sentinel_ban", e->ip, secs);
                    g_stat_bans_total++;
                    aksi_catat(e->ip, "ban", "auto", reason, secs);
                    notif_ban(e->ip, secs, reason);
                    char b[32]; u2ip(e->ip, b, sizeof(b));
                    logmsg("BAN %s -> %u detik | %s", b, secs, reason);
                }
                e->level = LVL_BAN;
                e->score = 0;
                e->scan = e->brute = e->badua = e->distinct = e->e404 = 0;
            } else if (cfg.enforce && e->score >= (uint32_t)cfg.throttle_score) {
                ban_t *bb = ban_find(e->ip);
                if (e->level < LVL_THROTTLE && (!bb || bb->until < now)) {
                    uint32_t secs = (uint32_t)(cfg.win_ban / 2);
                    if (secs < 300) secs = 300;
                    e->level = LVL_THROTTLE;
                    ban_upsert(e->ip, kind, e->score, "batas-laju-5rps", now,
                               secs);
                    ipset_add("sentinel_throttle", e->ip, secs);
                    g_stat_throttles_total++;
                    aksi_catat(e->ip, "throttle", "auto",
                               "batas laju terlampaui", secs);
                    notif_throttle(e->ip, secs, e->score);
                    char b[32]; u2ip(e->ip, b, sizeof(b));
                    logmsg("THROTTLE %s -> %u detik (skor=%u)", b, secs, e->score);
                }
            }

            /* Mengosongkan tabel dilakukan lewat ip_evict_one (daftar
             * umur) ketika tabel penuh, bukan di sini. Loop ini cukup
             * untuk menghitung ulang skor dan lvl. */
            e = next;
        }
    }
}

static long rss_kb(void)
{
    long total = 0, p = 0;
    FILE *f = fopen("/proc/self/statm", "re");
    if (f) { if (fscanf(f, "%ld %ld", &total, &p) != 2) p = 0; fclose(f); }
    return p * 4;
}

int main(int argc, char **argv)
{
    int foreground = 1;
    const char *conf = "/www/server/sentinel/etc/guardd.conf";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) conf = argv[++i];
        else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--foreground")) foreground = 1;
        else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemon")) foreground = 0;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("pakai: guardd [-c <berkas>] [-f|-d] [-V]\n"
                   "\n"
                   "  -c <berkas>  berkas konfigurasi\n"
                   "               bawaan: /www/server/sentinel/etc/guardd.conf\n"
                   "  -f           tetap di depan (dipakai systemd)\n"
                   "  -d           Daemon di belakang layar\n"
                   "  -V            tampilkan versi lalu keluar\n"
                   "\n"
                   "Semua nilai konfigurasi hanya dibaca sekali saat proses\n"
                   "mulai, jadi setiap perubahan harus disertai restart daemon.\n");
            return 0;
        }
        else if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) {
            printf("guardd %s\n", VERSION); return 0;
        }
    }

    if (!foreground) {
        pid_t p = fork();
        if (p < 0) die("fork gagal: %s", strerror(errno));
        if (p > 0) _exit(0);
        setsid();
    }

    umask(027);
    cfg_load(conf);

    /* pidfile & kunci_instans Tunggal.
     *
     * Berkas kunci WAJIB mengikuti cfg.run_dir. Kalau jalurnya
     * dikunci langsung, dua konfigurasi berbeda tidak akan pernah bisa
     * berjalan bersamaan di satu server: instans uji terisolasi akan
     * ditolak hanya karena daemon produksi sedang memegang kunci yang
     * sama, padahal keduanya tidak boleh saling mengganggu. */
    char pidpath[PATH_MAX];
    char lockpath[PATH_MAX];
    snprintf(pidpath, PATH_MAX, "%s/guardd.pid", cfg.run_dir);
    snprintf(lockpath, PATH_MAX, "%s/.guardd.lock", cfg.run_dir);
    int lockfd = open(lockpath, O_RDWR | O_CREAT, 0640);
    if (lockfd >= 0 && flock(lockfd, LOCK_EX | LOCK_NB) != 0)
        die("guardd sudah berjalan (kunci_instans dipegang: %s)", lockpath);

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGHUP, on_hup);
    signal(SIGPIPE, SIG_IGN);

    g_buckets = xcalloc(IP_BUCKETS, sizeof(ip_ent *));
    allow_init();
    allow_load_file(cfg.allow_file);

    /* alamat publik utama dipakai untuk menandai request dari diri sendiri */
    g_self_ip = 0;
    {
        FILE *f = fopen("/proc/net/route", "re");
        if (f) {
            char line[512];
            if (fgets(line, sizeof(line), f))
                while (fgets(line, sizeof(line), f)) {
                    char ifn[64]; unsigned long dest, gw;
                    if (sscanf(line, "%63s %lx %lx", ifn, &dest, &gw) == 3 && dest == 0) {
                        int fd = socket(AF_INET, SOCK_DGRAM, 0);
                        if (fd >= 0) {
                            struct sockaddr_in sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sin_family = AF_INET;
                            sa.sin_port = htons(53);
                            sa.sin_addr.s_addr = htonl(gw);
                            if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
                                struct sockaddr_in la;
                                socklen_t sl = sizeof(la);
                                if (getsockname(fd, (struct sockaddr *)&la, &sl) == 0) {
                                    g_self_ip = ntohl(la.sin_addr.s_addr);
                                    allow_add_exact(g_self_ip);
                                }
                            }
                            close(fd);
                            break;
                        }
                    }
                }
            fclose(f);
        }
        char b[32]; u2ip(g_self_ip, b, sizeof(b));
        logmsg("alamat utama server: %s (dialihkan dari allowlist)", b);
    }

    db_open();
    g_start = now_t();
    min_roll(g_start);

    ctl_setup();

    /* Pastikan set ipset siap sebelumapa pun dipakai. */
    ipset_ensure("sentinel_ban", (uint32_t)cfg.win_ban);
    ipset_ensure("sentinel_throttle", (uint32_t)(cfg.win_ban / 2));

    rediscover();

    /* Titik mulai baca tiap log:
     *   startup_backfill > 0  -> lewati N detik terakhir (produksi)
     *   startup_backfill == 0 -> mulai dari ujung berkas, abaikan
     *                           seluruh riwayat (bawaan produksi)
     *   startup_backfill < 0  -> proses dari awal berkas, dipakai
     *                           untuk menganalisis ulang log lama
     */
    if (cfg.startup_backfill > 0)
        logmsg("backfill: lewati %d detik terakhir tiap log", cfg.startup_backfill);
    else if (cfg.startup_backfill < 0)
        logmsg("backfill: proses ulang dari awal berkas");
    for (int i = 0; i < g_tail_n; i++) {
        if (!g_tail[i].in_use) continue;
        if (g_tail[i].fd < 0) continue;
        struct stat st;
        if (fstat(g_tail[i].fd, &st) != 0) continue;
        g_tail[i].ino = st.st_ino;
        off_t off;
        if (cfg.startup_backfill < 0) {
            off = 0;
        } else {
            off = st.st_size;
            if (cfg.startup_backfill > 0) {
                off_t skip = (off_t)cfg.startup_backfill;
                if (off > skip) off -= skip;
            }
        }
        g_tail[i].off = off;
        lseek(g_tail[i].fd, off, SEEK_SET);
        logmsg("mulai dari offset %lld / %lld pada %s",
               (long long)off, (long long)st.st_size, g_tail[i].path);
    }

    {
        FILE *pf = fopen(pidpath, "we");
        if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }
    }

    logmsg("=== guardd %s aktif === enforce=%d watch=%d throttle=%d ban=%d",
           VERSION, cfg.enforce, cfg.watch_score, cfg.throttle_score, cfg.ban_score);
    logmsg("memori awal %ld KB, maks IP %d, pagu tick %d baris",
           rss_kb(), cfg.max_ips, cfg.max_lines_per_tick);

    time_t last_rescan = 0, last_flush = 0, last_prune = 0, last_status = 0;
    int ticks_since_work = 0;

    while (!g_stop) {
        time_t now = now_t();

        if (g_rescan || (now - last_rescan >= cfg.rescan_interval)) {
            rediscover();
            /* Muat ulang allowlist setiap siklus penemuan, supaya IP
             * yang ditambahkan lewat panel langsung berlaku tanpa
             * perlu me-restart daemon. */
            allow_load_file(cfg.allow_file);
            /* Cabut juga dari ipset. Aturan iptables whitelist baru
             * dipasang ulang oleh sentinel-fw.timer (tiap 5 menit),
             * jadi tanpa langkah ini IP yang baru di-whitelist tetap
             * kena ban atau throttle di kernel sampai timer berjalan. */
            allow_release_ipsets();
            last_rescan = now;
            g_rescan = 0;
        }

        /* ---------- baca log ---------- */
        long lines = 0;
        long bytes = 0;
        int capped = 0;
        tailer_retry();
        for (int i = 0; i < g_tail_n && !g_stop; i++) {
            tailer_t *t = &g_tail[i];
            if (!t->in_use || t->fd < 0) continue;

            /* Rotasi harus dideteksi dengan stat() atas NAMA PATH,
             * bukan fstat() atas descriptor yang sedang dipegang.
             *
             * Alasannya: begitu berkas dirotasi lewat rename, daemon
             * masih memegang descriptor ke berkas lama. Berkas lama
             * tidak langsung hilang, jadi fstat(descriptor itu) selalu
             * mengembalikan inode LAMA yang persis sama dengan t->ino.
             * Dengan cara itu rotasi tidak akan pernah terlihat dan
             * daemon membaca berkas lama sampai penuh, lalu berhenti
             * membaca log yang baru sama sekali.
             *
             * stat(path) melihat keadaan nama berkas saat ini, sehingga
             * inode baru langsung terbandingkan dengan t->ino. */
            struct stat pst;
            if (stat(t->path, &pst) != 0) { t->degraded = 1; continue; }
            if (pst.st_ino != t->ino || pst.st_dev != t->dev) {
                close(t->fd);
                int nfd = open(t->path, O_RDONLY);
                if (nfd < 0) { t->degraded = 1; continue; }
                struct stat nst;
                if (fstat(nfd, &nst) != 0) { close(nfd); t->degraded = 1; continue; }
                t->fd = nfd;
                t->ino = nst.st_ino;
                t->dev = nst.st_dev;
                t->off = 0;
                t->carry_len = 0;   /* sisa baris lama tidak berlaku lagi */
                logmsg("rotasi log terdeteksi: %s (offset -> 0)", t->path);
                pst = nst;
            }
            struct stat st = pst;
            if (st.st_size < t->off) {
                t->off = 0;
                t->carry_len = 0;
                lseek(t->fd, 0, SEEK_SET);
                logmsg("log terpotong: %s (offset -> 0)", t->path);
            }
            if (st.st_size == t->off) continue;

            if (lseek(t->fd, t->off, SEEK_SET) == (off_t)-1) continue;

            long lines_file = 0;
            /* Pagu di sini HANYA membatasi kerja per siklus. Jangan
             * pernah menambahkan syarat "idle" ke kondisi ini: begitu
             * syarat itu masuk, daemon berhenti membaca log begitu saja
             * setelah idle dan tidak pernah pulih. */
            while (lines < cfg.max_lines_per_tick &&
                   bytes < cfg.max_bytes_per_tick) {
                /* Baca satu blok byte lalu proses baris-baris lengkapnya.
                 *
                 * read() mengembalikan potongan byte, bukan baris, dan
                 * potongan terakhir bisa terpotong di tengah baris.
                 * Sisa itu ditahan di t->carry lalu disambung pada
                 * bacaan berikutnya. Tanpa mekanisme ini baris
                 * terpotong akan terhitung sebagai baris utuh dan
                 * bagian sisanya terhitung lagi sebagai baris baru,
                 * sehingga jumlah baris terproses melebihi jumlah
                 * baris sebenarnya.
                 *
                 * Panjang blok baca (SENT_READ_CHUNK) harus lebih kecil
                 * dari SENT_LINE_MAX. Kalau sama besar, carry_len + n
                 * bisa melampaui ukuran carry setiap kali ada sisa baris,
                 * dan cabang "baris kepanjangan" ikut menghitung baris
                 * terpotong sebagai baris utuh -- persis sumber selisih
                 * 4 persen pada pengujian ulang log produksi. */
                ssize_t n = read(t->fd, g_readbuf, sizeof(g_readbuf));
                if (n <= 0) break;
                t->off += n;
                bytes += n;

                /* Sisa baris sebelumnya sudah tidak mungkin dilengkapi
                 * dalam satu baris log yang wajar: buang, hitung sekali
                 * sebagai baris rusak, lalu mulai baris baru. */
                if (t->carry_len + (size_t)n > SENT_LINE_MAX) {
                    g_stat_parse_fail++;
                    t->carry_len = 0;
                }
                memcpy(t->carry + t->carry_len, g_readbuf, (size_t)n);
                size_t len = t->carry_len + (size_t)n;

                /* Pisahkan baris lengkap; sisanya ditahan. */
                size_t cur = 0;
                for (;;) {
                    char *nl = memchr(t->carry + cur, '\n', len - cur);
                    if (!nl) break;
                    size_t llen = (size_t)(nl - (t->carry + cur));
                    if (llen > 0) process_line(t, t->carry + cur, llen, now);
                    lines++; lines_file++;
                    cur += llen + 1;
                }
                t->carry_len = len - cur;
                if (t->carry_len)
                    memmove(t->carry, t->carry + cur, t->carry_len);
                if (lines >= cfg.max_lines_per_tick || bytes >= cfg.max_bytes_per_tick) {
                    capped = 1;
                    break;
                }
            }
            t->lines += (uint64_t)lines_file;
        }
        if (capped) {
            g_stat_dropped_cap++;
        }

        /* ---------- siklus ---------- */
        min_roll(now);
        sweep(now);
        pantau_panic();

        if (now - last_flush >= cfg.flush_interval) { db_flush(); last_flush = now; }
        if (now - last_status >= 2) { write_status(now); last_status = now; }
        if (now - last_prune >= cfg.prune_interval) { db_flush(); db_prune(); last_prune = now; }

        /* ---------- kontrol ---------- */
        if (g_ctl_fd >= 0) {
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(g_ctl_fd, &rf);
            struct timeval tv = { 0, 200000 };
            int r = select(g_ctl_fd + 1, &rf, NULL, NULL, &tv);
            if (r > 0 && FD_ISSET(g_ctl_fd, &rf)) {
                int c = accept(g_ctl_fd, NULL, NULL);
                if (c >= 0) { handle_ctl(c); close(c); }
            }
        } else {
            struct timespec ts = { 0, 200000000L };
            nanosleep(&ts, NULL);
        }

        /* Jeda adaptif. Idle 200 ms supaya daemon tidak membakar CPU
         * pada server sepi, dan langsung kontinu saat ada traffic atau
         * saat pagu per siklus tercapai (log harus tertinggal sesedikit
         * mungkin). */
        if (lines > 0 || capped) {
            ticks_since_work = 0;
        } else if (ticks_since_work < 4) {
            ticks_since_work++;
        }

        if (!capped && lines == 0) {
            struct timespec ts = { 0, 200000000L };
            nanosleep(&ts, NULL);
        }
    }

    logmsg("mematikan daemon, menyimpan statistik terakhir");
    min_roll(now_t());
    db_flush();
    write_status(now_t());
    if (g_ctl_fd >= 0) close(g_ctl_fd);
    if (g_db) sqlite3_close(g_db);
    unlink(pidpath);
    logmsg("selesai, memori akhir %ld KB", rss_kb());
    return 0;
}
