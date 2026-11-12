/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens). */
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
#include <utmpx.h>

#include <sqlite3.h>


#define VERSION "v2.0.1"

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
    char conf_dirs[16][CFG_PATH];
    int  n_conf_dirs;
    char log_dirs[16][CFG_PATH];
    int  n_log_dirs;
    char db_path[CFG_PATH];
    char run_dir[CFG_PATH];
    char log_file[CFG_PATH];
    char allow_file[CFG_PATH];
    char proxy_file[CFG_PATH];
    char learn_file[CFG_PATH];   /* pelajaran dari keputusan operator (learned.tsv) */

    /* Ambang kecocokan pelajaran blokir sebelum IP diblokir. Makin sempit
     * pola yang dipelajari (path + UA), makin sedikit kecocokan yang
     * dibutuhkan. */
    int  learn_hits_both;         /* path dan UA sama-sama dipelajari */
    int  learn_hits_path;         /* hanya path */
    int  learn_hits_ua;           /* hanya UA */

    /* Flood per IP, dalam permintaan per jendela 64 detik (0 = mati). */
    int  flood_throttle_req;
    int  flood_ban_req;
    /* Penghitung kategori dibagi dua setiap sekian detik. */
    int  decay_seconds;

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
    .proxy_file = "/www/server/sentinel/etc/proxy-ranges.txt",
    .learn_file = "/www/server/sentinel/etc/learned.tsv",
    .learn_hits_both = 1,
    .learn_hits_path = 2,
    .learn_hits_ua = 3,
    .flood_throttle_req = 3840,     /* rata-rata 60 permintaan/detik */
    .flood_ban_req = 12800,         /* rata-rata 200 permintaan/detik */
    .decay_seconds = 60,
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
    .cap_scan = 20,      /* 20 x 8 = 160: scanner murni kini mencapai ambang ban 150 */
    .cap_brute = 20,
    .cap_badua = 20,
    .cap_distinct = 20,
    .max_ips = MAX_IP,
    .max_lines_per_tick = 20000,
    .max_bytes_per_tick = 64 * 1024 * 1024,
    .flush_interval = 5,
    .prune_interval = 3600,
};

/* gerbang lisensi: lihat blok 'Gerbang lisensi' di bawah */
static unsigned g_lic_mask = 0;
static int      g_enforce_conf = 0;     /* nilai enforce di guardd.conf (sebelum gerbang) */
static time_t   g_lic_ts = 0;

/* Jumlah baris kunci=nilai di berkas konfigurasi (-1 bila tidak terbaca). */
static int cfg_jumlah_kunci(const char *path)
{
    FILE *f = fopen(path, "re");
    char line[1024];
    int n = 0;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *k = line;
        while (*k == ' ' || *k == '\t') k++;
        if (*k && *k != '#' && *k != ';' && *k != '\n' && strchr(k, '=')) n++;
    }
    fclose(f);
    return n;
}

/* guardd.conf yang ADA tetapi kosong/terpotong (disk penuh, tulis terputus) dulu dibaca sebagai "semua bawaan": enforce=0, ambang,
 * geo, dan notify kembali bawaan tanpa tanda. Bila tidak ada satu kunci pun, cadangan guardd.conf.bak (ditulis panel setiap
 * menyimpan) dipakai bila berisi. */
static const char *cfg_pilih(const char *path)
{
    static char bak[PATH_MAX];
    if (cfg_jumlah_kunci(path) != 0) return path;
    snprintf(bak, sizeof(bak), "%s.bak", path);
    if (cfg_jumlah_kunci(bak) > 0) {
        logmsg("config %s kosong/rusak: memakai cadangan %s", path, bak);
        return bak;
    }
    logmsg("PERINGATAN: config %s kosong/rusak dan tanpa cadangan; memakai bawaan", path);
    return path;
}

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
        /* Nilai berkutip ("..." atau '...') = isi tanpa kutip. Templat menulis notify_url = "" untuk "mati";
           tanpa ini dua karakter kutip terbaca sebagai URL sehingga setiap ban/throttle masuk antrean notif. */
        end = v + strlen(v);
        if (end - v >= 2 && (v[0] == '"' || v[0] == '\'') && end[-1] == v[0]) { end[-1] = '\0'; v++; }

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
        else if (!strcmp(k, "proxy_file"))          snprintf(cfg.proxy_file, CFG_PATH, "%s", v);
        else if (!strcmp(k, "learn_file"))          snprintf(cfg.learn_file, CFG_PATH, "%s", v);
        else if (!strcmp(k, "learn_hits_both"))     cfg.learn_hits_both = atoi(v);
        else if (!strcmp(k, "learn_hits_path"))     cfg.learn_hits_path = atoi(v);
        else if (!strcmp(k, "learn_hits_ua"))       cfg.learn_hits_ua = atoi(v);
        else if (!strcmp(k, "flood_throttle_req"))  cfg.flood_throttle_req = atoi(v);
        else if (!strcmp(k, "flood_ban_req"))       cfg.flood_ban_req = atoi(v);
        else if (!strcmp(k, "decay_seconds"))       cfg.decay_seconds = atoi(v);
        else if (!strcmp(k, "conf_dir")) {
            /* entri PERTAMA menggeser daftar bawaan, entri berikutnya
             * menambah. Kalau hanya menambah, mengubah conf_dir di
             * pengujian tidak akan benar-benar mengisolasi daemon dari
             * log produksi. */
            if (cfg.n_conf_dirs == 0) logmsg("conf_dir bawaan digantikan oleh config");
            if (cfg.n_conf_dirs < 16) snprintf(cfg.conf_dirs[cfg.n_conf_dirs++], CFG_PATH, "%s", v);
        } else if (!strcmp(k, "log_dir")) {
            if (cfg.n_log_dirs == 0) logmsg("log_dir bawaan digantikan oleh config");
            if (cfg.n_log_dirs < 16) snprintf(cfg.log_dirs[cfg.n_log_dirs++], CFG_PATH, "%s", v);
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

    if (cfg.learn_hits_both < 1) cfg.learn_hits_both = 1;
    if (cfg.learn_hits_path < 1) cfg.learn_hits_path = 1;
    if (cfg.learn_hits_ua < 1) cfg.learn_hits_ua = 1;
    if (cfg.learn_hits_both > 50) cfg.learn_hits_both = 50;
    if (cfg.learn_hits_path > 50) cfg.learn_hits_path = 50;
    if (cfg.learn_hits_ua > 50) cfg.learn_hits_ua = 50;

    if (cfg.decay_seconds < 15) cfg.decay_seconds = 15;
    if (cfg.decay_seconds > 600) cfg.decay_seconds = 600;
    if (cfg.flood_throttle_req < 0) cfg.flood_throttle_req = 0;
    if (cfg.flood_ban_req < 0) cfg.flood_ban_req = 0;
    if (cfg.flood_throttle_req > 65000) cfg.flood_throttle_req = 65000;
    if (cfg.flood_ban_req > 65000) cfg.flood_ban_req = 65000;

    g_enforce_conf = cfg.enforce;
    if (cfg.max_ips < 1024) cfg.max_ips = 1024;
    if (cfg.max_ips > MAX_IP) cfg.max_ips = MAX_IP;
    if (cfg.rescan_interval < 5) cfg.rescan_interval = 5;
    if (cfg.max_lines_per_tick < 100) cfg.max_lines_per_tick = 100;
    if (cfg.win_ban < 60) cfg.win_ban = 60;
    if (cfg.win_ban_max < cfg.win_ban) cfg.win_ban_max = cfg.win_ban;
    if (cfg.watch_score <= 0) cfg.watch_score = 20;
    if (cfg.throttle_score <= cfg.watch_score) cfg.throttle_score = cfg.watch_score + 40;
    if (cfg.ban_score <= cfg.throttle_score) cfg.ban_score = cfg.throttle_score + 90;

    /* Bawaan hanya dipakai bila config tidak menyebut sama sekali. Mendukung aaPanel,
     * panel hosting lain (DirectAdmin, cPanel, CyberPanel), dan Linux Standalone. */
    if (cfg.n_conf_dirs == 0) {
        const char *cand_conf[] = {
            "/www/server/panel/vhost/nginx",
            "/www/server/nginx/conf",
            "/www/server/panel/vhost/apache",
            "/www/server/panel/vhost/openlitespeed",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
            "/etc/apache2/sites-enabled",
            "/etc/httpd/conf.d",
            "/usr/local/directadmin/data/users",
            NULL
        };
        for (int i = 0; cand_conf[i] && cfg.n_conf_dirs < 16; i++) {
            struct stat st;
            if (stat(cand_conf[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                snprintf(cfg.conf_dirs[cfg.n_conf_dirs++], CFG_PATH, "%s", cand_conf[i]);
            }
        }
        if (cfg.n_conf_dirs == 0) {
            snprintf(cfg.conf_dirs[0], CFG_PATH, "%s", "/www/server/panel/vhost/nginx");
            snprintf(cfg.conf_dirs[1], CFG_PATH, "%s", "/www/server/nginx/conf");
            cfg.n_conf_dirs = 2;
        }
    }
    if (cfg.n_log_dirs == 0) {
        const char *cand_log[] = {
            "/www/wwwlogs",
            "/var/log/nginx",
            "/var/log/apache2",
            "/var/log/httpd",
            NULL
        };
        for (int i = 0; cand_log[i] && cfg.n_log_dirs < 16; i++) {
            struct stat st;
            if (stat(cand_log[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                snprintf(cfg.log_dirs[cfg.n_log_dirs++], CFG_PATH, "%s", cand_log[i]);
            }
        }
        if (cfg.n_log_dirs == 0) {
            snprintf(cfg.log_dirs[0], CFG_PATH, "%s", "/www/wwwlogs");
            cfg.n_log_dirs = 1;
        }
    }
}

/* ------------------------------------------------------------------ *
 * Allowlist: tidak boleh pernah diblokir.
 * ------------------------------------------------------------------ */
static uint32_t allow_net[256];
static uint32_t allow_mask[256];      /* mask prefiks; dulu semua dianggap /24 */
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
        uint32_t m = allow_mask[i];
        if ((ip & m) == (net[i] & m)) return 1;
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
    static uint32_t allow_base[256], allow_base_mask[256];
    static int      allow_base_n = 0;
    static int      first = 1;

    if (first) {
        /* salinan builtin saat allow_init sudah selesai bekerja */
        memcpy(allow_base, allow_net, sizeof(allow_net));
        memcpy(allow_base_mask, allow_mask, sizeof(allow_mask));
        allow_base_n = allow_n;
        first = 0;
    }
    memcpy(allow_net, allow_base, sizeof(allow_net));
    memcpy(allow_mask, allow_base_mask, sizeof(allow_mask));
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

static uint32_t prefix_mask(int len)
{
    if (len <= 0) return 0;
    if (len >= 32) return 0xffffffffu;
    return 0xffffffffu << (32 - len);
}

/* Tambahkan satu CIDR ke daftar putih jaringan, dengan prefiks sebenarnya.
 * Dulu setiap entri dibandingkan per /24: "103.127.134.23/32" memutihkan
 * seluruh 103.127.134.0/24, sedangkan "10.0.0.0/8" hanya 10.0.0.0/24. */
static void allow_add(const char *cidr)
{
    char buf[64];
    char *slash;
    int len = 32;
    snprintf(buf, sizeof(buf), "%s", cidr);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *e = NULL;
        long v = strtol(slash + 1, &e, 10);
        if (!e || *e || v < 8 || v > 32) return;   /* prefiks rusak/terlalu lebar: tolak */
        len = (int)v;
    }
    uint32_t ip = ip2u(buf);
    if (!ip) return;
    if (allow_n < 256) {
        allow_mask[allow_n] = prefix_mask(len);
        allow_net[allow_n++] = ip & prefix_mask(len);
    }
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

static const char *get_ipset_bin(void)
{
    static const char *cached = NULL;
    if (cached) return cached;
    if (access("/usr/sbin/ipset", X_OK) == 0) cached = "/usr/sbin/ipset";
    else if (access("/sbin/ipset", X_OK) == 0) cached = "/sbin/ipset";
    else if (access("/usr/bin/ipset", X_OK) == 0) cached = "/usr/bin/ipset";
    else cached = "ipset";
    return cached;
}

/* Minggirkan juga jaringan internal & link-local; hanya /24 yang dipakai
 * untuk efficiency, cukup untuk 10/8, 172.16/12, 192.168/16, loopback. */
static void allow_init(void)
{
    allow_hash = xcalloc(IP_BUCKETS, sizeof(uint32_t));
    allow_base_exact_n = 0;
    allow_sedang_builtin = 1;

    /* jaringan internal selalu aman: 127/8, 10/8, 172.16/12, 192.168/16 */
    allow_mask[allow_n] = prefix_mask(8);  allow_net[allow_n++] = 0x7f000000u;   /* 127.0.0.0/8 */
    allow_mask[allow_n] = prefix_mask(8);  allow_net[allow_n++] = 0x0a000000u;   /* 10.0.0.0/8 */
    allow_mask[allow_n] = prefix_mask(12); allow_net[allow_n++] = 0xac100000u;   /* 172.16.0.0/12 */
    allow_mask[allow_n] = prefix_mask(16); allow_net[allow_n++] = 0xc0a80000u;   /* 192.168.0.0/16 */
    allow_mask[allow_n] = prefix_mask(16); allow_net[allow_n++] = 0xa9fe0000u;   /* 169.254.0.0/16 */
    allow_mask[allow_n] = prefix_mask(10); allow_net[allow_n++] = 0x64400000u;   /* 100.64.0.0/10 */

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

    /* CDN Cloudflare edge ranges: tidak boleh diblokir bila webserver di belakang CDN */
    static const struct { uint32_t net; int pfx; } cdn_ranges[] = {
        { 0xadf53000u, 20 }, /* 173.245.48.0/20 */
        { 0x6715f400u, 22 }, /* 103.21.244.0/22 */
        { 0x6716c800u, 22 }, /* 103.22.200.0/22 */
        { 0x671f0400u, 22 }, /* 103.31.4.0/22 */
        { 0x8d654000u, 18 }, /* 141.101.64.0/18 */
        { 0x6ca2c000u, 18 }, /* 108.162.192.0/18 */
        { 0xbe5df000u, 20 }, /* 190.93.240.0/20 */
        { 0xbc726000u, 20 }, /* 188.114.96.0/20 */
        { 0xc5eaf000u, 22 }, /* 197.234.240.0/22 */
        { 0xc6298000u, 17 }, /* 198.41.128.0/17 */
        { 0xa29e0000u, 15 }, /* 162.158.0.0/15 */
        { 0x68100000u, 13 }, /* 104.16.0.0/13 */
        { 0x68180000u, 14 }, /* 104.24.0.0/14 */
        { 0xac400000u, 13 }, /* 172.64.0.0/13 */
        { 0x83004800u, 22 }  /* 131.0.72.0/22 */
    };
    for (size_t i = 0; i < sizeof(cdn_ranges)/sizeof(cdn_ranges[0]); i++) {
        if (allow_n < 256) {
            allow_mask[allow_n] = prefix_mask(cdn_ranges[i].pfx);
            allow_net[allow_n++] = cdn_ranges[i].net;
        }
    }

    /* Alamat IP admin dari pembatasan port firewall (admin_restrict) */
    const char *pjson_paths[] = {
        "/www/server/sentinel/data/ports.json",
        "/www/server/panel/plugin/sentinel/data/ports.json",
        "/etc/sentinel/ports.json",
        NULL
    };
    for (int pidx = 0; pjson_paths[pidx]; pidx++) {
        FILE *pj = fopen(pjson_paths[pidx], "r");
        if (pj) {
            char pbuf[4096];
            size_t prd = fread(pbuf, 1, sizeof(pbuf) - 1, pj);
            fclose(pj);
            if (prd > 0) {
                pbuf[prd] = '\0';
                char *pos = strstr(pbuf, "admin_restrict");
                if (pos) {
                    char *brace = strchr(pos, '}');
                    if (brace) *brace = '\0';
                    char *ip_cur = pos;
                    while ((ip_cur = strchr(ip_cur, '"')) != NULL) {
                        ip_cur++;
                        char *qend = strchr(ip_cur, '"');
                        if (!qend) break;
                        *qend = '\0';
                        if (strchr(ip_cur, '.') && !strchr(ip_cur, ':') && strlen(ip_cur) <= 15) {
                            uint32_t aip = ip2u(ip_cur);
                            if (aip) allow_add_exact(aip);
                        }
                        ip_cur = qend + 1;
                    }
                }
            }
            break;
        }
    }

    /* whitelist yang sudah dikelola panel aaPanel */
    const char *pcmd[] = { get_ipset_bin(), "list", "aapanel.ipv4.whitelist", NULL };
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
        execvp(pcmd[0], (char *const *)pcmd);
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

/* ------------------------------------------------------------------ *
 * Rentang proxy/CDN tepercaya (Cloudflare, Fastly, Sucuri, ...; ditulis sentinel-proxy.py, "cidr provider" per baris).
 * Di balik proxy, IP di log adalah IP TEPI proxy bila web server belum memakai real IP: IP itu membawa banyak pengunjung, jadi
 * tidak pernah dinilai, diberi event, di-ban, atau masuk review (dulu satu penyerang lewat Cloudflare bisa membuat IP tepi
 * Cloudflare di-ban dan memutus semua pengunjung yang lewat tepi itu). Hanya IPv4 (guardd membaca alamat IPv4).
 * ------------------------------------------------------------------ */
#define MAX_PROXY 4096
static uint32_t proxy_net[MAX_PROXY], proxy_mask[MAX_PROXY];
static int      proxy_n = 0;
static uint64_t g_stat_proxy = 0;

static void proxy_load(const char *path)
{
    FILE *f = fopen(path, "re");
    char line[256];
    int n = 0;
    if (!f) { proxy_n = 0; return; }
    while (fgets(line, sizeof(line), f) && n < MAX_PROXY) {
        char *p = line, *sl;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *sp = strpbrk(p, " \t\n");
        if (sp) *sp = '\0';
        if (strchr(p, ':')) continue;                    /* IPv6 */
        int pre = 32;
        if ((sl = strchr(p, '/'))) { *sl = '\0'; pre = atoi(sl + 1); }
        uint32_t ip = ip2u(p);
        if (!ip || pre < 8 || pre > 32) continue;
        uint32_t m = pre == 32 ? 0xffffffffu : ~(0xffffffffu >> pre);
        proxy_net[n] = ip & m; proxy_mask[n] = m; n++;
    }
    fclose(f);
    if (n != proxy_n) logmsg("rentang proxy tepercaya dimuat: %d (IPv4) dari %s", n, path);
    proxy_n = n;
}

static int is_proxy(uint32_t ip)
{
    for (int i = 0; i < proxy_n; i++)
        if ((ip & proxy_mask[i]) == proxy_net[i]) return 1;
    return 0;
}

/* IP sesi login interaktif (SSH/konsol jarak jauh) yang sedang aktif, dibaca dari utmp tiap 30 detik. IP ini tidak pernah
 * di-ban atau di-throttle: log akses milik akun web (www) bisa disisipi baris palsu oleh proses web yang sudah disusupi,
 * dan baris itu tidak boleh bisa mengunci admin keluar dari servernya sendiri. */
#define SESI_MAKS 64
static uint32_t g_sesi_ip[SESI_MAKS];
static int      g_sesi_n = 0;
static time_t   g_sesi_ts = 0;

static void sesi_admin_muat(time_t now)
{
    if (g_sesi_ts && now - g_sesi_ts < 30) return;
    g_sesi_ts = now;
    int n = 0;
    struct utmpx *u;
    setutxent();
    while ((u = getutxent()) != NULL && n < SESI_MAKS) {
        if (u->ut_type != USER_PROCESS) continue;
        /* IPv4 disimpan di elemen pertama (network order), sisanya nol */
        if (!u->ut_addr_v6[0] || u->ut_addr_v6[1] || u->ut_addr_v6[2] || u->ut_addr_v6[3]) continue;
        uint32_t ip = ntohl((uint32_t)u->ut_addr_v6[0]);
        int ada = 0;
        for (int i = 0; i < n; i++) if (g_sesi_ip[i] == ip) { ada = 1; break; }
        if (!ada) g_sesi_ip[n++] = ip;
    }
    endutxent();
    if (n != g_sesi_n) logmsg("sesi admin aktif: %d IP dilindungi dari ban", n);
    g_sesi_n = n;
}

static int is_sesi_admin(uint32_t ip)
{
    for (int i = 0; i < g_sesi_n; i++) if (g_sesi_ip[i] == ip) return 1;
    return 0;
}

static int is_allowed(uint32_t ip)
{
    if (!ip) return 1;
    if (net_contains(allow_net, allow_n, ip)) return 1;
    if (allow_exact(ip)) return 1;
    if (is_sesi_admin(ip)) return 1;
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
    /* /wp-content, /wp-includes, /wp-json SENGAJA tidak ada: itu jalur aset
     * dan API yang dipakai setiap pengunjung situs WordPress. Penjelajahan
     * plugin rentan di bawahnya sudah tertangkap oleh hitungan path 4xx. */
    "/wp-login", "/wp-admin", "/wp-config", "/xmlrpc.php", "/wordpress/",
    /* config & secret bocor */
    "/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "/.docker",
    "/.vscode", "/.idea", "/.zsh_history", "/.bash_history", "/.ds_store",
    "/config.json", "/config.yaml", "/config.php.bak", "/web.config",
    "/database.yml", "/.htpasswd", "/.npmrc", "/.netrc",
    /* webshell & RCE marker */
    "/shell.php", "/shell/", "/c99.php", "/r57.php", "/b374k.php", "/cgi-bin/",
    "/.ssh/authorized_keys", "/vendor/phpunit", "/eval-stdin", "/base64_decode",
    "/boaform", "/hnap1", "/favicon.ico.bak", "/.php5", "/.php7",
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
    "/zremotescheduler", "/invoker/jmxinvokerservlet", "/cluster/domain",
    "/solr/admin", "/api/v1/../", "/../", "/boa", "/hnap",
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
    "libwww-perl", "lwp::simple", "apachebench", "siege", "ab -", "jmeter",
    "apache-httpclient", "java/", "okhttp", "axios/", "node-fetch",
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

/* Path dinormalkan seperti nginx sebelum dicocokkan: %XX didekode, huruf
 * kecil, "//" dan "/./" diringkas, garis miring penutup dibuang. Tanpa ini
 * "//.env", "/./.env", "/%2eenv" dan "/.ENV" lolos dari daftar padahal
 * nginx melayani berkas yang sama. */
static size_t path_norm(const char *p, size_t n, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '%' && i + 2 < n && isxdigit((unsigned char)p[i + 1])
            && isxdigit((unsigned char)p[i + 2])) {
            char hx[3] = { p[i + 1], p[i + 2], 0 };
            c = (unsigned char)strtol(hx, NULL, 16);
            i += 2;
        }
        c = (unsigned char)tolower(c);
        if (c == '/' && o > 0 && out[o - 1] == '/') continue;               /* // */
        if (c == '/' && o > 1 && out[o - 1] == '.' && out[o - 2] == '/') {   /* /./ */
            o--;
            continue;
        }
        out[o++] = (char)c;
    }
    while (o > 1 && out[o - 1] == '/') o--;
    out[o] = '\0';
    return o;
}

/* Berkas rahasia/dotfile dicari di SEGMEN mana pun ("/blog/.env",
 * "/app/.git/config"); entri lain cukup sebagai awalan. */
static int path_is_scanner(const char *np, size_t n)
{
    if (in_list(PAT_SCANNER, np, n)) return 1;
    for (int i = 0; PAT_SCANNER[i]; i++) {
        const char *pt = PAT_SCANNER[i];
        if (pt[0] == '/' && (pt[1] == '.' || !strncmp(pt, "/wp-login", 9)
                             || !strncmp(pt, "/wp-config", 10)
                             || !strncmp(pt, "/etc/passwd", 11)
                             || !strncmp(pt, "/vendor/phpunit", 15))
            && memmem(np, n, pt, strlen(pt)))
            return 1;
    }
    return 0;
}

static int path_is_brute(const char *path, size_t len)
{
    return in_list(PATH_BRUTE, path, len);
}

static int ua_is_tool(const char *ua, size_t len)
{
    if (len == 0) return 0;
    if (len < 5) return 1;                     /* UA sangat pendek = bukan browser */
    /* Di mana saja dalam UA, bukan hanya awalan: "Mozilla/5.0 (... Nuclei)"
     * dan "Mozilla/5.0 (compatible; GPTBot/1.0)" harus tetap tertangkap. */
    for (int i = 0; UA_TOOL[i]; i++)
        if (memmem(ua, len, UA_TOOL[i], strlen(UA_TOOL[i]))) return 1;
    return 0;
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
    uint8_t  learn_n;                 /* kecocokan pelajaran blokir dalam jendela 60 detik */
    uint8_t  reviewed;                /* sudah masuk antrean review; jangan kueri ulang tiap detak */
    uint32_t learn_ts;                /* kecocokan terakhir; jendela dihitung dari sini */
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
    uint16_t last_status;
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
    uint16_t status;
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
/* Baris dengan IP klien IPv6: tabel skor/ban daemon ini hanya IPv4, jadi baris ini dilewati dan pengunjung IPv6 hanya
 * dilindungi lapisan WAF (L7). Dihitung terpisah supaya celah cakupan ini terlihat di status dan UI, bukan tersembunyi. */
static uint64_t g_stat_ipv6_skip = 0;
static uint64_t g_stat_ipv6_bans = 0;   /* prefix /64 yang diblokir penilai IPv6 */
static uint64_t g_stat_lines = 0;
static uint64_t g_stat_dropped_cap = 0;  /* line dilewati karena pagu tick */
static uint64_t g_stat_bans_total = 0;
static uint64_t g_stat_throttles_total = 0;
static uint64_t g_stat_long_lines = 0;    /* baris > SENT_LINE_MAX: kepala dinilai */
static int      g_line_truncated = 0;     /* baris yang sedang diproses terpotong */

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
    /* Utamakan skor terendah (0 lebih dulu), baru yang paling tua: dulu entri NORMAL paling tua dibuang walau skornya sedang naik,
     * sehingga banjir IP baru bisa mengosongkan skor penyerang sebelum mencapai ambang (audit 29 Okt 2026). */
    ip_ent *best = NULL;
    scanned = 0;
    for (ip_ent *e = g_lru_head; e && scanned < 4096; e = e->lru_next, scanned++) {
        if (e->level != LVL_NORMAL) continue;
        if (!best || e->score < best->score || (e->score == best->score && e->last_seen < best->last_seen)) best = e;
        if (best->score == 0 && e == best) break;     /* daftar umur: skor 0 pertama sudah yang tertua dengan skor 0 */
    }
    if (best) { ip_unlink_bucket(best->ip); return 1; }

    /* Lapis 3: tabel penuh oleh IP berlevel (mis. ribuan IP yang sengaja
     * menyentuh ambang WATCH). Entri yang sudah diam >= 10 menit dan tidak
     * punya ban aktif boleh digusur; tanpa ini IP baru tidak pernah
     * dinilai sama sekali. */
    best = NULL;
    scanned = 0;
    for (ip_ent *e = g_lru_head; e && scanned < 4096; e = e->lru_next, scanned++) {
        if ((uint32_t)(now - e->last_seen) < 600) continue;
        ban_t *b = ban_find(e->ip);
        if (b && b->until >= (time_t)now) continue;
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
    char     carry[SENT_LINE_MAX + 1];
    size_t   carry_len;
    int      skip_nl;       /* sedang membuang ekor baris kepanjangan */
    time_t   potong_ts;     /* notifikasi "log terpotong" terakhir (dibatasi 1 per 10 menit per log) */
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
    /* Apache aaPanel: <host>-access_log; OpenLiteSpeed aaPanel: <host>_ols.access_log */
    /* server tanpa aaPanel: nginx Debian/Ubuntu menamai log <situs>.access.log / <situs>-access.log */
    static const char *const suf[] = { "_ols.access_log", ".access_log", "-access_log", "_access_log", ".access", "-access", NULL };
    for (int i = 0; suf[i]; i++) {
        size_t sl = strlen(suf[i]);
        l = strlen(out);
        if (l > sl && !strcmp(out + l - sl, suf[i])) { out[l - sl] = '\0'; break; }
    }
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
/* Buka log untuk ditail. Folder induk yang bukan milik root (mis. /www/wwwlogs milik www) dibuka dengan O_NOFOLLOW: pemilik folder
 * bisa mengganti berkas log dengan symlink ke berkas root mana pun. Symlink di folder milik root (layout distro) tetap diikuti. */
static int buka_log(const char *path)
{
    int fl = O_RDONLY | O_NONBLOCK | O_CLOEXEC;
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *sl = strrchr(dir, '/');
    if (sl && sl != dir) *sl = '\0';
    struct stat ds;
    if (!sl || stat(dir, &ds) != 0 || ds.st_uid != 0) fl |= O_NOFOLLOW;
    return open(path, fl);
}

static int looks_like_access_log(const char *path)
{
    /* /www/wwwlogs dimiliki www: berkas bisa ditukar FIFO di antara stat() pemanggil dan open() ini. fopen() biasa
     * (tanpa O_NONBLOCK) pada FIFO tanpa penulis menggantung selamanya dan membekukan loop utama guardd.
     * Buka non-blocking, pastikan berkas biasa dari fd yang sama, baru bungkus dengan FILE. */
    int ofd = buka_log(path);
    if (ofd < 0) return 0;
    struct stat ost;
    if (fstat(ofd, &ost) != 0 || !S_ISREG(ost.st_mode)) { close(ofd); return 0; }
    FILE *f = fdopen(ofd, "r");
    if (!f) { close(ofd); return 0; }
    char line[SENT_LINE_MAX];
    int found = 0;
    for (int i = 0; i < 20 && !found; i++) {
        if (!fgets(line, sizeof(line), f)) break;
        if (line[0] == '\0' || line[0] == '\n') continue;
        /* harus diawali alamat IPv4, atau IPv6 (dulu hanya IPv4: log situs yang hanya dikunjungi lewat IPv6 tidak pernah ditail) */
        int dots = 0, ok = 1;
        for (const char *p = line; *p == '.' || isdigit((unsigned char)*p); p++) {
            if (*p == '.') dots++;
            if (!isdigit((unsigned char)*p) && *p != '.') { ok = 0; break; }
            if (p - line > 40) { ok = 0; break; }
        }
        if (!ok || dots < 3) {
            size_t k = strcspn(line, " ");
            char a6[64];
            struct in6_addr x6;
            if (k == 0 || k >= sizeof(a6)) continue;
            memcpy(a6, line, k); a6[k] = '\0';
            if (inet_pton(AF_INET6, a6, &x6) != 1) continue;
        }
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
    /* Pakai ulang slot yang sudah dilepas. Dulu slot baru selalu diambil di ujung dan yang dilepas tidak pernah dipakai
     * lagi: jalur log dari conf yang diganti FIFO/non-berkas oleh pemilik direktori log (www) menghabiskan 1 slot tiap
     * siklus penemuan, sampai pagu MAX_TAILERS penuh dan vhost baru tidak pernah ditail. */
    int slot = -1;
    for (int i = 0; i < g_tail_n; i++)
        if (!g_tail[i].in_use) { slot = i; break; }
    if (slot < 0) {
        if (g_tail_n >= MAX_TAILERS) {
            logmsg("pagu tailer penuh (%d), log %s diabaikan", MAX_TAILERS, path);
            return -1;
        }
        slot = g_tail_n++;
    }

    tailer_t *t = &g_tail[slot];
    memset(t, 0, sizeof(*t));
    snprintf(t->path, PATH_MAX, "%s", path);
    host_from_path(path, t->host, sizeof(t->host));
    t->added = now_t();
    t->fd = -1;
    t->in_use = 1;

    /* O_NONBLOCK: FIFO yang ditanam pemilik log tidak boleh membekukan loop utama */
    int fd = buka_log(path);
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
    tailer_release(slot);
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
        /* O_NONBLOCK: jalur ini milik www; FIFO yang ditanam di sana tidak boleh menggantung open() */
        int fd = buka_log(t->path);
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

/* Nama berkas access log Apache/OLS aaPanel yang tidak berakhiran .log: <host>-access_log, <host>_ols.access_log. Dulu hanya
 * *.log yang diterima sehingga situs Apache/OpenLiteSpeed tidak pernah ditail (tanpa skor, ban, maupun pelajaran). */
static int log_nama_akses(const char *nama)
{
    size_t n = strlen(nama);
    return (n > 10 && !strcmp(nama + n - 10, "access_log"));
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
        /* nginx access_log, Apache CustomLog/TransferLog, OpenLiteSpeed accesslog (huruf besar/kecil bebas) */
        size_t dl = 0;
        if (!strncasecmp(q, "access_log", 10)) dl = 10;
        else if (!strncasecmp(q, "customlog", 9)) dl = 9;
        else if (!strncasecmp(q, "transferlog", 11)) dl = 11;
        else if (!strncasecmp(q, "accesslog", 9)) dl = 9;
        if (!dl) continue;
        q += dl;
        if (*q != ' ' && *q != '\t') continue;

        while (*q == ' ' || *q == '\t') q++;
        if (*q == '\0' || *q == '\n' || *q == '#') continue;
        if (*q == '"' || *q == '\'') q++;          /* Apache: CustomLog "/www/wwwlogs/x-access_log" combined */

        /* token pertama = target */
        char target[PATH_MAX];
        size_t i = 0;
        while (*q && *q != ' ' && *q != '\t' && *q != ';' && *q != '\n' && *q != '"' && *q != '\'' && *q != '{' && i < PATH_MAX - 1)
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
        if (!strstr(target, ".log") && !log_nama_akses(target)) continue;
        if (strstr(target, "error")) continue;

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
/* wajib_root: hanya berkas milik root. Dipakai bila salinan log root (AKSES_DIR) aktif: log yang hanya ditemukan lewat pemindaian direktori
 * (tidak dirujuk conf vhost) dan dibuat akun web bisa berisi baris karangan yang membuat IP pihak lain diblokir (evaluasi 30 Okt 2026). */
static void scan_logdir(const char *dir, int depth, int *found, int wajib_root)
{
    if (depth > 2 || *found >= MAX_TAILERS) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    int entries = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (dir_should_skip(de->d_name)) continue;
        if (++entries > 256) break; /* Batasi entri per direktori per siklus agar www tidak menahan loop */
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", dir, de->d_name) >= PATH_MAX) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { scan_logdir(path, depth + 1, found, wajib_root); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        if (wajib_root && st.st_uid != 0) continue;
        size_t ln = strlen(de->d_name);
        if ((ln < 5 || strcmp(de->d_name + ln - 4, ".log") != 0) && !log_nama_akses(de->d_name)) continue;
        /* jangan ikut error log */
        if (strstr(de->d_name, "error")) continue;
        if (want_has(path)) continue;
        if (!looks_like_access_log(path)) continue;
        if (want_add(path)) (*found)++;
        if (*found >= MAX_TAILERS) break;
    }
    closedir(d);
}

static int g_logs_seen = 0;

/* Siklus penemuan. Dipanggil berkala dan setiap SIGHUP.
 * Tidak ada daftar vhost yang disimpan di kode: seluruhnya berasal dari
 * pembacaan berkas conf dan direktori log saat runtime. */
/* Salinan access log per vhost milik root (snippet WAF nginx menulis access_log kedua ke sini; master nginx membukanya sebagai root).
 * Log aaPanel di /www/wwwlogs milik akun web: proses web yang disusupi bisa menghapus isinya atau menyisipkan baris palsu. Bila salinan
 * root untuk sebuah host ada, log /www/wwwlogs host itu tidak dibaca (tidak dihitung ganda dan tidak bisa diracuni). */
#ifndef AKSES_DIR
#define AKSES_DIR "/www/server/sentinel/log/akses"   /* uji: -DAKSES_DIR=... */
#endif
#define AKSES_ROTASI_BYTES (64LL * 1024 * 1024)

static int akses_dir_aman(void)
{
    struct stat st;
    if (lstat(AKSES_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    if (st.st_uid != 0 || (st.st_mode & 077)) {
        static time_t peringatan = 0;
        if (now_t() - peringatan > 3600) {
            logmsg("PERINGATAN: %s bukan milik root atau izinnya longgar (%o); salinan log root diabaikan", AKSES_DIR, st.st_mode & 0777);
            peringatan = now_t();
        }
        return 0;
    }
    return 1;
}

static int di_akses_dir(const char *p)
{
    size_t n = strlen(AKSES_DIR);
    return !strncmp(p, AKSES_DIR, n) && p[n] == '/';
}

/* Buang dari daftar keinginan log non-root untuk host yang punya salinan root; salinan root yang tidak aman dibuang semua. */
static void want_utamakan_akses(int aman)
{
    int j = 0;
    for (int i = 0; i < g_want_n; i++) {
        int buang = 0;
        if (di_akses_dir(g_want[i])) {
            buang = !aman;
        } else if (aman) {
            char h[256], cand[PATH_MAX];
            host_from_path(g_want[i], h, sizeof(h));
            /* hanya bila salinan root BENAR-BENAR ada (milik root): conf sudah merujuknya tetapi nginx belum di-reload, atau rotasi
             * belum dibuka ulang, berarti salinan belum menerima baris dan log host itu tidak boleh dibuang (host jadi tidak terpantau) */
            struct stat cs;
            if (h[0] && snprintf(cand, sizeof(cand), "%s/%s.log", AKSES_DIR, h) < (int)sizeof(cand) && want_has(cand)
                && lstat(cand, &cs) == 0 && S_ISREG(cs.st_mode) && cs.st_uid == 0) buang = 1;
        }
        if (buang) free(g_want[i]); else g_want[j++] = g_want[i];
    }
    g_want_n = j;
}

/* PID dari pidfile hanya dipakai bila prosesnya memang server web milik root (uid 0, exe bernama nginx/httpd/apache2): pidfile basi bisa
 * menunjuk proses lain yang kebetulan memakai PID yang sama, dan SIGUSR1 mengakhiri proses yang tidak menanganinya. */
static pid_t pid_server_web(const char *const *pidf)
{
    for (int i = 0; pidf[i]; i++) {
        FILE *f = fopen(pidf[i], "re");
        if (!f) continue;
        long pid = 0;
        int ok = fscanf(f, "%ld", &pid) == 1 && pid > 1;
        fclose(f);
        if (!ok) continue;
        char p[64], exe[PATH_MAX];
        struct stat st;
        snprintf(p, sizeof(p), "/proc/%ld", pid);
        if (stat(p, &st) != 0 || st.st_uid != 0) continue;
        snprintf(p, sizeof(p), "/proc/%ld/exe", pid);
        ssize_t n = readlink(p, exe, sizeof(exe) - 1);
        if (n <= 0) continue;
        exe[n] = 0;
        const char *b = strrchr(exe, '/');
        b = b ? b + 1 : exe;
        if (!strncmp(b, "nginx", 5) || !strncmp(b, "httpd", 5) || !strncmp(b, "apache2", 7)) return (pid_t)pid;
    }
    return 0;
}

/* Rotasi salinan root yang melewati AKSES_ROTASI_BYTES: rename ke .1 lalu USR1 ke master server web (buka ulang log). Tailer melihat
 * inode baru lewat stat(path) dan mulai dari offset 0. Tanpa master yang terverifikasi tidak ada rename: berkas yang diganti nama tanpa
 * dibuka ulang membuat server terus menulis ke .1 dan host tidak terpantau. Bila guardd tidak berjalan, logrotate (install.sh) membatasi
 * ukuran salinan ini. */
static void akses_rotasi(void)
{
    static const char *const NGX[] = { "/www/server/nginx/logs/nginx.pid", "/run/nginx.pid", "/var/run/nginx.pid", NULL };
    static const char *const APC[] = { "/www/server/apache/logs/httpd.pid", "/run/httpd/httpd.pid", "/var/run/apache2/apache2.pid", NULL };
    int besar = 0;
    for (int i = 0; i < g_tail_n && !besar; i++) {
        struct stat st;
        besar = g_tail[i].in_use && di_akses_dir(g_tail[i].path) && stat(g_tail[i].path, &st) == 0 && st.st_size >= AKSES_ROTASI_BYTES;
    }
    if (!besar) return;
    pid_t pn = pid_server_web(NGX), pa = pid_server_web(APC);
    if (!pn && !pa) {
        static time_t peringatan = 0;
        if (now_t() - peringatan > 3600) { logmsg("rotasi salinan log root ditunda: master nginx/Apache tidak terverifikasi"); peringatan = now_t(); }
        return;
    }
    int perlu = 0;
    for (int i = 0; i < g_tail_n; i++) {
        tailer_t *t = &g_tail[i];
        if (!t->in_use || !di_akses_dir(t->path)) continue;
        struct stat st;
        if (stat(t->path, &st) != 0 || st.st_size < AKSES_ROTASI_BYTES) continue;
        char lama[PATH_MAX];
        if (snprintf(lama, sizeof(lama), "%s.1", t->path) >= (int)sizeof(lama)) continue;
        if (rename(t->path, lama) == 0) { perlu = 1; logmsg("rotasi salinan log root: %s -> %s", t->path, lama); }
    }
    if (!perlu) return;
    /* USR1: nginx = buka ulang log; Apache = graceful restart (koneksi berjalan diselesaikan, log dibuka ulang) */
    if (pn) kill(pn, SIGUSR1);
    if (pa) kill(pa, SIGUSR1);
}

static void rediscover(void)
{
    int found = 0;
    want_reset();
    for (int i = 0; i < cfg.n_conf_dirs; i++)
        scan_conf_recursive(cfg.conf_dirs[i], 0, &found);
    int aman = akses_dir_aman();
    for (int i = 0; i < cfg.n_log_dirs; i++)
        scan_logdir(cfg.log_dirs[i], 0, &found, aman);
    if (aman) scan_logdir(AKSES_DIR, 0, &found, 1);
    want_utamakan_akses(aman);
    akses_rotasi();

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
        "/health", "/ping", "/pong", "/up/", "/readyz", "/livez",
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
    for (const char *q = end - 1; q > s; q--) {
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

static char g_ua_lower_buf[256];

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
                    size_t plen, const char *ua, size_t ulen, uint16_t status)
{
    if (g_ev_n >= MAX_EVENTS_BATCH) return;
    ev_t *e = &g_ev[g_ev_n++];
    memset(e, 0, sizeof(*e));
    e->ts = ts; e->ip = ip; e->score = score; e->level = level; e->kind = kind;
    e->status = status;
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
        /* hanya berlaku pada database BARU (sebelum tabel dibuat): halaman kosong sesudah retensi dikembalikan bertahap lewat
         * incremental_vacuum di db_prune, jadi berkas tidak tumbuh permanen. Database lama tetap mode semula (tanpa VACUUM penuh). */
        "PRAGMA auto_vacuum=INCREMENTAL",
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
        " kind TEXT, score INTEGER, level INTEGER, host TEXT, path TEXT, ua TEXT, status INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS bans("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ip INTEGER, kind TEXT,"
        " score INTEGER, start INTEGER, until INTEGER, offenses INTEGER, reason TEXT);"
        "CREATE TABLE IF NOT EXISTS verdict("
        " ip INTEGER PRIMARY KEY, offenses INTEGER DEFAULT 0, last_kill INTEGER DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);"
        /* dialog Total Attackers/Threats dan kartu: COUNT(DISTINCT ip), GROUP BY kind/host tanpa memindai seluruh tabel */
        "CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip);"
        "CREATE INDEX IF NOT EXISTS ix_events_kind ON events(kind);"
        "CREATE INDEX IF NOT EXISTS ix_events_host ON events(host);"
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
    sqlite3_exec(g_db, "ALTER TABLE events ADD COLUMN status INTEGER DEFAULT 0;", NULL, NULL, NULL);
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

/* Entri g_ban dipakai juga untuk throttle (alasan tetap di bawah). */

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
        execvp(argv[0], (char *const *)argv);
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
        (const char *const[]){ get_ipset_bin(), "test", set, b, NULL },
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
        execvp(argv[0], (char *const *)argv);
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
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "%s list 2>/dev/null", get_ipset_bin());
    FILE *f = popen(cmd, "re");
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
    run_ps((const char *const[]){ get_ipset_bin(), "restore", NULL }, cmd, strlen(cmd));
    if (ipset_exists(set))
        logmsg("ipset %s dibuat (timeout bawaan %u detik)", set, def_timeout);
    else
        logmsg("PERINGATAN: gagal membuat ipset %s", set);
}

/* ------------------------------------------------------------------ *
 * Gerbang lisensi (paket berlangganan).
 *
 * guardd TIDAK memverifikasi tanda tangan sendiri: ia bertanya ke biner
 * sentinel-license (satu-satunya pemverifikasi Ed25519) fitur mana yang
 * diizinkan. Gagal tertutup: biner hilang/rusak/lambat = tidak diizinkan.
 *   enforce : pemblokiran OTOMATIS berdasarkan skor (ban, throttle, flood).
 *             Ban manual dari operator (paksa=1) tetap jalan di paket Free.
 *   learn   : pelajaran dari Blokir/Izinkan di Event Feed (learned.tsv).
 * Daemon memeriksa ulang tiap 30 detik, jadi paket yang habis menurunkan
 * perlindungan otomatis tanpa restart, dan upgrade berlaku tanpa restart.
 * ------------------------------------------------------------------ */

static cfg_t g_cfg_def, g_cfg_conf;     /* bawaan biner dan hasil guardd.conf; ambang kustom hanya berlaku di paket Max */
static void lic_ambang(void)
{
    /* edisi Free: ambang bawaan biner saja (ambang kustom adalah fitur Max) */
    const cfg_t *src = &g_cfg_def;
    cfg.watch_score = src->watch_score; cfg.throttle_score = src->throttle_score; cfg.ban_score = src->ban_score;
    cfg.win_ban = src->win_ban; cfg.win_ban_max = src->win_ban_max;
    cfg.w_scan = src->w_scan; cfg.w_brute = src->w_brute; cfg.w_badua = src->w_badua; cfg.w_distinct = src->w_distinct;
    cfg.cap_scan = src->cap_scan; cfg.cap_brute = src->cap_brute; cfg.cap_badua = src->cap_badua; cfg.cap_distinct = src->cap_distinct;
}

static void lic_refresh(time_t now, int paksa)
{
    /* edisi Free: pemblokiran otomatis, pelajaran, dan ambang kustom tidak ada (sama dengan edisi Pro berlisensi Free) */
    (void)now;
    if (paksa == 2)
        logmsg("edisi Free: enforce=TERKUNCI learn=TERKUNCI ambang_kustom=TERKUNCI (tersedia di ZySentinel Pro)");
    g_lic_mask = 0; g_lic_ts = 0;
    cfg.enforce = 0;
    lic_ambang();
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
        get_ipset_bin(), "add", "-exist", set, b, "timeout", secsbuf, NULL
    }, NULL, 0);
}


static void ipset_del(const char *set, uint32_t ip)
{
    char b[32], line[128];
    u2ip(ip, b, sizeof(b));
    snprintf(line, sizeof(line), "del %s %s\n", set, b);
    run_ps((const char *const[]){ get_ipset_bin(), "restore", NULL }, line, strlen(line));
}

/* Ban yang masih berlaku dimuat ulang saat daemon mulai. Ban hanya hidup di ipset kernel dan di g_ban: setelah reboot semua ban
 * (termasuk ban manual dari panel) hilang walau baris bans.until masih di masa depan; setelah restart tanpa reboot ipset masih
 * berisi tetapi g_ban kosong, sehingga bans_active di status.json 0. IP di allowlist tidak dipulihkan. */
static void ban_restore(time_t now)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (!g_db || sqlite3_prepare_v2(g_db,
            "SELECT ip, MAX(until), kind, score, reason FROM bans WHERE until > ?1 GROUP BY ip ORDER BY MAX(until) DESC LIMIT ?2",
            -1, &st, NULL) != SQLITE_OK) { saverr(g_db, "ban_restore"); return; }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    sqlite3_bind_int(st, 2, MAX_BAN_ENTRIES);
    while (sqlite3_step(st) == SQLITE_ROW && g_ban_n < MAX_BAN_ENTRIES) {
        uint32_t ip = (uint32_t)sqlite3_column_int64(st, 0);
        time_t until = (time_t)sqlite3_column_int64(st, 1);
        if (!ip || until <= now || is_allowed(ip) || ban_find(ip)) continue;
        ban_t *b = &g_ban[g_ban_n++];
        memset(b, 0, sizeof(*b));
        b->ip = ip; b->until = until; b->start = now; b->offenses = 1; b->active = 1;
        b->score = (uint32_t)sqlite3_column_int64(st, 3);
        const char *k = (const char *)sqlite3_column_text(st, 2);
        for (int i = 0; k && i < (int)(sizeof(KIND_NAME) / sizeof(KIND_NAME[0])); i++)
            if (KIND_NAME[i] && !strcmp(KIND_NAME[i], k)) { b->kind = (uint8_t)i; break; }
        const char *rs = (const char *)sqlite3_column_text(st, 4);
        snprintf(b->reason, sizeof(b->reason), "%s", rs ? rs : "dipulihkan");
        ipset_add_ex("sentinel_ban", ip, (uint32_t)(until - now), 1);
        n++;
    }
    sqlite3_finalize(st);
    if (n) logmsg("%d ban yang masih berlaku dipulihkan dari database", n);
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
            "INSERT INTO events(ts,ip,kind,score,level,host,path,ua,status)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", -1, &st, NULL) == SQLITE_OK) {
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
                sqlite3_bind_int64(st, 9, (sqlite3_int64)e->status);
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
        /* Dulu lima tabel ini tumbuh tanpa batas. */
        { "DELETE FROM aksi WHERE ts < ?1", t - 90 * 86400 },
        { "DELETE FROM notif WHERE ts < ?1 AND terkirim <> 0", t - 30 * 86400 },
        { "DELETE FROM notif WHERE ts < ?1", t - 90 * 86400 },
        { "DELETE FROM review WHERE ts < ?1 AND status <> 'tunggu'", t - 30 * 86400 },
        { "DELETE FROM verdict WHERE last_kill < ?1", t - 30 * 86400 },
        { "DELETE FROM watch WHERE ts < ?1", t - 30 * 86400 },
        /* cache negara lama milik panel (tidak lagi ditulis; tabel boleh tidak ada) */
        { "DELETE FROM geo WHERE ts < ?1", t - 30 * 86400 },
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
    /* kembalikan paling banyak 2000 halaman kosong per jam (no-op bila auto_vacuum bukan INCREMENTAL) */
    sqlite3_exec(g_db, "PRAGMA incremental_vacuum(2000)", NULL, NULL, NULL);
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
    /* berkas status sementara di run/ (status.json, ditulis tiap 2 detik) tidak perlu fsync: setelah mati listrik ditulis ulang
     * dalam 2 detik; dulu ~43 ribu fsync sehari. Berkas lain tetap fsync sebelum rename. */
    if (!strstr(path, "/run/")) fsync(fd);
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
    for (int i = 0; i < g_nhost && o + 700 < sizeof(hostbuf); i++) {
        agg_t *a = &g_host[i];
        if (!a->req && !a->bytes) continue;
        char hn[256];   /* nama host berasal dari nama berkas log: wajib di-escape */
        json_escape(hn, sizeof(hn), g_hostname[i], strlen(g_hostname[i]));
        o += (size_t)snprintf(hostbuf + o, sizeof(hostbuf) - o,
            "%s{\"host\":\"%s\",\"req\":%llu,\"bytes\":%llu,\"s2\":%llu,\"s3\":%llu,"
            "\"s4\":%llu,\"s5\":%llu,\"s429\":%llu}",
            shown ? "," : "", hn,
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
    for (int i = 0; i < g_ban_n && bn < 60 && bo + 400 < sizeof(banbuf); i++) {
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

    char logs[16384];
    size_t lo = 0;
    int ln = 0;
    lo += (size_t)snprintf(logs + lo, sizeof(logs) - lo, "[");
    /* Batas ukuran diperiksa SEBELUM menulis tiap entri: o += snprintf() melewati
     * ukuran buffer membuat (sizeof - o) menjadi size_t raksasa dan menulis di luar
     * buffer (stack overflow yang bisa dipicu penyerang lewat banyak berkas log). */
    for (int i = 0; i < g_tail_n && lo + 1500 < sizeof(logs); i++) {
        if (!g_tail[i].in_use) continue;
        char ep[512], eh[256];
        json_escape(ep, sizeof(ep), g_tail[i].path, strlen(g_tail[i].path));
        json_escape(eh, sizeof(eh), g_tail[i].host, strlen(g_tail[i].host));
        lo += (size_t)snprintf(logs + lo, sizeof(logs) - lo,
            "%s{\"path\":\"%s\",\"host\":\"%s\",\"lines\":%llu}",
            ln ? "," : "", ep, eh,
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
        "\"rescan_interval\":%d,\"startup_backfill\":%d,"
        "\"enforce_conf\":%d,\"lic_mask\":%u,\"proxy_lines\":%llu,\"proxy_ranges\":%d,\"ipv6_skipped\":%llu,\"ipv6_bans\":%llu}\n",
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
        cfg.rescan_interval, cfg.startup_backfill,
        g_enforce_conf, g_lic_mask, (unsigned long long)g_stat_proxy, proxy_n,
        (unsigned long long)g_stat_ipv6_skip, (unsigned long long)g_stat_ipv6_bans);

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

/* Keadaan modul pelajaran (definisi lengkap ada di bagian PELAJARAN). */
static int      g_les_n = 0, g_les_block = 0, g_les_allow = 0;
static uint64_t g_stat_learn_bans = 0;
static void learn_load(const char *path);

static void handle_ctl(int cfd)
{
    char buf[512];
    ssize_t n = read(cfd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = '\0';
    }

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

    if (!strcmp(cmd, "cloud_base")) {
        /* Base URL backend resmi ZySentinel (didekripsi dinamis dari segmen data tanpa string literal) */
        static const unsigned char enc_url[] = { 50, 46, 46, 42, 41, 96, 117, 117, 41, 63, 57, 116, 32, 35, 41, 63, 52, 41, 116, 57, 53, 55 };
        char dec[sizeof(enc_url) + 1];
        for (size_t i = 0; i < sizeof(enc_url); i++) {
            dec[i] = (char)(enc_url[i] ^ 0x5A);
        }
        dec[sizeof(enc_url)] = '\0';
        ctl_reply(cfd, dec);
        return;
    }

    if (!strcmp(cmd, "ban")) {
        uint32_t ip = ip2u(arg);
        if (!ip) { ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip tidak valid\"}"); return; }
        if (is_allowed(ip)) {
            ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip ada di allowlist\"}");
            return;
        }
        if (is_proxy(ip)) {
            ctl_reply(cfd, "{\"ok\":false,\"err\":\"ip milik proxy/CDN tepercaya (mis. Cloudflare): ban akan memutus semua pengunjung yang lewat proxy itu\"}");
            return;
        }
        uint32_t d = (secs > 0) ? (uint32_t)secs : (uint32_t)cfg.win_ban;
        if (secs > 0 && d > (uint32_t)cfg.win_ban_max) d = (uint32_t)cfg.win_ban_max;
        ban_upsert(ip, K_MIXED, cfg.ban_score, "manual-panel", t, d);
        verdict_bump(ip, t);
        /* paksa = 1: perintah operator berlaku juga saat enforce = 0 */
        ipset_add_ex("sentinel_ban", ip, d, 1);
        /* Disetujui dari antrean review: keluarkan dari set review supaya
         * penanda review tidak lagi dianggap "menunggu". */
        ipset_del("sentinel_review", ip);
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

    if (!strcmp(cmd, "learnload")) {
        learn_load(cfg.learn_file);
        char lb[160];
        snprintf(lb, sizeof(lb),
                 "{\"ok\":true,\"lessons\":%d,\"block\":%d,\"allow\":%d,\"bans\":%llu}",
                 g_les_n, g_les_block, g_les_allow,
                 (unsigned long long)g_stat_learn_bans);
        ctl_reply(cfd, lb);
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

/* ------------------------------------------------------------------ *
 * PELAJARAN DARI KEPUTUSAN OPERATOR
 * ------------------------------------------------------------------ *
 * Saat operator menekan Blokir atau Izinkan pada Event Feed, panel
 * menurunkan satu pola (path dan/atau user-agent) dari kejadian itu dan
 * menuliskannya ke learned.tsv. Daemon hanya MEMBACA berkas ini; seluruh
 * siklus hidup pelajaran (membuat, menggabungkan, mencabut) ada di panel.
 *
 *   B  pelajaran blokir: kecocokan memblokir IP pengirimnya, tanpa
 *      menunggu skor mencapai ambang. Hanya berlaku untuk permintaan
 *      yang dijawab 4xx (server menolaknya = tanda meraba-raba), supaya
 *      pengunjung sah yang kebetulan memakai path/UA yang sama tidak
 *      kena.
 *   A  pelajaran izinkan: permintaan yang cocok tidak dihitung sebagai
 *      scanner/enumerasi (path) atau UA alat (user-agent). Tidak pernah
 *      menjadikan IP kebal; itu urusan allowlist.
 *
 * Bila pelajaran izinkan dan blokir sama-sama cocok, izinkan menang.
 * Pelajaran blokir juga mengikuti enforce: saat enforce = 0 kecocokan
 * masuk antrian review, bukan ipset.
 *
 * Format satu baris (dipisah TAB): id aksi kategori path ua
 * path/ua kosong ditulis "-". Baris tidak valid dilewati satu per satu.
 */
#define MAX_LESSONS 512
typedef struct {
    char     id[12];
    char     aksi;            /* 'B' atau 'A' */
    uint8_t  kind;
    uint8_t  need;            /* kecocokan sebelum IP diblokir */
    char     path[192];
    size_t   plen;
    char     ua[48];
    size_t   ulen;
} lesson_t;



/* path tanpa query/fragmen, huruf kecil, tanpa garis miring penutup */

static void learn_load(const char *path)
{
    (void)path;                 /* edisi Free: pelajaran dari keputusan operator adalah fitur Pro */
    g_les_n = 0; g_les_block = 0; g_les_allow = 0;
}

typedef struct { int skip_path, skip_ua, skip_distinct, block_idx; } learn_res_t;

static void learn_match(const parsed_t *r, learn_res_t *out)
{
    (void)r;                    /* edisi Free: tidak ada pelajaran */
    out->skip_path = out->skip_ua = out->skip_distinct = 0;
    out->block_idx = -1;
}


/* Penanda eksploit pada path ternormalisasi: dotfile rahasia, marker webshell, traversal ke /etc/passwd, endpoint debug framework.
 * Dipakai jalur IPv4 dan IPv6 supaya klasifikasi keduanya sama. */
static int ada_penanda_eksploit(const char *np, size_t npl)
{
    return memmem(np, npl, "/.", 2) != NULL
        || memmem(np, npl, "shell", 5) != NULL
        || memmem(np, npl, "c99", 3) != NULL
        || memmem(np, npl, "r57", 3) != NULL
        || memmem(np, npl, "eval-stdin", 10) != NULL
        || memmem(np, npl, "/etc/passwd", 11) != NULL
        || memmem(np, npl, "_ignition", 9) != NULL;
}

/* ------------------------------------------------------------------ *
 * IPv6 (T-152, 29 Okt 2026): tabel skor utama hanya IPv4, jadi pengunjung IPv6 dinilai di tabel kecil terpisah per prefix /64
 * (satu pelanggan biasanya memegang satu /64; memblokir alamat tunggal mudah dihindari dengan rotasi alamat). Sengaja KONSERVATIF:
 * hanya sinyal yang jelas jahat (path pemindai/eksploit yang ditolak server atau bermarker eksploit, User-Agent alat serangan),
 * tanpa hitungan flood/brute yang rawan salah di CDN/NAT. Rentang CDN, alamat lokal, alamat server sendiri, sesi login aktif, dan
 * rentang IPv6 di proxy_file tidak pernah dinilai. Blokir masuk ipset sentinel_ban6 (hash:net inet6, DROP di ip6tables oleh
 * sentinel-fw.sh), dengan gerbang yang sama dengan IPv4 (cfg.enforce = konfigurasi DAN lisensi).
 * ------------------------------------------------------------------ */
#define V6_MAKS 4096
#define V6_RESET_DETIK 600
typedef struct { uint64_t pfx; uint32_t last, ban_until; uint16_t scan, badua; uint8_t dipakai; } v6_ent;
static v6_ent   g_v6[V6_MAKS];
#define V6_KECUALI_MAKS 192
static uint64_t g_v6x_net[V6_KECUALI_MAKS];
static int      g_v6x_len[V6_KECUALI_MAKS];
static int      g_v6x_n = 0, g_v6x_bawaan = 0;
static time_t   g_v6x_ts = 0;
static void notif_tambah(uint32_t ip, const char *jenis, const char *isi);

static uint64_t v6_pfx(const struct in6_addr *a)
{
    uint64_t p = 0;
    for (int i = 0; i < 8; i++) p = (p << 8) | a->s6_addr[i];
    return p;
}

static void v6x_tambah(const char *teks, int len)
{
    struct in6_addr a;
    if (g_v6x_n >= V6_KECUALI_MAKS || inet_pton(AF_INET6, teks, &a) != 1) return;
    if (len < 0 || len > 64) len = 64;                      /* lebih sempit dari /64 = seluruh /64 dikecualikan */
    uint64_t m = len ? (~0ULL << (64 - len)) : 0;
    g_v6x_net[g_v6x_n] = v6_pfx(&a) & m;
    g_v6x_len[g_v6x_n++] = len;
}

/* Baris IPv6 dari proxy_file/allowlist: "alamat[/panjang]". Panjang wajib angka 16..128 (lebih sempit dari /64 = seluruh /64); yang lain
 * ditolak dengan pesan. Dulu "/0" atau "/abc" dibaca atoi sebagai 0: SEMUA IPv6 dikecualikan tanpa pesan (evaluasi 30 Okt 2026). */
static void v6x_muat_berkas(const char *path)
{
    FILE *f = path && path[0] ? fopen(path, "re") : NULL;
    if (!f) return;
    char ln[256];
    while (fgets(ln, sizeof(ln), f)) {
        char *p = ln;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || !strchr(p, ':')) continue;
        char *e = p + strcspn(p, " \t\r\n#"); *e = '\0';
        char *sl = strchr(p, '/');
        int len = 64;
        if (sl) {
            *sl = '\0';
            char *akhir = NULL;
            long v = strtol(sl + 1, &akhir, 10);
            if (!sl[1] || *akhir || v < 16 || v > 128) {
                static time_t peringatan = 0;
                if (now_t() - peringatan > 3600) {
                    logmsg("PERINGATAN: rentang IPv6 %s/%s di %s diabaikan (panjang prefix harus 16..128)", p, sl + 1, path);
                    peringatan = now_t();
                }
                continue;
            }
            len = (int)v;
        }
        v6x_tambah(p, len);
    }
    fclose(f);
}

/* Muat ulang pengecualian dinamis tiap 60 detik: alamat server sendiri, sesi login aktif (utmp), rentang IPv6 di proxy_file dan allowlist. */
static void v6x_muat(time_t now)
{
    if (g_v6x_ts && now - g_v6x_ts < 60) return;
    g_v6x_ts = now;
    if (!g_v6x_bawaan) {
        static const char *const bawaan[][2] = {
            { "2400:cb00::", "32" }, { "2606:4700::", "32" }, { "2803:f800::", "32" }, { "2405:b500::", "32" },   /* Cloudflare */
            { "2405:8100::", "32" }, { "2a06:98c0::", "29" }, { "2c0f:f248::", "32" },
            { "2a04:4e40::", "32" },                                                                         /* Fastly */
            { "fe80::", "10" }, { "fc00::", "7" }, { "::", "8" }, { "ff00::", "8" },                         /* lokal, khusus */
        };
        for (size_t i = 0; i < sizeof(bawaan) / sizeof(bawaan[0]); i++) v6x_tambah(bawaan[i][0], atoi(bawaan[i][1]));
        g_v6x_bawaan = g_v6x_n;
    }
    g_v6x_n = g_v6x_bawaan;
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) == 0) {
        for (struct ifaddrs *q = ifa; q; q = q->ifa_next) {
            if (!q->ifa_addr || q->ifa_addr->sa_family != AF_INET6) continue;
            char b[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)q->ifa_addr)->sin6_addr, b, sizeof(b))) v6x_tambah(b, 64);
        }
        freeifaddrs(ifa);
    }
    struct utmpx *u;
    setutxent();
    while ((u = getutxent()) != NULL) {
        if (u->ut_type != USER_PROCESS || !(u->ut_addr_v6[1] || u->ut_addr_v6[2] || u->ut_addr_v6[3])) continue;
        char b[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, u->ut_addr_v6, b, sizeof(b))) v6x_tambah(b, 64);
    }
    endutxent();
    v6x_muat_berkas(cfg.proxy_file);
    v6x_muat_berkas(cfg.allow_file);        /* allowlist berlaku juga untuk IPv6 (baris berisi ':'), sama dengan IPv4 */
}

static int v6_dikecualikan(uint64_t pfx)
{
    for (int i = 0; i < g_v6x_n; i++) {
        uint64_t m = g_v6x_len[i] ? (~0ULL << (64 - g_v6x_len[i])) : 0;
        if ((pfx & m) == g_v6x_net[i]) return 1;
    }
    return 0;
}

static v6_ent *v6_get(uint64_t pfx, time_t now)
{
    uint32_t h = (uint32_t)((pfx * 0x9E3779B97F4A7C15ULL) >> 52) & (V6_MAKS - 1);
    v6_ent *tua = NULL;
    for (int i = 0; i < 32; i++) {
        v6_ent *e = &g_v6[(h + i) & (V6_MAKS - 1)];
        if (e->dipakai && e->pfx == pfx) return e;
        if (!e->dipakai) { memset(e, 0, sizeof(*e)); e->dipakai = 1; e->pfx = pfx; e->last = (uint32_t)now; return e; }
        if ((!tua || e->last < tua->last) && e->ban_until < (uint32_t)now) tua = e;
    }
    if (tua && (uint32_t)now - tua->last >= V6_RESET_DETIK) {   /* lingkaran penuh: pakai ulang entri lama yang tidak sedang diblokir */
        memset(tua, 0, sizeof(*tua)); tua->dipakai = 1; tua->pfx = pfx; tua->last = (uint32_t)now; return tua;
    }
    return NULL;
}

/* Agregasi /48 (evaluasi 30 Okt 2026): penyerang yang memegang /48 bisa berganti /64 setelah diblokir, dan tabel /64 (V6_MAKS) bisa
 * dipenuhi ribuan /64 sehingga penilaian buta. Tabel /48 menghitung /64 yang diblokir (>= V6_48_N64 dalam jendela = /48 diblokir) dan
 * menjadi penilai cadangan saat tabel /64 penuh, dengan ambang dua kali lipat. /48 yang memuat rentang dikecualikan tidak diblokir. */
#define V6_48_MAKS 1024
#define V6_48_N64 3
#define V6_48_JENDELA 3600
static v6_ent   g_v6a[V6_48_MAKS];                  /* pfx = 48 bit atas, scan/badua = penilaian cadangan, ban_until = blokir /48 */
static uint16_t g_v6a_n64[V6_48_MAKS];

static v6_ent *v6a_get(uint64_t p48, time_t now, uint16_t **n64)
{
    uint32_t h = (uint32_t)((p48 * 0x9E3779B97F4A7C15ULL) >> 54) & (V6_48_MAKS - 1);
    v6_ent *tua = NULL;
    for (int i = 0; i < 32; i++) {
        uint32_t k = (h + i) & (V6_48_MAKS - 1);
        v6_ent *e = &g_v6a[k];
        if (e->dipakai && e->pfx == p48) { *n64 = &g_v6a_n64[k]; return e; }
        if (!e->dipakai || ((!tua || e->last < tua->last) && e->ban_until < (uint32_t)now && (uint32_t)now - e->last >= V6_48_JENDELA)) {
            if (!e->dipakai) { memset(e, 0, sizeof(*e)); e->dipakai = 1; e->pfx = p48; e->last = (uint32_t)now; g_v6a_n64[k] = 0; *n64 = &g_v6a_n64[k]; return e; }
            tua = e;
        }
    }
    if (!tua) return NULL;
    uint32_t k = (uint32_t)(tua - g_v6a);
    memset(tua, 0, sizeof(*tua)); tua->dipakai = 1; tua->pfx = p48; tua->last = (uint32_t)now; g_v6a_n64[k] = 0;
    *n64 = &g_v6a_n64[k];
    return tua;
}


static void v6_proses(const char *s, size_t len, time_t now)
{
    size_t k = 0;
    while (k < len && k < 63 && s[k] != ' ') k++;
    if (k == 0 || k >= 63 || k >= len) return;
    char a[64];
    memcpy(a, s, k); a[k] = '\0';
    struct in6_addr in;
    if (inet_pton(AF_INET6, a, &in) != 1) return;
    uint64_t pfx = v6_pfx(&in);
    if (v6_dikecualikan(pfx)) return;
    /* sisa baris di-parse dengan parser combined yang sama: alamat diganti IPv4 tiruan */
    char buf[SENT_LINE_MAX + 16];
    size_t rest = len - k;
    if (rest > SENT_LINE_MAX) rest = SENT_LINE_MAX;
    memcpy(buf, "0.0.0.1", 7);
    memcpy(buf + 7, s + k, rest);
    parsed_t r;
    if (!parse_line(buf, 7 + rest, &r)) return;
    char np[256];
    size_t npl = path_norm(r.path, r.path_len, np, sizeof(np));
    learn_res_t lr;                                     /* pelajaran Izin operator berlaku juga untuk IPv6 (path/UA yang diizinkan) */
    learn_match(&r, &lr);
    int scan = !lr.skip_path && path_is_scanner(np, npl) && (r.status >= 400 || ada_penanda_eksploit(np, npl));
    int bad = !lr.skip_ua && !g_line_truncated && ua_is_tool_copy(r.ua, r.ua_len);
    if (!scan && !bad) return;
    uint64_t p48 = pfx & 0xFFFFFFFFFFFF0000ULL;
    uint16_t *n64 = NULL;
    v6_ent *e = v6_get(pfx, now);
    int cadangan = !e;
    if (cadangan) {
        e = v6a_get(p48, now, &n64);                    /* tabel /64 penuh: nilai per /48, ambang dua kali lipat */
        if (!e) return;
    }
    if ((uint32_t)now - e->last > V6_RESET_DETIK) { e->scan = 0; e->badua = 0; }
    e->last = (uint32_t)now;
    if (scan && e->scan < 65535) e->scan++;
    if (bad && e->badua < 65535) e->badua++;
    uint32_t sc = (uint32_t)(e->scan > cfg.cap_scan ? cfg.cap_scan : e->scan) * (uint32_t)cfg.w_scan
                + (uint32_t)(e->badua > cfg.cap_badua ? cfg.cap_badua : e->badua) * (uint32_t)cfg.w_badua;
    uint32_t ambang = (uint32_t)cfg.ban_score * (cadangan ? 2u : 1u);
    if (sc < ambang || e->ban_until > (uint32_t)now) return;
    (void)n64; (void)p48;
}

static void process_line(tailer_t *t, const char *s, size_t len, time_t now);

static void process_line(tailer_t *t, const char *s, size_t len, time_t now)
{
    parsed_t r;
    if (!parse_line(s, len, &r)) {
        /* IPv6: token pertama memuat ':' sebelum spasi (mis. 2001:db8::1 - - [..]) */
        size_t k = 0;
        while (k < len && k < 46 && s[k] != ' ' && s[k] != ':') k++;
        if (k < len && s[k] == ':' && k > 0 && k < 46 && isxdigit((unsigned char)s[0])) { g_stat_ipv6_skip++; v6_proses(s, len, now); }
        else g_stat_parse_fail++;
        return;
    }
    /* Kepala baris kepanjangan: kutipan terakhir bukan UA, jangan dinilai. */
    if (g_line_truncated) { r.ua = ""; r.ua_len = 0; }

    if (r.ip == 0) return;

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

    /* IP tepi proxy/CDN tepercaya (web server tanpa real IP): dihitung di statistik situs, TIDAK dinilai per IP */
    if (is_proxy(r.ip)) { g_stat_proxy++; return; }

    ip_ent *e = ip_get(r.ip, now);
    if (!e) { g_stat_dropped_cap++; return; }

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
    e->last_status = (uint16_t)r.status;
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

    /* --- pelajaran dari keputusan operator --- */
    learn_res_t lr;
    learn_match(&r, &lr);

    /* --- klasifikasi --- */
    if (r.status == 404 || r.status == 400 || r.status == 401 ||
        r.status == 403 || r.status == 429 || r.status == 499) {
        if (e->e404 < 65535) e->e404++;
        if (!lr.skip_path && !lr.skip_distinct && path_unlisted(r.path, r.path_len)) {
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

    char np[256];
    size_t npl = path_norm(r.path, r.path_len, np, sizeof(np));
    /* Scanner dihitung bila server menolak (4xx/5xx), atau bila path memuat
     * dotfile rahasia atau marker webshell/eksploitasi apa pun status kodenya. */
    int exploit_marker = ada_penanda_eksploit(np, npl);
    if (!lr.skip_path && path_is_scanner(np, npl)
        && (r.status >= 400 || exploit_marker)) {
        if (e->scan < 65535) e->scan++;
    }
    if (!lr.skip_path && path_is_brute(np, npl) &&
        (r.status == 401 || r.status == 403 || r.status == 429 ||
         r.status == 400 || r.status == 404 || r.status == 499 ||
         /* login WordPress gagal menjawab 200; POST ke sana selalu dihitung */
         (!strcmp(r.method, "POST") && !strncmp(np, "/wp-login", 9)))) {
        if (e->brute < 65535) e->brute++;
    }
    if (!lr.skip_ua && ua_is_tool_copy(r.ua, r.ua_len)) {
        if (e->badua < 65535) e->badua++;
    }

    /* Kecocokan pelajaran blokir dihitung dalam jendela 60 detik; begitu
     * cukup, IP diblokir seketika (tidak menunggu sweep berikutnya). */

    /* --- ip_minute: satu baris per (MENIT, IP). Dulu ts = detik, sehingga satu baris per detik per IP (jutaan baris
     *     dalam retensi 3 hari). Digabung di batch: entri terbaru untuk IP+menit yang sama dicari di ekor batch. --- */
    {
        uint32_t tm = (uint32_t)(now - now % 60);
        int gab = 0;
        for (int i = g_ipmin_n - 1; i >= 0 && i >= g_ipmin_n - 64; i--) {
            ipmin_t *m = &g_ipmin[i];
            if (m->ip == r.ip && m->ts == tm) {
                m->req++;
                if (e->score > m->score) m->score = e->score;
                gab = 1;
                break;
            }
        }
        if (!gab && g_ipmin_n < MAX_IPMIN_BATCH) {
            ipmin_t *m = &g_ipmin[g_ipmin_n++];
            m->ip = r.ip; m->ts = tm; m->req = 1; m->score = e->score;
        }
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
    /* redam penghitung berkala: setengah setiap decay_seconds (bawaan 60 detik) supaya IP yang
     * sudah berhenti langsung kehilangan skor tanpa perlu dihapus dari tabel */
    static time_t last_decay = 0;
    if (now - last_decay >= cfg.decay_seconds) {
        int steps = (int)((now - last_decay) / cfg.decay_seconds);
        if (steps < 1) steps = 1;
        if (steps > 10) steps = 10;
        for (int b = 0; b < IP_BUCKETS; b++) {
            ip_ent *e;
            for (e = g_buckets[b]; e; e = e->next) {
                for (int k = 0; k < steps && k < 8; k++) {
                    e->scan >>= 1; e->brute >>= 1; e->badua >>= 1;
                    e->distinct >>= 1; e->e404 >>= 1;
                }
                e->npath = 0;
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
            uint8_t kind = kind_of(e);

            /* FLOOD per IP. Dulu laju hanya membuat event dan tidak pernah
             * menambah skor: 200 permintaan/detik "GET /" tetap skor 0.
             * Batas dihitung dari jendela 64 detik (rata-rata), jadi
             * lonjakan sesaat halaman berat tidak terkena. 0 = mati. */
            if (cfg.flood_ban_req > 0 && e->req_window >= (uint32_t)cfg.flood_ban_req) {
                e->score += (uint32_t)cfg.ban_score;
                kind = K_FLOOD;
            } else if (cfg.flood_throttle_req > 0
                       && e->req_window >= (uint32_t)cfg.flood_throttle_req) {
                e->score += (uint32_t)cfg.throttle_score;
                if (kind == K_NONE) kind = K_FLOOD;
            }
            if (e->score > 60000) e->score = 60000;
            if (e->score > e->peak) e->peak = e->score;

            /* Level turun lagi begitu skor reda dan tidak ada ban/throttle
             * yang masih berlaku. Dulu level hanya pernah naik: IP yang
             * pernah WATCH tidak bisa digusur dari tabel (penyerang bisa
             * memenuhinya dan membutakan daemon) dan IP yang pernah di-
             * throttle tidak pernah di-throttle lagi. */
            if (e->score < (uint32_t)cfg.watch_score && e->level != LVL_NORMAL) {
                ban_t *bx = ban_find(e->ip);
                if (!bx || bx->until < now) { e->level = LVL_NORMAL; e->reviewed = 0; }
            }

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
                        e->last_ua, strlen(e->last_ua), e->last_status);
            } else if (!diaperlukannya && rps > 40
                       && e->last_ev + 30 <= (uint32_t)now) {
                g_stat_flood++;
                e->last_ev = (uint32_t)now;
                ev_push((uint32_t)now, e->ip, (uint16_t)(e->score + 40), LVL_WATCH,
                        K_FLOOD, e->last_host, e->last_path, strlen(e->last_path),
                        e->last_ua, strlen(e->last_ua), e->last_status);
            }

            int blocked = diaperlukannya;
            if (blocked) {
                e->level = LVL_NORMAL;
            } else if (cfg.review_score > 0
                       && e->score >= (uint32_t)cfg.review_score
                       && !cfg.enforce && !e->reviewed) {
                /* Hanya saat pemblokiran otomatis dimatikan. Kalau
                   enforce = 1, ambang ban sudah lebih tinggi dan
                   antrian hanya menambah langkah yang tidak perlu. */
                char alasan[140];
                snprintf(alasan, sizeof(alasan),
                         "skor=%u kategori=%s rps=%u request=%u 4xx=%u",
                         e->score, KIND_NAME[kind], rps, e->req_window, e->s4);
                review_tambah(e->ip, e->score, alasan);
                e->level = LVL_WATCH;
                e->reviewed = 1;
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
    g_cfg_def = cfg;
    cfg_load(cfg_pilih(conf));
    g_cfg_conf = cfg;

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
    int lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0640);
    if (lockfd >= 0 && flock(lockfd, LOCK_EX | LOCK_NB) != 0)
        die("guardd sudah berjalan (kunci_instans dipegang: %s)", lockpath);

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGHUP, on_hup);
    signal(SIGPIPE, SIG_IGN);

    g_buckets = xcalloc(IP_BUCKETS, sizeof(ip_ent *));
    allow_init();
    allow_load_file(cfg.allow_file);
    proxy_load(cfg.proxy_file);
    lic_refresh(now_t(), 2);
    learn_load(cfg.learn_file);

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
    /* Set review juga dipastikan ada: tanpa set ini penanda review gagal
     * diam-diam bila daemon mulai sebelum sentinel-fw.sh. */
    ipset_ensure("sentinel_review", 43200);
    ban_restore(g_start);

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
        sesi_admin_muat(now);
        v6x_muat(now);

        {   /* gerbang lisensi: cek ulang tiap 30 dtk; perubahan paket berlaku tanpa restart */
            unsigned m0 = g_lic_mask;
            lic_refresh(now, 0);
            if (m0 != g_lic_mask) learn_load(cfg.learn_file);
        }

        if (g_rescan || (now - last_rescan >= cfg.rescan_interval)) {
            rediscover();
            /* Muat ulang allowlist setiap siklus penemuan, supaya IP
             * yang ditambahkan lewat panel langsung berlaku tanpa
             * perlu me-restart daemon. */
            allow_load_file(cfg.allow_file);
            proxy_load(cfg.proxy_file);
            learn_load(cfg.learn_file);
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
                /* fd lama ditutup SEKALI lalu ditandai -1. Dulu nomornya dibiarkan: bila open() baru gagal atau berkas
                 * baru bukan berkas biasa (FIFO tanam penyerang), siklus berikut menutup nomor yang sama lagi, yang
                 * sudah dipakai berkas lain (log vhost lain atau fd SQLite). tailer_retry membukanya ulang. */
                close(t->fd);
                t->fd = -1;
                int nfd = buka_log(t->path);
                if (nfd < 0) { t->degraded = 1; continue; }
                struct stat nst;
                if (fstat(nfd, &nst) != 0 || !S_ISREG(nst.st_mode)) { close(nfd); t->degraded = 1; continue; }
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
                /* Rotasi aaPanel memakai rename (inode baru, ditangani di atas); pemotongan di tempat berarti logrotate
                 * copytruncate ATAU penghapusan isi log oleh pemilik direktori log (akun web) untuk menyembunyikan
                 * jejak dari deteksi. Admin diberi tahu supaya bisa memeriksa. */
                if (!t->potong_ts || now - t->potong_ts >= 600) {
                    char n[PATH_MAX + 200];
                    snprintf(n, sizeof(n), "Log akses %s terpotong di luar rotasi. Bila bukan logrotate copytruncate, "
                             "periksa proses milik akun web: isi log yang dihapus membuat deteksi kehilangan jejak.", t->path);
                    notif_tambah(0, "log-terpotong", n);
                    t->potong_ts = now;
                }
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

                /* Baris yang lebih panjang dari SENT_LINE_MAX (Referer atau
                 * UA raksasa, sepenuhnya dikendalikan klien) dulu dibuang
                 * utuh, sehingga penyerang cukup menambah header 4 KB untuk
                 * tidak pernah dinilai. Sekarang KEPALA baris (IP, request,
                 * status ada di awal) tetap dinilai dan ekornya dilewati
                 * sampai baris baru. */
                size_t off = 0;
                while (off < (size_t)n) {
                    if (t->skip_nl) {
                        char *nl = memchr(g_readbuf + off, '\n', (size_t)n - off);
                        if (!nl) { off = (size_t)n; break; }
                        off = (size_t)(nl - g_readbuf) + 1;
                        t->skip_nl = 0;
                        continue;
                    }
                    size_t room = SENT_LINE_MAX - t->carry_len;
                    size_t take = (size_t)n - off < room ? (size_t)n - off : room;
                    memcpy(t->carry + t->carry_len, g_readbuf + off, take);
                    off += take;
                    size_t len = t->carry_len + take;

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
                    if (t->carry_len == SENT_LINE_MAX) {
                        t->carry[SENT_LINE_MAX] = '\0';
                        g_line_truncated = 1;
                        process_line(t, t->carry, SENT_LINE_MAX, now);
                        g_line_truncated = 0;
                        g_stat_long_lines++;
                        lines++; lines_file++;
                        t->carry_len = 0;
                        t->skip_nl = 1;
                    }
                }
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
