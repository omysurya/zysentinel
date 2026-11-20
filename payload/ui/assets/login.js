// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
(function(){
  var body = document.body, mode = body.getAttribute('data-mode');
  var lang = (navigator.language || 'en').toLowerCase().indexOf('id') === 0 ? 'id' : 'en';
  document.documentElement.lang = lang;
  function t(el){ return el.getAttribute('data-' + lang) || el.textContent; }
  if(mode === 'app'){
    document.getElementById('zys-app').hidden = false;
    /* Dasbor ini ditulis sebagai dialog yang bisa ditutup di dalam aaPanel. Di UI standalone ia adalah halaman utama:
       menutupnya (silang, klik latar, tombol Esc, atau kode lain) hanya menyisakan halaman kosong. Jadi penutupan
       dimatikan di sini, tanpa mengubah index.html yang dipakai bersama dengan versi aaPanel. Gantinya: tombol Keluar. */
    var noop = function(){ return false; };
    window.snTutup = noop;
    window.snTutupLapis = noop;
    document.addEventListener('click', function(e){
      if(e.target && e.target.id === 'snBack'){ e.stopImmediatePropagation(); e.preventDefault(); }
    }, true);
    /* Penjaga terakhir: bila ada jalur lain yang menyembunyikan #snModal, pulihkan seketika. Dipasang setelah modal
       pertama kali tampil agar tidak mendahului inisialisasi dasbor. */
    var armTries = 0;
    (function arm(){
      var m = document.getElementById('snModal');
      if(!m){ return; }
      if(!m.classList.contains('on')){ if(armTries++ < 100){ setTimeout(arm, 200); } return; }
      if(!window.MutationObserver){ return; }
      new MutationObserver(function(){
        if(!m.classList.contains('on') || m.style.display === 'none'){ m.classList.add('on'); m.style.display = ''; }
      }).observe(m, {attributes: true, attributeFilter: ['class', 'style']});
    })();

    /* ---- Keluar (logout) --------------------------------------------------------------------------------------------
       Tujuan: tidak ada sisa yang bisa dipakai orang lain di browser ini. Server menghapus sesi dan mengirim
       Clear-Site-Data (cache, cookie, storage). Di sisi halaman: token CSRF dibuang dari DOM, isi dasbor dikosongkan,
       penyimpanan lokal dibersihkan, dan halaman diganti (replace) supaya tombol Kembali tidak membuka dasbor lagi. */
    var keluarTxt = lang === 'id' ? 'Keluar' : 'Logout';
    var keluarTip = lang === 'id' ? 'Keluar dan akhiri sesi di server' : 'Sign out and end the server session';
    var sudahKeluar = false;
    /* Ikon pintu-keluar (SVG inline, warna mengikuti teks; tidak bergantung pada font). Teks tombol tetap konstanta di atas. */
    var ikonKeluar = '<svg class="zys-ico" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
    function isiTombol(el){ el.innerHTML = ikonKeluar + '<span>' + keluarTxt + '</span>'; }
    function bersihkan(){
      try{ var t = document.getElementById('request_token_head'); if(t){ t.removeAttribute('token'); t.remove(); } }catch(e){}
      try{ var a = document.getElementById('zys-app'); if(a){ a.hidden = true; a.innerHTML = ''; } }catch(e){}
      try{ window.localStorage.clear(); }catch(e){}
      try{ window.sessionStorage.clear(); }catch(e){}
    }
    function keluar(alasan){
      if(sudahKeluar){ return; }
      sudahKeluar = true;
      /* hentikan polling dasbor agar tidak menyentuh server dengan sesi yang sedang dicabut */
      for(var k in window){ try{ if(/^SN_.*(TIMER|POLL|TICKER)$/.test(k) && window[k]){ clearInterval(window[k]); } }catch(e){} }
      var selesai = function(){ bersihkan(); window.location.replace('/'); };
      try{
        fetch('/api/logout', {method: 'POST', credentials: 'same-origin', cache: 'no-store', keepalive: true,
          headers: {'Content-Type': 'application/json'}, body: '{}'}).then(selesai, selesai);
      }catch(e){ selesai(); }
    }
    window.zysKeluar = keluar;
    var host = document.querySelector('#snModal .sn-mhead');
    if(host){
      var b = document.createElement('button');
      b.id = 'zysLogout'; b.type = 'button'; b.className = 'sn-btn sn-sm zys-logout';
      b.title = keluarTip; b.setAttribute('aria-label', keluarTip); isiTombol(b);
      var x = host.querySelector('.sn-mclose');
      if(x){ host.insertBefore(b, x); } else { host.appendChild(b); }
    } else {
      /* kerangka header tidak ditemukan (UI berubah): tombol tetap harus ada, apung di pojok kanan atas */
      var f = document.createElement('button');
      f.id = 'zysLogout'; f.type = 'button'; f.className = 'zys-logout zys-logout-float'; isiTombol(f); f.title = keluarTip;
      document.body.appendChild(f);
    }
    document.addEventListener('click', function(e){
      var t = e.target && e.target.closest ? e.target.closest('#zysLogout') : null;
      if(t){ e.preventDefault(); keluar('klik'); }
    });
    /* Sesi berakhir di server (kedaluwarsa, logout dari tab lain, restart uid): kembali ke halaman login, jangan
       biarkan dasbor tampil dengan data basi. */
    if(window.jQuery){
      window.jQuery(document).ajaxError(function(ev, xhr){ if(xhr && xhr.status === 401){ sudahKeluar = true; bersihkan(); window.location.replace('/'); } });
    }
    /* Tidak aktif 30 menit (sama dengan batas server): keluar otomatis. Polling dasbor memperpanjang sesi di server,
       jadi batas aktivitas pengguna dijaga di sini. */
    var terakhir = Date.now();
    ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel'].forEach(function(n){
      document.addEventListener(n, function(){ terakhir = Date.now(); }, {passive: true, capture: true});
    });
    setInterval(function(){ if(Date.now() - terakhir > 30 * 60 * 1000){ keluar('idle'); } }, 15000);
    /* Halaman dipulihkan dari cache bolak-balik (bfcache) setelah keluar: paksa muat ulang agar tidak menampilkan dasbor. */
    window.addEventListener('pageshow', function(e){ if(e.persisted){ window.location.reload(); } });
    return;
  }
  var box = document.getElementById('zys-login'); box.hidden = false;
  [].forEach.call(box.querySelectorAll('[data-en]'), function(el){ el.textContent = t(el); });
  var form = document.getElementById('zys-login-form'), err = document.getElementById('zys-err'),
      btn = document.getElementById('zys-submit'), otpRow = document.getElementById('zys-otp-row');
  var msgs = {
    bad_login: ['Login failed.', 'Login gagal.'],
    locked: ['Too many failed attempts. Try again later.', 'Terlalu banyak percobaan gagal. Coba lagi nanti.'],
    need_otp: ['Enter the code from your authenticator app.', 'Masukkan kode dari aplikasi autentikator.'],
    net: ['The service is not reachable.', 'Layanan tidak dapat dihubungi.']
  };
  function show(code){ var m = msgs[code] || msgs.bad_login; err.textContent = m[lang === 'id' ? 1 : 0]; err.hidden = false; }
  form.addEventListener('submit', function(ev){
    ev.preventDefault(); err.hidden = true; btn.disabled = true;
    fetch('/api/login', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({user: form.username.value, password: form.password.value, otp: form.otp.value})})
    .then(function(r){ return r.json(); })
    .then(function(r){
      if(r.status){ form.reset(); location.reload(); return; }
      if(r.code === 'need_otp'){ otpRow.hidden = false; document.getElementById('zys-otp').focus(); }
      show(r.code); btn.disabled = false; form.password.value = ''; form.otp.value = '';
    })
    .catch(function(){ show('net'); btn.disabled = false; });
  });
})();
