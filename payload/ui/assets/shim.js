// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
/* Shim kecil agar fragmen dasbor (index.html) yang ditulis untuk aaPanel berjalan di UI standalone.
   Menyediakan getCookie dan bt.* minimal; semua panggilan data tetap lewat snAjax -> /plugin. */
(function(){
  window.getCookie = function(n){
    var m = document.cookie.match(new RegExp('(?:^|; )' + n.replace(/[.$?*|{}()\[\]\\\/+^]/g, '\\$&') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
  };
  window.bt = window.bt || {
    soft: {},
    load: function(t){ return layer.msg(t || '...', {icon: 16, time: 0, shade: 0.1}); },
    open: function(o){ return layer.open(o); },
    send: function(){ if(window.console) console.warn('[sentinel] bt.send tidak tersedia di mode standalone'); }
  };
})();
