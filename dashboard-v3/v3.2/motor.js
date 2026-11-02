/*! dashboard-mikio v3.2 · motor de relatórios HTML
 *  Lê window.RELATORIO (JSON) e monta o dashboard inteiro.
 *  Paleta e tipografia da v2 (Valid, SGA, SENVS). Não contém dado de cliente.
 */
(function () {
  'use strict';

  /* ---------- base ---------- */
  var SCRIPT = document.currentScript;
  var BASE = SCRIPT ? SCRIPT.src.replace(/[^\/]*$/, '') : './';
  var R = window.RELATORIO;
  var root = document.documentElement;
  var REDUZ = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  var ASSINATURAS = {
    sga:   { empresa: 'SGA',   nome: 'Mikio Nakamaru', cargo: 'Cybersecurity Specialist',        email: 'mikio.nakamaru@sga.com.br', logo: 'logos/sga.svg' },
    valid: { empresa: 'Valid', nome: 'Mikio Nakamaru', cargo: 'Information Security Analyst II', email: 'felipe.nakamaru@valid.com', logo: 'logos/valid.webp' },
    senvs: { empresa: 'SENVS', nome: 'Mikio Nakamaru', cargo: '',                                email: 'mikio.nakamaru@senvs.com',  logo: 'logos/senvs.webp' }
  };
  var LINKEDIN = 'https://www.linkedin.com/in/mikionakamaru/';
  var CORES = ['var(--ink)', '#4BB1EA', '#9C7AD2', '#71E4D1', '#F6F183', '#9A9A9A', '#3C3C3C'];
  var ICO_COR = ['c-teal', 'c-blue', 'c-purple', 'c-yellow'];

  function falha(msg) {
    document.body.innerHTML = '<div style="font-family:system-ui,Arial;max-width:640px;margin:60px auto;padding:24px;border-radius:14px;background:#FBF6C9;color:#000"><b>O relatório não pôde ser montado.</b><br>' + esc(msg) + '</div>';
  }
  if (!R || typeof R !== 'object') { falha('O bloco window.RELATORIO não foi encontrado no arquivo.'); return; }
  var ASS = ASSINATURAS[String(R.empresa || '').toLowerCase()];
  if (!ASS) { falha('O campo "empresa" deve ser "sga", "valid" ou "senvs".'); return; }
  if (!R.paginas || !R.paginas.length) { falha('O relatório não tem páginas (campo "paginas").'); return; }

  /* ---------- utilidades ---------- */
  function $(s, c) { return (c || document).querySelector(s); }
  function $$(s, c) { return [].slice.call((c || document).querySelectorAll(s)); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  /* texto com **negrito** e [link](#/pagina) */
  function rico(s) {
    return esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/\[([^\]]+)\]\((#\/[a-z0-9\-]+)\)/gi, '<a href="$2">$1</a>');
  }
  function slug(s) { return String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''); }
  /* número: aceita 68.6 (JSON), "68.6" e "1.234,5" (formato brasileiro) */
  function num(v) {
    if (typeof v === 'number') return isFinite(v) ? v : 0;
    var t = String(v == null ? '' : v).trim().replace(/[^\d,.\-]/g, '');
    if (/^-?\d+(\.\d+)?$/.test(t)) return parseFloat(t);
    var n = parseFloat(t.replace(/\./g, '').replace(',', '.'));
    return isFinite(n) ? n : 0;
  }
  function soma(a) { return a.reduce(function (x, y) { return x + num(y); }, 0); }
  var NF = {
    int: new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 0 }),
    dec1: new Intl.NumberFormat('pt-BR', { minimumFractionDigits: 1, maximumFractionDigits: 1 }),
    dec2: new Intl.NumberFormat('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
    brl: new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL', maximumFractionDigits: 0 }),
    compact: new Intl.NumberFormat('pt-BR', { notation: 'compact', maximumFractionDigits: 1 })
  };
  function fmt(v, f) {
    v = num(v);
    switch (f) {
      case 'pct0': return NF.int.format(v) + '%';
      case 'pct1': return NF.dec1.format(v) + '%';
      case 'dec1': return NF.dec1.format(v);
      case 'dec2': return NF.dec2.format(v);
      case 'brl': return NF.brl.format(v);
      case 'x': return NF.dec1.format(v) + '×';
      case 'compact': return NF.compact.format(v);
      default: return NF.int.format(v);
    }
  }
  function isoData(s) { return /^\d{4}-\d{2}-\d{2}/.test(String(s)); }
  function dataCurta(s) { return isoData(s) ? new Date(String(s).slice(0, 10) + 'T12:00').toLocaleDateString('pt-BR', { day: '2-digit', month: 'short' }).replace('.', '') : String(s); }
  function dataBR(s) { return isoData(s) ? new Date(String(s).slice(0, 10) + 'T12:00').toLocaleDateString('pt-BR') : String(s == null ? '' : s); }
  function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
  function aviso(msg) { var t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(aviso._t); aviso._t = setTimeout(function () { t.classList.remove('show'); }, 2600); }

  function countTo(el, to, opt) {
    opt = opt || {}; var f = opt.fmt || el.dataset.fmt || 'int';
    var from = opt.from != null ? opt.from : num(el.dataset.current || 0);
    var dur = opt.dur || (900 + Math.min(500, String(Math.round(Math.abs(to))).length * 60));
    el.dataset.current = to; el.dataset.fmt = f;
    if (REDUZ || from === to) { el.textContent = fmt(to, f); return; }
    if (opt.flash) { el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }
    var t0 = performance.now(); cancelAnimationFrame(el._raf);
    (function step(now) { var p = Math.min(1, (now - t0) / dur); el.textContent = fmt(from + (to - from) * easeOut(p), f); if (p < 1) el._raf = requestAnimationFrame(step); })(t0);
  }
  function tween(dur, fn) { if (REDUZ) { fn(1); return; } var t0 = performance.now(); (function s(n) { var p = Math.min(1, (n - t0) / dur); fn(easeOut(p)); if (p < 1) requestAnimationFrame(s); })(t0); }

  var ICONS = {
    grid: '<rect x="3" y="3" width="7" height="8" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="15" width="7" height="6" rx="2"/>',
    shield: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/>',
    alert: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M12 8v5M12 16h.01"/>',
    bell: '<path d="M6 16V11a6 6 0 1 1 12 0v5l2 2H4z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2 2M14 9l2 2"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M21.5 20a6 6 0 0 0-4-5.7"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    doc: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    cloud: '<path d="M7 18a5 5 0 1 1 .9-9.9A6 6 0 0 1 19 10a4 4 0 0 1-1 8z"/>',
    lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
    up: '<path d="M12 19V5M6 11l6-6 6 6"/>', down: '<path d="M12 5v14M6 13l6 6 6-6"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
    print: '<path d="M7 9V3h10v6M7 17H4v-6h16v6h-3M7 14h10v7H7z"/>',
    moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h10"/>',
    panel: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M9 4v16M15 10l-2 2 2 2"/>',
    linkedin: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 10v7M12 17v-4a2.5 2.5 0 0 1 5 0v4M12 10v7"/><circle cx="8" cy="6.5" r="1" fill="currentColor"/>'
  };
  function ic(n, sw) { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="' + (sw || 2) + '" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[n] || ICONS.doc) + '</svg>'; }

  /* cor de pill pela palavra; o JSON pode forçar com "cores" no bloco */
  var PILL_AUTO = [
    [/^(aberto|aberta|pendente|atrasad|em andamento|aten[cç][aã]o|parcial|requer)/i, 'p-yellow'],
    [/^(resolvid|conclu[ií]d|ok|conforme|sem a[cç][aã]o|saud[aá]vel|ativo|protegid|sim$)/i, 'p-teal'],
    [/^(alta|cr[ií]tic|grave|bloquead|n[aã]o conforme|falha)/i, 'p-dark'],
    [/^(m[eé]dia|moderad)/i, 'p-purple'],
    [/^(baixa|informativ|em an[aá]lise|investiga)/i, 'p-blue']
  ];
  function pill(v, cores) {
    if (v == null || v === '') return '';
    var c = (cores && cores[v]) || '';
    if (!c) for (var i = 0; i < PILL_AUTO.length; i++) if (PILL_AUTO[i][0].test(String(v))) { c = PILL_AUTO[i][1]; break; }
    return '<span class="pill ' + c + '">' + esc(v) + '</span>';
  }
  function ring(v) {
    v = Math.max(0, Math.min(100, Math.round(num(v))));
    var c = 2 * Math.PI * 14, cr = v >= 80 ? 'var(--ink)' : v >= 60 ? '#9C7AD2' : '#71E4D1';
    return '<div class="ring" title="Pontuação ' + v + '"><svg viewBox="0 0 34 34"><circle class="rt" cx="17" cy="17" r="14"/><circle class="rf" cx="17" cy="17" r="14" stroke="' + cr + '" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '" data-off="' + (c * (1 - v / 100)) + '"/></svg><b>' + v + '</b></div>';
  }

  /* ---------- opções de interface ---------- */
  var UI = R.interface || R.ui || {};
  function opc(chaves, padrao) { for (var i = 0; i < chaves.length; i++) if (UI[chaves[i]] != null) return UI[chaves[i]] !== false; return padrao; }
  var COM_BUSCA = opc(['busca', 'buscaGlobal'], true), COM_IMPRIMIR = opc(['imprimir', 'imprimirPdf'], true), COM_EXPORTAR = opc(['exportar', 'exportarExcel'], true);

  /* ---------- páginas ---------- */
  var PAGS = R.paginas.map(function (p, i) {
    return { id: p.id ? slug(p.id) : (i === 0 ? 'visao-geral' : slug(p.titulo || ('pagina-' + i))), src: p };
  });
  var TABELAS = []; /* para a exportação */

  /* ---------- blocos ---------- */
  var B = {};
  var uid = 0;

  B.kpis = function (b) {
    var itens = b.itens || [];
    var cols = Math.min(4, Math.max(1, itens.length));
    return '<div class="kpi-strip" style="grid-template-columns:repeat(' + cols + ',minmax(0,1fr))">' + itens.map(function (k, i) {
      var d = '';
      if (k.anterior != null && num(k.anterior) !== 0) {
        var cur = num(k.valor), prev = num(k.anterior), dd = (cur - prev) / Math.abs(prev) * 100, sobe = dd >= 0, bom = k.menosEhMelhor ? !sobe : sobe;
        d = '<span class="delta ' + (bom ? 'good' : 'bad') + '">' + ic(sobe ? 'up' : 'down') + (sobe ? '+' : '−') + NF.dec1.format(Math.abs(dd)) + '%</span><span class="vs">vs ' + fmt(prev, k.formato) + '</span>';
      }
      return '<div class="kpi-tile"><div class="kpi__label"><span class="ico ' + (k.cor ? 'c-' + k.cor : ICO_COR[i % 4]) + '">' + ic(k.icone || 'chart') + '</span>' + esc(k.rotulo) + '</div><div class="kpi__val num" data-count="' + num(k.valor) + '" data-fmt="' + (k.formato || 'int') + '">0</div><div>' + d + (k.sub ? '<span class="vs" style="margin-left:' + (d ? '6px' : '0') + '">' + esc(k.sub) + '</span>' : '') + '</div></div>';
    }).join('') + '</div>';
  };

  B.desempenho = function (b) {
    var id = 'des' + (++uid), n = (b.rotulos || []).length;
    var ps = (b.periodos || [7, 30, 90]).filter(function (p) { return p < n; });
    ps.push(n);
    ps = ps.filter(function (p, i) { return ps.indexOf(p) === i; });
    var seg = ps.length > 1 ? '<div class="seg" role="group" aria-label="Período">' + ps.map(function (p, i) { return '<button type="button" data-p="' + p + '" aria-pressed="' + (i === ps.length - 1) + '">' + (p === n ? (b.rotuloTudo || 'Tudo') : p + ' dias') + '</button>'; }).join('') + '</div>' : '';
    var leg = '<div class="legend"><span><i class="now"></i>' + esc(b.rotuloAtual || 'Período atual') + '</span>' + ((b.indicadores || []).some(function (x) { return x.anterior; }) ? '<span><i class="dash"></i>' + esc(b.rotuloAnterior || 'Período anterior') + '</span>' : '') + ((b.eventos || []).length ? '<span><i class="ring"></i>Evento relevante, clique para ver</span>' : '') + '</div>';
    POS.push(function () { montarDesempenho(id, b, ps); });
    return cardHead(b, seg) + '<div class="kpi-group" id="' + id + '-k" role="group" aria-label="Indicador do gráfico" style="grid-template-columns:repeat(' + Math.min(4, (b.indicadores || []).length) + ',minmax(0,1fr))"></div><div class="chart" id="' + id + '-c"></div>' + leg;
  };

  function agrega(arr, modo) { if (!arr.length) return 0; if (modo === 'media') return soma(arr) / arr.length; if (modo === 'ultimo') return num(arr[arr.length - 1]); return soma(arr); }
  function niceMax(v) { if (v <= 0) return 1; var p = Math.pow(10, Math.floor(Math.log10(v))); var m = v / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; }
  function smooth(pts) {
    if (pts.length < 2) return pts.length ? 'M' + pts[0][0] + ',' + pts[0][1] : '';
    var d = 'M' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2, t = .18;
      d += ' C' + (p1[0] + (p2[0] - p0[0]) * t).toFixed(1) + ',' + (p1[1] + (p2[1] - p0[1]) * t).toFixed(1) + ' ' + (p2[0] - (p3[0] - p1[0]) * t).toFixed(1) + ',' + (p2[1] - (p3[1] - p1[1]) * t).toFixed(1) + ' ' + p2[0].toFixed(1) + ',' + p2[1].toFixed(1);
    }
    return d;
  }

  function montarDesempenho(id, b, ps) {
    var inds = b.indicadores || [], rot = b.rotulos || [];
    var st = { p: ps[ps.length - 1], k: 0, cur: null, W: 0 };
    var kg = $('#' + id + '-k'), box = $('#' + id + '-c'), card = box.closest('.card');
    kg.innerHTML = inds.map(function (k, i) {
      return '<button type="button" class="kpi" data-i="' + i + '" aria-pressed="' + (i === 0) + '"><div class="kpi__label"><span class="ico">' + ic(k.icone || 'chart') + '</span>' + esc(k.rotulo) + '</div><div class="kpi__val num" data-fmt="' + (k.formato || 'int') + '">0</div><div class="kpi__d"></div></button>';
    }).join('');
    function corte(a) { return (a || []).slice(-st.p).map(num); }
    function kpis(primeira) {
      inds.forEach(function (k, i) {
        var el = $('.kpi[data-i="' + i + '"]', kg), cur = agrega(corte(k.atual), k.agregacao), d = '';
        if (k.anterior && k.anterior.length) {
          var prev = agrega(corte(k.anterior), k.agregacao);
          if (prev) { var dd = (cur - prev) / Math.abs(prev) * 100, sobe = dd >= 0, bom = k.menosEhMelhor ? !sobe : sobe; d = '<span class="delta ' + (bom ? 'good' : 'bad') + '">' + ic(sobe ? 'up' : 'down') + (sobe ? '+' : '−') + NF.dec1.format(Math.abs(dd)) + '%</span><span class="vs">vs ' + fmt(prev, k.formato) + '</span>'; }
        }
        countTo($('.kpi__val', el), cur, { fmt: k.formato || 'int', from: primeira ? 0 : undefined, flash: !primeira });
        $('.kpi__d', el).innerHTML = d;
      });
    }
    var H = 240, pl = 48, pr = 8, pt = 12, pb = 26;
    function draw(animar) {
      var k = inds[st.k], a = corte(k.atual), bb = k.anterior ? corte(k.anterior) : null, n = a.length, labs = rot.slice(-st.p);
      var W = Math.max(300, Math.round(box.clientWidth || 760));
      if (!$('svg', box) || st.W !== W) {
        st.W = W;
        box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Gráfico: ' + esc(k.rotulo) + '"><defs><linearGradient id="' + id + 'g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#71E4D1" stop-opacity=".55"/><stop offset="1" stop-color="#71E4D1" stop-opacity="0"/></linearGradient></defs><g class="gy"></g><g class="gx"></g><path class="area" fill="url(#' + id + 'g)"/><path class="line-prev"/><path class="line-now"/><g class="evs"></g><line class="hover-line" y1="' + pt + '" y2="' + (H - pb) + '" visibility="hidden"/><circle class="hover-dot" r="5" visibility="hidden"/><rect class="hit" x="' + pl + '" y="0" width="' + (W - pl - pr) + '" height="' + H + '" fill="transparent"/></svg><div class="tip"></div>';
        hover();
      }
      var svg = $('svg', box), all = a.concat(bb || []), max = niceMax(Math.max.apply(null, all.concat([0])) * 1.1);
      var x = function (i) { return pl + (W - pl - pr) * (n <= 1 ? 0 : i / (n - 1)); }, y = function (v) { return H - pb - (H - pt - pb) * v / max; };
      var f = k.formato === 'pct1' || k.formato === 'pct0' ? 'pct0' : 'compact';
      $('.gy', svg).innerHTML = [0, .5, 1].map(function (p) { var yy = y(max * p); return '<line class="grid-line" x1="' + pl + '" x2="' + (W - pr) + '" y1="' + yy + '" y2="' + yy + '"/><text class="axis" x="' + (pl - 8) + '" y="' + (yy + 3) + '" text-anchor="end">' + fmt(max * p, f) + '</text>'; }).join('');
      var passo = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(W / 95)))), xs = '';
      for (var i = 0; i < n; i += passo) xs += '<text class="axis" x="' + x(i) + '" y="' + (H - 6) + '" text-anchor="middle">' + esc(dataCurta(labs[i])) + '</text>';
      $('.gx', svg).innerHTML = xs;
      var off = rot.length - n;
      $('.evs', svg).innerHTML = (b.eventos || []).map(function (e, j) {
        var idx = e.indice != null ? num(e.indice) : rot.indexOf(e.data); idx -= off;
        if (idx < 0 || idx >= n) return '';
        var cor = e.cor || ['#4BB1EA', '#9C7AD2', '#F6F183', '#71E4D1'][j % 4], xi = x(idx);
        return '<g class="ev" tabindex="0" role="button" aria-label="' + esc(e.titulo) + '" data-t="' + esc(dataCurta(e.data || labs[idx]) + ': ' + e.titulo) + '"><line class="ev-line" x1="' + xi + '" x2="' + xi + '" y1="' + pt + '" y2="' + (H - pb) + '" stroke="' + cor + '"/><circle cx="' + xi + '" cy="' + (H - pb) + '" r="5.5" stroke="' + cor + '"/></g>';
      }).join('');
      $$('.ev', svg).forEach(function (g) { g.addEventListener('click', function () { aviso(g.dataset.t); }); g.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); aviso(g.dataset.t); } }); });
      var de = st.cur && st.cur.a.length === n ? st.cur : { a: a.map(function () { return 0; }), b: bb ? bb.map(function () { return 0; }) : null };
      if (de.b && (!bb || de.b.length !== bb.length)) de.b = bb ? bb.map(function () { return 0; }) : null;
      st.x = x; st.y = y; st.n = n; st.f = k.formato; st.labs = labs;
      function pintar(p) {
        var aa = a.map(function (v, i) { return de.a[i] + (v - de.a[i]) * p; }), b2 = bb ? bb.map(function (v, i) { return (de.b ? de.b[i] : 0) + (v - (de.b ? de.b[i] : 0)) * p; }) : null;
        var la = smooth(aa.map(function (v, i) { return [x(i), y(v)]; }));
        $('.line-now', svg).setAttribute('d', la);
        $('.line-prev', svg).setAttribute('d', b2 ? smooth(b2.map(function (v, i) { return [x(i), y(v)]; })) : '');
        $('.area', svg).setAttribute('d', la ? la + ' L' + x(n - 1) + ',' + y(0) + ' L' + x(0) + ',' + y(0) + ' Z' : '');
        st.cur = { a: aa, b: b2 };
      }
      if (animar === false) pintar(1); else tween(700, pintar);
    }
    function hover() {
      var svg = $('svg', box), tip = $('.tip', box), hl = $('.hover-line', svg), hd = $('.hover-dot', svg);
      $('.hit', svg).addEventListener('pointermove', function (ev) {
        if (!st.cur) return;
        var r = svg.getBoundingClientRect(), sx = (ev.clientX - r.left) / r.width * st.W;
        var i = Math.round((sx - pl) / (st.W - pl - pr) * (st.n - 1)); i = Math.max(0, Math.min(st.n - 1, i));
        var xv = st.x(i), yv = st.y(st.cur.a[i]);
        hl.setAttribute('x1', xv); hl.setAttribute('x2', xv); hl.setAttribute('visibility', 'visible');
        hd.setAttribute('cx', xv); hd.setAttribute('cy', yv); hd.setAttribute('visibility', 'visible');
        tip.innerHTML = '<b>' + fmt(st.cur.a[i], st.f) + '</b>' + esc(dataCurta(st.labs[i])) + (st.cur.b ? ' · anterior ' + fmt(st.cur.b[i], st.f) : '');
        tip.style.left = (xv / st.W * r.width) + 'px'; tip.style.top = (yv / H * r.height) + 'px'; tip.classList.add('show');
      });
      $('.hit', svg).addEventListener('pointerleave', function () { hl.setAttribute('visibility', 'hidden'); hd.setAttribute('visibility', 'hidden'); tip.classList.remove('show'); });
    }
    $$('.kpi', kg).forEach(function (btn) { btn.addEventListener('click', function () { st.k = +btn.dataset.i; $$('.kpi', kg).forEach(function (x) { x.setAttribute('aria-pressed', x === btn); }); st.cur = null; draw(); }); });
    $$('.seg button', card).forEach(function (btn) { btn.addEventListener('click', function () { st.p = +btn.dataset.p; $$('.seg button', card).forEach(function (x) { x.setAttribute('aria-pressed', x === btn); }); kpis(false); st.cur = null; draw(); }); });
    card._entrar = function () { st.cur = null; kpis(true); draw(); };
    var rz; window.addEventListener('resize', function () { clearTimeout(rz); rz = setTimeout(function () { if (card.offsetParent) draw(false); }, 150); });
  }

  B.distribuicao = function (b) {
    var id = 'dis' + (++uid), med = b.medidas || { '': b.itens || [] }, nomes = Object.keys(med);
    var seg = nomes.length > 1 ? '<div class="seg full" role="group" aria-label="Medida">' + nomes.map(function (n, i) { return '<button type="button" data-m="' + esc(n) + '" aria-pressed="' + (i === 0) + '">' + esc(n) + '</button>'; }).join('') + '</div>' : '';
    POS.push(function () {
      var card = $('#' + id).closest('.card'), atual = nomes[0];
      function pr(m) {
        var L = (med[m] || []).map(function (r) { return [String(r[0]), num(r[1])]; }).sort(function (a, c) { return c[1] - a[1]; });
        if (L.length > 7) { var resto = L.slice(6); L = L.slice(0, 6); L.push(['Outros', soma(resto.map(function (r) { return r[1]; }))]); }
        return L;
      }
      function render(anima) {
        var L = pr(atual), tot = soma(L.map(function (r) { return r[1]; })) || 1, mx = Math.max.apply(null, L.map(function (r) { return r[1]; }).concat([1]));
        $('#' + id + '-s').innerHTML = L.map(function (r, i) { return '<span style="background:' + CORES[i % CORES.length] + '" data-w="' + (r[1] / tot * 100) + '"></span>'; }).join('');
        $('#' + id).innerHTML = L.map(function (r, i) { return '<div class="dist-row"><div class="dist-row__top"><span class="dot" style="background:' + CORES[i % CORES.length] + '"></span><b>' + esc(r[0]) + '</b><span class="v num" data-count="' + r[1] + '" data-fmt="' + (b.formato || 'int') + '">0</span><span class="p num">' + Math.round(r[1] / tot * 100) + '%</span></div><div class="bar"><span data-w="' + (r[1] / mx * 100) + '" style="background:' + CORES[i % CORES.length] + '"></span></div></div>'; }).join('');
        var rod = b.rodapes ? b.rodapes[atual] : b.rodape;
        $('#' + id + '-f').innerHTML = rod ? rico(rod) : '';
        $('#' + id + '-f').hidden = !rod;
        animar(card, false);
      }
      $$('.seg button', card).forEach(function (btn) { btn.addEventListener('click', function () { atual = btn.dataset.m; $$('.seg button', card).forEach(function (x) { x.setAttribute('aria-pressed', x === btn); }); render(true); }); });
      card._entrar = function () { render(); };
    });
    return cardHead(b) + seg + '<div class="stack" id="' + id + '-s" aria-hidden="true"></div><div id="' + id + '"></div><div class="card__foot" id="' + id + '-f"></div>';
  };

  B.progresso = function (b) {
    return cardHead(b) + '<div class="rows">' + (b.itens || []).map(function (a, i) {
      var tot = num(a.total) || 1, f = num(a.feito), p = Math.round(f / tot * 100), ok = f >= tot;
      var sit = a.situacao || (ok ? 'Concluída' : 'Em andamento');
      return '<div class="row"><span class="ico lg ' + ICO_COR[i % 4] + '">' + ic(a.icone || 'check') + '</span><div class="row__name"><b>' + esc(a.titulo) + '</b><small>' + esc(a.sub || '') + '</small></div><div class="row__prog"><div class="bar"><span data-w="' + Math.min(100, p) + '" style="background:' + (ok ? '#71E4D1' : 'var(--ink)') + '"></span></div><small><b>' + fmt(f) + '</b> de ' + fmt(tot) + '</small></div><div class="row__metric num"><span data-count="' + p + '" data-fmt="pct0">0%</span><small>concluído</small></div>' + pill(sit, b.cores) + '</div>';
    }).join('') + '</div>';
  };

  B.ranking = function (b) {
    return cardHead(b) + '<div class="rows">' + (b.itens || []).map(function (r) {
      return '<div class="row" style="grid-template-columns:minmax(0,1fr) auto auto"><div class="row__name"><b>' + esc(r.titulo) + '</b><small>' + esc(r.sub || '') + '</small></div>' + pill(r.pill, b.cores) + (r.risco != null ? ring(r.risco) : (r.valor != null ? '<div class="row__metric num">' + fmt(r.valor, b.formato) + '</div>' : '')) + '</div>';
    }).join('') + '</div>';
  };

  B.funil = function (b) {
    var E = (b.etapas || []).map(function (e) { return [e[0], num(e[1]), e[2]]; }), mx = E.length ? E[0][1] || 1 : 1, pior = -1, piorV = 2;
    E.forEach(function (e, i) { if (i && E[i - 1][1]) { var t = e[1] / E[i - 1][1]; if (t < piorV) { piorV = t; pior = i; } } });
    var cores = ['var(--ink)', 'var(--ink-soft)', '#9C7AD2', '#4BB1EA', '#71E4D1', '#F6F183'];
    return cardHead(b) + '<div class="funnel">' + E.map(function (e, i) {
      var pct = i && E[i - 1][1] ? e[1] / E[i - 1][1] * 100 : 100;
      var nota = e[2] || (i === pior && E.length > 2 ? 'Maior queda' : '');
      return '<div class="f-row"><div class="f-row__lab">' + esc(e[0]) + (nota ? '<small class="queda">' + esc(nota) + '</small>' : '') + '</div><div class="f-row__bar"><span data-w="' + Math.max(8, e[1] / mx * 100) + '" style="background:' + cores[i % cores.length] + '"></span></div><div class="f-row__val num"><span data-count="' + e[1] + '" data-fmt="compact">0</span><small>' + (i ? NF.dec1.format(pct) + '%' : 'início') + '</small></div></div>';
    }).join('') + '</div>';
  };

  B.medidor = function (b) {
    var tot = num(b.total) || 100, pct = Math.max(0, Math.min(1, num(b.valor) / tot)), len = Math.PI * 90;
    var meta = b.meta != null ? num(b.meta) / 100 : .9, cor = pct >= meta ? '#71E4D1' : pct >= meta - .2 ? '#4BB1EA' : '#F6F183';
    var t = ''; for (var i = 0; i <= 10; i++) { var a = Math.PI * (1 - i / 10), r1 = 72, r2 = i % 5 ? 66 : 62; t += '<line x1="' + (110 + r1 * Math.cos(a)) + '" y1="' + (110 - r1 * Math.sin(a)) + '" x2="' + (110 + r2 * Math.cos(a)) + '" y2="' + (110 - r2 * Math.sin(a)) + '" stroke="currentColor" stroke-width="1.4" opacity=".35"/>'; }
    return cardHead(b) + '<div class="gauge"><svg viewBox="0 0 220 124"><path class="track" d="M20 110 A90 90 0 0 1 200 110"/><path class="fill" d="M20 110 A90 90 0 0 1 200 110" stroke="' + cor + '" stroke-dasharray="' + len + '" stroke-dashoffset="' + len + '" data-off="' + (len * (1 - pct)) + '"/>' + t + '<g class="needle" data-rot="' + (pct * 180 - 90) + '" style="transform:rotate(-90deg)"><line x1="110" y1="110" x2="110" y2="44"/><circle cx="110" cy="110" r="6"/></g></svg><div class="gauge__val num" data-count="' + (pct * 100) + '" data-fmt="pct1">0%</div><div class="gauge__sub">' + esc(b.rotulo || '') + '</div>' + (b.nota ? '<p class="gauge__note">' + rico(b.nota) + '</p>' : '') + '</div>';
  };

  function rel(iso) {
    var t = new Date(iso); if (isNaN(t)) return esc(iso);
    var s = (Date.now() - t) / 1000;
    if (s < 0) return t.toLocaleDateString('pt-BR');
    if (s < 60) return 'agora'; if (s < 3600) return 'há ' + Math.floor(s / 60) + ' min'; if (s < 86400) return 'há ' + Math.floor(s / 3600) + ' h';
    var d = Math.floor(s / 86400); return d === 1 ? 'ontem' : d < 31 ? 'há ' + d + ' dias' : t.toLocaleDateString('pt-BR');
  }
  B.atividade = function (b) {
    var L = (b.itens || []).slice().sort(function (a, c) { return new Date(c.quando) - new Date(a.quando); });
    if (b.limite) L = L.slice(0, b.limite);
    return cardHead(b) + '<ul class="feed">' + L.map(function (a, i) {
      return '<li><span class="av" style="background:' + (i % 3 === 0 ? 'var(--teal)' : i % 3 === 1 ? 'var(--surface-3)' : 'rgba(156,122,210,.25)') + ';color:' + (i % 3 === 0 ? '#000' : 'inherit') + '">' + esc(String(a.quem || '').slice(0, 3)) + '</span><div><p>' + rico(a.texto) + '</p><time datetime="' + esc(a.quando) + '" data-rel>' + rel(a.quando) + '</time></div></li>';
    }).join('') + '</ul>';
  };

  B.texto = function (b) {
    return cardHead(b) + '<div class="bloco-texto">' + (b.paragrafos || []).map(function (p) { return '<p>' + rico(p) + '</p>'; }).join('') + '</div>';
  };

  B.tabela = function (b) {
    var id = 'tab' + (++uid), cols = b.colunas || [], linhas = b.linhas || [];
    if (!cols.length && linhas.length) cols = Object.keys(linhas[0]).map(function (k) { return { chave: k, titulo: k }; });
    TABELAS.push({ titulo: b.titulo || 'Dados', colunas: cols, linhas: linhas, id: id });
    var BASE_LIM = b.porPagina || b.limite || 500;
    var st = { f: 'Todos', q: '', lim: BASE_LIM, ord: b.ordem ? { k: b.ordem.chave, d: b.ordem.direcao === 'asc' ? 1 : -1 } : null };
    var fc = b.filtro, valores = [];
    if (fc) linhas.forEach(function (r) { var v = r[fc]; if (v != null && v !== '' && valores.indexOf(v) < 0) valores.push(v); });
    POS.push(function () {
      var t = $('#' + id), card = t.closest('.card');
      t.tHead.innerHTML = '<tr>' + cols.map(function (c) { return '<th aria-sort="none" data-k="' + esc(c.chave) + '"><button type="button">' + esc(c.titulo || c.chave) + '</button></th>'; }).join('') + '</tr>';
      $$('th', t).forEach(function (th) { $('button', th).addEventListener('click', function () { var k = th.dataset.k; st.ord = { k: k, d: st.ord && st.ord.k === k ? -st.ord.d : 1 }; st.lim = BASE_LIM; render(); }); });
      var chips = $('#' + id + '-chips');
      if (chips) { chips.innerHTML = ['Todos'].concat(valores).map(function (v) { return '<button type="button" data-v="' + esc(v) + '"></button>'; }).join(''); $$('button', chips).forEach(function (bt) { bt.addEventListener('click', function () { st.f = bt.dataset.v; st.lim = BASE_LIM; render(); }); }); }
      var q = $('#' + id + '-q'); if (q) q.addEventListener('input', function () { st.q = q.value; st.lim = BASE_LIM; render(); });
      function filtradas() {
        var qq = st.q.toLowerCase();
        var L = linhas.filter(function (r) { return (st.f === 'Todos' || String(r[fc]) === st.f) && (!qq || cols.some(function (c) { return String(r[c.chave] == null ? '' : r[c.chave]).toLowerCase().indexOf(qq) > -1 || (c.sub && String(r[c.sub] || '').toLowerCase().indexOf(qq) > -1); })); });
        if (st.ord) L = L.slice().sort(function (a, c) { var x = a[st.ord.k], y = c[st.ord.k]; var nx = typeof x === 'number' && typeof y === 'number'; return (nx ? x - y : String(x == null ? '' : x).localeCompare(String(y == null ? '' : y), 'pt-BR', { numeric: true })) * st.ord.d; });
        return L;
      }
      TABELAS.forEach(function (tb) { if (tb.id === id) tb.filtradas = filtradas; });
      function cel(c, r) {
        var v = r[c.chave];
        switch (c.tipo) {
          case 'titulo': return '<div class="cell-name"><div><b>' + esc(v) + '</b>' + (c.sub ? '<small>' + esc(r[c.sub] || '') + '</small>' : '') + '</div></div>';
          case 'pill': return pill(v, b.cores);
          case 'risco': return v == null || v === '' ? '' : ring(v);
          case 'data': return '<span class="num">' + esc(dataBR(v)) + '</span>';
          case 'numero': return '<span class="num">' + esc(v == null || v === '' ? '' : fmt(v, c.formato)) + '</span>';
          case 'barra': var p = Math.max(0, Math.min(100, num(v))); return '<div class="mini"><div class="bar"><span data-w="' + p + '" style="background:var(--ink)"></span></div><small class="num">' + fmt(p, 'pct0') + '</small></div>';
          case 'longo': return '<div class="cell-long">' + esc(v == null ? '' : v) + '</div>';
          case 'datahora': return '<span class="num">' + esc(isoData(v) ? new Date(String(v).replace(' ', 'T')).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : (v == null ? '' : v)) + '</span>';
          default: return esc(v == null ? '' : v);
        }
      }
      function render() {
        if (chips) $$('button', chips).forEach(function (bt) { var v = bt.dataset.v, n = v === 'Todos' ? linhas.length : linhas.filter(function (r) { return String(r[fc]) === v; }).length; bt.innerHTML = esc(v) + '<span class="n">' + n + '</span>'; bt.setAttribute('aria-pressed', v === st.f); });
        $$('th', t).forEach(function (th) { th.setAttribute('aria-sort', st.ord && th.dataset.k === st.ord.k ? (st.ord.d > 0 ? 'ascending' : 'descending') : 'none'); });
        var L = filtradas(), lim = st.lim, ini = arguments[0] === 'mais' ? lim - BASE_LIM : 0;
        t.tBodies[0].innerHTML = L.length ? L.slice(0, lim).map(function (r, i) { return '<tr' + (i >= ini ? ' class="enter" style="animation-delay:' + Math.min(i - ini, 20) * 25 + 'ms"' : '') + '>' + cols.map(function (c) { return '<td>' + cel(c, r) + '</td>'; }).join('') + '</tr>'; }).join('') : '<tr><td class="empty" colspan="' + cols.length + '">Nenhum item corresponde aos filtros atuais.</td></tr>';
        if (L.length > lim) {
          var resto = Math.min(BASE_LIM, L.length - lim), tr = document.createElement('tr');
          tr.innerHTML = '<td class="mais" colspan="' + cols.length + '"><button type="button">Mostrar mais ' + fmt(resto) + ' (exibindo ' + fmt(lim) + ' de ' + fmt(L.length) + ')</button></td>';
          t.tBodies[0].appendChild(tr);
          $('button', tr).addEventListener('click', function () { st.lim += BASE_LIM; render('mais'); });
        }
        var cnt = $('#' + id + '-n'); if (cnt) cnt.textContent = fmt(L.length) + ' de ' + fmt(linhas.length) + ' ' + (b.unidade || 'itens');
        animar(card, true);
      }
      card._entrar = render;
    });
    var tb = (b.busca !== false || fc) ? '<div class="toolbar">' + (b.busca !== false ? '<label class="search">' + ic('search') + '<input id="' + id + '-q" type="search" placeholder="Buscar" aria-label="Buscar na tabela"></label>' : '') + (fc ? '<div class="chips" role="group" aria-label="Filtro rápido" id="' + id + '-chips"></div>' : '') + '<span class="count" id="' + id + '-n" aria-live="polite"></span></div>' : '';
    return cardHead(b) + tb + '<div class="tablewrap"><table class="t" id="' + id + '"><thead></thead><tbody></tbody></table></div>';
  };

  function cardHead(b, direita) {
    if (!b.titulo && !b.sub && !direita && !b.link) return '';
    var lk = b.link ? '<a class="card__link" href="' + (/^#\//.test(b.link.href) ? esc(b.link.href) : '#') + '">' + esc(b.link.texto || 'Ver') + '</a>' : '';
    return '<div class="card__head"><div>' + (b.titulo ? '<div class="card__title">' + esc(b.titulo) + '</div>' : '') + (b.sub ? '<div class="card__sub">' + esc(b.sub) + '</div>' : '') + '</div>' + (direita || lk) + '</div>';
  }

  /* ---------- botão de download animado (exportação para Excel) ---------- */
  var BOTAO_DL = '<button class="dl" type="button" data-export data-state="idle" aria-label="Exportar para Excel (.xlsx)">' +
    '<span class="dl__orb" aria-hidden="true"><svg class="dl__ring" viewBox="0 0 48 48"><circle class="dl__track" cx="24" cy="24" r="21"/><circle class="dl__prog" cx="24" cy="24" r="21" pathLength="100"/></svg>' +
    '<svg class="dl__ico" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><path class="dl__shaft" d="M12 4v10.5" pathLength="1"/><path class="dl__head" d="M7.5 10.5L12 15l4.5-4.5"/><path class="dl__base" d="M5 19.5h14" pathLength="1"/><path class="dl__check" d="M6.5 12.5l3.6 3.6L17.5 8.5" pathLength="1"/></svg></span>' +
    '<span class="dl__txt"><b>Exportar Excel</b><small class="num">.xlsx</small></span></button>';

  /* ---------- montagem do DOM ---------- */
  var POS = [];
  var grupos = [], porGrupo = {};
  PAGS.forEach(function (p) { var g = p.src.grupo || ''; if (!(g in porGrupo)) { porGrupo[g] = []; grupos.push(g); } porGrupo[g].push(p); });

  var nav = grupos.map(function (g) {
    return (g ? '<div class="nav-group">' + esc(g) + '</div>' : '') + porGrupo[g].map(function (p) {
      var bd = p.src.badge != null && p.src.badge !== 0 ? '<span class="nav-badge' + (p.src.badgeCor === 'amarelo' ? ' b-yellow' : '') + '">' + esc(p.src.badge) + '</span>' : '';
      return '<a class="nav-item" href="#/' + p.id + '" data-tip="' + esc(p.src.titulo) + '">' + ic(p.src.icone || (p === PAGS[0] ? 'grid' : 'doc'), 1.8).replace('<svg ', '<svg class="ic" ') + '<span class="nav-label">' + esc(p.src.titulo) + '</span>' + bd + '</a>';
    }).join('');
  }).join('');

  var meta = '';
  if (R.meta) {
    var mt = num(R.meta.total) || 1, mf = num(R.meta.feito), mp = mf / mt * 100;
    meta = '<a class="goal" href="' + (R.meta.pagina ? '#/' + slug(R.meta.pagina) : '#/' + PAGS[0].id) + '"><div class="goal__top"><span><i></i>' + esc(R.meta.rotulo || 'Meta') + '</span><span class="goal__pct num" data-count="' + mp + '" data-fmt="pct0">0%</span></div><div class="goal__val num"><span data-count="' + mf + '">0</span> <small>de ' + fmt(mt) + ' ' + esc(R.meta.unidade || '') + '</small></div><div class="goal__bar"><span data-w="' + Math.min(100, mp) + '"></span></div>' + (R.meta.sub ? '<div class="goal__sub">' + esc(R.meta.sub) + '</div>' : '') + '</a>';
  }

  var paginasHtml = PAGS.map(function (p, pi) {
    var s = p.src;
    var acoes = '<div class="head__actions">' + (pi === 0 && COM_EXPORTAR ? BOTAO_DL : '') + '</div>';
    var corpo = (s.blocos || []).map(function (b) {
      var fn = B[b.tipo]; if (!fn) return '';
      if (b.tipo === 'kpis') return '<div class="span-12">' + fn(b) + '</div>';
      var larg = [12, 8, 7, 6, 5, 4, 3].indexOf(+b.largura) > -1 ? +b.largura : 12;
      return '<div class="card span-' + larg + '">' + fn(b) + '</div>';
    }).join('');
    return '<section class="page" data-page="' + p.id + '" data-title="' + esc(s.titulo) + '"' + (s.grupo ? ' data-group="' + esc(s.grupo) + '"' : '') + ' hidden><div class="head"><div><div class="eyebrow">' + ic(pi === 0 ? 'calendar' : (s.icone || 'doc')) + '<span>' + esc(pi === 0 ? (R.periodo || '') : (s.grupo || R.periodo || '')) + '</span></div><h1>' + esc(s.titulo) + '</h1>' + (s.resumo ? '<p class="lede">' + rico(s.resumo) + '</p>' : '') + '</div>' + acoes + '</div><div class="grid">' + corpo + '</div></section>';
  }).join('');

  var logoAlt = ASS.empresa;
  document.title = (R.titulo || 'Relatório') + ' · ' + (R.cliente || '');
  var html =
    '<a class="skip" href="#conteudo">Ir para o conteúdo</a>' +
    '<aside class="side" id="side" aria-label="Navegação"><div class="side__top"><a class="brand" href="#/' + PAGS[0].id + '" aria-label="' + esc(logoAlt) + ', início"><img class="brand-logo" src="' + BASE + ASS.logo + '" alt="' + esc(logoAlt) + '"></a><button class="side__toggle" id="sideToggle" type="button" aria-label="Recolher menu" aria-expanded="true">' + ic('panel') + '</button></div>' +
    '<div class="side__client"><small>Relatório para</small><b>' + esc(R.cliente || '') + '</b></div>' +
    '<nav class="nav" id="nav">' + nav + '</nav>' +
    '<div class="side__foot">' + meta +
    '<div class="who" data-tip="' + esc(ASS.nome) + '"><div class="who__av">MN</div><div class="who__txt"><b>' + esc(ASS.nome) + '</b>' + (ASS.cargo ? '<span>' + esc(ASS.cargo) + '</span>' : '<span>' + esc(ASS.empresa) + '</span>') + '</div><div class="who__links"><a href="' + LINKEDIN + '" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn">' + ic('linkedin', 1.8) + '</a><a href="mailto:' + esc(ASS.email) + '" aria-label="E-mail ' + esc(ASS.email) + '">' + ic('mail', 1.8) + '</a></div></div>' +
    '<div class="conf">Confidencial · ' + esc(ASS.empresa) + '</div></div></aside>' +
    '<span class="rail-tip" id="railTip" role="tooltip"></span><div class="scrim" id="scrim"></div>' +
    '<div class="main"><header class="top"><button class="icon-btn burger" id="burger" type="button" aria-label="Abrir menu" aria-controls="side" aria-expanded="false">' + ic('menu') + '</button><div class="crumbs" id="crumbs"></div>' +
    (COM_BUSCA ? '<label class="search">' + ic('search') + '<input id="quick" type="search" placeholder="Ir para página..." aria-label="Ir para página"><kbd>/</kbd></label>' : '') +
    '<div class="clock num" title="Hora local"><i></i><span id="clock"></span></div>' +
    '<button class="icon-btn" id="themeBtn" type="button" aria-label="Alternar tema claro ou escuro">' + ic('moon', 1.8) + '</button>' +
    (COM_IMPRIMIR ? '<button class="btn btn-primary" type="button" id="printBtn">' + ic('print') + '<span>Imprimir ou PDF</span></button>' : '') + '</header>' +
    '<main id="conteudo" tabindex="-1">' + paginasHtml +
    (R.fonte ? '<p class="fonte">Fonte dos dados: ' + esc(R.fonte) + (R.geradoEm ? ' · extraído em ' + esc(dataBR(R.geradoEm)) : '') + '</p>' : '') +
    '<div class="print-assinatura">' + esc(ASS.nome) + ', ' + (ASS.cargo ? esc(ASS.cargo) + ', ' : '') + esc(ASS.empresa) + '.<br>' + esc(ASS.email) + ' | linkedin.com/in/mikionakamaru<br>Confidencial</div>' +
    '</main></div><div class="toast" id="toast" role="status" aria-live="polite"></div>';

  var semMotor = document.getElementById('sem-motor'); if (semMotor) semMotor.remove();
  var wrap = document.createElement('div'); wrap.innerHTML = html;
  while (wrap.firstChild) document.body.appendChild(wrap.firstChild);
  POS.forEach(function (f) { try { f(); } catch (e) { console.error('[motor v3] bloco:', e); } });

  /* ---------- animação de entrada ---------- */
  function animar(sc, soVisuais) {
    requestAnimationFrame(function () { requestAnimationFrame(function () {
      $$('[data-w]', sc).forEach(function (e) { e.style.width = e.dataset.w + '%'; });
      $$('[data-off]', sc).forEach(function (e) { e.style.strokeDashoffset = e.dataset.off; });
      $$('[data-rot]', sc).forEach(function (e) { e.style.transform = 'rotate(' + e.dataset.rot + 'deg)'; });
      if (!soVisuais) $$('[data-count]', sc).forEach(function (e) { countTo(e, num(e.dataset.count), { from: 0 }); });
    }); });
  }
  function zerar(sc) {
    $$('[data-w]', sc).forEach(function (e) { e.style.transition = 'none'; e.style.width = '0'; e.getBoundingClientRect(); e.style.transition = ''; });
    $$('[data-off]', sc).forEach(function (e) { e.style.transition = 'none'; e.style.strokeDashoffset = e.getAttribute('stroke-dasharray'); e.getBoundingClientRect(); e.style.transition = ''; });
    $$('[data-rot]', sc).forEach(function (e) { e.style.transition = 'none'; e.style.transform = 'rotate(-90deg)'; e.getBoundingClientRect(); e.style.transition = ''; });
  }

  /* ---------- roteador ---------- */
  var PAGES = $$('.page');
  function rota() { return location.hash.replace(/^#\/?/, '') || PAGS[0].id; }
  function mostrar() {
    var id = rota(); if (!PAGES.some(function (p) { return p.dataset.page === id; })) id = PAGS[0].id;
    var pg;
    PAGES.forEach(function (p) { var on = p.dataset.page === id; p.hidden = !on; p.classList.toggle('is-active', on); if (on) pg = p; });
    $$('.card,.kpi-tile', pg).forEach(function (c, i) { c.style.setProperty('--i', i); });
    $$('.nav-item').forEach(function (a) { if (a.getAttribute('href') === '#/' + id) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    $('#crumbs').innerHTML = ic('grid', 1.8) + (pg.dataset.group ? '<span>' + esc(pg.dataset.group) + '</span><span>›</span>' : '') + '<b>' + esc(pg.dataset.title) + '</b>';
    zerar(pg);
    $$('.card', pg).forEach(function (c) { if (c._entrar) c._entrar(); });
    animar(pg);
    fecharMenu(); window.scrollTo({ top: 0 });
  }

  /* ---------- sidebar: cheia, trilho, gaveta ---------- */
  var mqFull = matchMedia('(min-width:1280px)'), mqMob = matchMedia('(max-width:760px)');
  function lerPref() { try { return localStorage.getItem('mv3-side'); } catch (e) { return null; } }
  function gravarPref(v) { try { localStorage.setItem('mv3-side', v); } catch (e) { } }
  function aplicarSide(m) { root.setAttribute('data-side', m); var t = $('#sideToggle'); t.setAttribute('aria-expanded', m === 'full'); t.setAttribute('aria-label', m === 'full' ? 'Recolher menu' : 'Expandir menu'); }
  function modoSide() { aplicarSide(mqMob.matches ? 'full' : (mqFull.matches ? (lerPref() || 'full') : 'rail')); }
  $('#sideToggle').addEventListener('click', function () { var n = root.getAttribute('data-side') === 'full' ? 'rail' : 'full'; if (mqFull.matches) gravarPref(n); aplicarSide(n); });
  if (mqFull.addEventListener) { mqFull.addEventListener('change', modoSide); mqMob.addEventListener('change', modoSide); }
  var tip = $('#railTip');
  $$('.nav-item,.who').forEach(function (a) {
    function show() { if (root.getAttribute('data-side') !== 'rail' || mqMob.matches) return; var r = a.getBoundingClientRect(); tip.textContent = a.dataset.tip || ''; tip.style.top = (r.top + r.height / 2 - 16) + 'px'; tip.style.left = (r.right + 14) + 'px'; tip.classList.add('show'); }
    function hide() { tip.classList.remove('show'); }
    a.addEventListener('mouseenter', show); a.addEventListener('focus', show); a.addEventListener('mouseleave', hide); a.addEventListener('blur', hide);
  });
  function fecharMenu() { root.classList.remove('menu-open'); $('#scrim').classList.remove('show'); $('#burger').setAttribute('aria-expanded', 'false'); }
  $('#burger').addEventListener('click', function () { var on = !root.classList.contains('menu-open'); root.classList.toggle('menu-open', on); $('#scrim').classList.toggle('show', on); this.setAttribute('aria-expanded', on); });
  $('#scrim').addEventListener('click', fecharMenu);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') fecharMenu();
    if (COM_BUSCA && e.key === '/' && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); $('#quick').focus(); }
  });
  if (COM_BUSCA) $('#quick').addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return; var q = this.value.trim().toLowerCase(); if (!q) return;
    var p = PAGES.filter(function (pg) { return pg.dataset.title.toLowerCase().indexOf(q) > -1; })[0];
    if (p) location.hash = '#/' + p.dataset.page; else aviso('Nenhuma página com esse nome.');
    this.value = ''; this.blur();
  });
  if (COM_IMPRIMIR) $('#printBtn').addEventListener('click', function () { window.print(); });

  /* ---------- tema ---------- */
  (function () {
    var t = null; try { t = localStorage.getItem('mv3-tema'); } catch (e) { }
    if (!t) t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    root.setAttribute('data-theme', t);
    $('#themeBtn').addEventListener('click', function () { var n = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'; root.setAttribute('data-theme', n); try { localStorage.setItem('mv3-tema', n); } catch (e) { } });
  })();

  /* ---------- exportação para Excel ---------- */
  function carregar(src) { return new Promise(function (ok, erro) { var s = document.createElement('script'); s.src = src; s.onload = ok; s.onerror = erro; document.head.appendChild(s); }); }
  $$('[data-export]').forEach(function (btn) {
    var txtB = $('.dl__txt b', btn), txtS = $('.dl__txt small', btn), prog = $('.dl__prog', btn);
    var alvo = 0, mostra = 0, raf = 0, rotulo = { b: txtB ? txtB.textContent : '', s: txtS ? txtS.textContent : '' };
    function pinta() {
      mostra += (alvo - mostra) * (REDUZ ? 1 : 0.12);
      if (alvo < 92 && btn.dataset.state === 'loading') alvo += 0.08; /* avança devagar enquanto espera */
      if (prog) prog.style.strokeDashoffset = String(100 - mostra);
      if (txtS && btn.dataset.state === 'loading') txtS.textContent = Math.round(mostra) + '%';
      if (btn.dataset.state === 'loading' || Math.abs(alvo - mostra) > .3) raf = requestAnimationFrame(pinta);
    }
    function etapa(p) { alvo = Math.max(alvo, p); }
    function estado(st) {
      btn.dataset.state = st;
      if (st === 'loading') { if (txtB) txtB.textContent = 'Gerando Excel'; btn.setAttribute('aria-busy', 'true'); }
      if (st === 'done') { alvo = 100; if (txtB) txtB.textContent = 'Excel pronto'; if (txtS) txtS.textContent = 'baixado'; btn.removeAttribute('aria-busy'); }
      if (st === 'error') { if (txtB) txtB.textContent = 'Tente de novo'; if (txtS) txtS.textContent = 'falhou'; btn.removeAttribute('aria-busy'); }
      if (st === 'idle') { alvo = 0; mostra = 0; if (prog) prog.style.strokeDashoffset = '100'; if (txtB) txtB.textContent = rotulo.b; if (txtS) txtS.textContent = rotulo.s; }
    }
    btn.addEventListener('click', function () {
      if (btn.dataset.state === 'loading') return;
      btn.disabled = true; estado('idle'); estado('loading'); etapa(6); cancelAnimationFrame(raf); raf = requestAnimationFrame(pinta);
      (window.ExcelJS ? Promise.resolve() : carregar('https://cdnjs.cloudflare.com/ajax/libs/exceljs/4.4.0/exceljs.min.js')).then(function () {
        etapa(35);
        var wb = new ExcelJS.Workbook(); wb.creator = ASS.nome + ' · ' + ASS.empresa;
        var F = 'Montserrat';
        var cp = wb.addWorksheet('Resumo', { views: [{ showGridLines: false }], properties: { tabColor: { argb: 'FF71E4D1' } } });
        cp.getColumn(1).width = 34; cp.getColumn(2).width = 18; cp.getColumn(3).width = 18;
        cp.addRow([R.titulo || 'Relatório']).font = { name: F, size: 16, bold: true };
        cp.addRow(['Cliente: ' + (R.cliente || '') + '  ·  ' + (R.periodo || '')]).font = { name: F, size: 10, color: { argb: 'FF3C3C3C' } };
        cp.addRow(['Responsável técnico: ' + ASS.nome + (ASS.cargo ? ', ' + ASS.cargo : '') + ' · ' + ASS.empresa]).font = { name: F, size: 10, color: { argb: 'FF3C3C3C' } };
        cp.addRow([]);
        var hr = cp.addRow(['Indicador', 'Valor', 'Anterior']);
        hr.eachCell(function (c) { c.font = { name: F, bold: true, color: { argb: 'FFFFFFFF' } }; c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF000000' } }; });
        R.paginas.forEach(function (p) { (p.blocos || []).forEach(function (b) { if (b.tipo === 'kpis') (b.itens || []).forEach(function (k) { var r = cp.addRow([p.titulo + ' · ' + k.rotulo, num(k.valor), k.anterior != null ? num(k.anterior) : null]); r.font = { name: F, size: 10 }; }); }); });
        TABELAS.forEach(function (tb, i) {
          var nome = String(tb.titulo).replace(/[\[\]:*?\/\\]/g, ' ').slice(0, 28) || ('Dados ' + (i + 1));
          var usado = wb.worksheets.map(function (w) { return w.name; }); if (usado.indexOf(nome) > -1) nome = nome.slice(0, 25) + ' ' + (i + 1);
          var ws = wb.addWorksheet(nome, { views: [{ state: 'frozen', ySplit: 1 }] });
          var L = tb.filtradas ? tb.filtradas() : tb.linhas, cols = [];
          tb.colunas.forEach(function (c) { cols.push({ h: c.titulo || c.chave, k: c.chave, t: c.tipo }); if (c.sub) cols.push({ h: (c.titulo || c.chave) + ' (detalhe)', k: c.sub }); });
          ws.columns = cols.map(function (c) { return { header: c.h, key: c.k, width: Math.min(60, Math.max(12, String(c.h).length + 4)) }; });
          L.forEach(function (r) { var o = {}; cols.forEach(function (c) { var v = r[c.k]; o[c.k] = c.t === 'data' && isoData(v) ? new Date(String(v).slice(0, 10) + 'T12:00') : v; }); ws.addRow(o); });
          ws.getRow(1).eachCell(function (c) { c.font = { name: F, bold: true, color: { argb: 'FFFFFFFF' } }; c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF000000' } }; });
          cols.forEach(function (c, j) { if (c.t === 'data') ws.getColumn(j + 1).numFmt = 'dd/mm/yyyy'; });
          ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };
          etapa(35 + 45 * (i + 1) / TABELAS.length);
        });
        etapa(85);
        return wb.xlsx.writeBuffer();
      }).then(function (buf) {
        etapa(100);
        var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
        a.download = slug(R.cliente || 'cliente') + '_' + slug(R.titulo || 'relatorio') + '_' + new Date().toISOString().slice(0, 10) + '.xlsx';
        document.body.appendChild(a); a.click(); a.remove(); estado('done'); aviso('Excel exportado');
        setTimeout(function () { estado('idle'); btn.disabled = false; }, 2800);
      }).catch(function (e) {
        console.error(e); estado('error'); btn.disabled = false;
        aviso('Não foi possível gerar o Excel. Verifique a conexão com a internet e tente de novo.');
        setTimeout(function () { if (btn.dataset.state === 'error') estado('idle'); }, 3500);
      });
    });
  });

  /* ---------- vivo: relógio e tempos relativos ---------- */
  function tick() {
    $('#clock').textContent = new Date().toLocaleString('pt-BR', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).replace('.', '');
    $$('[data-rel]').forEach(function (t) { t.textContent = rel(t.getAttribute('datetime')); });
  }
  var sb = $('.side'); $$('[data-count]', sb).forEach(function (e) { countTo(e, num(e.dataset.count), { from: 0 }); }); setTimeout(function () { animar(sb, true); }, 200);
  modoSide(); tick(); setInterval(tick, 30000);
  window.addEventListener('hashchange', mostrar); mostrar();
  window.MotorV3 = { versao: '3.2', aviso: aviso };
})();
