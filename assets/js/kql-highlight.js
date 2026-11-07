/* Colore blocos ```kql com as cores do editor do Advanced Hunting / Azure Data Explorer
   (tema escuro "kusto-dark" do monaco-kusto, github.com/Azure/monaco-kusto).
   O Rouge não tem lexer de KQL, então os blocos chegam sem cor. As cores de tabela e coluna
   são aproximadas: o editor real usa o esquema do workspace, aqui é por posição e maiúscula. */
(function () {
  'use strict';

  var KEYWORDS = toSet('by and or not in in~ !in !in~ has has_any has_all !has has_cs !has_cs hasprefix hassuffix contains !contains contains_cs startswith !startswith startswith_cs endswith !endswith endswith_cs between !between matches regex kind on asc desc nulls first last with let set true false inner leftouter rightouter fullouter leftanti rightanti leftsemi rightsemi innerunique anti semi typeof step from to like isfuzzy withsource bin_at hint.strategy hint.shufflekey string int long real double bool datetime timespan dynamic guid decimal');
  var TABLE_STARTERS = toSet('union join lookup');

  var TOKEN = /(\/\/[^\n]*)|(@?"(?:[^"\\\n]|\\.)*"|@?'(?:[^'\\\n]|\\.)*')|(\d+(?:\.\d+)?(?:d|h|m|s|ms|tick)?\b)|([A-Za-z_!][\w\-]*(?:~)?)|(\s+)|([\s\S])/g;

  function toSet(s) { var o = {}; s.split(' ').forEach(function (w) { o[w.toLowerCase()] = 1; }); return o; }
  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function span(cls, txt) { return '<span class="kq-' + cls + '">' + esc(txt) + '</span>'; }

  function paint(src) {
    var toks = [], m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(src))) {
      toks.push({
        t: m[1] ? 'comment' : m[2] ? 'string' : m[3] ? 'number' : m[4] ? 'id' : m[5] ? 'ws' : 'punct',
        v: m[0]
      });
    }

    // nomes criados com let viram variáveis
    var vars = {};
    for (var i = 0; i < toks.length; i++) {
      if (toks[i].t === 'id' && toks[i].v === 'let') {
        var j = next(toks, i);
        if (j > -1 && toks[j].t === 'id') vars[toks[j].v] = 1;
      }
    }

    var out = '', atLineStart = true, lineIndented = false, tableMode = false;
    for (i = 0; i < toks.length; i++) {
      var k = toks[i], v = k.v;
      if (k.t === 'ws') {
        if (v.indexOf('\n') > -1) { atLineStart = true; lineIndented = /\n[ \t]+$/.test(v); }
        else if (atLineStart && out === '' ) { lineIndented = true; }
        out += esc(v);
        continue;
      }
      var prev = prevSig(toks, i);
      var nxt = next(toks, i);
      var nextV = nxt > -1 ? toks[nxt].v : '';
      var cls = null;

      if (k.t === 'comment') cls = 'comment';
      else if (k.t === 'string') cls = 'string';
      else if (k.t === 'number') cls = 'plain';
      else if (k.t === 'punct') { cls = 'plain'; if (v === ';') tableMode = false; }
      else {
        var low = v.toLowerCase();
        if (prev && prev.v === '|') { cls = 'op'; tableMode = TABLE_STARTERS[low] === 1; }
        else if (TABLE_STARTERS[low] && atLineStart) { cls = 'op'; tableMode = true; }
        else if (vars[v]) cls = 'var';
        else if (nextV === '(' && !KEYWORDS[low]) cls = 'fn';
        else if (KEYWORDS[low]) cls = 'kw';
        else if (/^[A-Z]/.test(v) && ((atLineStart && !lineIndented) || tableMode)) cls = 'table';
        else if (/^[A-Z]/.test(v)) cls = 'col';
        else cls = 'plain';
        if (cls === 'kw' && (low === 'on' || low === 'by')) tableMode = false;
      }
      out += cls === 'plain' ? esc(v) : span(cls, v);
      atLineStart = false;
    }
    return out;
  }

  function next(toks, i) { for (var j = i + 1; j < toks.length; j++) if (toks[j].t !== 'ws') return j; return -1; }
  function prevSig(toks, i) { for (var j = i - 1; j >= 0; j--) if (toks[j].t !== 'ws') return toks[j]; return null; }

  function run() {
    document.querySelectorAll('div.language-kql, div.language-kusto').forEach(function (box) {
      var pre = box.querySelector('td.rouge-code pre') || box.querySelector('pre code') || box.querySelector('pre');
      if (!pre || pre.dataset.kql) return;
      pre.innerHTML = paint(pre.textContent);
      pre.dataset.kql = '1';
      box.classList.add('kusto-dark');
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
