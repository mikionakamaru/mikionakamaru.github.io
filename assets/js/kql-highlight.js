/* Colore blocos ```kql (o Rouge não tem lexer de KQL, então eles chegam sem cor). */
(function () {
  'use strict';
  var KW = 'where|extend|summarize|project|project-away|project-rename|order|sort|by|asc|desc|take|limit|top|join|kind|on|union|let|datatable|distinct|count|mv-expand|parse|evaluate|render|as|and|or|not|in|has|has_any|has_all|contains|startswith|endswith|matches|regex|between|isnotempty|isempty|isnull|isnotnull|lookup|invoke|materialize|range|search|getschema|serialize|make-series|find';
  var FN = 'ago|now|datetime|bin|count|dcount|countif|dcountif|sum|sumif|avg|min|max|arg_max|arg_min|make_set|make_list|make_bag|tostring|toint|tolong|todouble|tobool|todynamic|parse_json|extract|extract_all|coalesce|iff|iif|case|strcat|split|array_length|tolower|toupper|trim|replace_string|format_datetime|startofday|ipv4_is_private|ipv4_is_in_range|bag_unpack|percentile|round|strlen|substring|indexof|dynamic|set_has_element|array_concat|pack|pack_all|hash|base64_decode_tostring|geo_info_from_ip_address|column_ifexists|isnotempty';
  var re = new RegExp(
    '(//[^\\n]*)' +                                  // 1 comentário
    '|(@?"(?:[^"\\\\\\n]|\\\\.)*"|@?\'(?:[^\'\\\\\\n]|\\\\.)*\')' + // 2 string
    '|\\b(' + FN + ')(?=\\s*\\()' +                  // 3 função
    '|\\b(' + KW + ')\\b' +                          // 4 palavra-chave
    '|\\b(\\d+(?:\\.\\d+)?[dhms]?)\\b' +              // 5 número / timespan
    '|(\\||==|!=|=~|!~|>=|<=|=>|[<>=])',             // 6 operador
    'gi');
  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function paint(src) {
    var out = '', last = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(src))) {
      out += esc(src.slice(last, m.index));
      var cls = m[1] ? 'c' : m[2] ? 's' : m[3] ? 'f' : m[4] ? 'k' : m[5] ? 'n' : 'o';
      out += '<span class="kql-' + cls + '">' + esc(m[0]) + '</span>';
      last = re.lastIndex;
    }
    return out + esc(src.slice(last));
  }
  function run() {
    document.querySelectorAll('div.language-kql, div.language-kusto').forEach(function (box) {
      var pre = box.querySelector('td.rouge-code pre') || box.querySelector('pre code') || box.querySelector('pre');
      if (!pre || pre.dataset.kql) return;
      pre.innerHTML = paint(pre.textContent);
      pre.dataset.kql = '1';
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
