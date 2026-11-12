// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
/* CSP uyumlu olay işleyicileri: satır içi onclick= yerine data-on-<olay>="..." niteliği.
 * Nitelik değeri eval/Function olmadan çözülen küçük bir dildir:
 *   ifade; ifade; ...   (noktalı virgülle)
 *   ad(arg, ...)        window altındaki (noktalı) fonksiyon çağrısı
 *   return confirm('..')  / return false
 *   event.preventDefault() / event.stopPropagation() / if(window.event) window.event.stopPropagation()
 *   if(KOŞUL) ifade     KOŞUL: A===B (A,B: event.target | event.key | this | 'metin')
 * arg: 'metin', sayı, true/false/null, this, event, this.value, this.checked, this.getAttribute('x')
 */
(function () {
  'use strict';
  var EVENTS = ['click', 'change', 'input', 'submit', 'keyup', 'keydown', 'keypress',
                'mouseover', 'mouseout', 'focus', 'blur'];
  var NON_BUBBLING = {focus: 1, blur: 1};
  var cache = Object.create(null);

  function splitTop(src, sep) {
    var out = [], cur = '', q = null, depth = 0;
    for (var i = 0; i < src.length; i++) {
      var c = src[i];
      if (q) {
        cur += c;
        if (c === '\\') { cur += src[++i] || ''; } else if (c === q) { q = null; }
      } else if (c === '"' || c === "'") { q = c; cur += c; }
      else if (c === '(') { depth++; cur += c; }
      else if (c === ')') { depth--; cur += c; }
      else if (c === sep && depth === 0) { out.push(cur); cur = ''; }
      else { cur += c; }
    }
    if (cur.trim()) out.push(cur);
    return out.map(function (s) { return s.trim(); }).filter(Boolean);
  }

  function unquote(s) {
    var body = s.slice(1, -1), out = '';
    for (var i = 0; i < body.length; i++) {
      var c = body[i];
      if (c !== '\\') { out += c; continue; }
      c = body[++i];
      if (c === 'n') out += '\n';
      else if (c === 't') out += '\t';
      else if (c === 'r') out += '\r';
      else if (c === 'x') { out += String.fromCharCode(parseInt(body.substr(i + 1, 2), 16)); i += 2; }
      else if (c === 'u') { out += String.fromCharCode(parseInt(body.substr(i + 1, 4), 16)); i += 4; }
      else out += c;
    }
    return out;
  }

  function isStr(s) { return s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]; }

  function value(expr, ctx) {
    expr = expr.trim();
    if (isStr(expr)) return unquote(expr);
    if (/^-?\d+(\.\d+)?$/.test(expr)) return Number(expr);
    if (expr === 'true') return true;
    if (expr === 'false') return false;
    if (expr === 'null') return null;
    if (expr === 'this') return ctx.el;
    if (expr === 'event') return ctx.ev;
    if (expr === 'event.target') return ctx.ev.target;
    if (expr === 'event.key') return ctx.ev.key;
    if (expr === 'this.value') return ctx.el.value;
    if (expr === 'this.checked') return ctx.el.checked;
    var m = /^this\.getAttribute\((.+)\)$/.exec(expr);
    if (m) return ctx.el.getAttribute(value(m[1], ctx));
    throw new Error('desteklenmeyen ifade: ' + expr);
  }

  function call(expr, ctx) {
    var m = /^([A-Za-z_$][\w$.]*)\((.*)\)$/.exec(expr);
    if (!m) throw new Error('desteklenmeyen deyim: ' + expr);
    var path = m[1].split('.'), obj = window, parent = window;
    for (var i = 0; i < path.length; i++) { parent = obj; obj = obj == null ? undefined : obj[path[i]]; }
    if (typeof obj !== 'function') throw new Error('fonksiyon yok: ' + m[1]);
    var args = splitTop(m[2], ',').map(function (a) { return value(a, ctx); });
    return obj.apply(parent, args);
  }

  // true dönerse zincir durur (propagation durdurma bayrağı ctx.stop ile)
  function run(code, ctx) {
    var stmts = cache[code] || (cache[code] = splitTop(code, ';'));
    for (var i = 0; i < stmts.length; i++) {
      var s = stmts[i], m;
      if (s === 'return false') { ctx.ev.preventDefault(); return; }
      if (s === 'return true') return;
      if ((m = /^return\s+confirm\((.*)\)$/.exec(s))) {
        if (!window.confirm(value(m[1], ctx))) ctx.ev.preventDefault();
        continue;
      }
      if (s === 'event.preventDefault()') { ctx.ev.preventDefault(); continue; }
      if (s === 'event.stopPropagation()' || s === 'if(window.event) window.event.stopPropagation()') {
        ctx.stop = true; continue;
      }
      if ((m = /^if\((.+?)\)\s*(.+)$/.exec(s))) {
        var parts = m[1].split('===');
        if (parts.length !== 2) throw new Error('desteklenmeyen koşul: ' + m[1]);
        if (value(parts[0], ctx) === value(parts[1], ctx)) run(m[2], ctx);
        continue;
      }
      call(s, ctx);
    }
  }

  function handle(type) {
    var attr = 'data-on-' + type;
    return function (ev) {
      var el = ev.target;
      while (el && el.nodeType === 1) {
        var code = el.getAttribute(attr);
        if (code !== null) {
          var ctx = {el: el, ev: ev, stop: false};
          try { run(code, ctx); } catch (e) { if (window.console) console.error('[csp-actions]', e.message, code); }
          if (ctx.stop) { ev.stopPropagation(); return; }
        }
        if (NON_BUBBLING[type]) return;
        el = el.parentNode;
      }
    };
  }

  EVENTS.forEach(function (t) {
    document.addEventListener(t, handle(t), !!NON_BUBBLING[t]);
  });
})();
