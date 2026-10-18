// ==UserScript==
// @name         智慧树刷进度·任务面板
// @namespace    https://github.com/point-zip/fuck-zhs
// @author       point-zip
// @version      2.1.0
// @description  直接调用课程目录接口枚举全部视频，勾选批量入队；跨页面刷进度（配合后台引擎或内置回退引擎）
// @match        *://*.zhihuishu.com/*
// @match        *://zhihuishu.com/*
// @storageName  https://github.com/point-zip/fuck-zhs
// @connect      kg-ai-run.zhihuishu.com
// @connect      appcomm-user.zhihuishu.com
// @connect      *.zhihuishu.com
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_xmlhttpRequest
// @grant        GM_addValueChangeListener
// @grant        GM_log
// @run-at       document-idle
// @license      AGPL-3.0-or-later
// ==/UserScript==

(() => {
  "use strict";
  // ================= 加密核心（与后台引擎一致） =================
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64enc(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i += 3) {
      const b0 = u8[i], b1 = u8[i + 1], b2 = u8[i + 2];
      s += B64[b0 >> 2] + B64[(b0 & 3) << 4 | (b1 || 0) >> 4]
        + (b1 === undefined ? "=" : B64[(b1 & 15) << 2 | (b2 || 0) >> 6])
        + (b2 === undefined ? "=" : B64[b2 & 63]);
    }
    return s;
  }
  function b64dec(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, "");
    const bytes = [];
    let buf = 0, bits = 0;
    for (const ch of s) {
      if (ch === "=") break;
      const v = B64.indexOf(ch);
      if (v < 0) continue;
      buf = (buf << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 0xFF); }
    }
    return new Uint8Array(bytes);
  }
  const hexOf = u8 => Array.from(u8, x => x.toString(16).padStart(2, "0")).join("");
  function hexToBytes(h) {
    if (h.length % 2) h = "0" + h;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function modexp(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }

  const PUB = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgfZmpLpPEpEFRKBe+ZjWJUjPe+7qg7pGqcfN3j2egJ8H2mrKwaEqZEnPnpi2O3hN8HRyaFozDOp8gwZiYfiIZjWy0Jr/FNAiiKYh5bq0GsEn+ieMmRyJg/+i1rqizhvCXvFdrdGhFTw5EBwTpsGdwe1utdlrvIJUAFWj9Yh4qbQIDAQAB";
  let _pub = null;
  function parsePub() {
    if (_pub) return _pub;
    const der = b64dec(PUB);
    let i = 0;
    for (; i < der.length - 4; i++) if (der[i] === 2 && der[i + 1] === 0x81 && der[i + 2] === 0x81 && der[i + 3] === 0) break;
    const n = BigInt("0x" + hexOf(der.slice(i + 4, i + 4 + 128)));
    let j = i + 4 + 128, e = 65537n;
    if (der[j] === 2 && der[j + 1] === 3) e = BigInt("0x" + hexOf(der.slice(j + 2, j + 5)));
    return (_pub = { n, e });
  }
  function rsaEncrypt(obj) {
    const { n, e } = parsePub();
    const msg = new TextEncoder().encode(JSON.stringify(obj));
    const k = 128, em = new Uint8Array(k);
    em[0] = 0; em[1] = 2;
    let p = 2;
    while (p < k - msg.length - 1) em[p++] = 1 + Math.floor(Math.random() * 254);
    em[p++] = 0; em.set(msg, p);
    const c = modexp(BigInt("0x" + hexOf(em)), e, n);
    return b64enc(hexToBytes(c.toString(16).padStart(256, "0")));
  }
  function rsaUnwrap(b64) {
    const { n, e } = parsePub();
    const c = BigInt("0x" + hexOf(b64dec(b64)));
    const bytes = hexToBytes(modexp(c, e, n).toString(16).padStart(256, "0"));
    let k = 2; while (k < bytes.length && bytes[k] === 0xff) k++;
    return new TextDecoder().decode(bytes.slice(k + 1));
  }
  const IV = "1g3qqdh4jvbskb9x";
  async function aesEncrypt(plain, cKey) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(cKey), "AES-CBC", false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: enc.encode(IV) }, key, enc.encode(plain));
    return b64enc(new Uint8Array(ct));
  }

  // 传输层：优先页面 fetch（同源 Cookie 必在、CORS 白名单内），失败回退 GM_xmlhttpRequest
  let lastTransport = "?";
  async function xhrGM(url, opt = {}) {
    return new Promise((res, rej) => {
      GM_xmlhttpRequest({
        method: opt.method || "GET", url, timeout: 20000,
        headers: opt.headers || {}, data: opt.data,
        onload: r => res(r), onerror: () => rej(new Error("GM网络错误")), ontimeout: () => rej(new Error("GM超时")),
      });
    });
  }
  async function xhrPage(url, opt = {}) {
    const r = await fetch(url, {
      method: opt.method || "GET",
      headers: opt.headers || {},
      body: opt.data,
      credentials: "include",
    });
    return { status: r.status, responseText: await r.text() };
  }
  async function xhr(url, opt = {}) {
    try {
      const r = await xhrPage(url, opt);
      lastTransport = "页面fetch";
      return r;
    } catch (e) {
      const r = await xhrGM(url, opt);
      lastTransport = "GM";
      return r;
    }
  }

  // ================= 存储与常量 =================
  const BASE = "https://kg-ai-run.zhihuishu.com/run/gateway/t/stu";
  const STUDY = BASE + "/studyRecord/study";
  const REPORT = BASE + "/studyRecord/report";
  const TREE_URL = BASE + "/maptree/get-tree-map-tree";
  const RES_URL = BASE + "/resources/list-knowledge-resource";
  const HAS = "https://appcomm-user.zhihuishu.com/app-commserv-user/c/has?uid=";
  const DEF_CKEY = "hw2fdlwcj4cs1mx7";
  const DEF_HDR = ""; // 无默认值：XQJZXHIZ 一律运行时从 mapUid 派生（学习页 sessionStorage / URL 参数）
  const K_TASKS = "zhs_tasks_v1", K_STATE = "zhs_engine_state", K_SET = "zhs_settings", K_HDR = "zhs_header_xq", K_UI = "zhs_ui_pos", K_COURSE = "zhs_course_v1", K_SERVERPROG = "zhs_serverprog_v1";
  const MY_ID = "panel-" + Math.random().toString(36).slice(2, 9);
  const getJ = (k, d) => { try { const v = GM_getValue(k); return v == null ? d : (typeof v === "string" ? JSON.parse(v) : v); } catch (e) { return d; } };
  const setJ = (k, v) => GM_setValue(k, JSON.stringify(v));
  const rnd = (a, b) => a + Math.random() * (b - a);
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function refreshCKey() {
    const s = getJ(K_SET, {});
    try {
      const r = await xhr(HAS + encodeURIComponent(rsaEncrypt({ module: 6 })));
      const j = JSON.parse(rsaUnwrap(JSON.parse(r.responseText).rt.sl));
      if (j.cKey) { s.cKey = j.cKey; setJ(K_SET, s); }
    } catch (e) { toast("密钥刷新失败，用缓存 cKey", true); }
    return s.cKey || DEF_CKEY;
  }
  // XQJZXHIZ = AES(mapUid)：mapUid 每门课不同；优先读页面 sessionStorage / URL 参数，拉到树后用 map.mapUid 权威重算
  async function headerFromMapUid(mapUid, cKey) {
    if (!mapUid) return null;
    try { const h = await aesEncrypt(String(mapUid), cKey); setJ(K_HDR, h); return h; } catch (e) { return null; }
  }
  function pageMapUid() {
    try { const mu = sessionStorage.getItem("mapUid"); if (mu) return mu; } catch (e) {}
    try { const mu = new URL(location.href).searchParams.get("mapUid"); if (mu) return mu; } catch (e) {}
    return "";
  }
  async function currentHeader(cKey) {
    const h = await headerFromMapUid(pageMapUid(), cKey);
    if (h) return h;
    return getJ(K_HDR, DEF_HDR);
  }

  // 加密 POST，返回解析后的 {code,data,message}；网络层失败抛异常
  async function apiPost(url, payload, cKey, header) {
    const sec = await aesEncrypt(JSON.stringify(Object.assign({ uuid: getUuid(), date: Date.now() }, payload)), cKey);
    const headers = { "Content-Type": "application/json;charset=UTF-8", Accept: "application/json, text/plain, */*" };
    if (header) headers.XQJZXHIZ = header;
    const r = await xhr(url, {
      method: "POST",
      headers,
      data: JSON.stringify({ secretStr: sec, date: Date.now() }),
    });
    let j = null; try { j = JSON.parse(r.responseText); } catch (e) {}
    if (!j) throw new Error("响应异常 http=" + r.status);
    return j;
  }
  function getUuid() {
    try { return JSON.parse(document.cookie.match(/CASLOGC=([^;]*)/)[1].replace(/%22/g, '"')).uuid || ""; } catch (e) { return ""; }
  }

  // ================= 课程视频枚举 =================
  function collectNodes(nodeList) {
    const out = [];
    (function walk(arr) { for (const n of arr || []) { out.push({ uid: n.nodeUid, name: (n.nodeName || "").replace(/<br\s*\/?>/gi, " ") }); walk(n.children); } })(nodeList);
    return out;
  }
  let lastDiag = { transport: "?", treeCode: 0, nodes: 0, ok: 0, empty: 0, fail: 0, firstErr: "" };
  async function fetchCourseVideos(courseId, classId, cKey, headerRef, onProg) {
    const tree = await apiPost(TREE_URL, { courseId, classId }, cKey, headerRef.v);
    lastDiag.treeCode = tree.code;
    if (tree.code !== 200) throw new Error("目录获取失败: " + (tree.message || tree.code));
    // 用树响应里的权威 mapUid 重算请求头（跨课程正确）
    const mu = (tree.data || {}).map && tree.data.map.mapUid;
    const h2 = await headerFromMapUid(mu, cKey);
    if (h2) headerRef.v = h2;
    const nodes = collectNodes((tree.data || {}).nodeList);
    lastDiag.nodes = nodes.length;
    if (!nodes.length) throw new Error("目录为空");
    const videos = [];
    let done = 0;
    lastDiag.ok = 0; lastDiag.empty = 0; lastDiag.fail = 0; lastDiag.firstErr = "";
    const queue = nodes.slice();
    await Promise.all(Array(5).fill(0).map(async () => {
      while (queue.length) {
        const n = queue.shift();
        try {
          const r = await apiPost(RES_URL, { courseId, classId, knowledgeId: n.uid }, cKey, headerRef.v);
          const list = ((r.data || {}).resourceList) || [];
          if (r.code === 200 && !list.length) lastDiag.empty++;
          let got = 0;
          for (const it of list) {
            const d = it.resourcesDetail || {};
            const dur = Number(d.resourcesTime);
            if (d.resourcesFileId && dur > 0 && (d.resourcesSuffix === "mp4" || d.resourcesDataType === 11)) {
              videos.push({
                knowledgeId: n.uid, nodeName: n.name, fileId: String(d.resourcesFileId),
                name: (d.resourcesName || n.name).slice(0, 80), duration: dur,
                schedule: it.schedule || 0, studyTotalTime: it.studyTotalTime || 0,
                studyStatus: it.studyStatus, resourcesUid: d.resourcesUid,
              });
              got++;
            }
          }
          if (got) lastDiag.ok++;
        } catch (e) {
          lastDiag.fail++;
          if (!lastDiag.firstErr) lastDiag.firstErr = (e && e.message) || String(e);
        }
        done++; if (onProg) onProg(done, nodes.length);
      }
    }));
    const seen = new Set();
    const uniq = videos.filter(v => { const k = v.knowledgeId + "|" + v.fileId; if (seen.has(k)) return false; seen.add(k); return true; });
    uniq.sort((a, b) => a.nodeName.localeCompare(b.nodeName, "zh") || a.duration - b.duration);
    return uniq;
  }

  // URL 兜底：/learnPage/{courseId}/{x}/{classId}
  function parsePageIds() {
    try {
      const ids = (location.pathname.match(/\d{16,21}/g) || []);
      return { courseId: ids[0] || "", classId: ids[2] || "" };
    } catch (e) { return { courseId: "", classId: "" }; }
  }

  // ================= 回退引擎（后台脚本不在时由面板驱动） =================
  const ticking = {};
  async function tickTask(t, prog, cKey) {
    if (ticking[t.id]) return;
    ticking[t.id] = 1;
    try {
      let st = prog.fresh ? rnd(2, 4) : rnd(9.2, 9.99);
      prog.fresh = false;
      if (t.duration) {
        const remaining = t.duration - prog.lastWatchTime;
        if (remaining < 1) { prog.status = "done"; return; }
        st = Math.min(st, remaining);
      }
      // 真实协议：studyTime 是累计观看秒数（=lastWatchTime+小数），lastWatchTime 是其整数
      const lwt = Math.round((prog.lastWatchTime + st) * 1000) / 1000;
      const sec = Math.floor(Date.now() / 1000) * 1000;
      const header = t.headerXq || getJ(K_HDR, DEF_HDR);
      const base = { courseId: t.courseId, classId: t.classId, knowledgeId: t.knowledgeId };
      const study = Object.assign({}, base, { source: 1, studyFileType: 1, fileId: t.fileId, studyTime: lwt, lastWatchTime: Math.floor(lwt), dateFormate: sec });
      const rep = Object.assign({}, base, { fileId: t.fileId, studyTotalTime: Math.max(1, Math.floor(st)), lastWatchTime: Math.floor(lwt), shareCourseId: "", watchUId: 1, nodeType: t.nodeType || 0, dateFormate: sec });
      const r1 = await apiPost(STUDY, study, cKey, header);
      if (r1.code !== 200) throw Object.assign(new Error("study " + r1.code + " " + (r1.message || "")), { fatal: r1.code === 401 || r1.code === 403 });
      const r2 = await apiPost(REPORT, rep, cKey, header);
      if (r2.code !== 200) throw Object.assign(new Error("report " + r2.code + " " + (r2.message || "")), { fatal: r2.code === 401 || r2.code === 403 });
      prog.lastWatchTime = lwt; prog.attempts = 0; prog.status = "running"; prog.err = "";
      if (t.duration && t.duration - lwt < 1) prog.status = "done";
    } catch (e) {
      prog.attempts = (prog.attempts || 0) + 1; prog.err = e.message;
      prog.status = e.fatal || prog.attempts >= 3 ? "error" : "retrying";
    } finally { delete ticking[t.id]; }
  }
  // 驱动仲裁：内存态跨秒保留（修复异步写丢失），lastDriver/lastTickAt 防双发
  let memState = null;
  function loopOnce(cKey) {
    const now = Date.now();
    const stored = getJ(K_STATE, {});
    if (stored.masterPaused) return;
    // 别的驱动者刚有产出 → 让位（引擎活着就别抢；它失联 12 秒内即接管）
    if (stored.lastDriver && stored.lastDriver !== MY_ID && now - (stored.lastTickAt || 0) < 12000) return;
    if (!memState) memState = { progress: stored.progress ? JSON.parse(JSON.stringify(stored.progress)) : {} };
    const state = memState;
    const tasks = getJ(K_TASKS, []);
    const set = getJ(K_SET, { concurrency: 2 });
    const progAll = state.progress;
    const active = tasks.filter(t => !t.paused && (!progAll[t.id] || !["done", "error"].includes(progAll[t.id].status)));
    active.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    let ticked = 0;
    for (const t of active.slice(0, Math.max(1, set.concurrency || 2))) {
      const p = progAll[t.id] || (progAll[t.id] = { lastWatchTime: t.lastWatchTime || 0, fresh: true, status: "queued", attempts: 0, nextTickAt: now + rnd(800, 9000) });
      if (now >= p.nextTickAt) { p.nextTickAt = now + 10000 + rnd(0, 1200); ticked++; tickTask(t, p, cKey); }
    }
    for (const id of Object.keys(progAll)) if (!tasks.find(t => t.id === id)) delete progAll[id];
    if (ticked || stored.lastDriver !== MY_ID) { state.lastDriver = MY_ID; state.lastTickAt = now; state.lastTickCount = ticked; }
    setJ(K_STATE, state);
  }

  // ================= UI =================
  const CSS = `
#zhs-panel{position:fixed;top:80px;right:16px;width:360px;background:#fff;border:1px solid #d0d7de;border-radius:10px;
 box-shadow:0 4px 18px rgba(0,0,0,.15);z-index:2147483647;font:12px/1.5 system-ui,"Microsoft YaHei";color:#24292f}
#zhs-panel .hd{padding:7px 10px;background:#1f6feb;color:#fff;border-radius:10px 10px 0 0;cursor:move;user-select:none;display:flex;justify-content:space-between;align-items:center}
#zhs-panel .hd b{font-size:13px}
#zhs-panel .bd{padding:8px 10px;max-height:480px;overflow:auto}
#zhs-panel .row{display:flex;gap:5px;margin-bottom:6px;align-items:center;flex-wrap:wrap}
#zhs-panel input.zin{width:130px;border:1px solid #d0d7de;border-radius:6px;padding:2px 6px;font-size:11px}
#zhs-panel button{cursor:pointer;border:1px solid #d0d7de;background:#f6f8fa;border-radius:6px;padding:2px 8px;font-size:12px}
#zhs-panel button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
#zhs-panel button.danger{background:#da3633;color:#fff;border-color:#da3633}
#zhs-panel button:disabled{opacity:.5;cursor:default}
#zhs-panel .task{border:1px solid #eaeef2;border-radius:8px;padding:6px 8px;margin-bottom:6px}
#zhs-panel .task .nm{font-weight:600;word-break:break-all}
#zhs-panel .task .meta{color:#57606a;font-size:11px}
#zhs-panel .pg{height:6px;background:#eaeef2;border-radius:4px;margin:4px 0;overflow:hidden}
#zhs-panel .pg i{display:block;height:100%;background:#2da44e}
#zhs-panel .st-done{color:#2da44e}.st-error{color:#da3633}.st-running{color:#1f6feb}.st-retrying{color:#bf8700}.st-queued{color:#57606a}
#zhs-panel .ops{display:flex;gap:4px;margin-top:4px}
#zhs-panel #zhs-msg{font-size:11px;color:#57606a;margin:4px 0;min-height:14px;word-break:break-all}
#zhs-panel #zhs-msg.err{color:#da3633}
#zhs-panel .vid{border:1px solid #eaeef2;border-radius:6px;padding:3px 6px;margin-bottom:3px;font-size:11px;display:flex;gap:6px;align-items:center}
#zhs-panel .vid label{flex:1;word-break:break-all;cursor:pointer}
#zhs-panel .vid .sch{color:#57606a;white-space:nowrap}
#zhs-panel .divider{border-top:1px solid #eaeef2;margin:8px 0 6px;font-weight:600;color:#57606a;font-size:11px}`;
  const doc = document;
  const panel = doc.createElement("div");
  panel.id = "zhs-panel";
  doc.body.appendChild(panel);
  { const st = doc.createElement("style"); st.textContent = CSS; (doc.head || doc.documentElement).appendChild(st); }

  const $ = s => panel.querySelector(s);
  const saved = getJ(K_COURSE, {});
  const pp = parsePageIds();
  panel.innerHTML = `
<div class="hd"><b>🌳 智慧树刷进度</b><span style="cursor:pointer" data-act="collapse">—</span></div>
<div class="bd">
  <div class="row">
    <input class="zin" id="zhs-cid" placeholder="courseId" value="${esc(saved.courseId || pp.courseId)}">
    <input class="zin" id="zhs-cls" placeholder="classId" value="${esc(saved.classId || pp.classId)}">
    <button data-act="load" class="primary">📚 读取视频</button>
  </div>
  <div id="zhs-msg"></div>
  <div id="zhs-leader" style="color:#57606a;margin-bottom:6px"></div>
  <div id="zhs-picker" style="display:none"></div>
  <div class="divider">任务列表 <button data-act="refresh" style="font-size:10px;padding:0 6px">↻ 服务端进度</button></div>
  <div class="row">
    <button data-act="pauseall" id="zhs-pauseall">⏸ 全部暂停</button>
    <span style="margin-left:auto">并发 <input class="zin" id="zhs-concin" type="number" min="1" step="1" style="width:52px"></span>
  </div>
  <div id="zhs-list"></div>
</div>`;
  function toast(m, isErr) {
    const el = $("#zhs-msg");
    el.textContent = m; el.className = isErr ? "err" : "";
    clearTimeout(toast._t); toast._t = setTimeout(() => { el.textContent = ""; }, 10000);
  }

  // 拖动 + 位置恢复
  const pos = getJ(K_UI, null);
  if (pos) { panel.style.left = pos.x + "px"; panel.style.top = pos.y + "px"; panel.style.right = "auto"; }
  $(".hd").addEventListener("mousedown", e => {
    if (e.target.dataset.act) return;
    const sx = e.clientX - panel.offsetLeft, sy = e.clientY - panel.offsetTop;
    const mv = ev => { panel.style.left = ev.clientX - sx + "px"; panel.style.top = ev.clientY - sy + "px"; panel.style.right = "auto"; };
    const up = () => { doc.removeEventListener("mousemove", mv); doc.removeEventListener("mouseup", up); setJ(K_UI, { x: panel.offsetLeft, y: panel.offsetTop }); };
    doc.addEventListener("mousemove", mv); doc.addEventListener("mouseup", up);
  });

  let lastVideos = [];
  panel.addEventListener("click", e => {
    try {
      const act = e.target.dataset && e.target.dataset.act;
      if (!act) return;
      if (act === "collapse") { const bd = $(".bd"); bd.style.display = bd.style.display === "none" ? "" : "none"; }
      if (act === "load") loadVideos();
      if (act === "addsel") addSelected();
      if (act === "selall") { panel.querySelectorAll("#zhs-picker input[type=checkbox]:not(:disabled)").forEach(c => { c.checked = true; }); }
      if (act === "selnone") { panel.querySelectorAll("#zhs-picker input[type=checkbox]").forEach(c => { c.checked = false; }); }
      if (act === "merge") { const s = getJ(K_SET, {}); s.mergeByFile = s.mergeByFile === false; setJ(K_SET, s); renderPicker(); }
      if (act === "refresh") refreshServerProgress();
      if (act === "pauseall") { const s = getJ(K_STATE, {}); s.masterPaused = !s.masterPaused; setJ(K_STATE, s); render(); }
      if (act === "del") { const id = e.target.closest("[data-id]").dataset.id; setJ(K_TASKS, getJ(K_TASKS, []).filter(t => t.id !== id)); render(); }
      if (act === "tpause") {
        const id = e.target.closest("[data-id]").dataset.id;
        const ts = getJ(K_TASKS, []); const t = ts.find(x => x.id === id);
        if (t) { t.paused = !t.paused; setJ(K_TASKS, ts); }
        render();
      }
      if (act === "reset") {
        const id = e.target.closest("[data-id]").dataset.id;
        const st = getJ(K_STATE, {});
        st.progress = st.progress || {};
        const t = getJ(K_TASKS, []).find(x => x.id === id) || {};
        st.progress[id] = { lastWatchTime: t.lastWatchTime || 0, fresh: true, status: "queued", attempts: 0, nextTickAt: Date.now() + rnd(500, 3000) };
        st.progressGen = (st.progressGen || 0) + 1; // 让任一驱动者的内存态失效，强制重载
        memState = null;
        setJ(K_STATE, st); render();
      }
    } catch (e2) { toast("操作失败：" + (e2 && e2.message), true); }
  });
  // 并发输入：无上限
  panel.addEventListener("change", e => {
    if (e.target && e.target.id === "zhs-concin") {
      const v = Math.max(1, Math.floor(Number(e.target.value) || 2));
      const s = getJ(K_SET, {}); s.concurrency = v; setJ(K_SET, s);
      e.target.value = v;
    }
  });

  // ---- 读取整门课视频 ----
  async function loadVideos() {
    const courseId = $("#zhs-cid").value.trim(), classId = $("#zhs-cls").value.trim();
    if (!courseId || !classId) return toast("courseId / classId 必填（学习页 URL 前后两段 ID，已自动填则直接点读取）", true);
    const btn = panel.querySelector('[data-act="load"]');
    btn.disabled = true; btn.textContent = "读取中…";
    toast("正在拉取目录并枚举视频，几百个节点约需 20-40 秒…");
    try {
      const cKey = await refreshCKey();
      const headerRef = { v: await currentHeader(cKey) };
      setJ(K_COURSE, { courseId, classId });
      try { setJ("zhs_cookie", document.cookie); } catch (e) {}
      lastVideos = await fetchCourseVideos(courseId, classId, cKey, headerRef, (d, n) => {
        btn.textContent = d + "/" + n;
      });
      lastDiag.transport = lastTransport;
      const cur = getJ(K_HDR, DEF_HDR);
      lastVideos.forEach(v => { v.headerXq = cur; });
      renderPicker();
      const diagTxt = `[${lastDiag.transport}] 树${lastDiag.treeCode} 节点${lastDiag.nodes} 成功${lastDiag.ok} 空${lastDiag.empty} 失败${lastDiag.fail}` + (lastDiag.firstErr ? ` 首错:${lastDiag.firstErr}` : "");
      if (lastVideos.length) toast(`✓ 共发现 ${lastVideos.length} 个视频，勾选后添加 ${diagTxt}`);
      else if (lastDiag.fail) toast(`节点查询失败 ${lastDiag.fail}/${lastDiag.nodes}（${lastDiag.firstErr}）`, true);
      else if (lastDiag.empty) toast(`接口正常但 ${lastDiag.empty} 个节点都没匹配到视频字段，请把此提示截图发我`, true);
      else toast("未发现视频（检查 courseId/classId）", true);
    } catch (e) {
      toast("读取失败：" + (e && e.message), true);
    } finally { btn.disabled = false; btn.textContent = "📚 读取视频"; }
  }
  function renderPicker() {
    const pk = $("#zhs-picker");
    if (!lastVideos.length) { pk.style.display = "none"; return; }
    const mergeOn = (getJ(K_SET, {}) || {}).mergeByFile !== false;
    // 合并模式：同一 mp4 被切片引用到多个节点时只建一个任务（默认开）
    let items = lastVideos.map((v, idx) => ({ v, idx }));
    if (mergeOn) { const seen = new Set(); items = items.filter(({ v }) => { if (seen.has(v.fileId)) return false; seen.add(v.fileId); return true; }); }
    const existingKeys = new Set(getJ(K_TASKS, []).map(t => t.knowledgeId + "|" + t.fileId));
    const existingFiles = new Set(getJ(K_TASKS, []).map(t => String(t.fileId)));
    pk.style.display = "";
    pk.innerHTML = `<div class="divider">视频清单 ${items.length} 个（<button data-act="selall" style="font-size:10px;padding:0 6px">全选</button> <button data-act="selnone" style="font-size:10px;padding:0 6px">清空</button> <button data-act="merge" style="font-size:10px;padding:0 6px">按文件合并:${mergeOn ? "开" : "关"}</button> <button data-act="addsel" class="primary" style="font-size:10px;padding:0 8px">➕ 添加选中</button>）</div>` +
      items.map(({ v, idx }) => {
        const dup = existingKeys.has(v.knowledgeId + "|" + v.fileId) || (mergeOn && existingFiles.has(String(v.fileId)));
        return `<div class="vid"><input type="checkbox" data-vi="${idx}" ${dup ? "disabled" : "checked"}>
        <label>${esc(v.name)}</label><span class="sch">${Math.floor(v.duration / 60)}分${v.duration % 60}秒${v.schedule ? " · 已" + v.schedule + "%" : ""}</span></div>`;
      }).join("");
  }
  async function addSelected() {
    const mergeOn = (getJ(K_SET, {}) || {}).mergeByFile !== false;
    const courseId = $("#zhs-cid").value.trim(), classId = $("#zhs-cls").value.trim();
    const checked = [...panel.querySelectorAll("#zhs-picker input[type=checkbox]:checked")].map(c => lastVideos[Number(c.dataset.vi)]).filter(Boolean);
    if (!checked.length) return toast("未勾选任何视频", true);
    const ts = getJ(K_TASKS, []);
    const st = getJ(K_STATE, {});
    st.progress = st.progress || {};
    let added = 0;
    const pickedFiles = new Set();
    for (const v of checked) {
      if (mergeOn) { if (pickedFiles.has(String(v.fileId))) continue; pickedFiles.add(String(v.fileId)); }
      const key = v.knowledgeId + "|" + v.fileId;
      if (ts.some(t => t.knowledgeId + "|" + t.fileId === key)) continue;
      const t = {
        id: "t" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        name: v.name, courseId, classId, knowledgeId: v.knowledgeId, fileId: v.fileId,
        duration: v.duration, nodeType: 0, createdAt: Date.now(), paused: false,
        lastWatchTime: Math.min(v.studyTotalTime || 0, Math.max(0, v.duration - 5)),
        headerXq: v.headerXq || getJ(K_HDR, DEF_HDR),
      };
      ts.push(t);
      st.progress[t.id] = { lastWatchTime: t.lastWatchTime, fresh: true, status: "queued", attempts: 0, nextTickAt: Date.now() + rnd(800, 9000) };
      added++;
    }
    setJ(K_TASKS, ts); setJ(K_STATE, st);
    renderPicker(); render();
    toast("✅ 已添加 " + added + " 个任务（共 " + ts.length + " 个）");
  }

  // ---- 服务端真实进度刷新（独立存储键，避免被驱动者内存态每秒覆盖） ----
  async function refreshServerProgress() {
    const ts = getJ(K_TASKS, []);
    if (!ts.length) return toast("无任务", true);
    const cKey = (getJ(K_SET, {}) || {}).cKey || DEF_CKEY;
    const btn = panel.querySelector('[data-act="refresh"]');
    if (btn) { btn.disabled = true; btn.textContent = "刷新中…"; }
    toast("刷新服务端进度中…");
    let updated = 0, fail401 = 0;
    const map = {};
    for (const t of ts) {
      try {
        const r = await apiPost(RES_URL, { courseId: t.courseId, classId: t.classId, knowledgeId: t.knowledgeId }, cKey, t.headerXq || getJ(K_HDR, DEF_HDR));
        const it = (((r.data || {}).resourceList) || []).find(x => String((x.resourcesDetail || {}).resourcesFileId) === String(t.fileId));
        if (it) {
          map[t.id] = { schedule: it.schedule || 0, total: it.studyTotalTime || 0, at: Date.now() };
          updated++;
        }
      } catch (e) {
        if (String(e && e.message).indexOf("401") >= 0) fail401++;
      }
    }
    setJ(K_SERVERPROG, map);
    if (btn) { btn.disabled = false; btn.textContent = "↻ 服务端进度"; }
    render();
    if (fail401 && !updated) toast("刷新失败：登录已过期（401），请重新登录后重试", true);
    else toast("✓ 已更新 " + updated + "/" + ts.length + " 个任务的服务端进度" + (fail401 ? "（" + fail401 + " 个 401）" : ""), !!fail401 && !updated);
  }

  function fmt(s) { s = Math.floor(s || 0); const m = Math.floor(s / 60); return (m ? m + "分" : "") + (s % 60) + "秒"; }
  function render() {
    try {
      const tasks = getJ(K_TASKS, []);
      const state = getJ(K_STATE, {});
      const set = getJ(K_SET, {});
      const prog = state.progress || {};
      const spMap = getJ(K_SERVERPROG, {}) || {};
      const tickAge = state.lastTickAt ? Math.round((Date.now() - state.lastTickAt) / 1000) : null;
      $("#zhs-leader").textContent = state.masterPaused
        ? "⛔ 已全局暂停"
        : "驱动：" + (tickAge != null && tickAge < 12
          ? (state.lastDriver === MY_ID ? "本页（接管中）· " + tickAge + "秒前有产出" : "后台引擎 · " + tickAge + "秒前有产出")
          : "无产出（本页接管中）");
      const concIn = $("#zhs-concin");
      if (document.activeElement !== concIn) concIn.value = set.concurrency || 2;
      $("#zhs-pauseall").textContent = state.masterPaused ? "▶ 全部恢复" : "⏸ 全部暂停";
      const list = $("#zhs-list");
      if (!tasks.length) { list.innerHTML = '<div style="color:#57606a">暂无任务。填 courseId/classId 点「📚 读取视频」批量添加。</div>'; return; }
      list.innerHTML = tasks.map(t => {
        const p = prog[t.id] || { lastWatchTime: t.lastWatchTime || 0, status: "queued" };
        const pct = t.duration ? Math.min(100, (p.lastWatchTime / t.duration) * 100) : 0;
        const sp = spMap[t.id];
        const stMap = { done: "✅ 完成", error: "❌ 失败" + (p.err ? "：" + p.err : ""), running: "▶ 刷ing", retrying: "⏳ 重试中", queued: "…排队" };
        const shownStatus = sp && Number(sp.schedule) >= 100 ? "done" : p.status;
        const st = shownStatus === "done" ? "st-done" : shownStatus === "error" ? "st-error" : shownStatus === "running" ? "st-running" : shownStatus === "retrying" ? "st-retrying" : "st-queued";
        const sch = sp ? " · 服务端" + sp.schedule + "%" + (Number(sp.schedule) >= 100 ? " 🎉" : "") : "";
        return `<div class="task" data-id="${esc(t.id)}">
        <div class="nm">${esc(t.name)}${t.paused ? "（已暂停）" : ""}</div>
        ${t.duration ? `<div class="pg"><i style="width:${pct}%"></i></div>` : ""}
        <div class="meta">${fmt(p.lastWatchTime)} / ${t.duration ? fmt(t.duration) : "?"}${sch} · <span class="${st}">${stMap[shownStatus] || esc(shownStatus)}</span></div>
        <div class="ops">
          <button data-act="tpause">${t.paused ? "▶" : "⏸"}</button>
          <button data-act="reset">↺</button>
          <button data-act="del" class="danger">✕</button>
        </div>
      </div>`;
      }).join("");
    } catch (e) { /* 静默，下轮重试 */ }
  }

  // ================= 主循环：渲染 + 回退引擎接管 =================
  let cKey = null;
  (async () => {
    cKey = await refreshCKey();
    setInterval(() => {
      render();
      const state = getJ(K_STATE, {});
      if (!cKey || state.masterPaused) return;
      const now = Date.now();
      // 本页就是驱动者，或现任驱动者 12 秒无产出 → 接管
      if (state.lastDriver === MY_ID || now - (state.lastTickAt || 0) > 12000) loopOnce(cKey);
    }, 1000);
  })();

  render();
})();
