// ==UserScript==
// @name         智慧树刷进度·后台引擎
// @namespace    https://github.com/point-zip/fuck-zhs
// @author       point-zip
// @version      1.3.0
// @description  ScriptCat 后台脚本：按真实节奏(10s/跳)提交 studyRecord，浏览器全关页面也能刷
// @background
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
// @license      AGPL-3.0-or-later
// ==/UserScript==

(() => {
  // ---------- 共享核心（与面板脚本内嵌的回退引擎完全一致） ----------
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
  function b64i(c) { return B64.indexOf(c); }
  function hex(u8) { return Array.from(u8, x => x.toString(16).padStart(2, "0")).join(""); }

  const PUB = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgfZmpLpPEpEFRKBe+ZjWJUjPe+7qg7pGqcfN3j2egJ8H2mrKwaEqZEnPnpi2O3hN8HRyaFozDOp8gwZiYfiIZjWy0Jr/FNAiiKYh5bq0GsEn+ieMmRyJg/+i1rqizhvCXvFdrdGhFTw5EBwTpsGdwe1utdlrvIJUAFWj9Yh4qbQIDAQAB";
  let _pub = null;
  function parsePub() {
    if (_pub) return _pub;
    const der = b64dec(PUB);
    let i = 0;
    for (; i < der.length - 4; i++)
      if (der[i] === 2 && der[i + 1] === 0x81 && der[i + 2] === 0x81 && der[i + 3] === 0) break;
    const n = BigInt("0x" + hex(der.slice(i + 4, i + 4 + 128)));
    let j = i + 4 + 128, e = 65537n;
    if (der[j] === 2 && der[j + 1] === 3) e = BigInt("0x" + hex(der.slice(j + 2, j + 5)));
    return (_pub = { n, e });
  }
  function modexp(b, e, m) {
    let r = 1n; b %= m;
    while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; }
    return r;
  }
  // rt.sl：服务端私钥加密的密钥信封，硬编码公钥可解开（PKCS1 v1.5 recover）
  function rsaUnwrap(b64) {
    const { n, e } = parsePub();
    const c = BigInt("0x" + hex(b64dec(b64)));
    const bytes = hexToBytes(modexp(c, e, n).toString(16).padStart(256, "0"));
    let k = 2; while (k < bytes.length && bytes[k] === 0xff) k++;
    return new TextDecoder().decode(bytes.slice(k + 1));
  }
  // uid 参数：公钥加密 {"module":6}
  function rsaEncrypt(obj) {
    const { n, e } = parsePub();
    const msg = new TextEncoder().encode(JSON.stringify(obj));
    const k = 128, em = new Uint8Array(k);
    em[0] = 0; em[1] = 2;
    let p = 2;
    while (p < k - msg.length - 1) em[p++] = 1 + Math.floor(Math.random() * 254);
    em[p++] = 0; em.set(msg, p);
    const c = modexp(BigInt("0x" + hex(em)), e, n);
    return b64enc(hexToBytes(c.toString(16).padStart(256, "0")));
  }
  function hexToBytes(h) {
    if (h.length % 2) h = "0" + h;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  const IV = "1g3qqdh4jvbskb9x";
  async function aesEncrypt(plain, cKey) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(cKey), "AES-CBC", false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: enc.encode(IV) }, key, enc.encode(plain));
    return b64enc(new Uint8Array(ct));
  }

  function xhr(url, opt = {}) {
    return new Promise((res, rej) => {
      GM_xmlhttpRequest({
        method: opt.method || "GET", url, timeout: 15000,
        headers: opt.headers || {},
        data: opt.data,
        onload: r => res(r),
        onerror: () => rej(new Error("network")),
        ontimeout: () => rej(new Error("timeout")),
      });
    });
  }

  const STUDY = "https://kg-ai-run.zhihuishu.com/run/gateway/t/stu/studyRecord/study";
  const REPORT = "https://kg-ai-run.zhihuishu.com/run/gateway/t/stu/studyRecord/report";
  const HAS = "https://appcomm-user.zhihuishu.com/app-commserv-user/c/has?uid=";
  const DEF_CKEY = "hw2fdlwcj4cs1mx7";
  const K_TASKS = "zhs_tasks_v1", K_STATE = "zhs_engine_state", K_SET = "zhs_settings";
  const MY_ID = "eng-" + Math.random().toString(36).slice(2, 9);

  const getJ = (k, d) => { try { const v = GM_getValue(k); return v == null ? d : (typeof v === "string" ? JSON.parse(v) : v); } catch { return d; } };
  const setJ = (k, v) => GM_setValue(k, JSON.stringify(v));
  const rnd = (a, b) => a + Math.random() * (b - a);

  async function refreshCKey() {
    const s = getJ(K_SET, {});
    if (!s.cKey) s.cKey = DEF_CKEY;
    try {
      const r = await xhr(HAS + encodeURIComponent(rsaEncrypt({ module: 6 })));
      const sl = JSON.parse(r.responseText).rt.sl;
      const j = JSON.parse(rsaUnwrap(sl));
      if (j.cKey) { s.cKey = j.cKey; setJ(K_SET, s); GM_log("cKey refreshed: " + j.cKey, "info"); }
    } catch (e) { GM_log("cKey refresh failed, use cached: " + e.message, "warn"); }
    return s.cKey;
  }

  async function postEnc(url, payload, cKey, header, cookie) {
    const sec = await aesEncrypt(JSON.stringify(payload), cKey);
    const body = JSON.stringify({ secretStr: sec, date: Date.now() });
    const headers = { "Content-Type": "application/json;charset=UTF-8", "XQJZXHIZ": header, "Accept": "application/json, text/plain, */*" };
    if (cookie) headers.Cookie = cookie; // 显式 Cookie：GM 跨域默认不带时兜底
    const r = await xhr(url, { method: "POST", headers, data: body });
    let j = null; try { j = JSON.parse(r.responseText); } catch {}
    return { ok: r.status === 200 && j && j.code === 200, status: r.status, code: j && j.code, body: j };
  }

  let ticking = {};
  async function tickTask(t, prog, cKey) {
    if (ticking[t.id]) return;
    ticking[t.id] = 1;
    try {
      // 首跳小步（模拟刚点开播放），后续每跳 9.2~10 秒；接近片尾时截断
      let st = prog.fresh ? rnd(2, 4) : rnd(9.2, 9.99);
      prog.fresh = false;
      if (t.duration) {
        const remaining = t.duration - prog.lastWatchTime;
        if (remaining < 1) { prog.status = "done"; return; }
        st = Math.min(st, remaining);
      }
      // 真实协议：studyTime 是累计观看秒数（=lastWatchTime+小数），lastWatchTime 取整
      const lwt = Math.round((prog.lastWatchTime + st) * 1000) / 1000;
      const sec = Math.floor(Date.now() / 1000) * 1000;
      // 每次动态读取：面板捕获到 XQJZXHIZ 晚于引擎启动也能用上；任务级 header 优先
      const header = t.headerXq || GM_getValue("zhs_header_xq") || "";
      const cookie = prog.useCookie ? (GM_getValue("zhs_cookie") || "") : "";
      const base = { courseId: t.courseId, classId: t.classId, knowledgeId: t.knowledgeId };
      const study = Object.assign({}, base, { source: 1, studyFileType: 1, fileId: t.fileId, studyTime: lwt, lastWatchTime: Math.floor(lwt), dateFormate: sec });
      const rep = Object.assign({}, base, { fileId: t.fileId, studyTotalTime: Math.max(1, Math.floor(st)), lastWatchTime: Math.floor(lwt), shareCourseId: "", watchUId: 1, nodeType: t.nodeType || 0, dateFormate: sec });
      let r1 = await postEnc(STUDY, study, cKey, header, cookie);
      // 默认方式遇到 401 且面板存过页面 Cookie → 切显式 Cookie 重试并记住
      if (!r1.ok && (r1.status === 401 || r1.code === 401) && !prog.useCookie && GM_getValue("zhs_cookie")) {
        prog.useCookie = true;
        GM_log("任务[" + t.name + "]默认请求401，改用面板Cookie重试", "warn");
        r1 = await postEnc(STUDY, study, cKey, header, GM_getValue("zhs_cookie"));
      }
      if (!r1.ok) throw Object.assign(new Error("study http=" + r1.status + " code=" + r1.code), { fatal: r1.status === 401 || r1.status === 403 || r1.code === 401 || r1.code === 403 });
      const r2 = await postEnc(REPORT, rep, cKey, header, prog.useCookie ? GM_getValue("zhs_cookie") : "");
      if (!r2.ok) throw Object.assign(new Error("report http=" + r2.status + " code=" + r2.code), { fatal: r2.status === 401 || r2.status === 403 || r2.code === 401 || r2.code === 403 });
      prog.lastWatchTime = lwt;
      prog.attempts = 0; prog.status = "running"; prog.err = "";
      if (t.duration && lwt >= t.duration - 1.5) prog.status = "done";
    } catch (e) {
      prog.attempts = (prog.attempts || 0) + 1;
      prog.err = e.message;
      if (e.fatal) { prog.status = "error"; prog.nextTickAt = 0; GM_log("任务[" + t.name + "]登录失效: " + e.message, "error"); }
      else if (prog.attempts >= 3) { prog.status = "error"; prog.nextTickAt = 0; GM_log("任务[" + t.name + "]连续失败3次，已暂停: " + e.message, "error"); }
      else prog.status = "retrying";
    } finally { delete ticking[t.id]; }
  }

  // 驱动仲裁：内存态跨秒保留（修复异步写丢失），lastDriver/lastTickAt 防双发
  let memState = null;
  function loopOnce(cKey) {
    const now = Date.now();
    const stored = getJ(K_STATE, {});
    if (stored.masterPaused) return;
    // 别的驱动者刚有产出 → 让位（面板开着就让它跑；它失联 12 秒内即接管）
    if (stored.lastDriver && stored.lastDriver !== MY_ID && now - (stored.lastTickAt || 0) < 12000) return;
    if (!memState) memState = { progress: stored.progress ? JSON.parse(JSON.stringify(stored.progress)) : {} };
    const state = memState;
    const tasks = getJ(K_TASKS, []);
    const settings = getJ(K_SET, { concurrency: 2 });
    const progAll = state.progress;
    const active = tasks.filter(t => !t.paused && (!progAll[t.id] || !["done", "error"].includes(progAll[t.id].status)));
    active.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    let ticked = 0;
    for (const t of active.slice(0, Math.max(1, settings.concurrency || 2))) {
      const p = progAll[t.id] || (progAll[t.id] = { lastWatchTime: t.lastWatchTime || 0, fresh: true, status: "queued", attempts: 0, nextTickAt: now + rnd(800, 9000) });
      if (now >= p.nextTickAt) {
        p.nextTickAt = now + 10000 + rnd(0, 1200); // 先占位再发送，防重
        ticked++;
        tickTask(t, p, cKey);
      }
    }
    // 清理已删除任务的进度
    for (const id of Object.keys(progAll)) if (!tasks.find(t => t.id === id)) delete progAll[id];
    if (ticked || stored.lastDriver !== MY_ID) { state.lastDriver = MY_ID; state.lastTickAt = now; state.lastTickCount = ticked; }
    if (now - (state.lastDiagLog || 0) > 60000) {
      state.lastDiagLog = now;
      GM_log("引擎tick: 任务" + tasks.length + " 活跃" + active.length + " 本轮" + ticked + " 并发" + (settings.concurrency || 2), "info");
    }
    setJ(K_STATE, state);
  }

  let cKey = null, booted = false;
  async function boot() {
    if (booted) return;
    booted = true;
    cKey = await refreshCKey();
    GM_log("后台引擎启动 " + MY_ID, "info");
    loopOnce(cKey); // 启动即扫一次队列（service worker 被挂起后唤醒时立即补上到期 tick）
    setInterval(() => { if (cKey) loopOnce(cKey); }, 1000);
  }
  // MV3 service worker 会被挂起：顶层注册闹钟，挂起期间靠闹钟唤醒补 tick
  try {
    chrome.alarms.create("zhs-tick", { periodInMinutes: 0.5 });
    chrome.alarms.onAlarm.addListener(al => {
      if (al && al.name === "zhs-tick") { if (!cKey) boot(); else loopOnce(cKey); }
    });
  } catch (e) { GM_log("alarms 不可用: " + e.message, "warn"); }
  boot();
})();
