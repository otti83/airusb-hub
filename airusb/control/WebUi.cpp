#include "WebUi.h"

namespace airusb::control {

namespace {

// --- chunk 1: head, and the whole visual language ---------------------------
constexpr const char* kPart1 = R"HTML(<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AirUSB Hub</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#14181d; --muted:#5d6875; --line:#dfe3e8;
  --accent:#1c6fd0; --accent-ink:#ffffff; --good:#137a4b; --bad:#b3261e;
  --warn:#8a5a00; --warn-bg:#fff6e0; --code:#eef1f5;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#12151a; --panel:#1a1f26; --ink:#e8ecf1; --muted:#9aa5b1; --line:#2a323c;
    --accent:#4c9aff; --accent-ink:#0b1017; --good:#5fd39a; --bad:#ff7b72;
    --warn:#e0b25c; --warn-bg:#3a2f14; --code:#111721;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans JP",sans-serif}
header{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;
  padding:14px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{font-size:17px;margin:0;letter-spacing:.2px}
.machine{color:var(--muted)}
.fp{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--muted)}
main{display:grid;gap:16px;padding:16px 20px 40px;
  grid-template-columns:repeat(auto-fit,minmax(360px,1fr));max-width:1200px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.9px;color:var(--muted);
  margin:0 0 12px}
.notice{margin:0 20px;padding:10px 14px;border-radius:8px;background:var(--warn-bg);
  color:var(--warn);border:1px solid var(--line)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
label{color:var(--muted);font-size:13px}
input{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:7px;
  background:var(--bg);color:var(--ink);min-width:0}
input.host{flex:1 1 160px} input.port{width:88px}
button{font:inherit;padding:7px 14px;border-radius:7px;border:1px solid var(--line);
  background:var(--bg);color:var(--ink);cursor:pointer}
button:hover:not(:disabled){border-color:var(--accent)}
button:disabled{opacity:.45;cursor:default}
button.primary{background:var(--accent);color:var(--accent-ink);border-color:transparent}
button.danger{color:var(--bad)}
.state{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
.dot.on{background:var(--good)} .dot.warn{background:var(--warn)} .dot.off{background:var(--line)}
ul.devices{list-style:none;margin:0;padding:0}
ul.devices li{display:flex;gap:10px;align-items:center;padding:9px 0;
  border-top:1px solid var(--line)}
ul.devices li:first-child{border-top:0}
.dev-name{flex:1;min-width:0}
.dev-name b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.dev-name span{color:var(--muted);font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
.empty{color:var(--muted);font-size:13px;padding:6px 0}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px;
  overflow-x:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:10px 0 0}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13px;margin-top:10px}
.kv dt{color:var(--muted)} .kv dd{margin:0;
  font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.verdict{font-weight:600} .verdict.pass{color:var(--good)} .verdict.fail{color:var(--bad)}
)HTML";

// --- chunk 2: the pairing dialog, and the page skeleton ---------------------
constexpr const char* kPart2 = R"HTML(
.pair{border:2px solid var(--accent);border-radius:10px;padding:14px;margin-bottom:14px}
.pair h3{margin:0 0 6px;font-size:14px}
.pair p{margin:0 0 10px;color:var(--muted);font-size:13px}
.sas{font:600 34px/1.1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  letter-spacing:.32em;text-align:center;padding:12px 0 14px;
  /* The trailing letter-spacing pads the right edge; pull it back so six
     digits read as centred rather than as five digits and a gap. */
  text-indent:.32em}
.hidden{display:none}
.session{margin-top:6px}
footer{color:var(--muted);font-size:12px;padding:0 20px 24px;max-width:1200px}
</style></head><body>
<header>
  <h1>AirUSB Hub</h1>
  <span class="machine" id="machine"></span>
  <span class="fp" id="identity"></span>
  <span class="state" style="margin-left:auto"><i class="dot" id="live"></i>
    <span id="livetext">connecting</span></span>
</header>
<p class="notice" id="notice"></p>
<main>
  <section>
    <h2>Share a device from this machine</h2>
    <div class="row">
      <label for="sharePort">Port</label>
      <input class="port" id="sharePort" value="7714" inputmode="numeric">
      <button class="primary" id="shareStart">Start sharing</button>
      <button id="shareStop">Stop</button>
    </div>
    <div class="state"><i class="dot" id="shareDot"></i><span id="shareState"></span></div>
    <div class="fp session hidden" id="shareSession"></div>

    <div class="pair hidden" id="sharePair">
      <h3>A machine wants to use a device from here</h3>
      <p>It shows a six-digit number. Accept only if it is the same as this one.</p>
      <div class="fp" id="sharePeerFp"></div>
      <div class="sas" id="shareSas"></div>
      <div class="row" style="margin:0">
        <button class="primary" id="shareAccept">The numbers match</button>
        <button class="danger" id="shareRefuse">Refuse</button>
      </div>
    </div>

    <ul class="devices" id="shareDevices"></ul>
    <div class="empty hidden" id="shareEmpty"></div>
  </section>

  <section>
    <h2>Use a device from another machine</h2>
    <div class="row">
      <label for="host">Address</label>
      <input class="host" id="host" placeholder="192.168.2.15" autocomplete="off">
      <input class="port" id="port" value="7714" inputmode="numeric">
      <button class="primary" id="connect">Connect</button>
      <button id="disconnect">Disconnect</button>
    </div>
    <div class="state"><i class="dot" id="importDot"></i><span id="importState"></span></div>
    <div class="fp session hidden" id="importSession"></div>

    <div class="pair hidden" id="importPair">
      <h3>Is this the machine you meant?</h3>
      <p>Compare the number with the one on that machine's screen. If they differ,
         something is between you and it.</p>
      <div class="fp" id="importPeerFp"></div>
      <div class="sas" id="importSas"></div>
      <div class="row" style="margin:0">
        <button class="primary" id="importAccept">The numbers match</button>
        <button class="danger" id="importRefuse">Refuse</button>
      </div>
    </div>

    <ul class="devices" id="importDevices"></ul>
    <div class="empty hidden" id="importEmpty"></div>
    <div id="attached" class="hidden"></div>
  </section>
</main>
<footer id="foot"></footer>
)HTML";

// --- chunk 3: the script, part one ------------------------------------------
constexpr const char* kPart3 = R"HTML(
<script>
"use strict";
// The token rides in the fragment, not the query string. A browser never sends
// a fragment to a server, so it stays out of the access log, out of Referer and
// out of anything that records URLs. The page lifts it out and puts it in a
// header on every call.
var TOKEN = (location.hash || "").replace(/^#/, "");
if (TOKEN.indexOf("t=") === 0) TOKEN = TOKEN.slice(2);

var $ = function (id) { return document.getElementById(id); };
var last = null, failures = 0, busy = false;

function text(el, s) { if (el.textContent !== s) el.textContent = s; }
function show(el, on) { el.classList.toggle("hidden", !on); }

function api(path, body) {
  return fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-AirUSB-Token": TOKEN, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body)
  }).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (j) {
      if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
      return j;
    });
  });
}

function act(path, body) {
  if (busy) return;
  busy = true;
  api(path, body || {}).then(function (s) { render(s); })
    .catch(function (e) { text($("notice"), e.message); })
    .then(function () { busy = false; });
}

function devLine(d) {
  var id = ("0000" + d.vendorId.toString(16)).slice(-4) + ":" +
           ("0000" + d.productId.toString(16)).slice(-4);
  return id + "  " + d.speed;
}

function renderList(ul, empty, devices, emptyText, action) {
  ul.textContent = "";
  if (!devices || !devices.length) {
    show(ul, false); show(empty, true); text(empty, emptyText);
    return;
  }
  show(ul, true); show(empty, false);
  devices.forEach(function (d) {
    var li = document.createElement("li");
    var box = document.createElement("div");
    box.className = "dev-name";
    var b = document.createElement("b");
    b.textContent = d.name || "USB device";
    var s = document.createElement("span");
    s.textContent = devLine(d);
    box.appendChild(b); box.appendChild(s);
    li.appendChild(box);
    if (action) li.appendChild(action(d));
    ul.appendChild(li);
  });
}
)HTML";

// --- chunk 4: the script, part two ------------------------------------------
constexpr const char* kPart4 = R"HTML(
function render(s) {
  last = s;
  text($("machine"), s.machine);
  text($("identity"), "this machine: " + s.identity);
  text($("notice"), s.notice || "Nothing has happened yet.");
  text($("foot"), s.pinnedPeers + " machine(s) paired with this one. " +
       "This window is served to 127.0.0.1 only and is not reachable from the network.");

  var sh = s.share;
  $("shareDot").className = "dot " +
    (sh.state === "serving" ? "on" : sh.state === "off" ? "off" : "warn");
  text($("shareState"),
    sh.state === "off"       ? (sh.canShare ? "not sharing" : "this build has nothing to share")
    : sh.state === "listening" ? "waiting for a machine on port " + sh.port
    : sh.state === "handshaking" ? "a machine is connecting"
    : sh.state === "awaiting-approval" ? "waiting for you to check the number"
    : "serving — " + sh.transfersServed + " transfer(s), " + sh.messagesHandled + " message(s)");
  $("shareStart").disabled = !sh.canShare || sh.state !== "off";
  $("shareStop").disabled = sh.state === "off";
  show($("sharePair"), sh.needsApproval);
  if (sh.sas) { text($("shareSas"), sh.sas); text($("sharePeerFp"), sh.peerFingerprint); }
  // Shown even when this side has nothing to decide. The number changes with
  // every connection, so a pairing interrupted halfway leaves the already-paired
  // side with no prompt — and the other person with a number and nothing to
  // check it against.
  show($("shareSession"), !!sh.sas && !sh.needsApproval);
  if (sh.sas) text($("shareSession"), "this connection's number: " + sh.sas);
  renderList($("shareDevices"), $("shareEmpty"), sh.devices,
    sh.canShare ? "No device on this machine can be shared right now."
                : "This build has no capture backend, so it offers nothing.", null);

  var im = s.import;
  $("importDot").className = "dot " +
    (im.state === "attached" ? "on" : im.state === "off" ? "off" : "warn");
  text($("importState"),
    im.state === "off"       ? "not connected"
    : im.state === "connecting" ? "connecting"
    : im.state === "awaiting-approval" ? "waiting for you to check the number"
    : im.state === "waiting-for-peer" ? "accepted here — waiting for the other machine"
    : im.state === "connected" ? ("connected to " + im.host + ":" + im.port)
    : ("attached — " + im.manifest));
  $("connect").disabled = im.state !== "off";
  $("disconnect").disabled = im.state === "off";
  show($("importPair"), im.needsApproval);
  if (im.sas) { text($("importSas"), im.sas); text($("importPeerFp"), im.peerFingerprint); }
  show($("importSession"), !!im.sas && !im.needsApproval);
  if (im.sas) text($("importSession"), "this connection's number: " + im.sas);

  renderList($("importDevices"), $("importEmpty"), im.devices,
    im.state === "off" ? "Connect to a machine to see what it offers."
                       : "That machine is offering nothing right now.",
    function (d) {
      var b = document.createElement("button");
      if (im.attachedUid === d.uid) {
        b.textContent = "Release"; b.className = "danger";
        b.onclick = function () { act("/api/import/detach"); };
      } else {
        b.textContent = "Use it"; b.className = "primary";
        b.disabled = im.state !== "connected";
        b.onclick = function () { act("/api/import/attach", { uid: d.uid }); };
      }
      return b;
    });

  renderAttached(im, im.probe);
}
)HTML";

// --- chunk 5: the attached panel, wiring and the poll loop ------------------
constexpr const char* kPart5 = R"HTML(
function renderAttached(im, probe) {
  var host = $("attached");
  show(host, im.state === "attached");
  if (im.state !== "attached") return;
  host.textContent = "";

  var row = document.createElement("div");
  row.className = "row";
  row.style.marginTop = "14px";
  var v = document.createElement("button");
  v.className = "primary";
  v.textContent = "Check it really works";
  v.onclick = function () { act("/api/import/verify"); };
  var p = document.createElement("button");
  p.textContent = "Ping";
  p.onclick = function () { act("/api/import/ping"); };
  row.appendChild(v); row.appendChild(p);
  host.appendChild(row);

  var dl = document.createElement("dl");
  dl.className = "kv";
  function kv(k, val) {
    var dt = document.createElement("dt"); dt.textContent = k;
    var dd = document.createElement("dd"); dd.textContent = val;
    dl.appendChild(dt); dl.appendChild(dd);
  }
  kv("device", im.manifest);
  kv("transfers", String(im.transfersIssued));
  kv("segmented", im.segmentedOut + " out / " + im.segmentedIn + " in, " +
                  "one record holds " + im.maxSegmentBytes + " B");
  if (im.rttMicros) kv("round trip", im.rttMicros + " µs");
  host.appendChild(dl);

  if (!probe) return;
  var verdict = document.createElement("p");
  verdict.className = "verdict " + (probe.passed ? "pass" : "fail");
  verdict.textContent = probe.passed
    ? ("PASS — " + (probe.vendor || "") + " " + (probe.product || "") + ", " +
       probe.blockCount + " blocks of " + probe.blockSize + " bytes read over the " +
       "encrypted session")
    : ("FAIL — " + probe.failure);
  host.appendChild(verdict);
  var pre = document.createElement("pre");
  pre.textContent = probe.summary;
  host.appendChild(pre);
}

$("shareStart").onclick = function () {
  act("/api/share/start", { port: Number($("sharePort").value) || 7714 });
};
$("shareStop").onclick   = function () { act("/api/share/stop"); };
$("shareAccept").onclick = function () { act("/api/share/approve", { accept: true }); };
$("shareRefuse").onclick = function () { act("/api/share/approve", { accept: false }); };
$("connect").onclick = function () {
  act("/api/import/connect",
      { host: $("host").value.trim(), port: Number($("port").value) || 7714 });
};
$("disconnect").onclick   = function () { act("/api/import/disconnect"); };
$("importAccept").onclick = function () { act("/api/import/approve", { accept: true }); };
$("importRefuse").onclick = function () { act("/api/import/approve", { accept: false }); };

function poll() {
  // Skipped while an action is in flight. The daemon is single-threaded, so a
  // poll landing behind a long action would only queue behind it and then paint
  // a state the action has already replaced.
  if (busy) return;
  api("/api/state").then(function (s) {
    failures = 0;
    $("live").className = "dot on";
    text($("livetext"), "connected");
    render(s);
  }).catch(function (e) {
    if (++failures >= 2) {
      $("live").className = "dot warn";
      text($("livetext"), TOKEN ? "the hub is not answering" : "no control token in the URL");
      if (!TOKEN) text($("notice"),
        "Open the address the daemon printed — it carries the control token " +
        "after the # and this page cannot talk to the hub without it.");
      else text($("notice"), e.message);
    }
  });
}
poll();
setInterval(poll, 1000);
</script></body></html>
)HTML";

} // namespace

std::string indexHtml()
{
    std::string s;
    s.reserve(20000);
    s += kPart1;
    s += kPart2;
    s += kPart3;
    s += kPart4;
    s += kPart5;
    return s;
}

} // namespace airusb::control
