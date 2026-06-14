"""
Web Dashboard
==============
Optional real-time web dashboard built on FastAPI.
Streams live scan results via Server-Sent Events (SSE).

Run with: btaudit dashboard --port 8080

Made by Monish Paramasivam
"""

from __future__ import annotations
import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator

logger = logging.getLogger(__name__)

# ── HTML template (self-contained, no external CDN required) ─────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BTAudit Live Dashboard</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#0f172a;color:#e2e8f0;min-height:100vh;}
    .header{background:#1e293b;border-bottom:1px solid #334155;
            padding:16px 24px;display:flex;align-items:center;gap:16px;}
    .logo{font-size:22px;font-weight:800;color:#60a5fa;letter-spacing:-.5px;}
    .subtitle{font-size:13px;color:#64748b;}
    .author{font-size:11px;color:#475569;margin-left:auto;}
    .status-dot{width:10px;height:10px;border-radius:50%;background:#22c55e;
                animation:pulse 2s infinite;}
    @keyframes pulse{0%,100%{opacity:1;}50%{opacity:.4;}}
    .status-dot.idle{background:#64748b;animation:none;}
    .main{padding:24px;max-width:1200px;margin:0 auto;}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
           gap:14px;margin-bottom:24px;}
    .stat-card{background:#1e293b;border:1px solid #334155;border-radius:10px;
               padding:16px;text-align:center;}
    .stat-value{font-size:28px;font-weight:800;color:#f8fafc;}
    .stat-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;margin-top:4px;}
    .controls{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;}
    .btn{padding:9px 18px;border-radius:8px;border:none;cursor:pointer;
         font-size:14px;font-weight:600;transition:opacity .15s;}
    .btn:hover{opacity:.85;}
    .btn-primary{background:#3b82f6;color:#fff;}
    .btn-danger{background:#dc2626;color:#fff;}
    .btn-outline{background:transparent;color:#94a3b8;border:1px solid #334155;}
    .devices-grid{display:grid;gap:14px;}
    .device-card{background:#1e293b;border:1px solid #334155;border-radius:10px;
                 overflow:hidden;animation:fadeIn .3s ease;}
    @keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:none;}}
    .device-header{padding:12px 16px;background:#0f172a;border-bottom:1px solid #334155;
                   display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;}
    .device-name{font-weight:700;font-size:15px;color:#f1f5f9;}
    .device-mac{font-size:12px;color:#64748b;font-family:monospace;margin-top:2px;}
    .badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.4px;}
    .badge-critical{background:#450a0a;color:#fca5a5;border:1px solid #dc2626;}
    .badge-high{background:#431407;color:#fdba74;border:1px solid #ea580c;}
    .badge-medium{background:#451a03;color:#fcd34d;border:1px solid #d97706;}
    .badge-low{background:#1e3a8a;color:#93c5fd;border:1px solid #2563eb;}
    .badge-info{background:#1e293b;color:#94a3b8;border:1px solid #475569;}
    .device-body{padding:14px 16px;display:grid;
                 grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;}
    .meta-item .label{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;}
    .meta-item .value{font-size:13px;font-weight:600;color:#cbd5e1;margin-top:2px;}
    .findings{padding:0 16px 14px;}
    .finding{border-left:3px solid;padding:8px 10px;margin:6px 0;border-radius:0 6px 6px 0;}
    .finding-title{font-size:13px;font-weight:600;margin-bottom:2px;}
    .finding-desc{font-size:12px;color:#94a3b8;}
    .filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;}
    .filter-btn{padding:5px 12px;border-radius:20px;border:1px solid #334155;
                background:transparent;color:#64748b;cursor:pointer;font-size:12px;transition:all .15s;}
    .filter-btn.active{border-color:#3b82f6;color:#3b82f6;background:rgba(59,130,246,.1);}
    #log{background:#0f172a;border:1px solid #334155;border-radius:8px;
         padding:12px;height:120px;overflow-y:auto;font-family:monospace;
         font-size:12px;color:#64748b;margin-top:20px;}
    .log-entry{padding:2px 0;border-bottom:1px solid #1e293b;}
    .log-entry.new{color:#4ade80;}
    #scan-progress{display:none;align-items:center;gap:10px;
                   padding:10px 14px;background:#1e3a8a;border-radius:8px;
                   margin-bottom:16px;font-size:13px;color:#bfdbfe;}
    #scan-progress.active{display:flex;}
    .spinner{width:16px;height:16px;border:2px solid #bfdbfe;
             border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>

<div class="header">
  <div class="status-dot idle" id="status-dot"></div>
  <div>
    <div class="logo">🔵 BTAudit</div>
    <div class="subtitle">Bluetooth Security Auditing &amp; Inventory Dashboard</div>
  </div>
  <div class="author">Made by <strong>Monish Paramasivam</strong></div>
</div>

<div class="main">

  <div id="scan-progress">
    <div class="spinner"></div>
    <span id="scan-status-text">Scanning…</span>
  </div>

  <div class="stats" id="stats">
    <div class="stat-card"><div class="stat-value" id="stat-total">0</div><div class="stat-label">Total Devices</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-ble" style="color:#818cf8;">0</div><div class="stat-label">BLE</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-classic" style="color:#22d3ee;">0</div><div class="stat-label">Classic</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-critical" style="color:#f87171;">0</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-high" style="color:#fb923c;">0</div><div class="stat-label">High Risk</div></div>
  </div>

  <div class="controls">
    <button class="btn btn-primary" onclick="startScan()">▶ Start Scan</button>
    <button class="btn btn-danger" onclick="stopScan()">⏹ Stop</button>
    <button class="btn btn-outline" onclick="clearDevices()">🗑 Clear</button>
    <button class="btn btn-outline" onclick="downloadReport('json')">⬇ JSON</button>
    <button class="btn btn-outline" onclick="downloadReport('csv')">⬇ CSV</button>
    <button class="btn btn-outline" onclick="downloadReport('html')">⬇ HTML</button>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
    <button class="filter-btn" onclick="setFilter('CRITICAL',this)">Critical</button>
    <button class="filter-btn" onclick="setFilter('HIGH',this)">High</button>
    <button class="filter-btn" onclick="setFilter('MEDIUM',this)">Medium</button>
    <button class="filter-btn" onclick="setFilter('BLE',this)">BLE</button>
    <button class="filter-btn" onclick="setFilter('Classic',this)">Classic</button>
  </div>

  <div class="devices-grid" id="devices"></div>

  <div id="log"><div class="log-entry">BTAudit dashboard ready. Start a scan to discover nearby devices.</div></div>

</div>

<script>
const RISK_COLORS = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#2563eb',INFO:'#475569'};
const RISK_BG    = {CRITICAL:'#450a0a',HIGH:'#431407',MEDIUM:'#451a03',LOW:'#1e3a8a',INFO:'#1e293b'};

let devices = {};
let currentFilter = 'all';
let eventSource = null;
let sessionId = null;

function log(msg, isNew=false){
  const el=document.getElementById('log');
  const d=document.createElement('div');
  d.className='log-entry'+(isNew?' new':'');
  d.textContent=`[${new Date().toLocaleTimeString()}] ${msg}`;
  el.prepend(d);
  if(el.children.length>50)el.removeChild(el.lastChild);
}

function badge(level){
  return `<span class="badge badge-${level.toLowerCase()}">${level}</span>`;
}

function scoreBar(score){
  const c=score>=70?RISK_COLORS.CRITICAL:score>=50?RISK_COLORS.HIGH:score>=30?RISK_COLORS.MEDIUM:score>=10?RISK_COLORS.LOW:'#22c55e';
  return `<div style="display:flex;align-items:center;gap:6px;">
    <div style="flex:1;height:6px;background:#334155;border-radius:3px;">
      <div style="width:${score}%;height:100%;background:${c};border-radius:3px;"></div>
    </div>
    <span style="font-size:12px;font-weight:700;color:${c};">${score}</span></div>`;
}

function renderDevice(d){
  const findingsHtml = (d.findings||[]).map(f=>`
    <div class="finding" style="border-color:${RISK_COLORS[f.risk_level]};background:${RISK_BG[f.risk_level]}20;">
      <div class="finding-title" style="color:${RISK_COLORS[f.risk_level]};">[${f.finding_id}] ${f.title}</div>
      <div class="finding-desc">${f.description}</div>
    </div>`).join('');

  const servicesHtml = (d.services||[]).slice(0,5).map(s=>
    `<div style="font-size:12px;padding:3px 0;border-bottom:1px solid #1e293b;color:#94a3b8;">
       <code style="color:#818cf8;">${s.uuid.slice(0,8)}…</code> ${s.name}</div>`
  ).join('');

  return `
<div class="device-card" data-risk="${d.highest_risk}" data-proto="${d.protocol}">
  <div class="device-header">
    <div>
      <div class="device-name">${d.name}</div>
      <div class="device-mac">${d.address}</div>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;">
      ${badge(d.highest_risk)}
      <span class="badge" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;">${d.protocol}</span>
    </div>
  </div>
  <div class="device-body">
    <div class="meta-item"><div class="label">Manufacturer</div><div class="value">${d.manufacturer}</div></div>
    <div class="meta-item"><div class="label">RSSI</div><div class="value">${d.rssi} dBm (${d.signal_strength})</div></div>
    <div class="meta-item"><div class="label">Distance</div><div class="value">${d.distance_estimate}</div></div>
    <div class="meta-item"><div class="label">Category</div><div class="value">${d.category}</div></div>
    <div class="meta-item"><div class="label">Risk Score</div><div class="value">${scoreBar(d.risk_score)}</div></div>
    <div class="meta-item"><div class="label">Connectable</div><div class="value">${d.is_connectable?'Yes':'No'}</div></div>
  </div>
  ${servicesHtml?`<div class="findings"><div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;margin-bottom:6px;">Services</div>${servicesHtml}</div>`:''}
  ${findingsHtml?`<div class="findings"><div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;margin-bottom:6px;">Findings</div>${findingsHtml}</div>`:''}
</div>`;
}

function updateStats(){
  const devs = Object.values(devices);
  document.getElementById('stat-total').textContent=devs.length;
  document.getElementById('stat-ble').textContent=devs.filter(d=>d.protocol.includes('Low Energy')).length;
  document.getElementById('stat-classic').textContent=devs.filter(d=>d.protocol.includes('Classic')).length;
  document.getElementById('stat-critical').textContent=devs.filter(d=>d.highest_risk==='CRITICAL').length;
  document.getElementById('stat-high').textContent=devs.filter(d=>d.highest_risk==='HIGH').length;
}

function renderAll(){
  const container=document.getElementById('devices');
  const devs = Object.values(devices)
    .filter(d=>{
      if(currentFilter==='all')return true;
      if(['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(currentFilter))return d.highest_risk===currentFilter;
      return d.protocol.includes(currentFilter);
    })
    .sort((a,b)=>b.risk_score-a.risk_score);
  container.innerHTML=devs.map(renderDevice).join('');
  updateStats();
}

function setFilter(f,btn){
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderAll();
}

function clearDevices(){devices={};renderAll();log('Devices cleared.');}

async function startScan(){
  if(eventSource){eventSource.close();eventSource=null;}
  log('Starting scan…');
  document.getElementById('status-dot').classList.remove('idle');
  document.getElementById('scan-progress').classList.add('active');
  document.getElementById('scan-status-text').textContent='Scanning for Bluetooth devices…';

  try{
    const resp=await fetch('/api/scan/start',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({duration:15,ble:true,classic:true})});
    const data=await resp.json();
    sessionId=data.session_id;
    log('Scan session started: '+sessionId,true);

    eventSource=new EventSource('/api/scan/stream/'+sessionId);
    eventSource.onmessage=e=>{
      const d=JSON.parse(e.data);
      if(d.type==='device'){
        const isNew=!devices[d.device.address];
        devices[d.device.address]=d.device;
        renderAll();
        if(isNew)log(`Discovered: ${d.device.name} [${d.device.address}] Risk=${d.device.highest_risk}`,true);
      } else if(d.type==='complete'){
        log('Scan complete. '+Object.keys(devices).length+' devices found.',true);
        eventSource.close();
        document.getElementById('status-dot').classList.add('idle');
        document.getElementById('scan-progress').classList.remove('active');
      }
    };
    eventSource.onerror=()=>{
      document.getElementById('status-dot').classList.add('idle');
      document.getElementById('scan-progress').classList.remove('active');
    };
  }catch(err){
    log('Error: '+err.message);
    document.getElementById('status-dot').classList.add('idle');
    document.getElementById('scan-progress').classList.remove('active');
  }
}

function stopScan(){
  if(eventSource){eventSource.close();eventSource=null;}
  document.getElementById('status-dot').classList.add('idle');
  document.getElementById('scan-progress').classList.remove('active');
  fetch('/api/scan/stop',{method:'POST'});
  log('Scan stopped.');
}

async function downloadReport(fmt){
  if(!sessionId){log('No active session. Start a scan first.');return;}
  window.open(`/api/report/${sessionId}/${fmt}`,'_blank');
}
</script>
</body>
</html>"""


def create_app(scan_manager: object = None) -> object:
    """
    Create the FastAPI dashboard application.
    Returns None if FastAPI is not installed.
    """
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
    except ImportError:
        logger.error("FastAPI not installed. Install with: pip install btaudit[dashboard]")
        return None

    app = FastAPI(
        title="BTAudit Dashboard",
        description="Bluetooth Security Auditing Dashboard — Made by Monish Paramasivam",
        version="1.0.0",
    )

    # In-memory session store (production would use Redis/DB)
    sessions: dict[str, dict] = {}
    scan_queues: dict[str, asyncio.Queue] = {}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    @app.post("/api/scan/start")
    async def start_scan(request: dict = None) -> dict:
        from ..scanners import BLEScanner, ClassicScanner
        from ..analyzers import SecurityAnalyzer, DeviceCategorizer
        from ..models import ScanSession
        import uuid as _uuid

        session_id = str(_uuid.uuid4())[:8]
        queue: asyncio.Queue = asyncio.Queue()
        scan_queues[session_id] = queue
        sessions[session_id] = {"devices": {}, "started": datetime.utcnow().isoformat()}

        async def run_scan() -> None:
            analyzer = SecurityAnalyzer()
            categorizer = DeviceCategorizer()

            def on_device(device: object) -> None:
                categorizer.categorize(device)
                analyzer.analyze(device)
                sessions[session_id]["devices"][device.address] = device
                queue.put_nowait({"type": "device", "device": device.to_dict()})

            try:
                scanner = BLEScanner(scan_duration=15.0, callback=on_device)
                await scanner.scan()
            except Exception as exc:
                logger.error("BLE scan error in dashboard: %s", exc)
            finally:
                queue.put_nowait({"type": "complete"})

        asyncio.create_task(run_scan())
        return {"session_id": session_id, "status": "started"}

    @app.get("/api/scan/stream/{session_id}")
    async def scan_stream(session_id: str) -> StreamingResponse:
        from fastapi.responses import StreamingResponse

        async def event_generator() -> AsyncGenerator[str, None]:
            queue = scan_queues.get(session_id)
            if not queue:
                yield "data: {\"type\":\"error\",\"message\":\"Session not found\"}\n\n"
                return
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("type") == "complete":
                        break
                except asyncio.TimeoutError:
                    yield "data: {\"type\":\"ping\"}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/scan/stop")
    async def stop_scan() -> dict:
        return {"status": "stopped"}

    @app.get("/api/report/{session_id}/{fmt}")
    async def get_report(session_id: str, fmt: str) -> Response:
        from ..models import ScanSession
        from ..reporters import JSONReporter, CSVReporter, HTMLReporter
        import io
        import tempfile

        session_data = sessions.get(session_id)
        if not session_data:
            return JSONResponse({"error": "Session not found"}, status_code=404)

        session = ScanSession(
            session_id=session_id,
            started_at=datetime.fromisoformat(session_data["started"]),
            ended_at=datetime.utcnow(),
            devices=list(session_data["devices"].values()),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            if fmt == "json":
                path = JSONReporter(tmppath).generate(session)
                return Response(
                    path.read_text(),
                    media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={path.name}"},
                )
            elif fmt == "csv":
                path = CSVReporter(tmppath).generate(session)
                return Response(
                    path.read_text(),
                    media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={path.name}"},
                )
            elif fmt == "html":
                path = HTMLReporter(tmppath).generate(session)
                return Response(
                    path.read_text(),
                    media_type="text/html",
                    headers={"Content-Disposition": f"attachment; filename={path.name}"},
                )
            else:
                return JSONResponse({"error": "Unknown format"}, status_code=400)

    return app
