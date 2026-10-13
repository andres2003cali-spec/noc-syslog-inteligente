/* =====================================================================
   app.js - Lógica del tablero NOC Syslog Inteligente (JavaScript sin frameworks)

   Reglas de seguridad del frontend:
   - Todo dato que viene del servidor (en especial los logs) se escapa con esc()
     antes de insertarlo: un log con <script> se muestra como texto (anti-XSS).
   - No hay manejadores inline (onclick=""): la política CSP solo permite este archivo.
   - El rol NO se decide aquí: el servidor lo calcula a partir del usuario.
   ===================================================================== */
'use strict';

const SEV = [['Emergencia', 'Emergency'], ['Alerta', 'Alert'], ['Crítico', 'Critical'], ['Error', 'Error'],
  ['Advertencia', 'Warning'], ['Aviso', 'Notice'], ['Informativo', 'Informational'], ['Depuración', 'Debug']];
const FLAG_LABEL = {
  posible_inyeccion_prompt: 'inyección de prompt', fuente_no_autorizada: 'fuente no autorizada',
  secreto_enmascarado: 'secreto enmascarado', cambio_configuracion: 'cambio de config.',
  fuera_de_horario: 'fuera de horario', fallo_autenticacion: 'fallo de autenticación',
  cuenta_servicio_o_agente: 'cuenta de servicio/agente'
};
const TRANSITIONS = {
  abierto: ['asignado', 'en_progreso', 'cerrado'], asignado: ['en_progreso', 'resuelto', 'cerrado'],
  en_progreso: ['resuelto', 'asignado'], resuelto: ['cerrado', 'en_progreso'], cerrado: []
};
const FLOW = ['Evento detectado', 'Validación', 'Propuesta de acción', 'Revisión humana', 'Aprobación',
  'Ejecución autorizada', 'Verificación', 'Auditoría'];

const state = { user: 'operador.demo', role: 'operador', devices: [], profiles: {}, currentIncident: null };
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** Escapa texto para insertarlo en HTML de forma segura. */
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Llamada a la API con el usuario seleccionado; lanza Error con el mensaje del servidor. */
async function api(path, opts = {}) {
  const headers = { 'X-NOC-User': state.user, ...(opts.headers || {}) };
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.json); }
  const res = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body });
  let data = null;
  try { data = await res.json(); } catch (_) { /* respuesta sin JSON */ }
  if (!res.ok) throw new Error((data && data.error) || `Error HTTP ${res.status}`);
  return data;
}

function toast(msg, isError = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.className = 'toast'; }, 3200);
}

const sevPill = n => `<span class="pill s${n}">${n} · ${SEV[n][0]}</span>`;
const flagTags = flags => (flags || '').split(',').filter(Boolean)
  .map(f => `<span class="tag">${esc(FLAG_LABEL[f] || f)}</span>`).join('');
const originTag = o => `<span class="tag ${o === 'real' ? 'real' : 'sim'}">${esc(o)}</span>`;
const st = s => `<span class="st ${esc(s)}">${esc(String(s).replace('_', ' '))}</span>`;
const code = id => `INC-${String(id).padStart(4, '0')}`;
/** Fecha local 'AAAA-MM-DD HH:MM:SS', mismo formato que guarda el servidor. */
function localNow() {
  const d = new Date(), p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ------------------------------------------------------------------ */
/* Identidad y pestañas                                                */
/* ------------------------------------------------------------------ */
async function loadMe() {
  const me = await api('/api/me');
  state.role = me.role;
  const b = $('#roleBadge');
  b.textContent = me.role;
  b.className = 'role ' + me.role;
}

const loaders = {
  dashboard: loadDashboard, inventory: loadInventory, events: loadEvents, incidents: loadIncidents,
  approvals: loadProposals, config: () => {}, console: loadConsoleAudit, security: loadSecurity, audit: loadAudit
};

function showTab(name) {
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + name));
  location.hash = name;
  Promise.resolve((loaders[name] || (() => {}))()).catch(e => toast(e.message, true));
}

/* ------------------------------------------------------------------ */
/* Tablero                                                             */
/* ------------------------------------------------------------------ */
async function loadSpectrum() {
  const s = await api('/api/events/stats');
  const total = Object.values(s.by_severity).reduce((a, b) => a + b, 0) || 1;
  $('#spectrum').innerHTML = [...Array(8).keys()].map(i =>
    `<span class="s${i}" data-grow="${(s.by_severity[i] / total) * 20 + 1}" title="${i} · ${SEV[i][0]}: ${s.by_severity[i]} eventos">${s.by_severity[i]}</span>`).join('');
  $$('#spectrum span').forEach(el => { el.style.flexGrow = el.dataset.grow; });
  return s;
}

async function loadDashboard() {
  const [d, devices, stats, incidents] = await Promise.all([
    api('/api/dashboard'), api('/api/devices'), loadSpectrum(), api('/api/incidents?open=1')]);
  state.devices = devices;
  const k = [
    ['ok', `${d.devices_comm['en línea'] || 0}/${d.devices_total}`, 'Equipos en línea'],
    ['bad', d.devices_comm['sin comunicación'] || 0, 'Sin comunicación'],
    ['info', d.events_24h, 'Eventos últimas 24 h'],
    ['bad', d.critical_24h, 'Críticos 0–2 (24 h)'],
    ['warn', `${d.incidents_open}`, `Incidentes abiertos · ${d.incidents_p1} P1`],
    ['warn', d.proposals_pending, 'Propuestas por aprobar'],
    ['bad', d.security_flags, 'Eventos con bandera de seguridad'],
    ['info', d.duplicates_absorbed, 'Duplicados absorbidos'],
  ];
  $('#kpis').innerHTML = k.map(([c, v, l]) => `<div class="kpi ${c}"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join('');
  $('#pendingCount').textContent = d.proposals_pending || '';

  $('#deviceStatus').innerHTML = devices.map(dev => {
    const cls = dev.comm_status === 'en línea' ? 'online' : dev.comm_status === 'sin comunicación' ? 'offline' : dev.comm_status;
    return `<div class="dev ${esc(cls)}"><strong>${esc(dev.name)}</strong>
      <small>${esc(dev.vendor)} ${esc(dev.model)} · ${esc(dev.ip)}</small>
      <small>${esc(dev.comm_status)}${dev.last_seen ? ' · último evento ' + esc(dev.last_seen.slice(11)) : ''}</small></div>`;
  }).join('');

  const max = Math.max(1, ...Object.values(stats.by_severity));
  $('#sevBars').innerHTML = [...Array(8).keys()].map(i => `<div class="sev-row">
      <span>${sevPill(i)} <small>${SEV[i][1]}</small></span>
      <div class="sev-track"><div class="sev-fill s${i}" data-w="${(stats.by_severity[i] / max) * 100}"></div></div>
      <b>${stats.by_severity[i]}</b></div>`).join('');
  requestAnimationFrame(() => $$('#sevBars .sev-fill').forEach(el => { el.style.width = el.dataset.w + '%'; }));

  $('#recentCritical').innerHTML = d.recent_critical.length ? `<table class="dense"><tr><th>Hora</th><th>Sev.</th><th>Equipo</th><th>Mensaje</th></tr>
    ${d.recent_critical.map(e => `<tr><td class="mono">${esc(e.event_time.slice(5))}</td><td>${sevPill(e.severity)}</td>
      <td>${esc(e.device_name || '—')}</td><td class="msg-cell">${esc(e.message.slice(0, 110))} ${flagTags(e.flags)}</td></tr>`).join('')}</table>`
    : '<p class="empty">Sin eventos críticos. Genere el escenario "Críticos 0–2" para probar el flujo.</p>';

  $('#openIncidents').innerHTML = incidents.length ? `<table class="dense"><tr><th>ID</th><th>Prio.</th><th>Título</th><th>Estado</th></tr>
    ${incidents.slice(0, 7).map(i => `<tr class="clickable" data-open-inc="${i.id}"><td class="mono">${esc(i.code)}</td>
      <td class="prio ${esc(i.priority)}">${esc(i.priority)}</td><td>${esc(i.title.slice(0, 80))}</td><td>${st(i.status)}</td></tr>`).join('')}</table>`
    : '<p class="empty">No hay incidentes abiertos.</p>';
}

async function setupScenarios() {
  const sc = await api('/api/events/scenarios');
  const labels = { mixto: 'Tráfico mixto', critico: 'Críticos 0–2', inyeccion: 'Inyección de prompt', tormenta: 'Tormenta de eventos',
    fuera_horario: 'Cambio fuera de horario', fuerza_bruta: 'Fuerza bruta', no_autorizado: 'Fuente no autorizada', secreto: 'Secreto en log' };
  $('#scenarioRow').innerHTML = Object.entries(sc).map(([k, v]) =>
    `<button data-scenario="${esc(k)}" title="${esc(v)}">${esc(labels[k] || k)}</button>`).join('');
}

async function runScenario(name) {
  try {
    const r = await api('/api/events/simulate', { method: 'POST', json: { scenario: name } });
    const out = $('#scenarioResult');
    out.hidden = false;
    out.textContent = `Escenario: ${r.escenario}\nRecibidas: ${r.recibidas} · Almacenadas: ${r.almacenadas} · Duplicadas: ${r.duplicadas} · ` +
      `Descartadas por tormenta: ${r.descartadas_tormenta} · Inválidas: ${r.invalidas}\n` +
      `Incidentes creados/actualizados: ${r.incidentes.map(code).join(', ') || 'ninguno'}\n` +
      `Banderas: ${Object.entries(r.banderas).map(([f, n]) => `${FLAG_LABEL[f] || f}=${n}`).join(', ') || 'ninguna'}`;
    toast('Eventos simulados procesados.');
    loadDashboard();
  } catch (e) { toast(e.message, true); }
}

/* ------------------------------------------------------------------ */
/* Inventario                                                          */
/* ------------------------------------------------------------------ */
async function loadInventory() {
  state.devices = await api('/api/devices');
  $('#invCount').textContent = `${state.devices.length} equipos`;
  $('#invTable').innerHTML = `<tr><th>Nombre</th><th>IP</th><th>Marca</th><th>Modelo</th><th>SO / versión</th><th>Ubicación</th>
    <th>Estado</th><th>Comunicación</th><th>Dato</th><th>Actualizado</th><th></th></tr>` +
    state.devices.map(d => `<tr><td><strong>${esc(d.name)}</strong> ${d.is_simulated ? '<span class="tag sim">simulado</span>' : ''}</td>
      <td class="mono">${esc(d.ip)}</td><td>${esc(d.vendor)}</td><td>${esc(d.model)}</td><td>${esc(d.os_version)}</td>
      <td>${esc(d.location)}</td><td>${st(d.status)}</td>
      <td>${esc(d.comm_status)}${d.last_seen ? `<br><small class="mono">${esc(d.last_seen)}</small>` : ''}</td>
      <td>${d.data_quality === 'confirmado' ? 'confirmado' : '<span class="tag sim">por verificar</span>'}</td>
      <td class="mono">${esc(d.updated_at)}</td>
      <td><button class="small" data-edit-dev="${d.id}">Editar</button> <button class="small danger" data-del-dev="${d.id}">Eliminar</button></td></tr>`).join('');
}

function fillDeviceForm(d) {
  const f = $('#devForm');
  f.reset();
  f.id.value = d ? d.id : '';
  ['name', 'ip', 'vendor', 'model', 'os_version', 'location', 'status', 'data_quality'].forEach(k => { if (d) f[k].value = d[k]; });
  f.is_simulated.checked = d ? !!d.is_simulated : true;
  $('#devFormTitle').textContent = d ? `Editar ${d.name}` : 'Registrar equipo';
  $('#devMsg').textContent = '';
}

async function saveDevice(ev) {
  ev.preventDefault();
  const f = ev.target;
  const body = Object.fromEntries(new FormData(f));
  body.is_simulated = f.is_simulated.checked ? 1 : 0;
  const msg = $('#devMsg');
  try {
    const r = body.id ? await api(`/api/devices/${body.id}`, { method: 'PUT', json: body })
      : await api('/api/devices', { method: 'POST', json: body });
    msg.className = 'msg success'; msg.textContent = r.message;
    fillDeviceForm(null); $('#devMsg').className = 'msg success'; $('#devMsg').textContent = r.message;
    loadInventory();
  } catch (e) { msg.className = 'msg error'; msg.textContent = e.message; }
}

async function deleteDevice(id) {
  const d = state.devices.find(x => x.id === id);
  if (!confirm(`¿Eliminar ${d ? d.name : id}? Sus eventos se conservan sin equipo asociado.`)) return;
  try { await api(`/api/devices/${id}`, { method: 'DELETE' }); toast('Equipo eliminado.'); loadInventory(); }
  catch (e) { toast(e.message, true); }
}

/* ------------------------------------------------------------------ */
/* Eventos                                                             */
/* ------------------------------------------------------------------ */
function deviceOptions(sel, first) {
  sel.innerHTML = (first !== undefined ? `<option value="">${esc(first)}</option>` : '') +
    state.devices.map(d => `<option value="${d.id}">${esc(d.name)} (${esc(d.vendor)})</option>`).join('');
}

function eventQuery() {
  const p = new URLSearchParams();
  for (const [k, v] of new FormData($('#evFilters'))) if (v) p.set(k, v);
  return p;
}

async function loadEvents() {
  if (!state.devices.length) state.devices = await api('/api/devices');
  const keep = $('#evDevice').value;
  deviceOptions($('#evDevice'), 'Todos');
  $('#evDevice').value = keep;
  const q = eventQuery();
  $('#evExport').href = '/api/events/export.csv?' + q.toString();
  q.set('limit', '300');
  const r = await api('/api/events?' + q.toString());
  $('#evTotal').textContent = `${r.total} eventos coinciden con el filtro`;
  $('#evTable').innerHTML = `<tr><th>Fecha del evento</th><th>Severidad</th><th>Equipo</th><th>Marca</th><th>Facility</th>
    <th>Tipo / mnemónico</th><th>Mensaje</th><th>Origen</th><th>Rep.</th><th>Incidente</th></tr>` +
    (r.items.map(e => `<tr><td class="mono">${esc(e.event_time)}</td><td>${sevPill(e.severity)}</td>
      <td>${esc(e.device_name || e.source)}</td><td>${esc(e.vendor)}</td><td class="mono">${esc(e.facility_name)}</td>
      <td class="mono">${esc(e.app_name)}</td><td class="msg-cell">${esc(e.message)} ${flagTags(e.flags)}</td>
      <td>${originTag(e.origin_label)}<br><small>${esc(e.ingest_channel)}</small></td><td>${e.repeat_count > 1 ? '×' + e.repeat_count : ''}</td>
      <td>${e.incident_id ? `<a href="#" data-open-inc="${e.incident_id}">${code(e.incident_id)}</a>`
        : `<button class="small" data-inc-from-event="${e.id}">Crear</button>`}</td></tr>`).join('') ||
      '<tr><td colspan="10" class="empty">No hay eventos con ese filtro.</td></tr>');
}

async function importFile(ev) {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const out = $('#importResult');
  try {
    const res = await fetch('/api/events/import', { method: 'POST', headers: { 'X-NOC-User': state.user }, body: fd });
    const r = await res.json();
    if (!res.ok) throw new Error(r.error);
    out.hidden = false;
    out.textContent = `Recibidas: ${r.recibidas} · Almacenadas: ${r.almacenadas} · Duplicadas: ${r.duplicadas} · Inválidas (rechazadas): ${r.invalidas} · ` +
      `Descartadas por tormenta: ${r.descartadas_tormenta}\nIncidentes: ${r.incidentes.map(code).join(', ') || 'ninguno'}\n` +
      `Banderas de seguridad: ${Object.entries(r.banderas).map(([f, n]) => `${FLAG_LABEL[f] || f}=${n}`).join(', ') || 'ninguna'}`;
    toast('Archivo importado.');
    loadEvents(); loadSpectrum();
  } catch (e) { toast(e.message, true); }
}

async function incidentFromEvent(id) {
  try {
    const r = await api('/api/incidents', { method: 'POST', json: { event_id: id } });
    toast(`${r.code} creado desde el evento #${id}.`);
    openIncident(r.id);
  } catch (e) { toast(e.message, true); }
}

/* ------------------------------------------------------------------ */
/* Incidentes                                                          */
/* ------------------------------------------------------------------ */
async function loadIncidents() {
  if (!state.devices.length) state.devices = await api('/api/devices');
  deviceOptions($('#incDevice'), '(ninguno)');
  const status = $('#incStatusFilter').value;
  const list = await api('/api/incidents' + (status ? '?status=' + encodeURIComponent(status) : ''));
  $('#incTable').innerHTML = `<tr><th>ID</th><th>Prio.</th><th>Título</th><th>Equipo</th><th>Estado</th><th>Responsable</th><th>SLA vence</th><th>Ev.</th></tr>` +
    (list.map(i => `<tr class="clickable ${state.currentIncident === i.id ? 'selected' : ''}" data-open-inc="${i.id}">
      <td class="mono">${esc(i.code)}</td><td class="prio ${esc(i.priority)}">${esc(i.priority)}</td>
      <td>${esc(i.title)}${i.pending_proposals ? ' <span class="tag sim">propuesta pendiente</span>' : ''}</td>
      <td>${esc(i.device_name || '—')}</td><td>${st(i.status)}</td><td>${esc(i.assignee || '—')}</td>
      <td class="mono">${esc(i.sla_due.slice(5, 16))}</td><td>${i.event_count}</td></tr>`).join('') ||
      '<tr><td colspan="8" class="empty">No hay incidentes.</td></tr>');
  if (state.currentIncident) renderIncident(state.currentIncident);
}

async function openIncident(id) {
  state.currentIncident = id;
  if (!$('#tab-incidents').classList.contains('active')) showTab('incidents');
  else loadIncidents();
}

async function renderIncident(id) {
  let i;
  try { i = await api(`/api/incidents/${id}`); } catch (e) { $('#incDetail').innerHTML = `<p class="empty">${esc(e.message)}</p>`; return; }
  const breached = i.status !== 'cerrado' && i.status !== 'resuelto' && i.sla_due < localNow();
  const users = ['operador.demo', 'operador2.demo', 'admin.demo'];
  $('#incDetail').innerHTML = `
    <div class="inc-head"><h2>${esc(i.code)}</h2><span class="prio ${esc(i.priority)}">${esc(i.priority)}</span>
      ${sevPill(i.severity)} ${st(i.status)} <span class="tag">${esc(i.category)}</span></div>
    <strong>${esc(i.title)}</strong>
    <div class="inc-meta">
      <div><small>Equipo</small>${esc(i.device_name || '—')}</div>
      <div><small>Responsable</small>${esc(i.assignee || 'sin asignar')}</div>
      <div><small>SLA vence</small>${esc(i.sla_due)}${breached ? ' <span class="tag">vencido</span>' : ''}</div>
      <div><small>Creado por</small>${esc(i.created_by)}</div>
      <div><small>Creado</small>${esc(i.created_at)}</div>
      <div><small>Cerrado</small>${esc(i.closed_at || '—')}</div>
    </div>
    <p>${esc(i.description)}</p>
    ${i.cause ? `<p><b>Causa:</b> ${esc(i.cause)}</p>` : ''}${i.resolution ? `<p><b>Resolución:</b> ${esc(i.resolution)}</p>` : ''}
    ${i.status !== 'cerrado' ? `<form class="inc-form" id="incUpdate" data-id="${i.id}">
      <label>Asignar a<select name="assignee"><option value="">(sin cambio)</option>${users.map(u => `<option ${u === i.assignee ? 'selected' : ''}>${u}</option>`).join('')}</select></label>
      <label>Nuevo estado<select name="status"><option value="">(sin cambio)</option>${TRANSITIONS[i.status].map(s => `<option value="${s}">${s.replace('_', ' ')}</option>`).join('')}</select></label>
      <label class="full">Causa raíz<input name="cause" value="${esc(i.cause)}" maxlength="2000"></label>
      <label class="full">Resolución<input name="resolution" value="${esc(i.resolution)}" maxlength="2000"></label>
      <label class="full">Nota de seguimiento<textarea name="note" rows="2" maxlength="2000"></textarea></label>
      <div class="actions full"><button class="primary" type="submit">Guardar seguimiento</button></div>
      <p class="msg full" id="incMsg"></p></form>` : '<p class="hint">Incidente cerrado: solo lectura.</p>'}
    <h2 class="mt">Seguimiento</h2>
    <ul class="timeline">${i.updates.map(u => `<li><time>${esc(u.created_at)}</time> · <b>${esc(u.actor)}</b> · ${esc(u.action)}<br>${esc(u.note)}</li>`).join('')}</ul>
    <h2>Eventos vinculados (${i.event_count})</h2>
    <table class="dense">${i.events.map(e => `<tr><td class="mono">${esc(e.event_time)}</td><td>${sevPill(e.severity)}</td>
      <td class="msg-cell">${esc(e.message)} ${originTag(e.origin_label)}${e.repeat_count > 1 ? ' ×' + e.repeat_count : ''}</td></tr>`).join('') ||
      '<tr><td class="empty">Sin eventos vinculados.</td></tr>'}</table>
    <h2>Propuestas de acción</h2>
    <table class="dense">${i.proposals.map(p => `<tr><td class="mono">${esc(p.command)}</td><td>${esc(p.proposed_by)}</td><td>${st(p.status)}</td></tr>`).join('') ||
      '<tr><td class="empty">Sin propuestas. Puede proponer una en "Aprobaciones".</td></tr>'}</table>`;
}

async function updateIncident(ev) {
  ev.preventDefault();
  const f = ev.target;
  const body = Object.fromEntries([...new FormData(f)].filter(([, v]) => v));
  try {
    const r = await api(`/api/incidents/${f.dataset.id}`, { method: 'PATCH', json: body });
    toast(r.message);
    loadIncidents();
  } catch (e) { $('#incMsg').className = 'msg error full'; $('#incMsg').textContent = e.message; }
}

async function createIncident(ev) {
  ev.preventDefault();
  const body = Object.fromEntries(new FormData(ev.target));
  try {
    const r = await api('/api/incidents', { method: 'POST', json: body });
    ev.target.reset(); toast(`${r.code} creado.`); openIncident(r.id);
  } catch (e) { $('#incCreateMsg').className = 'msg error'; $('#incCreateMsg').textContent = e.message; }
}

/* ------------------------------------------------------------------ */
/* Aprobaciones                                                        */
/* ------------------------------------------------------------------ */
async function loadProposals() {
  if (!state.devices.length) state.devices = await api('/api/devices');
  if (!$('#propDevice').options.length) deviceOptions($('#propDevice'));
  const list = await api('/api/proposals');
  $('#pendingCount').textContent = list.filter(p => p.status === 'pendiente').length || '';
  $('#propTable').innerHTML = `<tr><th>#</th><th>Equipo</th><th>Comando</th><th>Propuso</th><th>Política</th><th>Estado</th><th>Revisión / resultado</th><th>Acción</th></tr>` +
    (list.map(p => {
      let act = '';
      if (p.status === 'pendiente') act = `<button class="small ok" data-review="${p.id}" data-decision="aprobar">Aprobar</button>
        <button class="small danger" data-review="${p.id}" data-decision="rechazar">Rechazar</button>`;
      else if (p.status === 'aprobada') act = `<button class="small primary" data-execute="${p.id}">Ejecutar</button>`;
      else if (p.status === 'ejecutada') act = `<button class="small" data-verify="${p.id}">Verificar</button>`;
      const detail = [p.reviewed_by && `${p.status === 'rechazada' ? 'Rechazó' : 'Revisó'}: ${p.reviewed_by}`, p.execution_result,
        p.verification && `Verificó ${p.verified_by}: ${p.verification}`].filter(Boolean).map(esc).join('<br>');
      return `<tr><td>${p.id}${p.incident_id ? `<br><a href="#" data-open-inc="${p.incident_id}">${code(p.incident_id)}</a>` : ''}</td>
        <td>${esc(p.device_name)}</td><td class="mono">${esc(p.command)}</td><td>${esc(p.proposed_by)}</td>
        <td class="msg-cell"><small>${esc(p.policy_check)}</small></td><td>${st(p.status)}</td>
        <td class="msg-cell"><small>${detail}</small></td><td>${act}</td></tr>`;
    }).join('') || '<tr><td colspan="8" class="empty">No hay propuestas.</td></tr>');
}

async function proposalAction(path, body, okMsg) {
  try { await api(path, { method: 'POST', json: body }); toast(okMsg); loadProposals(); }
  catch (e) { toast(e.message, true); }
}

async function proposeAction(ev) {
  ev.preventDefault();
  const body = Object.fromEntries(new FormData(ev.target));
  const msg = $('#propMsg');
  try {
    const r = await api('/api/proposals', { method: 'POST', json: body });
    msg.className = 'msg success'; msg.textContent = `Propuesta #${r.id} ${r.status}. ${r.policy_check}`;
    loadProposals();
  } catch (e) { msg.className = 'msg error'; msg.textContent = e.message; loadProposals(); }
}

/* ------------------------------------------------------------------ */
/* Configuraciones                                                     */
/* ------------------------------------------------------------------ */
function highlight(text) {
  return text.split('\n').map(l => /^\s*[!#]/.test(l) ? `<span class="c">${esc(l)}</span>` : esc(l)).join('\n');
}

async function generateConfig(ev) {
  ev.preventDefault();
  const body = Object.fromEntries(new FormData(ev.target));
  const vendors = body.vendor === 'all' ? ['cisco', 'fortinet', 'huawei'] : [body.vendor];
  const names = { cisco: 'Cisco IOS / IOS XE', fortinet: 'Fortinet FortiOS', huawei: 'Huawei VRP' };
  $('#cfgMsg').textContent = '';
  try {
    const results = [];
    for (const v of vendors) results.push(await api('/api/config/generate', { method: 'POST', json: { ...body, vendor: v } }));
    $('#cfgOut').innerHTML = results.map(r => `<div class="panel cfg-card">
      <h3>${names[r.vendor]}</h3><small class="hint">Umbral: ${r.severity} · ${esc(r.severity_name)}</small>
      ${r.warnings.map(w => `<div class="warnbox">${esc(w)}</div>`).join('')}
      <h4>Configuración comentada</h4><pre>${highlight(r.config)}</pre>
      <h4>Verificación</h4><pre>${highlight(r.verify)}</pre>
      <h4>Plan de reversa (rollback)</h4><pre>${highlight(r.rollback)}</pre>
      <div class="actions"><button class="small" data-copy="${r.vendor}">Copiar</button>
      <button class="small" data-download="${r.vendor}">Descargar .txt</button></div></div>`).join('');
    state.lastConfigs = Object.fromEntries(results.map(r => [r.vendor, r]));
  } catch (e) { $('#cfgMsg').className = 'msg error'; $('#cfgMsg').textContent = e.message; }
}

function configText(v) {
  const r = state.lastConfigs[v];
  return `${r.config}\n\n# ---- Verificación ----\n${r.verify}\n\n# ---- Rollback ----\n${r.rollback}\n`;
}

/* ------------------------------------------------------------------ */
/* Consola simulada                                                    */
/* ------------------------------------------------------------------ */
async function setupConsole() {
  state.profiles = await api('/api/console/profiles');
  if (!state.devices.length) state.devices = await api('/api/devices');
  deviceOptions($('#conDevice'));
  $('#conProfile').innerHTML = Object.entries(state.profiles).map(([k, p]) => `<option value="${k}">${esc(p.label)}</option>`).join('');
  syncProfile();
}

function syncProfile(fromDevice = true) {
  const dev = state.devices.find(d => String(d.id) === $('#conDevice').value);
  if (fromDevice && dev) {
    const prof = { Cisco: 'cisco', Fortinet: 'fortinet', Huawei: 'huawei' }[dev.vendor];
    if (prof && $('#conProfile').value !== 'rommon') $('#conProfile').value = prof;
  }
  const p = state.profiles[$('#conProfile').value];
  const name = dev ? dev.name : 'LAB';
  $('#termPrompt').textContent = p.label.includes('ROMMON') ? 'rommon 1 >' :
    p.vendor === 'Huawei' ? `<${name}>` : p.vendor === 'Fortinet' ? `${name} #` : `${name}#`;
  $('#conAllowed').innerHTML = p.allowed.map(c => `<button type="button" data-cmd="${esc(c)}">${esc(c)}</button>`).join('');
  const t = $('#terminal');
  const banner = `<span class="sys">noc-console · ${esc(p.label)} · ${esc(name)} · SIMULACIÓN DE SOLO LECTURA\nNo existe conexión a equipos reales. Escriba "help" para ver los comandos permitidos.\n</span>`;
  // Al cambiar de perfil se conserva la sesión anterior para que el historial sea evidencia completa
  t.innerHTML = t.innerHTML ? t.innerHTML + '\n' + banner : banner;
  t.scrollTop = t.scrollHeight;
}

async function runConsole(ev) {
  ev.preventDefault();
  const input = $('#termCmd');
  const cmd = input.value;
  input.value = '';
  const t = $('#terminal');
  try {
    const r = await api('/api/console/exec', { method: 'POST', json: { profile: $('#conProfile').value, device_id: $('#conDevice').value, command: cmd } });
    t.innerHTML += `\n<span class="cmd">${esc(r.prompt)} ${esc(cmd)}</span>\n<span class="${r.decision === 'bloqueado' ? 'blocked' : ''}">${esc(r.output)}</span>\n`;
  } catch (e) { t.innerHTML += `\n<span class="blocked">${esc(e.message)}</span>\n`; }
  t.scrollTop = t.scrollHeight;
  loadConsoleAudit();
}

async function loadConsoleAudit() {
  if (!state.profiles.cisco) await setupConsole();
  const rows = await api('/api/audit/commands');
  $('#cmdAudit').innerHTML = `<tr><th>Fecha</th><th>Usuario (rol)</th><th>Equipo</th><th>Comando</th><th>Decisión</th><th>Motivo</th></tr>` +
    (rows.slice(0, 60).map(c => `<tr><td class="mono">${esc(c.created_at.slice(11))}</td><td>${esc(c.actor)} <small>(${esc(c.role)})</small></td>
      <td>${esc(c.device_name || '—')}</td><td class="mono">${esc(c.command)}</td><td>${st(c.decision)}</td>
      <td class="msg-cell"><small>${esc(c.reason)}</small></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Sin comandos registrados.</td></tr>');
}

/* ------------------------------------------------------------------ */
/* Defensa IA y auditoría                                              */
/* ------------------------------------------------------------------ */
const CONTROLS = [
  ['Logs = datos', 'Ningún texto de un log se usa como instrucción. El agente simulado elige sus acciones de una tabla fija.'],
  ['Detección de inyección', 'Patrones como "ignora las políticas" o "ejecuta reload" marcan el evento y abren un incidente de seguridad-IA.'],
  ['Fuentes autorizadas', 'Solo equipos del inventario generan incidentes operativos; el resto queda en cuarentena.'],
  ['Secretos', 'Contraseñas, tokens y comunidades se enmascaran antes de guardar. Los secretos viven en .env.'],
  ['Tormentas', 'Límite de eventos por fuente y minuto, deduplicación e incidentes agrupados por firma.'],
  ['Cambios y accesos', 'Se detectan cambios fuera de horario, fallos de autenticación repetidos y cuentas de servicio/agente.'],
  ['Allowlist de acciones', 'Comandos de lectura o cambio controlado; lo destructivo o encadenado se bloquea siempre.'],
  ['Aprobación humana', 'Flujo propuesta → revisión → aprobación → ejecución → verificación. Quien propone no aprueba.'],
  ['Roles', 'El agente de IA solo lee y propone: no aprueba, no ejecuta y no usa la consola.'],
  ['Integridad', 'Auditoría encadenada con SHA-256 y exportable como evidencia.'],
];

async function loadSecurity() {
  const [p, ev] = await Promise.all([api('/api/policy'), api('/api/events?flagged=1&limit=200')]);
  $('#polPrinciple').textContent = p.principio;
  $('#polControls').innerHTML = CONTROLS.map(([a, b]) => `<div class="ctrl"><b>${esc(a)}</b><span>${esc(b)}</span></div>`).join('');
  const u = p.umbrales;
  $('#polThresholds').innerHTML = `<div class="kv">
    <span>Severidad que abre incidente</span><b>0 a ${u.incidente_severidad_max}</b>
    <span>Límite por fuente</span><b>${u.rate_limit_por_minuto} eventos/min</b>
    <span>Ventana de deduplicación</span><b>${u.ventana_dedup_segundos} s</b>
    <span>Umbral "sin comunicación"</span><b>${u.umbral_sin_comunicacion_min} min</b>
    <span>Horario laboral</span><b>${esc(u.horario_laboral)}</b>
    <span>Tamaño máximo por mensaje</span><b>${u.max_linea_bytes} bytes</b></div>`;
  $('#polRoles').innerHTML = `<table class="dense"><tr><th>Rol</th><th>Permisos</th></tr>${Object.entries(p.roles).map(([r, perms]) =>
    `<tr><td><b>${esc(r)}</b></td><td><small>${perms.map(esc).join(', ')}</small></td></tr>`).join('')}</table>`;
  $('#secTotal').textContent = `${ev.total} eventos marcados`;
  $('#secTable').innerHTML = `<tr><th>Fecha</th><th>Sev.</th><th>Origen</th><th>Banderas</th><th>Mensaje (tratado como dato)</th><th>Autorizada</th><th>Incidente</th></tr>` +
    (ev.items.map(e => `<tr><td class="mono">${esc(e.event_time)}</td><td>${sevPill(e.severity)}</td><td>${esc(e.device_name || e.source)}</td>
      <td>${flagTags(e.flags)}</td><td class="msg-cell">${esc(e.message)}</td><td>${e.authorized ? 'sí' : '<b>no</b>'}</td>
      <td>${e.incident_id ? `<a href="#" data-open-inc="${e.incident_id}">${code(e.incident_id)}</a>` : '—'}</td></tr>`).join('') ||
      '<tr><td colspan="7" class="empty">Sin eventos marcados. Pruebe los escenarios de seguridad del tablero.</td></tr>');
}

async function loadAudit() {
  const r = await api('/api/audit');
  $('#chainState').innerHTML = r.chain.ok ? `<span class="st cerrado">Cadena íntegra · ${r.chain.total} registros</span>`
    : `<span class="st bloqueado">Cadena alterada en el registro #${r.chain.broken_at}</span>`;
  $('#auditTable').innerHTML = `<tr><th>#</th><th>Fecha</th><th>Actor</th><th>Acción</th><th>Entidad</th><th>Detalle</th><th>Hash</th></tr>` +
    r.items.map(a => `<tr><td>${a.id}</td><td class="mono">${esc(a.created_at)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td>
      <td>${esc(a.entity)} ${esc(a.entity_id)}</td><td class="msg-cell"><small class="mono">${esc(a.detail.slice(0, 220))}</small></td>
      <td class="mono"><small>${esc(a.hash.slice(0, 12))}…</small></td></tr>`).join('');
}

/* ------------------------------------------------------------------ */
/* Arranque y delegación de eventos                                    */
/* ------------------------------------------------------------------ */
function initSelects() {
  const sevOpts = [...Array(8).keys()].map(i => `<option value="${i}">${i} · ${SEV[i][0]}</option>`).join('');
  $('#evSeverity').innerHTML = '<option value="">Todas</option>' + sevOpts;
  $('#evSevMax').innerHTML = '<option value="">—</option>' + sevOpts;
  $('#incSev').innerHTML = sevOpts; $('#incSev').value = '3';
  $('#cfgSev').innerHTML = sevOpts; $('#cfgSev').value = '4';
  $('#cfgFac').innerHTML = [...Array(8).keys()].map(i => `<option value="${i}">local${i}</option>`).join(''); $('#cfgFac').value = '7';
  $('#flowSteps').innerHTML = FLOW.map((s, i) => `<li class="${[3, 4].includes(i) ? 'human' : ''}">${esc(s)}</li>`).join('');
}

document.addEventListener('click', ev => {
  const t = ev.target.closest('button, a, tr');
  if (!t) return;
  const d = t.dataset;
  if (d.tab) return showTab(d.tab);
  if (d.scenario) return runScenario(d.scenario);
  if (d.openInc) { ev.preventDefault(); return openIncident(Number(d.openInc)); }
  if (d.editDev) return fillDeviceForm(state.devices.find(x => x.id === Number(d.editDev)));
  if (d.delDev) return deleteDevice(Number(d.delDev));
  if (d.incFromEvent) return incidentFromEvent(Number(d.incFromEvent));
  if (d.review) return proposalAction(`/api/proposals/${d.review}/review`, { decision: d.decision }, `Propuesta ${d.decision === 'aprobar' ? 'aprobada' : 'rechazada'}.`);
  if (d.execute) return proposalAction(`/api/proposals/${d.execute}/execute`, {}, 'Ejecución simulada registrada.');
  if (d.verify) {
    const note = prompt('Describa la verificación realizada (qué observó tras la ejecución):', 'Salida revisada; el equipo responde y el evento no se repite.');
    if (note) proposalAction(`/api/proposals/${d.verify}/verify`, { verification: note }, 'Verificación registrada.');
    return;
  }
  if (d.cmd) { $('#termCmd').value = d.cmd; return $('#termForm').requestSubmit(); }
  if (d.copy) { navigator.clipboard.writeText(configText(d.copy)).then(() => toast('Configuración copiada.')); return; }
  if (d.download) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([configText(d.download)], { type: 'text/plain' }));
    a.download = `syslog_${d.download}.txt`; a.click(); URL.revokeObjectURL(a.href);
  }
});

document.addEventListener('submit', ev => {
  if (ev.target.id === 'incUpdate') updateIncident(ev);
});

async function init() {
  try { state.user = localStorage.getItem('nocUser') || 'operador.demo'; } catch (_) { /* sin almacenamiento */ }
  $('#userSel').value = state.user;
  $('#userSel').addEventListener('change', async e => {
    state.user = e.target.value;
    try { localStorage.setItem('nocUser', state.user); } catch (_) { /* opcional */ }
    await loadMe();
    toast(`Ahora opera como ${state.user} (${state.role}).`);
  });
  initSelects();
  $('#devForm').addEventListener('submit', saveDevice);
  $('#devCancel').addEventListener('click', () => fillDeviceForm(null));
  $('#evFilters').addEventListener('submit', e => { e.preventDefault(); loadEvents().catch(err => toast(err.message, true)); });
  $('#evReset').addEventListener('click', () => setTimeout(() => loadEvents(), 0));
  $('#importForm').addEventListener('submit', importFile);
  $('#incStatusFilter').addEventListener('change', () => loadIncidents());
  $('#incCreate').addEventListener('submit', createIncident);
  $('#propForm').addEventListener('submit', proposeAction);
  $('#cfgForm').addEventListener('submit', generateConfig);
  $('#termForm').addEventListener('submit', runConsole);
  $('#conDevice').addEventListener('change', () => syncProfile(true));
  $('#conProfile').addEventListener('change', () => syncProfile(false));
  await loadMe();
  await setupScenarios();
  await setupConsole();
  const start = (location.hash || '#dashboard').slice(1);
  showTab(loaders[start] ? start : 'dashboard');
}

init().catch(e => toast(e.message, true));
