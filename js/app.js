/*
 * app.js
 * Hace de cliente y de NAS, habla con el servidor AAA simulado y muestra
 * cómo avanza la secuencia RADIUS. La pantalla muestra solo lo esencial;
 * el detalle aparece al pasar el mouse sobre los botones "i".
 */
(() => {
  'use strict';

  const ESPERA_AUTO_MS = 10000;
  const MAX_LOG = 9;

  /* El NAS de la demo: un punto de acceso Wi-Fi con 802.1X. */
  const NAS = { ip: '10.10.0.2', nombre: 'AP-Biblioteca', puerto: 7, ssid: 'USC LIBRE', mac: 'A0-B1-C2-D3-E4-F5' };
  const MAC_CLIENTE = '3C-52-82-A1-7F-09';

  const ACLS = {
    'ACL-ESTUDIANTES': ['permit tcp any any eq 80, 443   (navegar)', 'permit udp any any eq 53         (DNS)', 'deny   ip any 10.99.0.0/16       (red de gestión)'],
    'ACL-GESTION': ['permit ip any any                 (acceso total)'],
  };

  const CAPAS = [
    { id: 'solicitud', nombre: 'Cliente → NAS', resumen: 'Solicitud de acceso',
      info: 'El cliente (portátil, celular) se conecta al Wi-Fi o al puerto del switch y entrega sus credenciales al NAS. El NAS deja el puerto cerrado hasta que el servidor AAA decida.' },
    { id: 'request', nombre: 'NAS → Servidor', resumen: 'Access-Request (1)',
      info: 'El NAS mete el usuario y la contraseña cifrada en un paquete <strong>Access-Request (Code 1)</strong> y lo envía al servidor por <strong>UDP 1812</strong>.' },
    { id: 'servidor', nombre: 'Servidor AAA', resumen: 'Valida el NAS y descifra',
      info: 'El servidor solo atiende a los NAS que tiene registrados. Con el <strong>secreto compartido</strong> verifica la firma del paquete y descifra la contraseña.' },
    { id: 'base', nombre: 'Base de usuarios', resumen: 'Autenticación',
      info: 'Primera A, <strong>autenticación</strong>: ¿quién eres? El servidor busca el usuario en la base (AD, LDAP o local) y compara la contraseña.' },
    { id: 'challenge', nombre: 'Servidor → NAS', resumen: 'Access-Challenge (11)',
      info: '<strong>Opcional.</strong> Si la cuenta tiene segundo factor, el servidor responde <strong>Access-Challenge (Code 11)</strong> pidiendo un token o código. El NAS reenvía la respuesta en otro Access-Request.' },
    { id: 'decision', nombre: 'Servidor → NAS', resumen: 'Access-Accept (2) / Reject (3)',
      info: 'El servidor decide. Si acepta, manda <strong>Access-Accept (Code 2)</strong> con los atributos de autorización (VLAN, ACL, privilegio). Si no, <strong>Access-Reject (Code 3)</strong>.' },
    { id: 'aplicar', nombre: 'NAS → Cliente', resumen: 'Autorización',
      info: 'Segunda A, <strong>autorización</strong>: ¿qué puedes hacer? El NAS aplica lo que dijo el servidor: VLAN, ACL o nivel de privilegio. O niega el acceso.' },
    { id: 'acct', nombre: 'Contabilidad', resumen: 'Accounting-Request (4) / Response (5)',
      info: 'Tercera A, <strong>contabilidad</strong>: ¿qué hiciste? Por <strong>UDP 1813</strong> el NAS reporta <em>Start</em>, <em>Interim-Update</em> y <em>Stop</em> con el tiempo y los bytes. El servidor confirma cada uno con <strong>Accounting-Response (5)</strong>.' },
  ];

  const MARCAS = { pendiente: '', ok: '✓', error: '✗', espera: '…', omitida: '–', na: '–' };
  const ESTADOS = { pendiente: 'Pendiente', ok: 'Superado', error: 'Rechazado', espera: 'Esperando', omitida: 'Omitido', na: 'No aplica' };

  const $ = (id) => document.getElementById(id);
  const el = {
    capas: $('listaCapas'),
    inspector: $('inspector'),
    formLogin: $('formLogin'),
    usuario: $('usuario'),
    contrasena: $('contrasena'),
    verClave: $('verClave'),
    entrar: $('btnEntrar'),
    mensaje: $('mensajeLogin'),
    tarjetaLogin: $('tarjetaLogin'),
    tarjetaMfa: $('tarjetaMfa'),
    formMfa: $('formMfa'),
    codigoMfa: $('codigoMfa'),
    codigoTelefono: $('codigoTelefono'),
    venceTelefono: $('venceTelefono'),
    tarjetaSesion: $('tarjetaSesion'),
    nombreSesion: $('nombreSesion'),
    grupoSesion: $('grupoSesion'),
    vlanSesion: $('vlanSesion'),
    ipSesion: $('ipSesion'),
    aclSesion: $('aclSesion'),
    tiempoSesion: $('tiempoSesion'),
    datosSesion: $('datosSesion'),
    interim: $('btnInterim'),
    salir: $('btnSalir'),
    bitacora: $('bitacora'),
    pistaCapas: $('pistaCapas'),
    arquitectura: document.querySelector('.arquitectura'),
    avisoCripto: $('avisoCripto'),
    tip: $('tip'),
  };

  const estado = {
    listo: false,
    corriendo: false,
    historial: {},
    vista: { id: null, n: 0 },
    flujo: 0,
    resolverPaso: null,
    temporizador: null,
    resolverMfa: null,
    relojMfa: null,
    sesion: null,
    identificador: Math.floor(Math.random() * 200),
  };

  class FlujoCancelado extends Error {}

  /* ================= Utilidades ================= */

  function esc(valor) {
    return String(valor).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  const json = (obj) => JSON.stringify(obj, null, 2);
  const recortar = (t, n = 14) => (t.length > n ? `${t.slice(0, n)}…` : t);
  const hex = (b) => Cripto.aHex(b);
  const hexEsp = (b) => Cripto.aHex(b, ' ');

  function siguienteId() {
    estado.identificador = (estado.identificador + 1) % 256;
    return estado.identificador;
  }

  function bytesLegibles(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 ** 2).toFixed(2)} MB`;
  }

  function duracion(s) {
    const m = Math.floor(s / 60);
    return m ? `${m} min ${s % 60} s` : `${s} s`;
  }

  /* ================= Globos de información ================= */

  /* Contenido fijo de las "i" que están en el HTML */
  const INFO = {
    acerca: () => `<strong class="tip-titulo">Sobre esta demostración</strong>
      <p>Un servidor AAA decide <strong>quién entra a la red</strong>, <strong>qué puede hacer</strong> y <strong>deja registro de lo que hizo</strong>. Aquí el NAS y el servidor corren en el navegador, pero los paquetes RADIUS se arman byte a byte (RFC 2865 y 2866) con MD5 reales.</p>
      <table><tr><th></th><th>RADIUS</th><th>TACACS+</th></tr>
        <tr><td>Transporte</td><td>UDP 1812 / 1813</td><td>TCP 49</td></tr>
        <tr><td>Cifrado</td><td>Solo la contraseña</td><td>Todo el cuerpo</td></tr>
        <tr><td>Uso típico</td><td>802.1X, Wi-Fi, VPN</td><td>Administrar equipos</td></tr>
        <tr><td>Estándar</td><td>IETF (RFC 2865)</td><td>Cisco</td></tr></table>
      <p style="margin-top:8px">Los pasos avanzan solos. Por simplicidad la contraseña viaja como en PAP; en 802.1X real va dentro de un túnel EAP (PEAP o EAP-TTLS).</p>`,
    'nodo-cliente': () => `<strong class="tip-titulo">Cliente</strong><p>El usuario o equipo que quiere entrar a la red. En 802.1X se le llama <em>suplicante</em>.</p><p>MAC: <code>${MAC_CLIENTE}</code></p>`,
    'nodo-nas': () => `<strong class="tip-titulo">NAS (Network Access Server)</strong><p>El equipo de red donde se conecta el cliente: switch, punto de acceso, router o concentrador VPN. No decide nada: le pregunta al servidor AAA y aplica la respuesta.</p><p><code>${NAS.nombre}</code> · <code>${NAS.ip}</code> · Wi-Fi <code>${NAS.ssid}</code></p>`,
    'nodo-servidor': () => `<strong class="tip-titulo">Servidor AAA (RADIUS)</strong><p>Toma las decisiones de autenticación y autorización y guarda la contabilidad. Ejemplos: FreeRADIUS, Cisco ISE, Microsoft NPS.</p>
      <table><tr><th>NAS registrado</th><th>Secreto compartido</th></tr><tr><td>${NAS.ip} (${NAS.nombre})</td><td><code>${esc(Servidor.cliente(NAS.ip).secreto)}</code></td></tr></table>
      <p style="margin-top:8px">El secreto compartido <strong>nunca viaja por la red</strong>: se configura a mano en el NAS y en el servidor.</p>`,
    'nodo-bd': () => `<strong class="tip-titulo">Base de usuarios</strong><p>Donde están las cuentas. En empresas suele ser Active Directory o LDAP; aquí es local. <strong>No guarda contraseñas</strong>, solo salt y hash PBKDF2.</p>${tablaUsuarios(null)}`,
    pruebas: () => `<strong class="tip-titulo">Usuarios de prueba</strong>
      <table><tr><th>Usuario</th><th>Contraseña</th><th>2.º factor</th><th>Autorización</th></tr>
      <tr><td>ana</td><td><code>usc2026</code></td><td>no</td><td>VLAN 20, ACL-ESTUDIANTES</td></tr>
      <tr><td>admin</td><td><code>admin123</code></td><td>sí</td><td>VLAN 99, ACL-GESTION, priv 15</td></tr></table>
      <p style="margin-top:8px">Prueba también: una contraseña mala, un usuario que no existe o un código equivocado.</p>`,
  };

  /* Contenido de las "i" que se crean al dibujar cada paso */
  let dinamicos = new Map();
  let contadorInfo = 0;

  function i(html) {
    const clave = `d${++contadorInfo}`;
    dinamicos.set(clave, html);
    return `<button type="button" class="info" data-info="${clave}" aria-label="Más información">i</button>`;
  }

  function contenidoInfo(clave) {
    if (INFO[clave]) return INFO[clave]();
    if (clave.startsWith('capa-')) {
      const c = CAPAS.find((x) => x.id === clave.slice(5));
      return c ? `<strong class="tip-titulo">${c.nombre} · ${c.resumen}</strong><p>${c.info}</p>` : '';
    }
    return dinamicos.get(clave) || '';
  }

  function mostrarTip(boton) {
    const html = contenidoInfo(boton.dataset.info);
    if (!html) return;
    el.tip.innerHTML = html;
    el.tip.hidden = false;
    const r = boton.getBoundingClientRect();
    const t = el.tip.getBoundingClientRect();
    const margen = 12;
    let x = r.left + r.width / 2 - t.width / 2;
    x = Math.max(margen, Math.min(x, window.innerWidth - t.width - margen));
    let y = r.bottom + 8;
    if (y + t.height > window.innerHeight - margen) y = Math.max(margen, r.top - t.height - 8);
    el.tip.style.left = `${x}px`;
    el.tip.style.top = `${y}px`;
  }

  function ocultarTip() {
    el.tip.hidden = true;
  }

  /* ================= Piezas visuales ================= */

  function tablaUsuarios(resaltar) {
    const filas = Servidor.tablaUsuarios().map((r) => `<tr${r.usuario === resaltar ? ' style="font-weight:700"' : ''}>
      <td>${esc(r.usuario)}</td><td><code>${esc(recortar(r.salt, 8))}</code></td><td><code>${esc(recortar(r.hash, 12))}</code></td><td>${esc(r.grupo)}</td><td>${r.mfa ? 'sí' : 'no'}</td></tr>`).join('');
    return `<table><tr><th>usuario</th><th>salt</th><th>hash</th><th>grupo</th><th>2FA</th></tr>${filas}</table>`;
  }

  function chequeos(lista) {
    return `<ul class="chequeos">${lista.map(([ok, texto]) => `<li data-ok="${ok}"><span class="marca">${ok ? '✓' : '✗'}</span><span>${texto}</span></li>`).join('')}</ul>`;
  }

  function hexdump(bytes) {
    const p = Radius.leer(bytes);
    const clase = new Array(bytes.length).fill('');
    clase[0] = 'hx-code';
    clase[1] = 'hx-id';
    clase[2] = clase[3] = 'hx-len';
    for (let k = 4; k < 20; k++) clase[k] = 'hx-auth';
    p.atributos.forEach((a, n) => {
      clase[a.offset] = clase[a.offset + 1] = 'hx-tl';
      for (let k = a.offset + 2; k < a.offset + a.length; k++) clase[k] = n % 2 ? 'hx-v2' : 'hx-v1';
    });
    let html = '';
    for (let fila = 0; fila < bytes.length; fila += 16) {
      html += `<span class="hx-off">${fila.toString(16).padStart(4, '0')}</span> `;
      for (let k = fila; k < Math.min(fila + 16, bytes.length); k++) html += `<span class="${clase[k]}">${bytes[k].toString(16).padStart(2, '0')}</span> `;
      html += '\n';
    }
    return `<strong class="tip-titulo">Bytes que viajan por el cable</strong><pre class="hexdump"><code>${html}</code></pre>
      <p class="leyenda-hex"><span><span style="color:var(--hx-code)">■</span> Code</span><span><span style="color:var(--hx-id)">■</span> Identifier</span><span><span style="color:var(--hx-len)">■</span> Length</span><span><span style="color:var(--hx-auth)">■</span> Authenticator</span><span><span style="color:var(--hx-tl)">■</span> Type y Length</span><span><span style="color:var(--hx-v1)">■</span> Value</span></p>`;
  }

  /* Paquete compacto: cabecera en una fila y los atributos TLV en una tabla.
     destacar: types que se resaltan. notas: {type: html} para su "i". */
  function paquete(bytes, { destacar = [], notas = {}, infoAutenticador = '' } = {}) {
    const p = Radius.leer(bytes);
    const filas = p.atributos.map((a) => `
      <tr class="${destacar.includes(a.type) ? 'destacado' : ''}">
        <td>${a.type}</td>
        <td>${esc(Radius.nombreAtributo(a.type))}${notas[a.type] ? i(notas[a.type]) : ''}</td>
        <td><code>${esc(Radius.valorLegible(a.type, a.value))}</code></td>
      </tr>`).join('');
    return `
      <div class="paquete" data-code="${p.code}">
        <div class="pq-titulo"><span>Paquete RADIUS de ${p.length} bytes</span>${i(hexdump(bytes))}</div>
        <div class="pq-regla" aria-hidden="true"><span>0</span><span>8</span><span>16</span><span>24<span>31</span></span></div>
        <div class="pq-fila">
          <div class="pq-campo hx-code"><small>Code</small><strong>${p.code} ${esc(Radius.CODIGOS[p.code])}</strong></div>
          <div class="pq-campo hx-id"><small>Identifier</small><strong>${p.id}</strong></div>
          <div class="pq-campo hx-len"><small>Length</small><strong>${p.length}</strong></div>
          <div class="pq-campo hx-auth"><small>Authenticator ${infoAutenticador ? i(infoAutenticador) : ''}</small><code>${hex(p.authenticator)}</code></div>
          <div class="pq-campo pq-completo">
            ${p.atributos.length ? `<table class="tabla-tlv"><tbody>${filas}</tbody></table>` : '<span class="pq-vacio">Sin atributos: solo confirma</span>'}
          </div>
        </div>
      </div>`;
  }

  /* ================= Diagrama de arquitectura ================= */

  function red(enlace, direccion, texto, tipo = 'normal') {
    document.querySelector('.arquitectura').dataset.tipo = tipo;
    document.querySelectorAll('.enlace').forEach((e) => {
      const activo = Number(e.dataset.enlace) === enlace;
      e.classList.remove('activo');
      if (activo) void e.offsetWidth; // vuelve a correr el paquete por el cable
      e.classList.toggle('activo', activo);
      e.dataset.dir = activo ? direccion : '';
      e.dataset.tipo = activo ? tipo : '';
      e.querySelector('.enlace-msg').textContent = activo ? texto : '';
    });
    const nodos = [['cliente', 'nas'], ['nas', 'servidor'], ['servidor', 'bd']][enlace] || [];
    document.querySelectorAll('.nodo').forEach((n) => n.classList.toggle('activo', nodos.includes(n.dataset.nodo)));
  }

  function nodoSolo(nodo) {
    red(-1);
    document.querySelectorAll('.nodo').forEach((n) => n.classList.toggle('activo', n.dataset.nodo === nodo));
  }

  /* ================= Secuencia ================= */

  function pintarCapas() {
    el.capas.innerHTML = CAPAS.map((c, n) => `
      <li class="capa" data-capa="${c.id}" data-estado="pendiente">
        <span class="capa-num">${n + 1}</span>
        <span class="capa-texto"><strong>${c.nombre}<button type="button" class="info" data-info="capa-${c.id}" aria-label="Qué pasa en este paso">i</button></strong><span>${c.resumen}</span></span>
        <span class="capa-estado" aria-label="Pendiente"></span>
      </li>`).join('');
  }

  function fijarCapa(id, est) {
    const li = el.capas.querySelector(`[data-capa="${id}"]`);
    li.dataset.estado = est;
    const marca = li.querySelector('.capa-estado');
    marca.textContent = MARCAS[est];
    marca.setAttribute('aria-label', ESTADOS[est]);
  }

  function enfocarCapa(id) {
    el.capas.querySelectorAll('.capa').forEach((li) => li.classList.toggle('actual', li.dataset.capa === id));
  }

  function reiniciarCapas() {
    CAPAS.forEach((c) => fijarCapa(c.id, 'pendiente'));
    enfocarCapa(null);
  }

  function capasNoAplican(...ids) {
    ids.forEach((c) => fijarCapa(c, 'na'));
  }

  function limpiarInfos() {
    ocultarTip();
  }

  /* Borra el contenido de las "i" que ya no están en pantalla */
  function podarInfos() {
    const vivos = new Set([...document.querySelectorAll('.info[data-info]')].map((b) => b.dataset.info));
    // Las "i" de los pasos guardados siguen vivas para poder volver a verlos
    Object.values(estado.historial).flat().forEach((v) => {
      for (const m of v.html.matchAll(/data-info="(dd+)"/g)) vivos.add(m[1]);
    });
    for (const clave of dinamicos.keys()) if (!vivos.has(clave)) dinamicos.delete(clave);
  }

  /* titulo y texto son HTML escrito aquí; todo dato del usuario se pasa por esc().
     detalle: HTML que va en la "i" junto al título. cuerpo: lo que se ve debajo. */
  function mostrar(id, est, { titulo, texto, detalle = '', cuerpo = '' }) {
    limpiarInfos();
    fijarCapa(id, est);
    enfocarCapa(id);
    const n = CAPAS.findIndex((c) => c.id === id);
    el.inspector.innerHTML = `
      <div class="insp-cabecera">
        <span class="insp-capa">Paso ${n + 1} de ${CAPAS.length}: ${CAPAS[n].nombre}</span>
        <span class="insignia" data-estado="${est}">${ESTADOS[est]}</span>
      </div>
      <h3>${titulo}${detalle ? i(detalle) : ''}</h3>
      <p class="insp-texto">${texto}</p>
      ${cuerpo}`;
    guardarVista(id);
    podarInfos();
  }

  /* ================= Repasar los pasos al terminar ================= */

  function guardarVista(id) {
    (estado.historial[id] ||= []).push({
      html: el.inspector.innerHTML,
      arq: el.arquitectura.innerHTML,
      tipo: el.arquitectura.dataset.tipo || '',
    });
  }

  function verVista(id) {
    const vistas = estado.historial[id];
    if (estado.corriendo || !vistas) return;
    const n = estado.vista.id === id ? (estado.vista.n + 1) % vistas.length : 0;
    estado.vista = { id, n };
    const v = vistas[n];
    ocultarTip();
    el.inspector.innerHTML = v.html;
    el.arquitectura.innerHTML = v.arq;
    el.arquitectura.dataset.tipo = v.tipo;
    if (vistas.length > 1) {
      const capa = el.inspector.querySelector('.insp-capa');
      if (capa) capa.textContent += `, parte ${n + 1} de ${vistas.length}`;
    }
    enfocarCapa(id);
  }

  function permitirRepaso(si) {
    el.capas.classList.toggle('navegable', si);
    el.capas.querySelectorAll('.capa').forEach((li) => {
      const tiene = si && Boolean(estado.historial[li.dataset.capa]);
      li.toggleAttribute('data-vista', tiene);
      if (tiene) { li.tabIndex = 0; li.setAttribute('role', 'button'); } else { li.removeAttribute('tabindex'); li.removeAttribute('role'); }
    });
    el.pistaCapas.hidden = !si || !Object.keys(estado.historial).length;
  }

  function mostrarIntro() {
    limpiarInfos();
    red(-1);
    enfocarCapa(null);
    el.inspector.innerHTML = `
      <h3>¿Qué es un servidor AAA?</h3>
      <p class="insp-texto">Un servicio centralizado que decide <strong>quién entra a la red</strong>, <strong>qué puede hacer</strong> y <strong>deja registro de lo que hizo</strong>.</p>
      <div class="tres-a">
        <div><b>A</b><strong>Autenticación</strong><span>¿Quién eres?</span></div>
        <div><b>A</b><strong>Autorización</strong><span>¿Qué puedes hacer?</span></div>
        <div><b>A</b><strong>Contabilidad</strong><span>¿Qué hiciste?</span></div>
      </div>
      <p class="insp-texto">Escribe un usuario y una contraseña y presiona <strong>Conectarse</strong> para ver la secuencia paso a paso. Pasa el mouse sobre cualquier <span class="info" aria-hidden="true">i</span> para ver más detalle.</p>`;
  }

  /* ================= Control del flujo (paso a paso / automático) ================= */

  function vigente(id) {
    if (id !== estado.flujo) throw new FlujoCancelado();
  }

  async function avanzar(id) {
    vigente(id);
    await new Promise((resolver) => {
      estado.resolverPaso = resolver;
      estado.temporizador = setTimeout(resolver, ESPERA_AUTO_MS);
    });
    clearTimeout(estado.temporizador);
    estado.resolverPaso = null;
    vigente(id);
  }

  function pasoSiguiente() {
    if (estado.resolverPaso) estado.resolverPaso();
  }

  function bloquearUI(bloquear) {
    const sinListo = bloquear || !estado.listo;
    [el.usuario, el.contrasena, el.entrar].forEach((c) => { c.disabled = sinListo; });
    [el.interim, el.salir].forEach((c) => { c.disabled = bloquear; });
  }

  function cancelarFlujo() {
    estado.flujo += 1;
    clearTimeout(estado.temporizador);
    if (estado.resolverPaso) estado.resolverPaso();
    if (estado.resolverMfa) estado.resolverMfa(null);
    estado.resolverPaso = null;
    estado.resolverMfa = null;
    ocultarMfa();
  }

  function iniciarFlujo() {
    cancelarFlujo();
    estado.corriendo = true;
    estado.historial = {};
    estado.vista = { id: null, n: 0 };
    permitirRepaso(false);
    bloquearUI(true);
    reiniciarCapas();
    return estado.flujo;
  }

  function terminarFlujo(id) {
    if (id !== estado.flujo) return;
    estado.corriendo = false;
    permitirRepaso(true);
    bloquearUI(false);
  }

  /* ================= Interfaz del cliente ================= */

  function avisar(texto, tipo) {
    el.mensaje.textContent = texto;
    el.mensaje.dataset.tipo = tipo || '';
  }

  /* Últimos paquetes que pasaron por la red */
  function registrar(code, nombre, ruta) {
    const tipo = { 1: 'peticion', 2: 'ok', 5: 'ok', 3: 'error', 11: 'espera', 4: 'acct', x: 'error' }[code] || 'nada';
    const li = document.createElement('li');
    li.innerHTML = `<span class="b-codigo" data-tipo="${tipo}">${code === 'x' ? '✗' : esc(code)}</span>
      <span class="b-texto">${esc(nombre)} <small>${esc(ruta)}</small></span>`;
    el.bitacora.prepend(li);
    while (el.bitacora.children.length > MAX_LOG) el.bitacora.lastElementChild.remove();
  }

  function registrarPaquete(bytes, ruta) {
    const p = Radius.leer(bytes);
    registrar(p.code, Radius.CODIGOS[p.code], ruta);
  }

  function mostrarMfa(codigo, segundos) {
    el.codigoTelefono.textContent = codigo;
    el.codigoMfa.value = '';
    el.tarjetaLogin.hidden = true;
    el.tarjetaMfa.hidden = false;
    let restantes = segundos;
    const pintar = () => { el.venceTelefono.textContent = restantes > 0 ? `Vence en ${restantes} s` : 'Código vencido'; };
    pintar();
    clearInterval(estado.relojMfa);
    estado.relojMfa = setInterval(() => {
      restantes -= 1;
      pintar();
      if (restantes <= 0) clearInterval(estado.relojMfa);
    }, 1000);
    el.codigoMfa.focus();
  }

  function ocultarMfa() {
    clearInterval(estado.relojMfa);
    el.tarjetaMfa.hidden = true;
    if (!estado.sesion) el.tarjetaLogin.hidden = false;
  }

  function esperarCodigoMfa() {
    return new Promise((resolver) => { estado.resolverMfa = resolver; });
  }

  /* ================= Sesión del usuario en la red ================= */

  function abrirSesion(registro, ip) {
    const a = registro.autorizacion;
    estado.sesion = {
      usuario: registro.usuario,
      ip,
      sesionId: hex(Cripto.aleatorios(4)).toUpperCase(),
      inicio: Date.now(),
      entrada: 0,
      salida: 0,
      reloj: null,
    };
    el.nombreSesion.textContent = registro.usuario;
    el.grupoSesion.textContent = registro.grupo;
    el.vlanSesion.textContent = String(a.vlan);
    el.ipSesion.textContent = ip;
    el.aclSesion.textContent = a.acl;
    el.tarjetaLogin.hidden = true;
    el.tarjetaSesion.hidden = false;
    el.contrasena.value = '';
    avisar('');
    pintarContadores();
    estado.sesion.reloj = setInterval(() => {
      const s = estado.sesion;
      if (!s) return;
      s.entrada += 2000 + Math.floor(Math.random() * 60000);
      s.salida += 10000 + Math.floor(Math.random() * 400000);
      pintarContadores();
    }, 1000);
  }

  function segundosSesion() {
    return estado.sesion ? Math.floor((Date.now() - estado.sesion.inicio) / 1000) : 0;
  }

  function pintarContadores() {
    if (!estado.sesion) return;
    el.tiempoSesion.textContent = duracion(segundosSesion());
    el.datosSesion.textContent = `↑ ${bytesLegibles(estado.sesion.entrada)} ↓ ${bytesLegibles(estado.sesion.salida)}`;
  }

  function cerrarSesion() {
    if (estado.sesion) clearInterval(estado.sesion.reloj);
    estado.sesion = null;
    el.tarjetaSesion.hidden = true;
    el.tarjetaLogin.hidden = false;
  }

  /* ================= Flujo 1: autenticación y autorización ================= */

  function secretos() {
    const delServidor = Servidor.cliente(NAS.ip).secreto;
    return { nas: delServidor, servidor: delServidor };
  }

  /* El NAS arma un Access-Request con las credenciales */
  function armarAccessRequest(usuario, clave, secreto, extra = []) {
    const { atr, v } = Radius;
    const ra = Cripto.aleatorios(16);
    const id = siguienteId();
    const oculto = Radius.ocultarClave(clave, secreto, ra);
    const bytes = Radius.peticion(1, id, ra, [
      atr(1, v.texto(usuario)),
      atr(2, oculto.cifrado),
      atr(4, v.ip(NAS.ip)),
      atr(5, v.entero(NAS.puerto)),
      atr(61, v.entero(19)),
      atr(31, v.texto(MAC_CLIENTE)),
      ...extra,
    ], secreto);
    return { bytes, ra, id, oculto };
  }

  /* El servidor recibe: comprueba el Message-Authenticator y descifra User-Password */
  function recibirEnServidor(bytes, secreto) {
    const p = Radius.leer(bytes);
    const ma = Radius.verificarMA(bytes, secreto);
    const clave = Radius.revelarClave(Radius.buscar(p, 2), secreto, p.authenticator);
    return { p, cli: Servidor.cliente(NAS.ip), ma, clave, usuario: Cripto.aTexto(Radius.buscar(p, 1)) };
  }

  const NOTA_MA = '<strong class="tip-titulo">Message-Authenticator (80)</strong><p>Firma de todo el paquete: HMAC-MD5 con el secreto compartido. Si alguien cambia un byte, o el NAS no conoce el secreto, la firma no cuadra.</p>';

  async function rechazar(id, peticion, sec, motivo) {
    if (el.capas.querySelector('[data-capa="challenge"]').dataset.estado === 'pendiente') capasNoAplican('challenge');
    const bytes = Radius.respuesta(3, peticion.id, peticion.ra, [Radius.atr(18, Radius.v.texto('Usuario o contraseña incorrectos'))], sec.servidor);
    red(1, 'izq', 'Access-Reject (3)', 'error');
    mostrar('decision', 'error', {
      titulo: 'Access-Reject (3)',
      texto: `${motivo} El servidor responde <strong>Access-Reject</strong>.`,
      detalle: '<p>El mensaje es genérico a propósito: si dijera "ese usuario no existe", un atacante podría averiguar qué cuentas son reales.</p>',
      cuerpo: paquete(bytes, { destacar: [18] }),
    });
    registrarPaquete(bytes, 'Servidor → NAS');
    await avanzar(id);

    red(0, 'izq', 'Acceso denegado', 'error');
    mostrar('aplicar', 'error', {
      titulo: 'El NAS niega el acceso',
      texto: 'El puerto sigue cerrado: sin VLAN y sin IP. Como no hubo sesión, <strong>no hay contabilidad</strong>.',
    });
    capasNoAplican('acct');
    registrar('x', 'Acceso denegado', 'NAS → Cliente');
    avisar('Acceso denegado.', 'error');
  }

  async function flujoConexion(usuario, contrasena) {
    const id = iniciarFlujo();
    avisar('Conectando...', '');
    try {
      /* ---- Paso 1: Cliente → NAS ---- */
      if (!usuario || !contrasena) {
        nodoSolo('cliente');
        mostrar('solicitud', 'error', { titulo: 'Faltan credenciales', texto: 'Escribe el usuario y la contraseña.' });
        avisar('Faltan el usuario o la contraseña.', 'error');
        return;
      }

      const sec = secretos();
      red(0, 'der', 'Solicitud de acceso');
      mostrar('solicitud', 'ok', {
        titulo: 'El cliente pide entrar a la red',
        texto: `El portátil se conecta al Wi-Fi <code>${NAS.ssid}</code> y le entrega sus credenciales al NAS, que todavía mantiene el puerto cerrado.`,
        detalle: '<p>En 802.1X real las credenciales van dentro de un túnel EAP cifrado (PEAP o EAP-TTLS). Aquí se simplifica como PAP para que se vea cómo RADIUS oculta la contraseña.</p>',
        cuerpo: `<div class="dato-grande">Usuario <strong>${esc(usuario)}</strong></div>`,
      });
      registrar('—', 'Solicitud de acceso', 'Cliente → NAS');
      await avanzar(id);

      /* ---- Paso 2: NAS → Servidor, Access-Request ---- */
      const req = armarAccessRequest(usuario, contrasena, sec.nas);
      const b = req.oculto.pasos[0];
      red(1, 'der', 'Access-Request (1)');
      mostrar('request', 'ok', {
        titulo: 'Access-Request (1)',
        texto: 'El NAS empaqueta las credenciales y las envía al servidor por <strong>UDP 1812</strong>. El usuario va en claro; <strong>solo la contraseña va cifrada</strong>.',
        detalle: '<p>Cualquiera que capture este paquete (por ejemplo con Wireshark) ve el usuario, la IP del NAS y la MAC. Esa es la diferencia con TACACS+, que cifra todo el cuerpo.</p>',
        cuerpo: paquete(req.bytes, {
          destacar: [1, 2],
          notas: {
            2: `<strong class="tip-titulo">Cómo se oculta User-Password (RFC 2865)</strong><pre><code>b1 = MD5(secreto + Request Authenticator)\nc1 = contraseña XOR b1\n\ncontraseña ${hexEsp(b.p)}\nb1         ${hexEsp(b.b)}\nc1 viaja   ${hexEsp(b.c)}</code></pre>`,
            80: NOTA_MA,
          },
          infoAutenticador: '<strong class="tip-titulo">Request Authenticator</strong><p>16 bytes aleatorios que elige el NAS. Se usan para ocultar la contraseña y para validar la respuesta.</p>',
        }),
      });
      registrarPaquete(req.bytes, 'NAS → Servidor');
      await avanzar(id);

      /* ---- Paso 3: Servidor AAA recibe ---- */
      const rec = recibirEnServidor(req.bytes, sec.servidor);
      nodoSolo('servidor');
      const revisiones = [
        [Boolean(rec.cli), `Viene de un NAS registrado (${NAS.ip})`],
        [rec.ma.valido, 'La firma del paquete cuadra con el secreto compartido'],
      ];

      if (!rec.ma.valido) {
        mostrar('servidor', 'error', {
          titulo: 'Paquete descartado en silencio',
          texto: 'El NAS no conoce el secreto correcto. El servidor <strong>no responde nada</strong>, ni siquiera un Reject, y el NAS se rinde por tiempo de espera.',
          detalle: `<strong class="tip-titulo">Message-Authenticator</strong><pre><code>calculado ${hex(rec.ma.esperado)}\nrecibido  ${hex(rec.ma.recibido)}</code></pre><p>Con el secreto equivocado, la contraseña descifrada sale como basura:</p><pre><code>${hexEsp(rec.clave.bytes.slice(0, 16))}</code></pre>`,
          cuerpo: chequeos(revisiones),
        });
        registrar('x', 'Descartado', 'sin respuesta');
        capasNoAplican('base', 'challenge', 'decision', 'aplicar', 'acct');
        avisar('El servidor no responde.', 'error');
        return;
      }

      mostrar('servidor', 'ok', {
        titulo: 'El servidor valida el paquete',
        texto: 'Revisa que venga de un NAS conocido y que esté firmado con el secreto compartido. Luego <strong>descifra la contraseña</strong> con ese mismo secreto.',
        detalle: '<p>El secreto compartido <strong>nunca viaja por la red</strong>: un administrador lo configura a mano en el NAS y en el servidor.</p>',
        cuerpo: chequeos([...revisiones, [true, `Contraseña descifrada (${rec.clave.texto.length} caracteres)`]]),
      });
      await avanzar(id);

      /* ---- Paso 4: Base de usuarios ---- */
      red(2, 'der', `¿existe "${rec.usuario}"?`);
      const registro = Servidor.buscarUsuario(rec.usuario);
      if (!registro) {
        mostrar('base', 'error', {
          titulo: 'El usuario no existe',
          texto: `No hay ninguna cuenta <code>${esc(rec.usuario)}</code> en la base de usuarios.`,
          detalle: tablaUsuarios(null),
          cuerpo: chequeos([[false, 'El usuario existe']]),
        });
        await avanzar(id);
        await rechazar(id, req, sec, 'La autenticación falló.');
        return;
      }

      const v = await Servidor.verificarContrasena(registro, rec.clave.texto);
      vigente(id);
      const detalleHash = `<strong class="tip-titulo">Comparación de hashes (PBKDF2-SHA256, ${v.iteraciones.toLocaleString('es-CO')} iteraciones)</strong><pre><code>guardado  ${v.guardado}\ncalculado ${v.calculado}</code></pre><p>La base nunca guarda la contraseña, solo el salt y el hash.</p>${tablaUsuarios(registro.usuario)}`;
      if (!v.coincide) {
        red(2, 'izq', 'no coincide', 'error');
        mostrar('base', 'error', {
          titulo: 'La contraseña no coincide',
          texto: 'El hash de la contraseña recibida no es igual al guardado.',
          detalle: detalleHash,
          cuerpo: chequeos([[true, 'El usuario existe'], [false, 'El hash de la contraseña coincide']]),
        });
        await avanzar(id);
        await rechazar(id, req, sec, 'La autenticación falló.');
        return;
      }
      red(2, 'izq', 'coincide', 'ok');
      mostrar('base', 'ok', {
        titulo: 'Autenticación correcta',
        texto: `<code>${esc(registro.usuario)}</code> existe y su contraseña es correcta. <strong>Ya sabemos quién es.</strong>`,
        detalle: detalleHash,
        cuerpo: chequeos([[true, 'El usuario existe'], [true, 'El hash de la contraseña coincide']]),
      });
      await avanzar(id);

      /* ---- Paso 5: Access-Challenge (opcional) ---- */
      let ultima = req;
      if (registro.mfa) {
        const des = Servidor.crearDesafio(registro.usuario);
        const chal = Radius.respuesta(11, req.id, req.ra, [
          Radius.atr(18, Radius.v.texto('Ingrese el código enviado a su teléfono')),
          Radius.atr(24, des.state),
        ], sec.servidor);
        red(1, 'izq', 'Access-Challenge (11)', 'espera');
        mostrar('challenge', 'espera', {
          titulo: 'Access-Challenge (11)',
          texto: `<code>${esc(registro.usuario)}</code> tiene segundo factor. El servidor pide un código. <strong>Escríbelo a la izquierda para seguir.</strong>`,
          cuerpo: paquete(chal, {
            destacar: [18, 24],
            notas: { 24: '<strong class="tip-titulo">State (24)</strong><p>Identifica esta conversación. El NAS debe devolverlo tal cual junto con el código.</p>' },
          }),
        });
        registrarPaquete(chal, 'Servidor → NAS');
        mostrarMfa(des.codigo, des.segundos);
        avisar('');
        const ingresado = await esperarCodigoMfa();
        vigente(id);
        ocultarMfa();

        const req2 = armarAccessRequest(registro.usuario, ingresado || '', sec.nas, [Radius.atr(24, des.state)]);
        registrarPaquete(req2.bytes, 'NAS → Servidor');
        const rec2 = recibirEnServidor(req2.bytes, sec.servidor);
        const r = Servidor.verificarDesafio(Radius.buscar(rec2.p, 24), rec2.usuario, rec2.clave.texto);
        ultima = req2;
        red(1, 'der', 'Access-Request (1)');
        const detalleReq2 = `<strong class="tip-titulo">Segundo Access-Request</strong><p>El código va en User-Password y el State se devuelve igual.</p>${paquete(req2.bytes)}`;
        if (!r.valido) {
          mostrar('challenge', 'error', {
            titulo: 'El segundo factor falló',
            texto: `${esc(r.motivo)} Sin el segundo factor no se entra.`,
            detalle: detalleReq2,
            cuerpo: chequeos([[true, 'Contraseña correcta'], [false, 'Código del teléfono']]),
          });
          await avanzar(id);
          await rechazar(id, req2, sec, 'El código no es válido.');
          return;
        }
        mostrar('challenge', 'ok', {
          titulo: 'Segundo factor verificado',
          texto: 'El NAS reenvió el código con el mismo State y el servidor lo validó. Dos pruebas: <strong>algo que sabe</strong> y <strong>algo que tiene</strong>.',
          detalle: detalleReq2,
          cuerpo: chequeos([[true, 'Contraseña correcta'], [true, 'Código del teléfono']]),
        });
      } else {
        nodoSolo('servidor');
        mostrar('challenge', 'omitida', {
          titulo: 'Sin Access-Challenge',
          texto: 'Este paso es <strong>opcional</strong>. Esta cuenta no tiene segundo factor; prueba con <code>admin</code> para verlo.',
        });
      }
      await avanzar(id);

      /* ---- Paso 6: Access-Accept con atributos de autorización ---- */
      const a = registro.autorizacion;
      const accept = Radius.respuesta(2, ultima.id, ultima.ra, Servidor.atributosAutorizacion(registro), sec.servidor);
      const autNas = Radius.verificarAutenticador(accept, ultima.ra, sec.nas);
      red(1, 'izq', 'Access-Accept (2)', 'ok');
      mostrar('decision', 'ok', {
        titulo: 'Access-Accept (2)',
        texto: `El servidor acepta y en la misma respuesta manda <strong>los permisos</strong>: VLAN ${a.vlan} y la ACL <code>${esc(a.acl)}</code>.`,
        detalle: `<strong class="tip-titulo">El NAS comprueba la respuesta</strong><p>Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Atributos + secreto)</p>${chequeos([[Radius.leer(accept).id === ultima.id, `El Identifier (${ultima.id}) es el de su petición`], [autNas.valido, 'La respuesta viene del servidor de verdad']])}`,
        cuerpo: paquete(accept, {
          destacar: [81, 11, 26],
          notas: {
            64: '<p>Tunnel-Type = VLAN y Tunnel-Medium-Type = 802: le dicen al NAS que va a asignar una VLAN.</p>',
            81: `<p>Número de la VLAN donde queda el usuario: <strong>${a.vlan}</strong>.</p>`,
            11: `<p>Nombre de la ACL que el NAS aplica al puerto:</p><pre><code>${ACLS[a.acl].join('\n')}</code></pre>`,
            27: '<p>Tiempo máximo de la sesión en segundos.</p>',
            26: '<p>Atributo del fabricante (Cisco): nivel de privilegio 15, el máximo.</p>',
          },
        }),
      });
      registrarPaquete(accept, 'Servidor → NAS');
      await avanzar(id);

      /* ---- Paso 7: NAS → Cliente ---- */
      const ip = `10.${a.vlan}.0.${40 + Math.floor(Math.random() * 150)}`;
      red(0, 'izq', `Acceso concedido, VLAN ${a.vlan}`, 'ok');
      mostrar('aplicar', 'ok', {
        titulo: 'El NAS aplica la autorización',
        texto: `Abre el puerto, mete al portátil en la <strong>VLAN ${a.vlan}</strong> y le aplica la ACL. El servidor decidió; <strong>el NAS hace cumplir</strong>.`,
        detalle: `<pre><code>${json({ puerto: NAS.puerto, mac: MAC_CLIENTE, usuario: registro.usuario, vlan: a.vlan, acl: a.acl, ip })}</code></pre><pre><code>${ACLS[a.acl].join('\n')}</code></pre>`,
        cuerpo: `<div class="dato-grande"><span>VLAN <strong>${a.vlan}</strong></span><span>IP <strong>${ip}</strong></span><span>ACL <strong>${esc(a.acl)}</strong></span></div>`,
      });
      registrar('—', `Acceso concedido, VLAN ${a.vlan}`, 'NAS → Cliente');
      abrirSesion(registro, ip);
      await avanzar(id);

      /* ---- Paso 8: Contabilidad Start ---- */
      await pasoContabilidad(id, 'Start');
    } catch (e) {
      if (e instanceof FlujoCancelado) return;
      console.error(e);
      avisar('Ocurrió un error inesperado. Revisa la consola.', 'error');
    } finally {
      terminarFlujo(id);
    }
  }

  /* ================= Flujo 2: contabilidad ================= */

  const TIPO_ACCT = { Start: 1, Stop: 2, 'Interim-Update': 3 };

  async function pasoContabilidad(id, tipo) {
    const s = estado.sesion;
    const sec = secretos().servidor;
    const { atr, v } = Radius;
    const segundos = segundosSesion();
    const lista = [
      atr(40, v.entero(TIPO_ACCT[tipo])),
      atr(44, v.texto(s.sesionId)),
      atr(1, v.texto(s.usuario)),
      atr(4, v.ip(NAS.ip)),
      atr(8, v.ip(s.ip)),
    ];
    if (tipo !== 'Start') lista.push(atr(46, v.entero(segundos)), atr(42, v.entero(s.entrada)), atr(43, v.entero(s.salida)));
    if (tipo === 'Stop') lista.push(atr(49, v.entero(1)));

    const idPkt = siguienteId();
    const peticion = Radius.contabilidad(4, idPkt, lista, sec);
    const textos = {
      Start: 'El usuario quedó conectado y el NAS avisa que <strong>empezó la sesión</strong>. Va por otro puerto: <strong>UDP 1813</strong>.',
      'Interim-Update': 'Reporte periódico con el <strong>tiempo y los bytes</strong> consumidos hasta ahora.',
      Stop: 'El usuario se desconectó. El NAS cierra el puerto y reporta el <strong>total consumido</strong>.',
    };
    red(1, 'der', `Accounting-Request (4) ${tipo}`, 'acct');
    mostrar('acct', 'espera', {
      titulo: `Accounting-Request (4) ${tipo}`,
      texto: textos[tipo],
      detalle: '<p>En contabilidad no hay contraseña. El autenticador es MD5(paquete con 16 ceros + secreto): prueba que el reporte lo mandó un NAS que conoce el secreto.</p>',
      cuerpo: paquete(peticion, { destacar: [40, 46, 42, 43] }),
    });
    registrarPaquete(peticion, `NAS → Servidor, ${tipo}`);
    await avanzar(id);

    const ver = Radius.verificarAutenticador(peticion, new Uint8Array(16), sec);
    const fila = Servidor.registrarContabilidad({ tipo, sesionId: s.sesionId, usuario: s.usuario, nas: NAS.nombre, ip: s.ip, segundos, entrada: s.entrada, salida: s.salida });
    const respuesta = Radius.contabilidad(5, idPkt, [], sec, peticion.slice(4, 20));
    red(1, 'izq', 'Accounting-Response (5)', 'ok');
    mostrar('acct', 'ok', {
      titulo: 'Accounting-Response (5)',
      texto: `El servidor guarda el registro y lo confirma. ${tipo === 'Stop' ? 'La sesión queda cerrada.' : 'Así se sabe quién se conectó, cuánto tiempo y cuánto consumió.'}`,
      detalle: `${chequeos([[ver.valido, 'El autenticador del reporte cuadra con el secreto']])}${paquete(respuesta)}`,
      cuerpo: `<div class="dato-grande"><span>Sesión <strong>${esc(fila.sesionId)}</strong></span><span>${esc(fila.usuario)}</span><span>${duracion(fila.segundos)}</span><span>↑ ${bytesLegibles(fila.entrada)} ↓ ${bytesLegibles(fila.salida)}</span><span><strong>${fila.estado}</strong></span></div>`,
    });
    registrarPaquete(respuesta, 'Servidor → NAS');
  }

  async function flujoContabilidad(tipo) {
    if (!estado.sesion) return;
    const id = iniciarFlujo();
    try {
      capasNoAplican('solicitud', 'request', 'servidor', 'base', 'challenge', 'decision', 'aplicar');
      if (tipo === 'Stop') {
        clearInterval(estado.sesion.reloj);
        registrar('—', 'Desconexión', 'Cliente → NAS');
      }
      await pasoContabilidad(id, tipo);
      if (tipo === 'Stop') {
        cerrarSesion();
        avisar('Te desconectaste de la red.', 'ok');
      }
    } catch (e) {
      if (e instanceof FlujoCancelado) return;
      console.error(e);
    } finally {
      terminarFlujo(id);
    }
  }

  /* ================= Eventos ================= */

  function enlazarEventos() {
    el.formLogin.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!estado.listo) return;
      flujoConexion(el.usuario.value.trim(), el.contrasena.value);
    });

    // Al terminar, clic (o Enter) en un paso lo vuelve a mostrar
    el.capas.addEventListener('click', (e) => {
      if (e.target.closest('.info')) return;
      const li = e.target.closest('.capa[data-vista]');
      if (li) verVista(li.dataset.capa);
    });
    el.capas.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const li = e.target.closest('.capa[data-vista]');
      if (li && e.target === li) { e.preventDefault(); verVista(li.dataset.capa); }
    });

    el.formMfa.addEventListener('submit', (e) => {
      e.preventDefault();
      if (estado.resolverMfa) {
        const resolver = estado.resolverMfa;
        estado.resolverMfa = null;
        resolver(el.codigoMfa.value);
      }
    });

    el.verClave.addEventListener('click', () => {
      const oculto = el.contrasena.type === 'password';
      el.contrasena.type = oculto ? 'text' : 'password';
      el.verClave.textContent = oculto ? 'Ocultar' : 'Ver';
      el.verClave.setAttribute('aria-label', oculto ? 'Ocultar contraseña' : 'Mostrar contraseña');
    });

    document.querySelectorAll('[data-usuario]').forEach((boton) => {
      boton.addEventListener('click', () => {
        if (el.usuario.disabled) return;
        el.usuario.value = boton.dataset.usuario;
        el.contrasena.value = boton.dataset.clave;
        el.entrar.focus();
      });
    });

    // Globos de información: aparecen al pasar el mouse o al enfocar con el teclado
    const buscarInfo = (e) => e.target.closest && e.target.closest('.info[data-info]');
    document.addEventListener('mouseover', (e) => { const b = buscarInfo(e); if (b) mostrarTip(b); });
    document.addEventListener('mouseout', (e) => { if (buscarInfo(e)) ocultarTip(); });
    document.addEventListener('focusin', (e) => { const b = buscarInfo(e); if (b) mostrarTip(b); });
    document.addEventListener('focusout', (e) => { if (buscarInfo(e)) ocultarTip(); });
    document.addEventListener('click', (e) => { if (buscarInfo(e)) e.preventDefault(); });
    window.addEventListener('resize', ocultarTip);

    el.interim.addEventListener('click', () => flujoContabilidad('Interim-Update'));
    el.salir.addEventListener('click', () => flujoContabilidad('Stop'));

    // Flecha derecha, Av Pág o el control de presentaciones adelantan el paso
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') ocultarTip();
      const etiqueta = (e.target.tagName || '').toLowerCase();
      if (etiqueta === 'input' || etiqueta === 'textarea') return;
      if ((e.key === 'ArrowRight' || e.key === 'PageDown') && estado.resolverPaso) {
        e.preventDefault();
        pasoSiguiente();
      }
    });
  }

  async function arrancar() {
    pintarCapas();
    enlazarEventos();
    el.inspector.innerHTML = '<h3>Preparando el servidor...</h3>';

    if (!Cripto.disponible()) {
      el.avisoCripto.hidden = false;
      el.entrar.textContent = 'No disponible';
      return;
    }
    try {
      await Servidor.iniciar();
    } catch (e) {
      console.error(e);
      el.avisoCripto.hidden = false;
      el.entrar.textContent = 'No disponible';
      return;
    }
    estado.listo = true;
    el.entrar.textContent = 'Conectarse';
    bloquearUI(false);
    mostrarIntro();
  }

  arrancar();
})();
