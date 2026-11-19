/*
 * app.js
 * Hace de cliente y de NAS, habla con el servidor AAA simulado y va mostrando
 * cada paso de la secuencia RADIUS en la columna central y en el inspector.
 */
(() => {
  'use strict';

  const ESPERA_AUTO_MS = 2800;

  /* El NAS de la demo: un punto de acceso Wi-Fi con 802.1X. */
  const NAS = {
    ip: '10.10.0.2',
    nombre: 'AP-Biblioteca',
    puerto: 7,
    ssid: 'USC-Campus',
    mac: 'A0-B1-C2-D3-E4-F5',
  };
  const MAC_CLIENTE = '3C-52-82-A1-7F-09';
  const SECRETO_EQUIVOCADO = 'secreto-viejo-2019';

  const ACLS = {
    'ACL-ESTUDIANTES': ['permit tcp any any eq 80, 443   (navegar)', 'permit udp any any eq 53         (DNS)', 'deny   ip any 10.99.0.0/16       (red de gestión)', 'permit ip any 10.20.0.0/16       (red de estudiantes)'],
    'ACL-GESTION': ['permit ip any any                 (acceso total)'],
  };

  const CAPAS = [
    { id: 'solicitud', nombre: 'Cliente → NAS', resumen: 'Solicitud de acceso con las credenciales' },
    { id: 'request', nombre: 'NAS → Servidor', resumen: 'Access-Request (1) por UDP 1812' },
    { id: 'servidor', nombre: 'Servidor AAA', resumen: 'Valida el NAS y descifra la contraseña' },
    { id: 'base', nombre: 'Base de usuarios', resumen: 'Autenticación: ¿quién eres?' },
    { id: 'challenge', nombre: 'Servidor → NAS', resumen: 'Access-Challenge (11), opcional' },
    { id: 'decision', nombre: 'Servidor → NAS', resumen: 'Access-Accept (2) / Reject (3)' },
    { id: 'aplicar', nombre: 'NAS → Cliente', resumen: 'Autorización: aplica VLAN y ACL o niega' },
    { id: 'acct', nombre: 'Contabilidad', resumen: 'Accounting-Request (4) / Response (5)' },
  ];

  const ESTADOS = {
    pendiente: 'Pendiente',
    ok: 'Superado',
    error: 'Rechazado',
    espera: 'Esperando',
    omitida: 'Omitido',
    na: 'No aplica',
  };

  const $ = (id) => document.getElementById(id);
  const el = {
    capas: $('listaCapas'),
    inspector: $('inspector'),
    siguiente: $('btnSiguiente'),
    reiniciar: $('btnReiniciar'),
    modoPaso: $('modoPaso'),
    modoAuto: $('modoAuto'),
    formLogin: $('formLogin'),
    usuario: $('usuario'),
    contrasena: $('contrasena'),
    verClave: $('verClave'),
    secretoMalo: $('secretoMalo'),
    entrar: $('btnEntrar'),
    mensaje: $('mensajeLogin'),
    tarjetaLogin: $('tarjetaLogin'),
    tarjetaMfa: $('tarjetaMfa'),
    textoDesafio: $('textoDesafio'),
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
    privSesion: $('privSesion'),
    tiempoSesion: $('tiempoSesion'),
    datosSesion: $('datosSesion'),
    interim: $('btnInterim'),
    salir: $('btnSalir'),
    tablaPruebas: $('tablaPruebas'),
    bitacora: $('bitacora'),
    bitacoraVacia: $('bitacoraVacia'),
    avisoCripto: $('avisoCripto'),
  };

  const estado = {
    listo: false,
    modo: 'paso',
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
  const hora = () => new Date().toLocaleTimeString('es-CO', { hour12: false });
  const recortar = (t, n = 14) => (t.length > n ? `${t.slice(0, n)}…` : t);
  const hex = (b) => Cripto.aHex(b);
  const hexEspaciado = (b) => Cripto.aHex(b, ' ');

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

  /* ================= Bloques del inspector ================= */

  const B = {
    codigo(etiqueta, contenido, clase = '') {
      return `<div class="bloque ${clase}"><div class="bloque-etiqueta">${esc(etiqueta)}</div><pre><code>${esc(contenido)}</code></pre></div>`;
    },
    html(etiqueta, html, clase = '') {
      return `<div class="bloque ${clase}"><div class="bloque-etiqueta">${esc(etiqueta)}</div>${html}</div>`;
    },
    nota(html, tipo = 'info') {
      return `<div class="nota nota-${tipo}">${html}</div>`;
    },
    comparar(referencia, calculado) {
      let html = '';
      for (let i = 0; i < calculado.length; i++) {
        html += `<span class="${calculado[i] === referencia[i] ? 'igual' : 'dif'}">${esc(calculado[i])}</span>`;
      }
      return `<pre><code>${html}</code></pre>`;
    },
    chequeos(lista) {
      return `<ul class="chequeos">${lista.map(([ok, texto]) => `<li data-ok="${ok}"><span class="marca">${ok ? '✓' : '✗'}</span><span>${texto}</span></li>`).join('')}</ul>`;
    },
    tabla(cabeceras, filas, resaltar = -1) {
      return `<div class="tabla-scroll"><table class="tabla-bd">
        <thead><tr>${cabeceras.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${filas.map((f, i) => `<tr class="${i === resaltar ? 'resaltada' : ''}">${f.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
      </table></div>`;
    },
    tablaUsuarios(resaltar) {
      const lista = Servidor.tablaUsuarios();
      return B.tabla(
        ['usuario', 'salt', 'hash_contrasena', 'grupo', '2FA', 'VLAN'],
        lista.map((r) => [esc(r.usuario), `<code>${esc(recortar(r.salt, 10))}</code>`, `<code>${esc(recortar(r.hash, 16))}</code>`, esc(r.grupo), r.mfa ? 'sí' : 'no', String(r.autorizacion.vlan)]),
        lista.findIndex((r) => r.usuario === resaltar)
      );
    },
    tablaContabilidad(resaltar) {
      const lista = Servidor.tablaContabilidad();
      return B.tabla(
        ['Acct-Session-Id', 'usuario', 'NAS', 'IP', 'último', 'duración', 'entrada', 'salida', 'estado'],
        lista.map((s) => [`<code>${esc(s.sesionId)}</code>`, esc(s.usuario), esc(s.nas), esc(s.ip), esc(s.ultimo), duracion(s.segundos), bytesLegibles(s.entrada), bytesLegibles(s.salida), esc(s.estado)]),
        lista.findIndex((s) => s.sesionId === resaltar)
      );
    },

    /* Dibuja el paquete como en la diapositiva: Code | Identifier | Length / Authenticator / Attributes */
    paquete(bytes, { ocultarValor = false } = {}) {
      const p = Radius.leer(bytes);
      const atributos = p.atributos.map((a) => `
        <tr>
          <td class="pq-num">${a.type}</td>
          <td class="pq-num">${a.length}</td>
          <td>${esc(Radius.nombreAtributo(a.type))}</td>
          <td><code>${esc(ocultarValor && a.type === 2 ? '••••' : Radius.valorLegible(a.type, a.value))}</code></td>
        </tr>`).join('');
      return `
        <div class="paquete">
          <div class="pq-bits"><span>0</span><span>8</span><span>16</span><span>31</span></div>
          <div class="pq-fila pq-cabecera">
            <div class="pq-campo hx-code"><small>Code</small><strong>${p.code} · ${esc(Radius.CODIGOS[p.code] || '?')}</strong></div>
            <div class="pq-campo hx-id"><small>Identifier</small><strong>${p.id}</strong></div>
            <div class="pq-campo pq-doble hx-len"><small>Length</small><strong>${p.length} bytes</strong></div>
          </div>
          <div class="pq-fila">
            <div class="pq-campo pq-completo hx-auth"><small>Authenticator (16 bytes)</small><code>${hexEspaciado(p.authenticator)}</code></div>
          </div>
          <div class="pq-fila">
            <div class="pq-campo pq-completo pq-atributos">
              <small>Attributes (lista de TLV: Type, Length, Value)</small>
              ${p.atributos.length ? `<table class="tabla-tlv">
                <thead><tr><th>Type</th><th>Len</th><th>Atributo</th><th>Value</th></tr></thead>
                <tbody>${atributos}</tbody>
              </table>` : '<em class="pq-vacio">Sin atributos</em>'}
            </div>
          </div>
        </div>`;
    },

    /* Volcado hexadecimal coloreado: lo que de verdad viaja por el cable */
    hex(bytes) {
      const p = Radius.leer(bytes);
      const clase = new Array(bytes.length).fill('');
      clase[0] = 'hx-code';
      clase[1] = 'hx-id';
      clase[2] = clase[3] = 'hx-len';
      for (let i = 4; i < 20; i++) clase[i] = 'hx-auth';
      p.atributos.forEach((a, k) => {
        clase[a.offset] = clase[a.offset + 1] = 'hx-tl';
        for (let i = a.offset + 2; i < a.offset + a.length; i++) clase[i] = k % 2 ? 'hx-v2' : 'hx-v1';
      });
      let html = '';
      for (let fila = 0; fila < bytes.length; fila += 16) {
        html += `<span class="hx-off">${fila.toString(16).padStart(4, '0')}</span>  `;
        for (let i = fila; i < Math.min(fila + 16, bytes.length); i++) {
          html += `<span class="${clase[i]}">${bytes[i].toString(16).padStart(2, '0')}</span> `;
        }
        html += '\n';
      }
      return `<pre class="hexdump"><code>${html}</code></pre>
        <p class="leyenda"><span class="hx-code">Code</span> · <span class="hx-id">Identifier</span> · <span class="hx-len">Length</span> · <span class="hx-auth">Authenticator</span> · <span class="hx-tl">Type y Length</span> · <span class="hx-v1">Value</span></p>`;
    },
  };

  /* ================= Diagrama de arquitectura ================= */

  function red(enlace, direccion, texto, tipo = 'normal') {
    document.querySelectorAll('.enlace').forEach((e) => {
      const activo = Number(e.dataset.enlace) === enlace;
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

  /* ================= Capas ================= */

  function pintarCapas() {
    el.capas.innerHTML = CAPAS.map((c, i) => `
      <li class="capa" data-capa="${c.id}" data-estado="pendiente">
        <span class="capa-num">${i + 1}</span>
        <span class="capa-texto"><strong>${c.nombre}</strong><span>${c.resumen}</span></span>
        <span class="capa-estado">${ESTADOS.pendiente}</span>
      </li>`).join('');
  }

  function fijarCapa(id, est) {
    const li = el.capas.querySelector(`[data-capa="${id}"]`);
    li.dataset.estado = est;
    li.querySelector('.capa-estado').textContent = ESTADOS[est];
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

  /* titulo y texto son HTML escrito aquí; todo dato del usuario se pasa por esc() */
  function mostrar(id, est, { titulo, texto, bloques = [] }) {
    fijarCapa(id, est);
    enfocarCapa(id);
    const i = CAPAS.findIndex((c) => c.id === id);
    el.inspector.innerHTML = `
      <div class="insp-cabecera">
        <span class="insp-capa">Paso ${i + 1} &middot; ${CAPAS[i].nombre}</span>
        <span class="insignia" data-estado="${est}">${ESTADOS[est]}</span>
      </div>
      <h3>${titulo}</h3>
      <p class="insp-texto">${texto}</p>
      ${bloques.join('')}`;
    el.inspector.scrollTop = 0;
  }

  function mostrarLibre(titulo, html) {
    enfocarCapa(null);
    el.inspector.innerHTML = `<h3>${titulo}</h3>${html}`;
  }

  function mostrarIntro() {
    red(-1);
    mostrarLibre('¿Qué es un servidor AAA?', `
      <p class="insp-texto">Un servicio centralizado que decide <strong>quién entra a la red</strong>, <strong>qué puede hacer</strong> y <strong>deja registro de lo que hizo</strong>.</p>
      <div class="tres-a">
        <div><b>A</b><strong>Autenticación</strong><span>¿Quién eres? Usuario y contraseña, certificado o token.</span></div>
        <div><b>A</b><strong>Autorización</strong><span>¿Qué puedes hacer? VLAN, ACL o nivel de privilegio.</span></div>
        <div><b>A</b><strong>Contabilidad</strong><span>¿Qué hiciste? Inicio, duración y consumo de la sesión.</span></div>
      </div>
      <p class="insp-texto">Escribe un usuario y una contraseña a la izquierda y presiona <strong>Conectarse</strong>. Arriba verás por dónde va cada paquete, en el centro el paso de la secuencia y aquí los bytes reales.</p>
      <ul class="lista">
        <li><strong>Paso a paso:</strong> avanzas con <em>Siguiente paso</em>, la flecha derecha o el control de presentaciones.</li>
        <li><strong>Automático:</strong> avanza solo cada ${(ESPERA_AUTO_MS / 1000).toLocaleString('es-CO')} segundos.</li>
      </ul>
      ${B.html('RADIUS frente a TACACS+', B.tabla(['', 'RADIUS', 'TACACS+'], [
        ['Transporte', 'UDP 1812 / 1813', 'TCP 49'],
        ['Cifrado', 'Solo la contraseña', 'Todo el cuerpo del paquete'],
        ['Uso típico', 'Acceso a red: 802.1X, Wi-Fi, VPN', 'Administración de equipos'],
        ['Estándar', 'IETF (RFC 2865)', 'Cisco'],
      ]))}
      ${B.html('Clientes RADIUS (NAS) registrados en el servidor', B.tabla(['IP', 'Nombre', 'Tipo', 'Secreto compartido'], [
        [NAS.ip, NAS.nombre, 'Punto de acceso Wi-Fi', `<code>${esc(Servidor.cliente(NAS.ip).secreto)}</code>`],
      ]))}
      ${B.html('Base de usuarios', B.tablaUsuarios(null))}
      ${B.nota('El servidor <strong>no guarda ninguna contraseña</strong>, solo un salt y un hash. Y el secreto compartido <strong>nunca viaja por la red</strong>: el NAS y el servidor lo configuran a mano y lo usan para ocultar la contraseña y firmar los paquetes.')}
    `);
  }

  /* ================= Control del flujo (paso a paso / automático) ================= */

  function vigente(id) {
    if (id !== estado.flujo) throw new FlujoCancelado();
  }

  async function avanzar(id) {
    vigente(id);
    el.siguiente.disabled = false;
    await new Promise((resolver) => {
      estado.resolverPaso = resolver;
      if (estado.modo === 'auto') estado.temporizador = setTimeout(resolver, ESPERA_AUTO_MS);
    });
    clearTimeout(estado.temporizador);
    estado.resolverPaso = null;
    el.siguiente.disabled = true;
    vigente(id);
  }

  function pasoSiguiente() {
    if (estado.resolverPaso) estado.resolverPaso();
  }

  function cambiarModo(modo) {
    estado.modo = modo;
    el.modoPaso.classList.toggle('activo', modo === 'paso');
    el.modoAuto.classList.toggle('activo', modo === 'auto');
    el.modoPaso.setAttribute('aria-pressed', String(modo === 'paso'));
    el.modoAuto.setAttribute('aria-pressed', String(modo === 'auto'));
    clearTimeout(estado.temporizador);
    if (modo === 'auto' && estado.resolverPaso) {
      estado.temporizador = setTimeout(estado.resolverPaso, ESPERA_AUTO_MS);
    }
  }

  function bloquearUI(bloquear) {
    const sinListo = bloquear || !estado.listo;
    [el.usuario, el.contrasena, el.secretoMalo, el.entrar].forEach((c) => { c.disabled = sinListo; });
    [el.interim, el.salir].forEach((c) => { c.disabled = bloquear; });
  }

  function cancelarFlujo() {
    estado.flujo += 1;
    clearTimeout(estado.temporizador);
    if (estado.resolverPaso) estado.resolverPaso();
    if (estado.resolverMfa) estado.resolverMfa(null);
    estado.resolverPaso = null;
    estado.resolverMfa = null;
    el.siguiente.disabled = true;
    ocultarMfa();
  }

  function iniciarFlujo() {
    cancelarFlujo();
    bloquearUI(true);
    reiniciarCapas();
    return estado.flujo;
  }

  function terminarFlujo(id) {
    if (id !== estado.flujo) return;
    el.siguiente.disabled = true;
    bloquearUI(false);
  }

  /* ================= Interfaz del cliente ================= */

  function avisar(texto, tipo) {
    el.mensaje.textContent = texto;
    el.mensaje.dataset.tipo = tipo || '';
  }

  /* Bitácora: cada paquete que pasa por la red */
  function registrar({ desde, hasta, proto, code, nombre, detalle }) {
    const tipo = { 2: 'ok', 5: 'ok', 3: 'error', 11: 'espera' }[code] || (code === 'x' ? 'error' : 'nada');
    const li = document.createElement('li');
    li.innerHTML = `
      <span class="b-hora">${hora()}</span>
      <span class="b-ruta">${esc(desde)} → ${esc(hasta)}</span>
      <span class="b-proto">${esc(proto)}</span>
      <span class="b-codigo" data-tipo="${tipo}">${code === 'x' ? '✗' : esc(code)}</span>
      <span class="b-nombre">${esc(nombre)}</span>
      <span class="b-detalle">${esc(detalle)}</span>`;
    el.bitacora.prepend(li);
    el.bitacoraVacia.hidden = true;
  }

  function registrarPaquete(bytes, desde, hasta, detalle) {
    const p = Radius.leer(bytes);
    const puerto = p.code === 4 || p.code === 5 ? Servidor.CONFIG.puertoAcct : Servidor.CONFIG.puertoAuth;
    registrar({ desde, hasta, proto: `UDP ${puerto}`, code: p.code, nombre: `${Radius.CODIGOS[p.code]} · id ${p.id}`, detalle });
  }

  function mostrarMfa(codigo, segundos, mensaje) {
    el.codigoTelefono.textContent = codigo;
    el.textoDesafio.textContent = `El NAS muestra el Reply-Message del servidor: "${mensaje}"`;
    el.codigoMfa.value = '';
    el.tarjetaMfa.hidden = false;
    let restantes = segundos;
    const pintar = () => {
      el.venceTelefono.textContent = restantes > 0 ? `Vence en ${restantes} s` : 'Código vencido';
    };
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
  }

  function esperarCodigoMfa() {
    return new Promise((resolver) => { estado.resolverMfa = resolver; });
  }

  /* ================= Sesión del usuario en la red ================= */

  function abrirSesion(registro, ip) {
    const a = registro.autorizacion;
    estado.sesion = {
      usuario: registro.usuario,
      registro,
      ip,
      sesionId: hex(Cripto.aleatorios(4)).toUpperCase(),
      inicio: Date.now(),
      entrada: 0,
      salida: 0,
      reloj: null,
    };
    el.nombreSesion.textContent = registro.nombre;
    el.grupoSesion.textContent = registro.grupo;
    el.vlanSesion.textContent = `${a.vlan} (${a.vlan === 99 ? 'gestión' : 'estudiantes'})`;
    el.ipSesion.textContent = ip;
    el.aclSesion.textContent = a.acl;
    el.privSesion.textContent = a.privilegio ? `nivel ${a.privilegio} (administrador)` : 'usuario normal';
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
    el.datosSesion.textContent = `↑ ${bytesLegibles(estado.sesion.entrada)} · ↓ ${bytesLegibles(estado.sesion.salida)}`;
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
    return { nas: el.secretoMalo.checked ? SECRETO_EQUIVOCADO : delServidor, servidor: delServidor };
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
      atr(30, v.texto(`${NAS.mac}:${NAS.ssid}`)),
      atr(31, v.texto(MAC_CLIENTE)),
      ...extra,
    ], secreto);
    return { bytes, ra, id, oculto };
  }

  /* El servidor recibe: comprueba el NAS, el Message-Authenticator y descifra User-Password */
  function recibirEnServidor(bytes, secreto) {
    const p = Radius.leer(bytes);
    const cli = Servidor.cliente(NAS.ip);
    const ma = Radius.verificarMA(bytes, secreto);
    const clave = Radius.revelarClave(Radius.buscar(p, 2), secreto, p.authenticator);
    return { p, cli, ma, clave, usuario: Cripto.aTexto(Radius.buscar(p, 1)) };
  }

  async function rechazar(id, peticion, sec, motivo, explicacion) {
    if (el.capas.querySelector('[data-capa="challenge"]').dataset.estado === 'pendiente') capasNoAplican('challenge');
    const bytes = Radius.respuesta(3, peticion.id, peticion.ra, [Radius.atr(18, Radius.v.texto('Usuario o contraseña incorrectos'))], sec.servidor);
    red(1, 'izq', 'Access-Reject (3)', 'error');
    mostrar('decision', 'error', {
      titulo: 'Access-Reject (3): acceso denegado',
      texto: `${explicacion} El servidor responde con un <strong>Access-Reject</strong> al mismo Identifier de la petición. El Reply-Message es genérico a propósito: si dijera "ese usuario no existe", un atacante podría averiguar qué cuentas son reales.`,
      bloques: [
        B.html('Paquete de respuesta', B.paquete(bytes)),
        B.html('Bytes en el cable', B.hex(bytes)),
      ],
    });
    registrarPaquete(bytes, 'Servidor', 'NAS', motivo);
    await avanzar(id);

    red(0, 'izq', 'Acceso denegado', 'error');
    mostrar('aplicar', 'error', {
      titulo: 'El NAS niega el acceso',
      texto: 'El AP no abre el puerto: el portátil se queda sin VLAN y sin dirección IP. No hubo sesión, así que <strong>no se envía nada de contabilidad</strong>.',
      bloques: [B.codigo('Estado del puerto en el NAS', json({ puerto: NAS.puerto, mac: MAC_CLIENTE, estado: 'no autorizado', vlan: null }))],
    });
    capasNoAplican('acct');
    registrar({ desde: 'NAS', hasta: 'Cliente', proto: 'EAPOL', code: 'x', nombre: 'EAP-Failure', detalle: 'Acceso denegado' });
    avisar('Acceso denegado: usuario o contraseña incorrectos.', 'error');
  }

  async function flujoConexion(usuario, contrasena) {
    const id = iniciarFlujo();
    avisar('Conectando...', '');
    try {
      /* ---- Paso 1: Cliente → NAS ---- */
      const errores = [];
      if (!usuario) errores.push('El usuario está vacío.');
      if (!contrasena) errores.push('La contraseña está vacía.');
      if (errores.length) {
        nodoSolo('cliente');
        mostrar('solicitud', 'error', {
          titulo: 'No se envió la solicitud',
          texto: 'El portátil no tiene credenciales que mandar. El NAS ni siquiera se entera.',
          bloques: [B.codigo('Errores', errores.join('\n'))],
        });
        avisar(errores[0], 'error');
        return;
      }

      const sec = secretos();
      red(0, 'der', 'Solicitud de acceso');
      mostrar('solicitud', 'ok', {
        titulo: 'El cliente pide entrar a la red',
        texto: `El portátil se asocia al Wi-Fi <code>${NAS.ssid}</code>. El punto de acceso es el <strong>NAS</strong> (Network Access Server): no sabe quién es quién, solo deja el puerto cerrado y le pide las credenciales al cliente.`,
        bloques: [
          B.codigo('Lo que envía el cliente al NAS', json({ red: NAS.ssid, mac: MAC_CLIENTE, usuario, contrasena: '•'.repeat(contrasena.length) })),
          B.nota('Aquí la contraseña viaja como en PAP para que se vea el mecanismo de RADIUS. En una red 802.1X real va dentro de un túnel EAP cifrado (PEAP o EAP-TTLS) entre el cliente y el servidor.'),
        ],
      });
      registrar({ desde: 'Cliente', hasta: 'NAS', proto: 'EAPOL', code: '—', nombre: 'EAP-Response/Identity', detalle: `Identidad: ${usuario}` });
      await avanzar(id);

      /* ---- Paso 2: NAS → Servidor, Access-Request ---- */
      const req = armarAccessRequest(usuario, contrasena, sec.nas);
      const paso1 = req.oculto.pasos[0];
      red(1, 'der', `Access-Request (1) · id ${req.id}`);
      mostrar('request', 'ok', {
        titulo: 'El NAS arma un Access-Request',
        texto: `El NAS mete las credenciales en un paquete RADIUS y lo envía al servidor <code>${Servidor.CONFIG.ip}</code> por <strong>UDP ${Servidor.CONFIG.puertoAuth}</strong>. Elige un <em>Identifier</em> para unir la respuesta con esta petición y un <em>Request Authenticator</em> de 16 bytes aleatorios.`,
        bloques: [
          B.html('Formato del paquete', B.paquete(req.bytes)),
          B.html('Bytes en el cable', B.hex(req.bytes)),
          B.codigo('Cómo se oculta User-Password (RFC 2865, sección 5.2)',
            `b1 = MD5(secreto compartido + Request Authenticator)\nc1 = contraseña (rellena con ceros a 16 bytes) XOR b1\n\ncontraseña  ${hexEspaciado(paso1.p)}\nb1          ${hexEspaciado(paso1.b)}\nc1 (viaja)  ${hexEspaciado(paso1.c)}`),
          B.nota(`Alguien que capture este paquete con Wireshark ve <strong>en claro</strong> el usuario <code>${esc(usuario)}</code>, la IP del NAS y las MAC. Solo la contraseña va oculta. Eso es justo lo que dice la tabla: RADIUS cifra solo la contraseña; TACACS+ cifra todo el cuerpo.`, 'aviso'),
        ],
      });
      registrarPaquete(req.bytes, 'NAS', 'Servidor', `User-Name: ${usuario}`);
      await avanzar(id);

      /* ---- Paso 3: Servidor AAA recibe ---- */
      const rec = recibirEnServidor(req.bytes, sec.servidor);
      nodoSolo('servidor');
      const chequeos = [
        [Boolean(rec.cli), `El paquete viene de un NAS registrado (<code>${NAS.ip}</code>, ${esc(rec.cli.nombre)})`],
        [rec.ma.valido, 'El Message-Authenticator (HMAC-MD5 con el secreto compartido) coincide'],
      ];

      if (!rec.ma.valido) {
        mostrar('servidor', 'error', {
          titulo: 'Paquete descartado en silencio',
          texto: 'El NAS usó un secreto compartido distinto al que tiene el servidor, así que la firma del paquete no cuadra. El RFC dice que el servidor debe <strong>descartarlo sin responder</strong>: ni siquiera un Access-Reject, para no darle pistas a un atacante. El NAS reintenta unas veces y se rinde por tiempo de espera.',
          bloques: [
            B.html('Revisiones', B.chequeos(chequeos)),
            B.codigo('Message-Authenticator que calcula el servidor', hex(rec.ma.esperado)),
            B.html('Message-Authenticator que trae el paquete', B.comparar(hex(rec.ma.esperado), hex(rec.ma.recibido)), 'no-coincide'),
            B.codigo('Así le queda la contraseña al servidor con el secreto que él conoce', hexEspaciado(rec.clave.bytes)),
            B.nota('Sin el secreto correcto la contraseña sale como basura: por eso un equipo que no esté registrado no puede usar el servidor.', 'aviso'),
          ],
        });
        registrar({ desde: 'Servidor', hasta: '—', proto: 'UDP 1812', code: 'x', nombre: 'Descartado', detalle: 'Message-Authenticator inválido, no hay respuesta' });
        capasNoAplican('base', 'challenge', 'decision', 'aplicar', 'acct');
        avisar('No se pudo conectar: el servidor de autenticación no responde.', 'error');
        return;
      }

      mostrar('servidor', 'ok', {
        titulo: 'El servidor valida el paquete',
        texto: 'Antes de mirar el usuario, el servidor revisa que el paquete venga de un NAS que él conoce y que esté firmado con el secreto compartido. Luego deshace el XOR de la contraseña con ese mismo secreto.',
        bloques: [
          B.html('Revisiones', B.chequeos(chequeos)),
          B.codigo('User-Password recuperada', `c1 XOR MD5(secreto + Request Authenticator)\n= ${hexEspaciado(rec.clave.bytes.slice(0, 16))}\n= "${'•'.repeat(rec.clave.texto.length)}" (${rec.clave.texto.length} caracteres)`),
          B.nota('El secreto compartido <strong>nunca viajó por la red</strong>. Solo lo conocen el NAS y el servidor porque un administrador lo configuró en los dos.'),
        ],
      });
      await avanzar(id);

      /* ---- Paso 4: Base de usuarios ---- */
      red(2, 'der', `¿existe "${rec.usuario}"?`);
      const registro = Servidor.buscarUsuario(rec.usuario);
      if (!registro) {
        mostrar('base', 'error', {
          titulo: 'El usuario no existe',
          texto: `No hay ningún usuario llamado <code>${esc(rec.usuario)}</code> en la base de usuarios.`,
          bloques: [B.html('Base de usuarios', B.tablaUsuarios(null))],
        });
        await avanzar(id);
        await rechazar(id, req, sec, 'Usuario no existe', 'La autenticación falló.');
        return;
      }

      const v = await Servidor.verificarContrasena(registro, rec.clave.texto);
      vigente(id);
      const bloquesClave = [
        B.html('Registro encontrado', B.tablaUsuarios(registro.usuario)),
        B.codigo('Hash guardado', v.guardado),
        B.html('Hash calculado con la contraseña que llegó', B.comparar(v.guardado, v.calculado), v.coincide ? 'coincide' : 'no-coincide'),
      ];
      if (!v.coincide) {
        red(2, 'izq', 'el hash no coincide', 'error');
        mostrar('base', 'error', {
          titulo: 'La contraseña no coincide',
          texto: `El servidor calculó PBKDF2-SHA256 (${v.iteraciones.toLocaleString('es-CO')} iteraciones) con la contraseña recibida y el salt del usuario. No da igual al hash guardado: los caracteres en rojo son los distintos.`,
          bloques: bloquesClave,
        });
        await avanzar(id);
        await rechazar(id, req, sec, 'Contraseña incorrecta', 'La autenticación falló.');
        return;
      }
      red(2, 'izq', 'el hash coincide', 'ok');
      mostrar('base', 'ok', {
        titulo: 'Autenticación correcta: sabemos quién eres',
        texto: `El usuario <code>${esc(registro.usuario)}</code> existe y el hash de la contraseña coincide con el guardado (PBKDF2-SHA256, ${v.ms} ms). Esta es la primera A: <strong>autenticación</strong>.`,
        bloques: bloquesClave,
      });
      await avanzar(id);

      /* ---- Paso 5: Access-Challenge (opcional) ---- */
      let ultima = req;
      if (registro.mfa) {
        const des = Servidor.crearDesafio(registro.usuario);
        const mensaje = 'Ingrese el código enviado a su teléfono';
        const chal = Radius.respuesta(11, req.id, req.ra, [
          Radius.atr(18, Radius.v.texto(mensaje)),
          Radius.atr(24, des.state),
        ], sec.servidor);
        red(1, 'izq', 'Access-Challenge (11)', 'espera');
        mostrar('challenge', 'espera', {
          titulo: 'Access-Challenge: se pide un segundo factor',
          texto: `La contraseña era correcta, pero <code>${esc(registro.usuario)}</code> tiene segundo factor. En lugar de aceptar, el servidor responde con un <strong>Access-Challenge (11)</strong>: un Reply-Message para el usuario y un atributo <strong>State</strong> que el NAS debe devolver para continuar la misma conversación. <strong>Escribe el código del teléfono para seguir.</strong>`,
          bloques: [B.html('Paquete de respuesta', B.paquete(chal))],
        });
        registrarPaquete(chal, 'Servidor', 'NAS', 'Pide segundo factor');
        mostrarMfa(des.codigo, des.segundos, mensaje);
        avisar('');
        const ingresado = await esperarCodigoMfa();
        vigente(id);
        ocultarMfa();

        // El NAS devuelve el State y el código en un nuevo Access-Request
        const req2 = armarAccessRequest(registro.usuario, ingresado || '', sec.nas, [Radius.atr(24, des.state)]);
        registrarPaquete(req2.bytes, 'NAS', 'Servidor', 'Respuesta al desafío (con State)');
        const rec2 = recibirEnServidor(req2.bytes, sec.servidor);
        const r = Servidor.verificarDesafio(Radius.buscar(rec2.p, 24), rec2.usuario, rec2.clave.texto);
        ultima = req2;
        red(1, 'der', `Access-Request (1) · id ${req2.id}`);
        const bloquesReq2 = [
          B.html('Segundo Access-Request: el código va en User-Password y se devuelve el State', B.paquete(req2.bytes)),
          B.html('Revisiones', B.chequeos([
            [rec2.ma.valido, 'Message-Authenticator válido'],
            [true, 'El State corresponde al desafío enviado'],
            [r.valido, r.valido ? 'El código coincide y llegó a tiempo' : esc(r.motivo)],
          ])),
        ];
        if (!r.valido) {
          mostrar('challenge', 'error', { titulo: 'El segundo factor falló', texto: `${esc(r.motivo)} Aunque la contraseña era correcta, sin el segundo factor no se entra.`, bloques: bloquesReq2 });
          await avanzar(id);
          await rechazar(id, req2, sec, 'Segundo factor inválido', 'El código de verificación no es válido.');
          return;
        }
        mostrar('challenge', 'ok', {
          titulo: 'Segundo factor verificado',
          texto: 'El NAS mandó un nuevo Access-Request con el código y el mismo State. Ahora el servidor tiene dos pruebas: <strong>algo que el usuario sabe</strong> (la contraseña) y <strong>algo que tiene</strong> (el teléfono).',
          bloques: bloquesReq2,
        });
      } else {
        nodoSolo('servidor');
        mostrar('challenge', 'omitida', {
          titulo: 'No hace falta Access-Challenge',
          texto: 'Este paso es <strong>opcional</strong>. Esta cuenta solo necesita usuario y contraseña, así que el servidor pasa directo a decidir. Prueba con <code>admin</code> para ver el desafío.',
        });
      }
      await avanzar(id);

      /* ---- Paso 6: Access-Accept con atributos de autorización ---- */
      const a = registro.autorizacion;
      const accept = Radius.respuesta(2, ultima.id, ultima.ra, Servidor.atributosAutorizacion(registro), sec.servidor);
      const autNas = Radius.verificarAutenticador(accept, ultima.ra, sec.nas);
      red(1, 'izq', 'Access-Accept (2)', 'ok');
      mostrar('decision', 'ok', {
        titulo: 'Access-Accept (2) con los permisos',
        texto: `El servidor acepta y aprovecha la respuesta para decir <strong>qué puede hacer</strong> este usuario según su grupo <code>${esc(registro.grupo)}</code>. Esta es la segunda A: <strong>autorización</strong>. Los permisos viajan como atributos TLV.`,
        bloques: [
          B.html('Paquete de respuesta', B.paquete(accept)),
          B.html('Qué significa cada atributo', B.tabla(['Atributo', 'Valor', 'Para qué sirve'], [
            ['Tunnel-Type + Tunnel-Medium-Type', 'VLAN, IEEE-802', 'Le dicen al NAS que va a asignar una VLAN'],
            ['Tunnel-Private-Group-ID', String(a.vlan), `Mete al usuario en la VLAN ${a.vlan}`],
            ['Filter-Id', esc(a.acl), 'Nombre de la ACL que el NAS aplica al puerto'],
            ['Session-Timeout', `${a.sesionMax} s`, 'Tiempo máximo de la sesión'],
            ...(a.privilegio ? [['Vendor-Specific (26)', `Cisco: priv-lvl=${a.privilegio}`, 'Atributo del fabricante: nivel de privilegio']] : []),
          ])),
          B.codigo('Response Authenticator', `MD5(Code + ID + Length + Request Authenticator + Atributos + secreto)\n= ${hexEspaciado(accept.slice(4, 20))}`),
          B.html('El NAS verifica la respuesta', B.chequeos([
            [Radius.leer(accept).id === ultima.id, `El Identifier (${ultima.id}) es el de su petición`],
            [autNas.valido, 'El Response Authenticator cuadra con su secreto: la respuesta viene del servidor de verdad'],
          ])),
        ],
      });
      registrarPaquete(accept, 'Servidor', 'NAS', `VLAN ${a.vlan}, ${a.acl}`);
      await avanzar(id);

      /* ---- Paso 7: NAS → Cliente ---- */
      const ip = `10.${a.vlan}.0.${40 + Math.floor(Math.random() * 150)}`;
      red(0, 'izq', `Acceso concedido · VLAN ${a.vlan}`, 'ok');
      mostrar('aplicar', 'ok', {
        titulo: 'El NAS aplica la autorización',
        texto: `El AP abre el puerto, mete al portátil en la <strong>VLAN ${a.vlan}</strong> y le aplica la ACL <code>${esc(a.acl)}</code>. El DHCP de esa VLAN le entrega la IP <code>${ip}</code>. El servidor AAA decidió; el NAS es el que hace cumplir.`,
        bloques: [
          B.codigo('Estado del puerto en el NAS', json({ puerto: NAS.puerto, mac: MAC_CLIENTE, usuario: registro.usuario, estado: 'autorizado', vlan: a.vlan, acl: a.acl, ip, sessionTimeout: `${a.sesionMax} s` })),
          B.codigo(`Reglas de ${a.acl}`, ACLS[a.acl].join('\n')),
        ],
      });
      registrar({ desde: 'NAS', hasta: 'Cliente', proto: 'EAPOL', code: '—', nombre: 'EAP-Success', detalle: `VLAN ${a.vlan}, IP ${ip}` });
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
      atr(5, v.entero(NAS.puerto)),
      atr(8, v.ip(s.ip)),
      atr(31, v.texto(MAC_CLIENTE)),
    ];
    if (tipo !== 'Start') {
      lista.push(atr(46, v.entero(segundos)), atr(42, v.entero(s.entrada)), atr(43, v.entero(s.salida)));
    }
    if (tipo === 'Stop') lista.push(atr(49, v.entero(1)));

    const idPkt = siguienteId();
    const peticion = Radius.contabilidad(4, idPkt, lista, sec);
    const textos = {
      Start: 'Apenas el usuario queda conectado, el NAS avisa al servidor que <strong>abrió una sesión</strong>. Esta es la tercera A: <strong>contabilidad</strong>. Va por otro puerto, <strong>UDP 1813</strong>.',
      'Interim-Update': 'Mientras la sesión sigue abierta, el NAS manda reportes periódicos con el <strong>tiempo y los bytes</strong> consumidos hasta ahora. En una red real los manda solo, cada cierto intervalo.',
      Stop: 'El usuario se desconectó. El NAS cierra el puerto y manda el <strong>total consumido</strong> y la causa de terminación.',
    };
    red(1, 'der', `Accounting-Request (4) · ${tipo}`);
    mostrar('acct', 'espera', {
      titulo: `Accounting-Request (4): Acct-Status-Type = ${tipo}`,
      texto: textos[tipo],
      bloques: [
        B.html('Formato del paquete', B.paquete(peticion)),
        B.codigo('Request Authenticator de contabilidad', `MD5(Code + ID + Length + 16 bytes en cero + Atributos + secreto)\n= ${hexEspaciado(peticion.slice(4, 20))}`),
        B.nota('En contabilidad no hay contraseña. El autenticador solo sirve para que el servidor compruebe que el reporte lo mandó un NAS que conoce el secreto.'),
      ],
    });
    registrarPaquete(peticion, 'NAS', 'Servidor', `${tipo} · sesión ${s.sesionId}`);
    await avanzar(id);

    const ver = Radius.verificarAutenticador(peticion, new Uint8Array(16), sec);
    const fila = Servidor.registrarContabilidad({ tipo, sesionId: s.sesionId, usuario: s.usuario, nas: NAS.nombre, ip: s.ip, segundos, entrada: s.entrada, salida: s.salida });
    const respuesta = Radius.contabilidad(5, idPkt, [], sec, peticion.slice(4, 20));
    red(1, 'izq', 'Accounting-Response (5)', 'ok');
    mostrar('acct', 'ok', {
      titulo: 'Accounting-Response (5): registro guardado',
      texto: `El servidor verifica el reporte, lo guarda y confirma con un <strong>Accounting-Response</strong>. Si no llega la confirmación, el NAS reenvía el reporte. ${tipo === 'Stop' ? 'La sesión queda cerrada con su total.' : 'Con estos registros se puede saber quién estuvo conectado, cuánto tiempo y cuánto consumió.'}`,
      bloques: [
        B.html('Revisiones del servidor', B.chequeos([[ver.valido, 'El Request Authenticator cuadra con el secreto compartido']])),
        B.html('Paquete de respuesta (sin atributos, solo confirma)', B.paquete(respuesta)),
        B.html('Registro de contabilidad en el servidor', B.tablaContabilidad(fila.sesionId)),
      ],
    });
    registrarPaquete(respuesta, 'Servidor', 'NAS', `${tipo} registrado`);
  }

  async function flujoContabilidad(tipo) {
    if (!estado.sesion) return;
    const id = iniciarFlujo();
    try {
      capasNoAplican('solicitud', 'request', 'servidor', 'base', 'challenge', 'decision', 'aplicar');
      if (tipo === 'Stop') {
        clearInterval(estado.sesion.reloj);
        registrar({ desde: 'Cliente', hasta: 'NAS', proto: 'EAPOL', code: '—', nombre: 'EAPOL-Logoff', detalle: 'El usuario se desconecta' });
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

  function reiniciarTodo() {
    cancelarFlujo();
    cerrarSesion();
    Servidor.reiniciar();
    reiniciarCapas();
    el.bitacora.innerHTML = '';
    el.bitacoraVacia.hidden = false;
    el.usuario.value = '';
    el.contrasena.value = '';
    el.secretoMalo.checked = false;
    avisar('');
    bloquearUI(false);
    mostrarIntro();
  }

  function enlazarEventos() {
    el.formLogin.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!estado.listo) return;
      flujoConexion(el.usuario.value.trim(), el.contrasena.value);
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

    el.siguiente.addEventListener('click', pasoSiguiente);
    el.modoPaso.addEventListener('click', () => cambiarModo('paso'));
    el.modoAuto.addEventListener('click', () => cambiarModo('auto'));
    el.reiniciar.addEventListener('click', reiniciarTodo);
    el.interim.addEventListener('click', () => flujoContabilidad('Interim-Update'));
    el.salir.addEventListener('click', () => flujoContabilidad('Stop'));

    // Flecha derecha, Av Pág o el control de presentaciones avanzan el paso
    document.addEventListener('keydown', (e) => {
      const etiqueta = (e.target.tagName || '').toLowerCase();
      if (etiqueta === 'input' || etiqueta === 'textarea') return;
      if ((e.key === 'ArrowRight' || e.key === 'PageDown') && estado.resolverPaso) {
        e.preventDefault();
        pasoSiguiente();
      }
    });
  }

  function pintarUsuariosDePrueba() {
    el.tablaPruebas.innerHTML = Servidor.usuariosDePrueba().map((u) => `
      <tr>
        <td><button type="button" class="btn-relleno" data-usuario="${esc(u.usuario)}" data-clave="${esc(u.contrasena)}" title="Llenar el formulario">${esc(u.usuario)}</button></td>
        <td><code>${esc(u.contrasena)}</code></td>
        <td>${u.mfa ? 'sí' : 'no'}</td>
      </tr>`).join('');
    el.tablaPruebas.addEventListener('click', (e) => {
      const boton = e.target.closest('[data-usuario]');
      if (!boton || el.tarjetaLogin.hidden || el.usuario.disabled) return;
      el.usuario.value = boton.dataset.usuario;
      el.contrasena.value = boton.dataset.clave;
      el.entrar.focus();
    });
  }

  async function arrancar() {
    pintarCapas();
    enlazarEventos();
    pintarUsuariosDePrueba();
    mostrarLibre('Preparando el servidor...', '<p class="insp-texto">Calculando los hashes de las contraseñas de prueba.</p>');

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
