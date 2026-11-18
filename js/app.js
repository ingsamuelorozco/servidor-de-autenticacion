/*
 * app.js
 * Conecta el formulario con el servidor simulado y va mostrando
 * cada capa del recorrido en la columna central y en el inspector.
 */
(() => {
  'use strict';

  const IP_CLIENTE = '181.49.23.105';
  const ESPERA_AUTO_MS = 2600;

  const CAPAS = [
    { id: 'cliente', nombre: 'Cliente (navegador)', resumen: 'Valida el formulario y arma la petición' },
    { id: 'tls', nombre: 'HTTPS / TLS', resumen: 'Cifra todo lo que viaja por la red' },
    { id: 'gateway', nombre: 'Gateway y límite de intentos', resumen: 'Frena los ataques de fuerza bruta' },
    { id: 'usuario', nombre: 'Búsqueda del usuario', resumen: 'Consulta la base de datos' },
    { id: 'clave', nombre: 'Verificación de contraseña', resumen: 'Compara hashes, nunca texto plano' },
    { id: 'mfa', nombre: 'Segundo factor (MFA)', resumen: 'Algo que tienes, además de algo que sabes' },
    { id: 'token', nombre: 'Emisión del token (JWT)', resumen: 'Firma la identidad del usuario' },
    { id: 'recurso', nombre: 'Recurso protegido', resumen: 'Verifica el token en cada petición' },
  ];

  const ESTADOS = {
    pendiente: 'Pendiente',
    ok: 'Superada',
    error: 'Rechazada',
    espera: 'Esperando',
    omitida: 'Omitida',
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
    rolSesion: $('rolSesion'),
    tokenCorto: $('tokenCorto'),
    venceSesion: $('venceSesion'),
    perfil: $('btnPerfil'),
    alterar: $('btnAlterar'),
    vencido: $('btnVencido'),
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
  };

  class FlujoCancelado extends Error {}

  /* ================= Utilidades ================= */

  function esc(valor) {
    return String(valor).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  const json = (obj) => JSON.stringify(obj, null, 2);
  const hora = () => new Date().toLocaleTimeString('es-CO', { hour12: false });
  const fechaUnix = (s) => new Date(s * 1000).toLocaleString('es-CO', { hour12: false });
  const recortar = (texto, n = 14) => (texto.length > n ? `${texto.slice(0, n)}…` : texto);

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
    jwt(partes) {
      const [h, p, f] = partes.map(esc);
      return `<pre class="jwt"><code><span class="jwt-h">${h}</span>.<span class="jwt-p">${p}</span>.<span class="jwt-f">${f}</span></code></pre>`;
    },
    comparar(referencia, calculado) {
      let html = '';
      for (let i = 0; i < calculado.length; i++) {
        const igual = calculado[i] === referencia[i];
        html += `<span class="${igual ? 'igual' : 'dif'}">${esc(calculado[i])}</span>`;
      }
      return `<pre><code>${html}</code></pre>`;
    },
    chequeos(lista) {
      return `<ul class="chequeos">${lista.map(([ok, texto]) => `<li data-ok="${ok}"><span class="marca">${ok ? '✓' : '✗'}</span><span>${texto}</span></li>`).join('')}</ul>`;
    },
    tablaBD(resaltar) {
      const filas = Servidor.tablaBaseDatos().map((r) => `
        <tr class="${r.usuario === resaltar ? 'resaltada' : ''}">
          <td>${esc(r.usuario)}</td>
          <td><code>${esc(recortar(r.salt, 10))}</code></td>
          <td><code>${esc(recortar(r.hash, 16))}</code></td>
          <td>${esc(r.rol)}</td>
          <td>${r.mfa ? 'sí' : 'no'}</td>
        </tr>`).join('');
      return `<div class="tabla-scroll"><table class="tabla-bd">
        <thead><tr><th>usuario</th><th>salt</th><th>hash_contrasena</th><th>rol</th><th>mfa</th></tr></thead>
        <tbody>${filas}</tbody></table></div>`;
    },
  };

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

  /* titulo y texto son HTML escrito aquí; todo dato del usuario se pasa por esc() */
  function mostrar(id, est, { titulo, texto, bloques = [] }) {
    fijarCapa(id, est);
    enfocarCapa(id);
    const i = CAPAS.findIndex((c) => c.id === id);
    el.inspector.innerHTML = `
      <div class="insp-cabecera">
        <span class="insp-capa">Capa ${i + 1} &middot; ${CAPAS[i].nombre}</span>
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
    mostrarLibre('Bienvenido a la demostración', `
      <p class="insp-texto">Escribe un usuario y una contraseña a la izquierda y presiona <strong>Iniciar sesión</strong>. Cada capa del centro se irá encendiendo y aquí verás exactamente qué datos se mueven en ese momento.</p>
      <ul class="lista">
        <li><strong>Paso a paso:</strong> avanzas con el botón <em>Siguiente paso</em>, con la flecha derecha del teclado o con el control de presentaciones.</li>
        <li><strong>Automático:</strong> avanza solo cada ${(ESPERA_AUTO_MS / 1000).toLocaleString('es-CO')} segundos.</li>
        <li>Todo lo criptográfico es real: PBKDF2, AES-GCM y HMAC-SHA256 del navegador.</li>
      </ul>
      ${B.html('Así se ve la base de datos del servidor', B.tablaBD(null))}
      ${B.nota('Fíjate que <strong>no hay ninguna columna con la contraseña</strong>. El servidor no la conoce: solo guarda un hash. Si alguien roba esta tabla, no puede leer las contraseñas.')}
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
    [el.usuario, el.contrasena, el.entrar].forEach((c) => { c.disabled = sinListo; });
    [el.perfil, el.alterar, el.vencido, el.salir].forEach((c) => { c.disabled = bloquear; });
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

  function registrar(metodo, ruta, codigo, detalle) {
    const li = document.createElement('li');
    const tipo = codigo === 0 ? 'nada' : codigo < 300 ? 'ok' : 'error';
    li.innerHTML = `
      <span class="b-hora">${hora()}</span>
      <span class="b-metodo">${esc(metodo)}</span>
      <span class="b-ruta">${esc(ruta)}</span>
      <span class="b-codigo" data-tipo="${tipo}">${codigo === 0 ? '—' : codigo}</span>
      <span class="b-detalle">${esc(detalle)}</span>`;
    el.bitacora.prepend(li);
    el.bitacoraVacia.hidden = true;
  }

  function mostrarMfa(codigo, segundos) {
    el.codigoTelefono.textContent = codigo;
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

  function abrirSesion(usuario, emitido) {
    estado.sesion = {
      usuario,
      nombre: emitido.payload.nombre,
      rol: emitido.payload.rol,
      token: emitido.token,
      exp: emitido.payload.exp,
    };
    el.nombreSesion.textContent = estado.sesion.nombre;
    el.rolSesion.textContent = estado.sesion.rol;
    el.tokenCorto.textContent = `${emitido.token.slice(0, 38)}…`;
    el.venceSesion.textContent = `El token vence el ${fechaUnix(emitido.payload.exp)}.`;
    el.tarjetaLogin.hidden = true;
    el.tarjetaSesion.hidden = false;
    el.contrasena.value = '';
    avisar('');
  }

  function cerrarSesion() {
    estado.sesion = null;
    el.tarjetaSesion.hidden = true;
    el.tarjetaLogin.hidden = false;
  }

  /* ================= Flujo 1: inicio de sesión ================= */

  async function flujoLogin(usuario, contrasena) {
    const id = iniciarFlujo();
    avisar('Enviando...', '');
    try {
      /* ---- Capa 1: cliente ---- */
      const errores = [];
      if (!usuario) errores.push('El usuario está vacío.');
      else if (usuario.length < 3) errores.push('El usuario debe tener al menos 3 caracteres.');
      if (!contrasena) errores.push('La contraseña está vacía.');

      if (errores.length) {
        mostrar('cliente', 'error', {
          titulo: 'El formulario no se envió',
          texto: 'El navegador encontró problemas antes de tocar la red. Ojo: esta validación es solo por comodidad. <strong>El servidor siempre vuelve a validar</strong>, porque cualquiera puede saltarse el JavaScript del navegador.',
          bloques: [B.codigo('Errores encontrados', errores.join('\n'))],
        });
        registrar('POST', '/login', 0, 'No se envió: el formulario tiene errores');
        avisar(errores[0], 'error');
        return;
      }

      const cuerpo = { usuario, contrasena };
      const peticionHttp = `POST /login HTTP/1.1\nHost: ${Servidor.CONFIG.dominio}\nContent-Type: application/json\n\n${json(cuerpo)}`;

      mostrar('cliente', 'ok', {
        titulo: 'Se arma la petición de inicio de sesión',
        texto: 'El navegador revisa que los campos no estén vacíos y arma una petición <code>POST /login</code>. Fíjate: la contraseña va <strong>tal cual la escribiste</strong>. Por eso la siguiente capa es tan importante.',
        bloques: [B.codigo('Petición HTTP', peticionHttp)],
      });
      await avanzar(id);

      /* ---- Capa 2: TLS ---- */
      const paquete = await Cripto.cifrarAES(peticionHttp);
      vigente(id);
      mostrar('tls', 'ok', {
        titulo: 'La petición viaja cifrada',
        texto: 'Antes de salir del computador, la petición se cifra con una llave de sesión que solo conocen tu navegador y el servidor (la acordaron en el <em>handshake</em> de TLS). Aquí se usa AES-GCM de 256 bits real.',
        bloques: [
          B.codigo('Lo que tú enviaste', json(cuerpo)),
          B.codigo('Lo que ve alguien espiando la red (por ejemplo en un Wi-Fi público)', paquete.base64, 'cifrado'),
          B.nota('Por esto nunca debes escribir una contraseña en un sitio que no tenga el candado de <strong>HTTPS</strong>.', 'aviso'),
        ],
      });
      await avanzar(id);

      // El servidor descifra con la misma llave de sesión
      const textoRecibido = await Cripto.descifrarAES(paquete);
      vigente(id);
      const recibido = JSON.parse(textoRecibido.slice(textoRecibido.indexOf('\n\n') + 2));

      /* ---- Capa 3: gateway ---- */
      const limite = Servidor.revisarLimite(IP_CLIENTE);
      if (!limite.permitido) {
        mostrar('gateway', 'error', {
          titulo: '429 Too Many Requests: demasiados intentos',
          texto: `Esta IP falló ${limite.fallidos} veces seguidas. El gateway la bloquea ${Servidor.CONFIG.bloqueoSegundos} segundos <strong>sin siquiera consultar la base de datos</strong>. Así se frena la fuerza bruta: probar millones de contraseñas se vuelve imposible.`,
          bloques: [
            B.codigo('Estado del límite', json({ ip: IP_CLIENTE, intentosFallidos: limite.fallidos, limite: Servidor.CONFIG.maxIntentos, desbloqueoEn: `${limite.segundosRestantes} s` })),
            B.codigo('Respuesta del servidor', `HTTP/1.1 429 Too Many Requests\nRetry-After: ${limite.segundosRestantes}\n\n${json({ error: 'demasiados_intentos' })}`),
          ],
        });
        registrar('POST', '/login', 429, `IP bloqueada, faltan ${limite.segundosRestantes} s`);
        avisar(`Demasiados intentos. Espera ${limite.segundosRestantes} segundos.`, 'error');
        return;
      }

      mostrar('gateway', 'ok', {
        titulo: 'Petición permitida',
        texto: 'El gateway es la puerta de entrada al sistema: recibe la conexión TLS, revisa cuántas veces ha fallado esta IP y decide si deja pasar la petición hacia el servidor de autenticación.',
        bloques: [
          B.codigo('Revisión del límite de intentos', json({ ip: IP_CLIENTE, intentosFallidos: `${limite.fallidos} de ${Servidor.CONFIG.maxIntentos}`, decision: 'dejar pasar' })),
        ],
      });
      await avanzar(id);

      /* ---- Capa 4: búsqueda del usuario ---- */
      const registro = Servidor.buscarUsuario(recibido.usuario);
      if (!registro) {
        const fallo = Servidor.registrarFallo(IP_CLIENTE);
        mostrar('usuario', 'error', {
          titulo: '401: el usuario no existe',
          texto: `No hay ningún registro llamado <code>${esc(recibido.usuario)}</code>. Detalle importante: el servidor responde <strong>"usuario o contraseña incorrectos"</strong>, el mismo mensaje que si la contraseña estuviera mala. Si dijera "ese usuario no existe", un atacante podría averiguar qué cuentas son reales.`,
          bloques: [
            B.html('Consulta en la base de datos', B.tablaBD(null)),
            B.codigo('Respuesta del servidor', `HTTP/1.1 401 Unauthorized\n\n${json({ error: 'usuario_o_contrasena_incorrectos' })}`),
            B.nota(`Intentos fallidos de esta IP: <strong>${fallo.fallidos} de ${Servidor.CONFIG.maxIntentos}</strong>.${fallo.bloqueado ? ' Se alcanzó el límite: la IP queda bloqueada.' : ''}`, 'aviso'),
          ],
        });
        registrar('POST', '/login', 401, 'Usuario o contraseña incorrectos');
        avisar('Usuario o contraseña incorrectos.', 'error');
        return;
      }

      mostrar('usuario', 'ok', {
        titulo: 'Usuario encontrado',
        texto: `El servidor busca <code>${esc(registro.usuario)}</code> en la base de datos. Observa qué hay guardado: <strong>no existe ninguna columna con la contraseña</strong>, solo un <em>salt</em> aleatorio y un <em>hash</em>.`,
        bloques: [
          B.codigo('Consulta', `SELECT salt, hash_contrasena, rol, mfa\nFROM usuarios\nWHERE usuario = ?;   -- parámetro: '${recibido.usuario}'`),
          B.html('Resultado', B.tablaBD(registro.usuario)),
          B.nota('El <code>?</code> es una consulta parametrizada: evita la inyección SQL.'),
        ],
      });
      await avanzar(id);

      /* ---- Capa 5: contraseña ---- */
      const v = await Servidor.verificarContrasena(registro, recibido.contrasena);
      vigente(id);
      const bloquesClave = [
        B.codigo('Salt de este usuario', registro.salt),
        B.codigo('Hash guardado en la base de datos', v.guardado),
        B.html('Hash calculado con la contraseña que llegó', B.comparar(v.guardado, v.calculado), v.coincide ? 'coincide' : 'no-coincide'),
      ];

      if (!v.coincide) {
        const fallo = Servidor.registrarFallo(IP_CLIENTE);
        bloquesClave.push(
          B.codigo('Respuesta del servidor', `HTTP/1.1 401 Unauthorized\n\n${json({ error: 'usuario_o_contrasena_incorrectos' })}`),
          B.nota(`Intentos fallidos de esta IP: <strong>${fallo.fallidos} de ${Servidor.CONFIG.maxIntentos}</strong>.${fallo.bloqueado ? ` Se alcanzó el límite: la IP queda bloqueada ${Servidor.CONFIG.bloqueoSegundos} segundos. Intenta otra vez para ver la capa 3 en acción.` : ''}`, 'aviso')
        );
        mostrar('clave', 'error', {
          titulo: '401: la contraseña no coincide',
          texto: `El servidor calculó el hash de lo que escribiste (PBKDF2-SHA256, ${v.iteraciones.toLocaleString('es-CO')} iteraciones, ${v.ms} ms) y no es igual al guardado. Los caracteres en rojo son los distintos: con cambiar una sola letra, el hash cambia por completo.`,
          bloques: bloquesClave,
        });
        registrar('POST', '/login', 401, 'Usuario o contraseña incorrectos');
        avisar(fallo.bloqueado ? 'Demasiados intentos fallidos. IP bloqueada temporalmente.' : 'Usuario o contraseña incorrectos.', 'error');
        return;
      }

      bloquesClave.push(B.nota('El salt hace que dos personas con la misma contraseña tengan hashes distintos, y que no sirvan las tablas de hashes precalculados.'));
      mostrar('clave', 'ok', {
        titulo: 'La contraseña es correcta',
        texto: `El servidor le pega el salt a la contraseña recibida y la pasa por PBKDF2-SHA256 con ${v.iteraciones.toLocaleString('es-CO')} iteraciones. El resultado es idéntico al hash guardado. Tardó <strong>${v.ms} ms</strong> a propósito: imperceptible para ti, pero muy lento para un atacante que quiere probar millones de contraseñas.`,
        bloques: bloquesClave,
      });
      await avanzar(id);

      /* ---- Capa 6: MFA ---- */
      if (registro.mfa) {
        const { codigo, segundos } = Servidor.generarMfa(registro.usuario);
        mostrarMfa(codigo, segundos);
        mostrar('mfa', 'espera', {
          titulo: 'Se pide un segundo factor',
          texto: `La contraseña era correcta, pero <code>${esc(registro.usuario)}</code> tiene MFA activado. El servidor envía un código de 6 dígitos al teléfono del usuario (está simulado a la izquierda). Si alguien robó la contraseña pero no tiene el teléfono, se queda afuera. <strong>Escribe el código para continuar.</strong>`,
          bloques: [B.codigo('Respuesta intermedia del servidor', `HTTP/1.1 200 OK\n\n${json({ estado: 'mfa_requerido', metodo: 'codigo_al_telefono', venceEn: `${segundos} s` })}`)],
        });
        avisar('');
        const ingresado = await esperarCodigoMfa();
        vigente(id);
        ocultarMfa();
        const resultado = Servidor.verificarMfa(registro.usuario, ingresado);
        if (!resultado.valido) {
          const fallo = Servidor.registrarFallo(IP_CLIENTE);
          mostrar('mfa', 'error', {
            titulo: '401: el segundo factor falló',
            texto: `${esc(resultado.motivo)} Aunque la contraseña era correcta, el servidor no entrega el token. Eso es justamente lo que protege el MFA.`,
            bloques: [
              B.codigo('Código recibido', ingresado || '(vacío)'),
              B.nota(`Intentos fallidos de esta IP: <strong>${fallo.fallidos} de ${Servidor.CONFIG.maxIntentos}</strong>.`, 'aviso'),
            ],
          });
          registrar('POST', '/login/mfa', 401, 'Código de verificación inválido');
          avisar('Código de verificación inválido. Vuelve a iniciar sesión.', 'error');
          return;
        }
        mostrar('mfa', 'ok', {
          titulo: 'Segundo factor verificado',
          texto: 'El código coincide y llegó a tiempo. Ahora el servidor tiene dos pruebas: <strong>algo que el usuario sabe</strong> (la contraseña) y <strong>algo que tiene</strong> (el teléfono).',
          bloques: [B.codigo('Código recibido', ingresado)],
        });
        registrar('POST', '/login/mfa', 200, 'Código correcto');
      } else {
        mostrar('mfa', 'omitida', {
          titulo: 'Este usuario no tiene MFA',
          texto: 'Con usuario y contraseña es suficiente para esta cuenta. En cuentas sensibles se activa un segundo factor: prueba con <code>admin</code> para verlo.',
        });
      }
      await avanzar(id);

      /* ---- Capa 7: token ---- */
      const emitido = await Servidor.emitirToken(registro.usuario);
      vigente(id);
      Servidor.limpiarFallos(IP_CLIENTE);
      mostrar('token', 'ok', {
        titulo: '200 OK: se emite el token',
        texto: 'Con la identidad comprobada, el servidor crea un <strong>JWT</strong> (JSON Web Token): tres partes en Base64URL separadas por puntos. La tercera es una <strong>firma HMAC-SHA256</strong> hecha con una llave secreta que solo conoce el servidor. Cualquiera puede <em>leer</em> el token, pero nadie puede <em>modificarlo</em> sin que la firma deje de coincidir.',
        bloques: [
          B.html('Token completo', `${B.jwt(emitido.partes)}<p class="leyenda"><span class="jwt-h">Header</span> · <span class="jwt-p">Payload (los datos)</span> · <span class="jwt-f">Firma</span></p>`),
          B.codigo('Header decodificado', json(emitido.header)),
          B.codigo('Payload decodificado', json(emitido.payload)),
          B.codigo('Fechas legibles', `iat (emitido):  ${fechaUnix(emitido.payload.iat)}\nexp (vence):    ${fechaUnix(emitido.payload.exp)}`),
          B.nota('El payload <strong>no está cifrado</strong>, solo codificado. Por eso nunca se pone la contraseña ni datos secretos dentro de un JWT.', 'aviso'),
        ],
      });
      registrar('POST', '/login', 200, `Token emitido para ${registro.usuario}`);
      abrirSesion(registro.usuario, emitido);
    } catch (e) {
      if (e instanceof FlujoCancelado) return;
      console.error(e);
      avisar('Ocurrió un error inesperado. Revisa la consola.', 'error');
    } finally {
      terminarFlujo(id);
    }
  }

  /* ================= Flujo 2: recurso protegido ================= */

  function alterarToken(token) {
    const [h, p, f] = token.split('.');
    const payload = JSON.parse(Cripto.base64urlATexto(p));
    const antes = { rol: payload.rol, exp: payload.exp };
    payload.rol = 'admin';
    payload.exp += 365 * 24 * 60 * 60;
    return {
      token: `${h}.${Cripto.textoABase64url(JSON.stringify(payload))}.${f}`,
      antes,
      despues: { rol: payload.rol, exp: payload.exp },
    };
  }

  async function flujoRecurso(variante) {
    if (!estado.sesion) return;
    const id = iniciarFlujo();
    try {
      let token = estado.sesion.token;
      const extras = [];
      let textoVariante = '';

      if (variante === 'alterado') {
        const a = alterarToken(token);
        token = a.token;
        textoVariante = ' <strong>Pero esta vez un atacante editó el payload</strong> para darse permisos de administrador y alargar la vida del token. No puede rehacer la firma porque no tiene la llave secreta del servidor, así que deja la firma vieja.';
        extras.push(B.codigo('Lo que cambió el atacante en el payload', `rol: "${a.antes.rol}"  ->  "${a.despues.rol}"\nexp: ${fechaUnix(a.antes.exp)}  ->  ${fechaUnix(a.despues.exp)}`));
      } else if (variante === 'vencido') {
        token = (await Servidor.emitirToken(estado.sesion.usuario, { vencido: true })).token;
        vigente(id);
        textoVariante = ' <strong>Esta vez se usa un token viejo:</strong> lo emitió el servidor de verdad (la firma es válida), pero hace más de 15 minutos.';
      }

      /* ---- Capa 1 ---- */
      const peticionHttp = `GET /api/perfil HTTP/1.1\nHost: ${Servidor.CONFIG.dominio}\nAuthorization: Bearer ${token}`;
      mostrar('cliente', 'ok', {
        titulo: 'Petición a una ruta protegida',
        texto: `Ya no se envía la contraseña. Ahora el navegador adjunta el token en la cabecera <code>Authorization</code> de cada petición, como quien muestra el carné en la portería de la universidad.${textoVariante}`,
        bloques: [B.codigo('Petición HTTP', peticionHttp), ...extras],
      });
      await avanzar(id);

      /* ---- Capa 2 ---- */
      const paquete = await Cripto.cifrarAES(peticionHttp);
      vigente(id);
      mostrar('tls', 'ok', {
        titulo: 'El token también viaja cifrado',
        texto: 'Igual que en el login, todo va por HTTPS. Si alguien robara el token en la red podría hacerse pasar por ti mientras no venza; por eso HTTPS es obligatorio y los tokens duran poco.',
        bloques: [B.codigo('Lo que ve alguien espiando la red', paquete.base64, 'cifrado')],
      });
      await avanzar(id);

      /* ---- Capa 3 ---- */
      mostrar('gateway', 'ok', {
        titulo: 'Ruta protegida: se revisa el token',
        texto: 'El gateway ve que <code>/api/perfil</code> es una ruta protegida. La petición trae un token, así que la deja pasar al verificador. Si no trajera ninguno, respondería 401 de una vez.',
        bloques: [B.codigo('Decisión', json({ ruta: '/api/perfil', requiereToken: true, traeToken: true, decision: 'verificar token' }))],
      });
      await avanzar(id);

      ['usuario', 'clave', 'mfa', 'token'].forEach((c) => fijarCapa(c, 'na'));

      /* ---- Capa 8 ---- */
      const v = await Servidor.verificarToken(token);
      vigente(id);

      const chequeos = [
        [Boolean(v.algoritmoValido), `Algoritmo permitido (<code>${esc(v.header ? v.header.alg : '?')}</code>)`],
        [Boolean(v.firmaValida), 'La firma coincide con la que calcula el servidor'],
        [Boolean(v.vigente), v.payload ? `No está vencido (vence: ${esc(fechaUnix(v.payload.exp))})` : 'No está vencido'],
      ];
      const bloques = [];
      if (v.partes) bloques.push(B.html('Token recibido', B.jwt(v.partes)));
      if (v.payload) bloques.push(B.codigo('Payload que dice traer', json(v.payload)));
      if (v.firmaEsperada) {
        bloques.push(
          B.codigo('Firma que calcula el servidor con su llave secreta', v.firmaEsperada),
          B.html('Firma que trae el token', B.comparar(v.firmaEsperada, v.firmaRecibida), v.firmaValida ? 'coincide' : 'no-coincide')
        );
      }
      bloques.push(B.html('Revisiones', B.chequeos(chequeos)));

      if (v.valido) {
        const perfil = Servidor.obtenerPerfil(v.payload.sub);
        bloques.push(B.codigo('Respuesta del servidor', `HTTP/1.1 200 OK\n\n${json(perfil)}`));
        mostrar('recurso', 'ok', {
          titulo: '200 OK: acceso concedido',
          texto: 'El servidor recalcula la firma con su llave secreta y es idéntica a la del token. Revisa que no esté vencido y responde con los datos. <strong>No volvió a pedir la contraseña ni consultó una tabla de sesiones</strong>: el token se basta solo. Por eso las capas 4 a 7 no se usan aquí.',
          bloques,
        });
        registrar('GET', '/api/perfil', 200, `Perfil de ${v.payload.sub}`);
      } else {
        bloques.push(B.codigo('Respuesta del servidor', `HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer error="invalid_token"\n\n${json({ error: 'token_invalido' })}`));
        mostrar('recurso', 'error', {
          titulo: '401 Unauthorized: acceso negado',
          texto: `${esc(v.motivo)} ${variante === 'alterado' ? 'Bastó con cambiar una palabra del payload para que la firma ya no corresponda. Así el servidor detecta cualquier manipulación.' : ''}`,
          bloques,
        });
        registrar('GET', '/api/perfil', 401, v.motivo);
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
    Servidor.limpiarFallos(IP_CLIENTE);
    reiniciarCapas();
    el.bitacora.innerHTML = '';
    el.bitacoraVacia.hidden = false;
    el.usuario.value = '';
    el.contrasena.value = '';
    avisar('');
    bloquearUI(false);
    mostrarIntro();
  }

  function enlazarEventos() {
    el.formLogin.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!estado.listo) return;
      flujoLogin(el.usuario.value.trim(), el.contrasena.value);
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

    el.perfil.addEventListener('click', () => flujoRecurso('normal'));
    el.alterar.addEventListener('click', () => flujoRecurso('alterado'));
    el.vencido.addEventListener('click', () => flujoRecurso('vencido'));
    el.salir.addEventListener('click', () => {
      cancelarFlujo();
      const usuario = estado.sesion ? estado.sesion.usuario : '';
      cerrarSesion();
      reiniciarCapas();
      bloquearUI(false);
      registrar('POST', '/logout', 200, `Sesión cerrada (${usuario})`);
      mostrarLibre('Sesión cerrada', `
        <p class="insp-texto">Con JWT el cierre de sesión pasa en el cliente: el navegador <strong>borra el token</strong> y ya no puede demostrar quién es. El servidor no guarda sesiones, por eso los tokens tienen una vida corta (aquí ${Servidor.CONFIG.vidaTokenSegundos / 60} minutos).</p>
        ${B.nota('En sistemas más estrictos el servidor también mantiene una lista de tokens revocados.')}`);
    });

    // Flecha derecha, Av Pág o el control de presentaciones avanzan el paso
    document.addEventListener('keydown', (e) => {
      const etiqueta = (e.target.tagName || '').toLowerCase();
      if (etiqueta === 'input' || etiqueta === 'textarea') return;
      if (e.key === 'ArrowRight' || e.key === 'PageDown') {
        if (estado.resolverPaso) {
          e.preventDefault();
          pasoSiguiente();
        }
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
    el.entrar.textContent = 'Iniciar sesión';
    bloquearUI(false);
    mostrarIntro();
  }

  arrancar();
})();
