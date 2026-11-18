/*
 * servidor.js
 * "Servidor" de autenticación simulado. En la vida real esto corre en otra
 * máquina; aquí vive en el navegador para poder mostrar cada paso.
 */
const Servidor = (() => {
  'use strict';

  const CONFIG = {
    dominio: 'servidor-auth.demo',
    maxIntentos: 3,
    bloqueoSegundos: 30,
    vidaTokenSegundos: 15 * 60,
    iteraciones: 100000,
    vidaMfaSegundos: 60,
  };

  /* Solo se usan al arrancar para crear los hashes. Nunca se guardan así. */
  const usuariosSemilla = [
    { usuario: 'ana', contrasena: 'usc2026', nombre: 'Ana Gómez', rol: 'estudiante', programa: 'Ingeniería de Sistemas', mfa: false },
    { usuario: 'admin', contrasena: 'admin123', nombre: 'Administrador del sistema', rol: 'admin', programa: 'Oficina de TI', mfa: true },
  ];

  const baseDatos = new Map();
  const intentosPorIp = new Map();
  const mfaPendientes = new Map();
  let claveFirma = null;

  async function iniciar() {
    claveFirma = await Cripto.crearClaveHMAC();
    for (const u of usuariosSemilla) {
      const salt = Cripto.saltAleatorio();
      const hash = await Cripto.pbkdf2(u.contrasena, salt, CONFIG.iteraciones);
      baseDatos.set(u.usuario, {
        usuario: u.usuario, nombre: u.nombre, rol: u.rol, programa: u.programa, mfa: u.mfa, salt, hash,
      });
    }
  }

  function usuariosDePrueba() {
    return usuariosSemilla.map(({ usuario, contrasena, mfa }) => ({ usuario, contrasena, mfa }));
  }

  function tablaBaseDatos() {
    return [...baseDatos.values()].map((r) => ({ ...r }));
  }

  /* ---------- Capa 3: límite de intentos por IP ---------- */

  function estadoIp(ip) {
    if (!intentosPorIp.has(ip)) intentosPorIp.set(ip, { fallidos: 0, bloqueadoHasta: 0 });
    return intentosPorIp.get(ip);
  }

  function revisarLimite(ip) {
    const e = estadoIp(ip);
    const ahora = Date.now();
    if (e.bloqueadoHasta > ahora) {
      return { permitido: false, fallidos: e.fallidos, segundosRestantes: Math.ceil((e.bloqueadoHasta - ahora) / 1000) };
    }
    if (e.bloqueadoHasta) {
      e.fallidos = 0;
      e.bloqueadoHasta = 0;
    }
    return { permitido: true, fallidos: e.fallidos };
  }

  function registrarFallo(ip) {
    const e = estadoIp(ip);
    e.fallidos += 1;
    let bloqueado = false;
    if (e.fallidos >= CONFIG.maxIntentos) {
      e.bloqueadoHasta = Date.now() + CONFIG.bloqueoSegundos * 1000;
      bloqueado = true;
    }
    return { fallidos: e.fallidos, bloqueado };
  }

  function limpiarFallos(ip) {
    intentosPorIp.set(ip, { fallidos: 0, bloqueadoHasta: 0 });
  }

  /* ---------- Capa 4: búsqueda del usuario ---------- */

  function buscarUsuario(usuario) {
    const registro = baseDatos.get(String(usuario).trim().toLowerCase());
    return registro ? { ...registro } : null;
  }

  /* ---------- Capa 5: verificación de la contraseña ---------- */

  async function verificarContrasena(registro, contrasena) {
    const inicio = performance.now();
    const calculado = await Cripto.pbkdf2(contrasena, registro.salt, CONFIG.iteraciones);
    const ms = Math.round(performance.now() - inicio);
    return {
      calculado,
      guardado: registro.hash,
      coincide: Cripto.compararSeguro(calculado, registro.hash),
      ms,
      iteraciones: CONFIG.iteraciones,
    };
  }

  /* ---------- Capa 6: segundo factor ---------- */

  function generarMfa(usuario) {
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
    const codigo = String(n).padStart(6, '0');
    mfaPendientes.set(usuario, { codigo, vence: Date.now() + CONFIG.vidaMfaSegundos * 1000 });
    return { codigo, segundos: CONFIG.vidaMfaSegundos };
  }

  function verificarMfa(usuario, codigo) {
    const pendiente = mfaPendientes.get(usuario);
    mfaPendientes.delete(usuario);
    if (!pendiente) return { valido: false, motivo: 'No había ningún código pendiente para este usuario.' };
    if (Date.now() > pendiente.vence) return { valido: false, motivo: 'El código venció. Los códigos solo duran unos segundos.' };
    if (String(codigo || '').trim() !== pendiente.codigo) return { valido: false, motivo: 'El código no coincide con el que se envió al teléfono.' };
    return { valido: true };
  }

  /* ---------- Capa 7: emisión del JWT ---------- */

  async function emitirToken(usuario, opciones = {}) {
    const r = baseDatos.get(usuario);
    const ahora = Math.floor(Date.now() / 1000);
    const iat = opciones.vencido ? ahora - CONFIG.vidaTokenSegundos - 120 : ahora;
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      iss: CONFIG.dominio,
      sub: r.usuario,
      nombre: r.nombre,
      rol: r.rol,
      iat,
      exp: iat + CONFIG.vidaTokenSegundos,
    };
    const h = Cripto.textoABase64url(JSON.stringify(header));
    const p = Cripto.textoABase64url(JSON.stringify(payload));
    const f = await Cripto.firmarHMAC(claveFirma, `${h}.${p}`);
    return { token: `${h}.${p}.${f}`, partes: [h, p, f], header, payload };
  }

  function decodificarToken(token) {
    const partes = String(token).split('.');
    if (partes.length !== 3) throw new Error('formato');
    return {
      partes,
      header: JSON.parse(Cripto.base64urlATexto(partes[0])),
      payload: JSON.parse(Cripto.base64urlATexto(partes[1])),
    };
  }

  /* ---------- Capa 8: verificación del token en cada petición ---------- */

  async function verificarToken(token) {
    let dec;
    try {
      dec = decodificarToken(token);
    } catch (e) {
      return { valido: false, codigo: 401, motivo: 'El token no tiene el formato de un JWT (tres partes separadas por puntos).' };
    }
    const { partes, header, payload } = dec;
    const r = { partes, header, payload, firmaRecibida: partes[2] };

    r.algoritmoValido = header.alg === 'HS256';
    if (!r.algoritmoValido) {
      return { ...r, valido: false, codigo: 401, motivo: `El algoritmo "${header.alg}" no está permitido. El servidor solo acepta HS256.` };
    }

    r.firmaEsperada = await Cripto.firmarHMAC(claveFirma, `${partes[0]}.${partes[1]}`);
    r.firmaValida = Cripto.compararSeguro(r.firmaEsperada, partes[2]);
    r.ahora = Math.floor(Date.now() / 1000);
    r.vigente = typeof payload.exp === 'number' && payload.exp > r.ahora;

    if (!r.firmaValida) {
      return { ...r, valido: false, codigo: 401, motivo: 'La firma no coincide: alguien modificó el contenido del token o no lo emitió este servidor.' };
    }
    if (!r.vigente) {
      return { ...r, valido: false, codigo: 401, motivo: 'El token está vencido. Hay que volver a iniciar sesión.' };
    }
    return { ...r, valido: true, codigo: 200 };
  }

  function obtenerPerfil(usuario) {
    const r = baseDatos.get(usuario);
    return r ? { usuario: r.usuario, nombre: r.nombre, rol: r.rol, programa: r.programa } : null;
  }

  return {
    CONFIG,
    iniciar,
    usuariosDePrueba,
    tablaBaseDatos,
    revisarLimite,
    registrarFallo,
    limpiarFallos,
    buscarUsuario,
    verificarContrasena,
    generarMfa,
    verificarMfa,
    emitirToken,
    decodificarToken,
    verificarToken,
    obtenerPerfil,
  };
})();
