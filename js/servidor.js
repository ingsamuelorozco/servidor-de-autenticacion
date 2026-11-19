/*
 * servidor.js
 * Servidor AAA (RADIUS) simulado. En la vida real es otra máquina, por ejemplo
 * FreeRADIUS o Cisco ISE; aquí vive en el navegador para poder mostrar cada paso.
 */
const Servidor = (() => {
  'use strict';

  const CONFIG = {
    ip: '10.10.0.10',
    puertoAuth: 1812,
    puertoAcct: 1813,
    iteraciones: 100000,
    vidaDesafioSegundos: 60,
  };

  /* Clientes RADIUS: los NAS que el servidor conoce, cada uno con su secreto compartido. */
  const CLIENTES = {
    '10.10.0.2': { nombre: 'AP-Biblioteca', tipo: 'Punto de acceso Wi-Fi (802.1X)', secreto: 'usc-radius-2026' },
  };

  /* Solo se usan al arrancar para crear los hashes. Nunca se guardan así. */
  const usuariosSemilla = [
    {
      usuario: 'ana', contrasena: 'usc2026', nombre: 'Ana Gómez', grupo: 'estudiantes', mfa: false,
      autorizacion: { vlan: 20, acl: 'ACL-ESTUDIANTES', sesionMax: 3600, privilegio: null },
    },
    {
      usuario: 'admin', contrasena: 'admin123', nombre: 'Administrador de red', grupo: 'administradores', mfa: true,
      autorizacion: { vlan: 99, acl: 'ACL-GESTION', sesionMax: 1800, privilegio: 15 },
    },
  ];

  const baseUsuarios = new Map();
  const desafios = new Map();
  const sesiones = new Map();

  async function iniciar() {
    for (const u of usuariosSemilla) {
      const salt = Cripto.aHex(Cripto.aleatorios(8));
      const hash = await Cripto.pbkdf2(u.contrasena, salt, CONFIG.iteraciones);
      baseUsuarios.set(u.usuario, {
        usuario: u.usuario, nombre: u.nombre, grupo: u.grupo, mfa: u.mfa, autorizacion: u.autorizacion, salt, hash,
      });
    }
  }

  function usuariosDePrueba() {
    return usuariosSemilla.map(({ usuario, contrasena, mfa }) => ({ usuario, contrasena, mfa }));
  }

  function tablaUsuarios() {
    return [...baseUsuarios.values()].map((r) => ({ ...r }));
  }

  /* ---------- Clientes RADIUS (NAS) ---------- */

  function cliente(ip) {
    return CLIENTES[ip] || null;
  }

  /* ---------- Autenticación: base de usuarios ---------- */

  function buscarUsuario(usuario) {
    return baseUsuarios.get(String(usuario).trim().toLowerCase()) || null;
  }

  async function verificarContrasena(registro, contrasena) {
    const inicio = performance.now();
    const calculado = await Cripto.pbkdf2(contrasena, registro.salt, CONFIG.iteraciones);
    return {
      calculado,
      guardado: registro.hash,
      coincide: Cripto.iguales(Cripto.texto(calculado), Cripto.texto(registro.hash)),
      ms: Math.round(performance.now() - inicio),
      iteraciones: CONFIG.iteraciones,
    };
  }

  /* ---------- Access-Challenge: segundo factor ---------- */

  function crearDesafio(usuario) {
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
    const codigo = String(n).padStart(6, '0');
    const state = Cripto.aleatorios(16);
    desafios.set(Cripto.aHex(state), { usuario, codigo, vence: Date.now() + CONFIG.vidaDesafioSegundos * 1000 });
    return { codigo, state, segundos: CONFIG.vidaDesafioSegundos };
  }

  function verificarDesafio(state, usuario, codigo) {
    const clave = state ? Cripto.aHex(state) : '';
    const d = desafios.get(clave);
    desafios.delete(clave);
    if (!d || d.usuario !== usuario) return { valido: false, motivo: 'El atributo State no corresponde a ningún desafío pendiente.' };
    if (Date.now() > d.vence) return { valido: false, motivo: 'El código venció. Los códigos solo duran unos segundos.' };
    if (String(codigo || '').trim() !== d.codigo) return { valido: false, motivo: 'El código no coincide con el que se envió al teléfono.' };
    return { valido: true };
  }

  /* ---------- Autorización: atributos del Access-Accept ---------- */

  function atributosAutorizacion(registro) {
    const a = registro.autorizacion;
    const { atr, v } = Radius;
    const lista = [
      atr(18, v.texto(`Bienvenido, ${registro.nombre}`)),
      atr(64, v.tunel(13)),
      atr(65, v.tunel(6)),
      atr(81, v.texto(String(a.vlan))),
      atr(11, v.texto(a.acl)),
      atr(27, v.entero(a.sesionMax)),
    ];
    if (a.privilegio) lista.push(atr(26, v.vsa(Radius.VENDOR_CISCO, 1, `shell:priv-lvl=${a.privilegio}`)));
    return lista;
  }

  /* ---------- Contabilidad ---------- */

  function registrarContabilidad(datos) {
    const anterior = sesiones.get(datos.sesionId) || { inicio: new Date() };
    const fila = {
      ...anterior,
      sesionId: datos.sesionId,
      usuario: datos.usuario,
      nas: datos.nas,
      ip: datos.ip,
      estado: datos.tipo === 'Stop' ? 'cerrada' : 'activa',
      ultimo: datos.tipo,
      segundos: datos.segundos,
      entrada: datos.entrada,
      salida: datos.salida,
    };
    sesiones.set(datos.sesionId, fila);
    return fila;
  }

  function tablaContabilidad() {
    return [...sesiones.values()].map((s) => ({ ...s }));
  }

  function reiniciar() {
    desafios.clear();
    sesiones.clear();
  }

  return {
    CONFIG,
    iniciar,
    usuariosDePrueba,
    tablaUsuarios,
    cliente,
    buscarUsuario,
    verificarContrasena,
    crearDesafio,
    verificarDesafio,
    atributosAutorizacion,
    registrarContabilidad,
    tablaContabilidad,
    reiniciar,
  };
})();
