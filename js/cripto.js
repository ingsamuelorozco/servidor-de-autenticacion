/*
 * cripto.js
 * Funciones criptográficas reales. RADIUS (RFC 2865) usa MD5 para ocultar la
 * contraseña y para los autenticadores, y HMAC-MD5 para el atributo
 * Message-Authenticator. La Web Crypto API no trae MD5, así que se implementa aquí.
 * PBKDF2 (para guardar las contraseñas en la base de usuarios) sí viene del navegador.
 * Se usan scripts clásicos (no módulos) para que la página funcione con doble clic.
 */
const Cripto = (() => {
  'use strict';

  const codificador = new TextEncoder();
  const decodificador = new TextDecoder();

  /* ---------- Conversión de datos ---------- */

  const texto = (t) => codificador.encode(t);
  const aTexto = (bytes) => decodificador.decode(bytes);

  function aHex(bytes, separador = '') {
    return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(separador);
  }

  function unir(...partes) {
    const total = partes.reduce((n, p) => n + p.length, 0);
    const salida = new Uint8Array(total);
    let pos = 0;
    for (const p of partes) { salida.set(p, pos); pos += p.length; }
    return salida;
  }

  function aleatorios(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  function xor(a, b) {
    return a.map((x, i) => x ^ b[i]);
  }

  /* Comparación en tiempo constante: no se detiene en el primer byte distinto. */
  function iguales(a, b) {
    if (a.length !== b.length) return false;
    let dif = 0;
    for (let i = 0; i < a.length; i++) dif |= a[i] ^ b[i];
    return dif === 0;
  }

  /* ---------- MD5 (RFC 1321) ---------- */

  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

  function md5(datos) {
    const largo = datos.length;
    const total = Math.ceil((largo + 9) / 64) * 64;
    const buf = new Uint8Array(total);
    buf.set(datos);
    buf[largo] = 0x80;
    const dv = new DataView(buf.buffer);
    const bits = largo * 8;
    dv.setUint32(total - 8, bits >>> 0, true);
    dv.setUint32(total - 4, Math.floor(bits / 2 ** 32), true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let off = 0; off < total; off += 64) {
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + dv.getUint32(off + g * 4, true)) >>> 0;
        const s = S[(i >> 4) * 4 + (i % 4)];
        A = D; D = C; C = B;
        B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    const o = new DataView(out.buffer);
    [a0, b0, c0, d0].forEach((v, i) => o.setUint32(i * 4, v, true));
    return out;
  }

  /* HMAC-MD5 (RFC 2104), usado por Message-Authenticator (RFC 3579). */
  function hmacMd5(clave, datos) {
    let k = clave.length > 64 ? md5(clave) : clave;
    const bloque = new Uint8Array(64);
    bloque.set(k);
    const ipad = bloque.map((b) => b ^ 0x36);
    const opad = bloque.map((b) => b ^ 0x5c);
    return md5(unir(opad, md5(unir(ipad, datos))));
  }

  /* ---------- PBKDF2 para la base de usuarios ---------- */

  async function pbkdf2(contrasena, saltHex, iteraciones) {
    const material = await crypto.subtle.importKey('raw', texto(contrasena), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: texto(saltHex), iterations: iteraciones, hash: 'SHA-256' },
      material,
      256
    );
    return aHex(new Uint8Array(bits));
  }

  function disponible() {
    return Boolean(typeof crypto !== 'undefined' && crypto.subtle && crypto.getRandomValues);
  }

  return { disponible, texto, aTexto, aHex, unir, aleatorios, xor, iguales, md5, hmacMd5, pbkdf2 };
})();
