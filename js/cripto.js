/*
 * cripto.js
 * Funciones criptográficas reales usando la Web Crypto API del navegador.
 * Se usan scripts clásicos (no módulos) para que la página funcione
 * abriendo index.html directamente desde el computador.
 */
const Cripto = (() => {
  'use strict';

  const codificador = new TextEncoder();
  const decodificador = new TextDecoder();

  function bytesAHex(buffer) {
    return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function bytesABase64(buffer) {
    let binario = '';
    new Uint8Array(buffer).forEach((b) => { binario += String.fromCharCode(b); });
    return btoa(binario);
  }

  function bytesABase64url(buffer) {
    return bytesABase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function textoABase64url(texto) {
    return bytesABase64url(codificador.encode(texto));
  }

  function base64urlATexto(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const binario = atob(b64);
    const bytes = Uint8Array.from(binario, (c) => c.charCodeAt(0));
    return decodificador.decode(bytes);
  }

  function saltAleatorio(longitud = 16) {
    return bytesAHex(crypto.getRandomValues(new Uint8Array(longitud)));
  }

  /* Hash de contraseña lento a propósito (PBKDF2 con SHA-256). */
  async function pbkdf2(contrasena, saltHex, iteraciones) {
    const material = await crypto.subtle.importKey(
      'raw', codificador.encode(contrasena), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: codificador.encode(saltHex), iterations: iteraciones, hash: 'SHA-256' },
      material,
      256
    );
    return bytesAHex(bits);
  }

  /* Comparación en tiempo constante: no se detiene en el primer carácter distinto. */
  function compararSeguro(a, b) {
    if (a.length !== b.length) return false;
    let diferencia = 0;
    for (let i = 0; i < a.length; i++) diferencia |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diferencia === 0;
  }

  /* Simula el cifrado del canal TLS con AES-GCM de 256 bits. */
  async function cifrarAES(texto) {
    const clave = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, clave, codificador.encode(texto));
    return { clave, iv, cifrado, base64: bytesABase64(cifrado), ivHex: bytesAHex(iv) };
  }

  async function descifrarAES(paquete) {
    const plano = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: paquete.iv }, paquete.clave, paquete.cifrado);
    return decodificador.decode(plano);
  }

  /* Llave secreta del servidor para firmar los JWT. */
  function crearClaveHMAC() {
    return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }

  async function firmarHMAC(clave, texto) {
    const firma = await crypto.subtle.sign('HMAC', clave, codificador.encode(texto));
    return bytesABase64url(firma);
  }

  function disponible() {
    return Boolean(window.crypto && window.crypto.subtle);
  }

  return {
    disponible,
    textoABase64url,
    base64urlATexto,
    saltAleatorio,
    pbkdf2,
    compararSeguro,
    cifrarAES,
    descifrarAES,
    crearClaveHMAC,
    firmarHMAC,
  };
})();
