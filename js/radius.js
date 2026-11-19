/*
 * radius.js
 * Arma y lee paquetes RADIUS reales, byte a byte (RFC 2865 y 2866).
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  |     Code      |  Identifier   |            Length             |
 *  |                     Authenticator (16 bytes)                  |
 *  |  Attributes (TLV: Type 1 byte, Length 1 byte, Value) ...
 */
const Radius = (() => {
  'use strict';

  const CODIGOS = {
    1: 'Access-Request',
    2: 'Access-Accept',
    3: 'Access-Reject',
    4: 'Accounting-Request',
    5: 'Accounting-Response',
    11: 'Access-Challenge',
  };

  /* Diccionario de atributos usados en la demo. formato: cómo leer el Value. */
  const ATRIBUTOS = {
    1: { nombre: 'User-Name', formato: 'texto' },
    2: { nombre: 'User-Password', formato: 'oculto' },
    4: { nombre: 'NAS-IP-Address', formato: 'ip' },
    5: { nombre: 'NAS-Port', formato: 'entero' },
    8: { nombre: 'Framed-IP-Address', formato: 'ip' },
    11: { nombre: 'Filter-Id', formato: 'texto' },
    18: { nombre: 'Reply-Message', formato: 'texto' },
    24: { nombre: 'State', formato: 'hex' },
    26: { nombre: 'Vendor-Specific', formato: 'vsa' },
    27: { nombre: 'Session-Timeout', formato: 'entero' },
    30: { nombre: 'Called-Station-Id', formato: 'texto' },
    31: { nombre: 'Calling-Station-Id', formato: 'texto' },
    40: { nombre: 'Acct-Status-Type', formato: 'enum', valores: { 1: 'Start', 2: 'Stop', 3: 'Interim-Update' } },
    42: { nombre: 'Acct-Input-Octets', formato: 'entero' },
    43: { nombre: 'Acct-Output-Octets', formato: 'entero' },
    44: { nombre: 'Acct-Session-Id', formato: 'texto' },
    46: { nombre: 'Acct-Session-Time', formato: 'entero' },
    49: { nombre: 'Acct-Terminate-Cause', formato: 'enum', valores: { 1: 'User-Request', 4: 'Idle-Timeout', 5: 'Session-Timeout' } },
    61: { nombre: 'NAS-Port-Type', formato: 'enum', valores: { 15: 'Ethernet', 19: 'Wireless-802.11' } },
    64: { nombre: 'Tunnel-Type', formato: 'tunel', valores: { 13: 'VLAN' } },
    65: { nombre: 'Tunnel-Medium-Type', formato: 'tunel', valores: { 6: 'IEEE-802' } },
    80: { nombre: 'Message-Authenticator', formato: 'hex' },
    81: { nombre: 'Tunnel-Private-Group-ID', formato: 'texto' },
  };

  const VENDOR_CISCO = 9;

  /* ---------- Codificar valores ---------- */

  const v = {
    texto: (t) => Cripto.texto(String(t)),
    ip: (ip) => Uint8Array.from(ip.split('.').map(Number)),
    entero(n) {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, n >>> 0);
      return b;
    },
    /* Tunnel-Type y Tunnel-Medium-Type: 1 byte de Tag + 3 bytes de valor (RFC 2868) */
    tunel(n) {
      const b = v.entero(n);
      b[0] = 0;
      return b;
    },
    /* Vendor-Specific: Vendor-Id (4 bytes) + sub-atributo TLV del fabricante */
    vsa(vendorId, tipo, valor) {
      const dato = Cripto.texto(valor);
      return Cripto.unir(v.entero(vendorId), Uint8Array.of(tipo, dato.length + 2), dato);
    },
  };

  const atr = (type, value) => ({ type, value });

  /* ---------- Armar y leer paquetes ---------- */

  function serializar(code, id, autenticador, atributos) {
    const cuerpo = Cripto.unir(...atributos.map((a) => Cripto.unir(Uint8Array.of(a.type, a.value.length + 2), a.value)));
    const largo = 20 + cuerpo.length;
    const cabecera = new Uint8Array(4);
    cabecera[0] = code;
    cabecera[1] = id;
    new DataView(cabecera.buffer).setUint16(2, largo);
    return Cripto.unir(cabecera, autenticador, cuerpo);
  }

  function leer(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const p = {
      code: bytes[0],
      id: bytes[1],
      length: dv.getUint16(2),
      authenticator: bytes.slice(4, 20),
      atributos: [],
    };
    let pos = 20;
    while (pos < p.length) {
      const type = bytes[pos];
      const len = bytes[pos + 1];
      p.atributos.push({ type, length: len, value: bytes.slice(pos + 2, pos + len), offset: pos });
      pos += len;
    }
    return p;
  }

  function buscar(paquete, type) {
    const a = paquete.atributos.find((x) => x.type === type);
    return a ? a.value : null;
  }

  /* Posición del Value de Message-Authenticator, para rellenarlo después de calcularlo. */
  function posicionMA(bytes) {
    const p = leer(bytes);
    const a = p.atributos.find((x) => x.type === 80);
    return a ? a.offset + 2 : -1;
  }

  /* ---------- Ocultar User-Password (RFC 2865, sección 5.2) ----------
   * b1 = MD5(secreto + Request Authenticator)   c1 = p1 XOR b1
   * b2 = MD5(secreto + c1)                      c2 = p2 XOR b2 ...
   */
  function ocultarClave(clave, secreto, ra) {
    const plano = Cripto.texto(clave);
    const largo = Math.max(16, Math.ceil(plano.length / 16) * 16);
    const relleno = new Uint8Array(largo);
    relleno.set(plano);
    const salida = new Uint8Array(largo);
    const pasos = [];
    let anterior = ra;
    for (let i = 0; i < largo; i += 16) {
      const b = Cripto.md5(Cripto.unir(Cripto.texto(secreto), anterior));
      const c = Cripto.xor(relleno.slice(i, i + 16), b);
      salida.set(c, i);
      pasos.push({ p: relleno.slice(i, i + 16), b, c });
      anterior = c;
    }
    return { cifrado: salida, pasos };
  }

  function revelarClave(cifrado, secreto, ra) {
    const plano = new Uint8Array(cifrado.length);
    let anterior = ra;
    for (let i = 0; i < cifrado.length; i += 16) {
      const c = cifrado.slice(i, i + 16);
      const b = Cripto.md5(Cripto.unir(Cripto.texto(secreto), anterior));
      plano.set(Cripto.xor(c, b), i);
      anterior = c;
    }
    let fin = plano.length;
    while (fin > 0 && plano[fin - 1] === 0) fin--;
    return { bytes: plano, texto: new TextDecoder('utf-8', { fatal: false }).decode(plano.slice(0, fin)) };
  }

  /* ---------- Message-Authenticator (RFC 3579) ----------
   * HMAC-MD5(secreto, paquete completo con el Message-Authenticator en ceros).
   * En las respuestas se calcula usando el Request Authenticator de la petición.
   */
  function calcularMA(bytes, secreto, autenticadorParaCalculo) {
    const copia = bytes.slice();
    const pos = posicionMA(copia);
    copia.fill(0, pos, pos + 16);
    if (autenticadorParaCalculo) copia.set(autenticadorParaCalculo, 4);
    return Cripto.hmacMd5(Cripto.texto(secreto), copia);
  }

  function ponerMA(bytes, secreto, autenticadorParaCalculo) {
    const ma = calcularMA(bytes, secreto, autenticadorParaCalculo);
    bytes.set(ma, posicionMA(bytes));
    return ma;
  }

  function verificarMA(bytes, secreto, autenticadorParaCalculo) {
    const pos = posicionMA(bytes);
    if (pos < 0) return { presente: false, valido: false };
    const recibido = bytes.slice(pos, pos + 16);
    const esperado = calcularMA(bytes, secreto, autenticadorParaCalculo);
    return { presente: true, valido: Cripto.iguales(recibido, esperado), recibido, esperado };
  }

  /* ---------- Autenticador de respuesta y de contabilidad ----------
   * Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Atributos + secreto)
   * Accounting Request Authenticator = igual, pero con 16 bytes en cero en lugar del RA.
   */
  function autenticadorMD5(bytes, autenticadorBase, secreto) {
    const copia = bytes.slice();
    copia.set(autenticadorBase, 4);
    return Cripto.md5(Cripto.unir(copia, Cripto.texto(secreto)));
  }

  /* ---------- Constructores de alto nivel ---------- */

  /* Petición con Message-Authenticator: lo calcula y lo rellena. */
  function peticion(code, id, autenticador, atributos, secreto) {
    const lista = [...atributos, atr(80, new Uint8Array(16))];
    const bytes = serializar(code, id, autenticador, lista);
    ponerMA(bytes, secreto);
    return bytes;
  }

  /* Respuesta (Accept, Reject, Challenge): MA con el RA de la petición, luego Response Authenticator. */
  function respuesta(code, id, ra, atributos, secreto) {
    const lista = [...atributos, atr(80, new Uint8Array(16))];
    const bytes = serializar(code, id, ra, lista);
    ponerMA(bytes, secreto, ra);
    bytes.set(autenticadorMD5(bytes, ra, secreto), 4);
    return bytes;
  }

  function contabilidad(code, id, atributos, secreto, raPeticion) {
    const bytes = serializar(code, id, new Uint8Array(16), atributos);
    bytes.set(autenticadorMD5(bytes, raPeticion || new Uint8Array(16), secreto), 4);
    return bytes;
  }

  function verificarAutenticador(bytes, autenticadorBase, secreto) {
    const recibido = bytes.slice(4, 20);
    const esperado = autenticadorMD5(bytes, autenticadorBase, secreto);
    return { valido: Cripto.iguales(recibido, esperado), recibido, esperado };
  }

  /* ---------- Mostrar valores ---------- */

  function valorLegible(type, value) {
    const d = ATRIBUTOS[type] || { formato: 'hex' };
    const dv = new DataView(value.buffer, value.byteOffset, value.byteLength);
    switch (d.formato) {
      case 'texto': return `"${Cripto.aTexto(value)}"`;
      case 'ip': return [...value].join('.');
      case 'entero': return String(dv.getUint32(0));
      case 'enum': { const n = dv.getUint32(0); return `${d.valores[n] || '?'} (${n})`; }
      case 'tunel': { const n = dv.getUint32(0) & 0xffffff; return `${d.valores[n] || '?'} (${n})`; }
      case 'oculto': return `${Cripto.aHex(value)} (cifrada)`;
      case 'vsa': {
        const vendor = dv.getUint32(0);
        const sub = Cripto.aTexto(value.slice(6));
        return `${vendor === VENDOR_CISCO ? 'Cisco (9)' : vendor}: "${sub}"`;
      }
      default: return Cripto.aHex(value);
    }
  }

  function nombreAtributo(type) {
    return (ATRIBUTOS[type] || { nombre: `Atributo ${type}` }).nombre;
  }

  return {
    CODIGOS, ATRIBUTOS, VENDOR_CISCO,
    v, atr, serializar, leer, buscar,
    ocultarClave, revelarClave,
    verificarMA, peticion, respuesta, contabilidad, verificarAutenticador,
    valorLegible, nombreAtributo,
  };
})();
