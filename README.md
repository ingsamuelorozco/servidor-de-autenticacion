# Servidor de autenticación AAA con RADIUS

Demostración interactiva para la exposición de **Redes y comunicaciones** en la **Universidad Santiago de Cali**. Muestra cómo un servidor AAA decide **quién entra a la red** (autenticación), **qué puede hacer** (autorización) y **deja registro de lo que hizo** (contabilidad), paquete por paquete.

Todo cabe en una sola pantalla, sin hacer scroll. Arriba está la arquitectura: **Cliente → NAS → Servidor AAA → Base de usuarios**, con una flecha que indica qué mensaje está viajando en cada momento. Debajo hay tres columnas:

1. **El usuario:** el formulario para conectarse al Wi-Fi, el teléfono con el código de verificación, la sesión conectada (VLAN, IP, ACL, tiempo y datos) y los últimos paquetes que pasaron por la red.
2. **La secuencia RADIUS:** los 8 pasos, que se marcan con ✓, ✗ u omitido según avanza el proceso.
3. **Paso actual:** una explicación corta y el paquete RADIUS de ese paso (Code, Identifier, Length, Authenticator y atributos TLV).

El detalle técnico aparece al pasar el mouse sobre los botones **i**: bytes en hexadecimal, cálculos de MD5, comparación de hashes, reglas de las ACL, la comparación RADIUS frente a TACACS+, etc.

## Cómo abrirlo

No necesita instalar nada ni internet. Solo hay que abrir `index.html` con doble clic en Chrome, Edge o Firefox.

## Usuarios de prueba

| Usuario | Contraseña | Segundo factor | Autorización |
|---------|------------|----------------|--------------|
| ana     | usc2026    | no             | VLAN 20, ACL-ESTUDIANTES |
| admin   | admin123   | sí (Access-Challenge) | VLAN 99, ACL-GESTION, priv-lvl 15 |

En la tabla de la página se puede dar clic al nombre del usuario para llenar el formulario.

Otros casos para mostrar:

- **Contraseña mala o usuario que no existe:** el servidor responde Access-Reject (3).
- **Código de verificación equivocado:** el Access-Challenge falla y llega un Access-Reject.

## La secuencia

| # | Paso | Qué muestra |
|---|------|-------------|
| 1 | Cliente → NAS | Solicitud de acceso con las credenciales |
| 2 | NAS → Servidor | Access-Request (1) por UDP 1812. La contraseña va oculta con MD5(secreto + Request Authenticator) y el resto va en claro |
| 3 | Servidor AAA | Revisa que el NAS esté registrado, verifica el Message-Authenticator (HMAC-MD5) y descifra la contraseña |
| 4 | Base de usuarios | Busca al usuario y compara el hash PBKDF2 (nunca guarda la contraseña) |
| 5 | Servidor → NAS | Access-Challenge (11), opcional: pide el segundo factor con Reply-Message y State |
| 6 | Servidor → NAS | Access-Accept (2) con atributos de autorización (VLAN, Filter-Id, Session-Timeout, Vendor-Specific) o Access-Reject (3) |
| 7 | NAS → Cliente | El NAS aplica la VLAN y la ACL, o niega el acceso |
| 8 | Contabilidad | Accounting-Request (4) Start, Interim-Update o Stop por UDP 1813, y su Accounting-Response (5) |

Con la sesión abierta, los botones **Enviar reporte** y **Desconectarse** mandan los mensajes Interim-Update y Stop.

## Cómo avanza

Los pasos avanzan solos cada 10 segundos, para alcanzar a leerlos. Con la flecha derecha o Av Pág (o el control de presentaciones) se puede adelantar un paso.

Cuando termina, se puede hacer clic en cualquier paso de la secuencia para volver a verlo con su paquete y su flecha. Si un paso tuvo varias partes (por ejemplo, Accounting-Request y Accounting-Response), cada clic muestra la siguiente.

## Estructura

```
index.html        estructura de la página
css/estilos.css   estilos, modo oscuro automático y diseño para celular
js/cripto.js      MD5, HMAC-MD5 y PBKDF2
js/radius.js      arma y lee paquetes RADIUS byte a byte (RFC 2865 y 2866)
js/servidor.js    servidor AAA simulado (NAS registrados, base de usuarios, desafíos, contabilidad)
js/app.js         hace de cliente y de NAS, y dibuja cada paso
```
