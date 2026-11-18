# Servidor de autenticación por capas

Demostración interactiva para la exposición en la **Universidad Santiago de Cali**. Muestra qué pasa por dentro de un servidor de autenticación desde que el usuario le da clic a "Iniciar sesión" hasta que puede usar una ruta protegida.

La página tiene tres columnas:

1. **Lo que ve el usuario:** el formulario de inicio de sesión, el teléfono para el código de verificación y la sesión iniciada.
2. **El recorrido por capas:** las 8 capas por las que pasa la petición, que se van marcando como superadas, rechazadas o no aplican.
3. **¿Qué está pasando?:** los datos reales de cada paso, como la petición HTTP, el texto cifrado, los hashes, el JWT y la respuesta del servidor.

Abajo hay una bitácora con todas las peticiones y sus códigos HTTP.

## Cómo abrirlo

No necesita instalar nada ni internet. Solo hay que abrir `index.html` con doble clic en Chrome, Edge o Firefox.

## Usuarios de prueba

| Usuario | Contraseña | MFA |
|---------|------------|-----|
| ana     | usc2026    | no  |
| admin   | admin123   | sí  |

En la tabla de la página se puede dar clic al nombre del usuario para llenar el formulario.

## Las capas

| # | Capa | Qué muestra |
|---|------|-------------|
| 1 | Cliente (navegador) | Validación del formulario y la petición `POST /login` |
| 2 | HTTPS / TLS | La petición cifrada con AES-GCM, lo que vería alguien espiando la red |
| 3 | Gateway y límite de intentos | Bloqueo de la IP con 429 después de 3 fallos (30 segundos) |
| 4 | Búsqueda del usuario | La tabla de la base de datos: solo salt y hash, nunca la contraseña |
| 5 | Verificación de contraseña | PBKDF2-SHA256 con 100.000 iteraciones y la comparación de hashes |
| 6 | Segundo factor (MFA) | Código de 6 dígitos enviado a un teléfono simulado |
| 7 | Emisión del token (JWT) | Header, payload y firma HMAC-SHA256 por colores |
| 8 | Recurso protegido | Verificación de la firma y la fecha de vencimiento en cada petición |

## Controles

- **Paso a paso:** se avanza con el botón "Siguiente paso", la flecha derecha o el control de presentaciones (Av Pág).
- **Automático:** avanza solo cada 2,6 segundos.
- **Reiniciar todo:** limpia la sesión, la bitácora y el bloqueo de intentos.

## Guion sugerido para la exposición

1. Mostrar la base de datos de la pantalla inicial: no hay contraseñas guardadas, solo hashes.
2. Iniciar sesión con `ana` en modo paso a paso y explicar cada capa.
3. Con la sesión iniciada, pedir el perfil: las capas 4 a 7 no se usan porque el token se basta solo.
4. Alterar el token para volverse admin: la firma no coincide y el servidor responde 401.
5. Usar un token vencido: la firma es válida, pero ya expiró.
6. Cerrar sesión e intentar con una contraseña mala tres veces: a la cuarta responde el gateway con 429.
7. Probar un usuario que no existe: el mensaje es el mismo que con la contraseña mala, para no revelar qué cuentas existen.
8. Iniciar sesión con `admin` para mostrar el segundo factor.

## Estructura

```
index.html        estructura de la página
css/estilos.css   estilos, modo oscuro automático y diseño para celular
js/cripto.js      funciones criptográficas con la Web Crypto API
js/servidor.js    servidor de autenticación simulado (usuarios, límite de intentos, MFA, JWT)
js/app.js         conecta el formulario con el servidor y dibuja cada capa
```

## Nota

Es una demostración educativa. El "servidor" corre dentro del mismo navegador para poder ver cada paso, pero la criptografía sí es real (PBKDF2, AES-GCM y HMAC-SHA256). En un sistema real el servidor está en otra máquina, la llave secreta nunca llega al navegador y el TLS lo maneja el protocolo HTTPS.
