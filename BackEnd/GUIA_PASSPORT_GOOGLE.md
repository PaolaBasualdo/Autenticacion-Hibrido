# 📚 Guía Completa: Passport.js y Google OAuth

Esta guía explica cómo funciona la autenticación en nuestro proyecto usando Passport.js y Google OAuth.

## 📋 Tabla de Contenidos
1. [¿Qué es Passport.js?](#qué-es-passportjs)
2. [¿Qué son las Estrategias?](#qué-son-las-estrategias)
3. [Dependencias Necesarias](#dependencias-necesarias)
4. [Configuración de Google OAuth](#configuración-de-google-oauth)
5. [Cómo Funciona el Flujo Completo](#cómo-funciona-el-flujo-completo)
6. [Estructura del Código](#estructura-del-código)
7. [Configuración Paso a Paso](#configuración-paso-a-paso)
8. [Testing y Debugging](#testing-y-debugging)

---

## 🔐 ¿Qué es Passport.js?

**Passport.js** es una biblioteca de autenticación para Node.js que:

- ✅ **Simplifica la autenticación** - Maneja la complejidad de diferentes métodos de login
- ✅ **Es modular** - Cada tipo de autenticación es una "estrategia" separada
- ✅ **Soporta 500+ estrategias** - Google, Facebook, Twitter, GitHub, etc.
- ✅ **Se integra fácilmente** - Con Express.js y otros frameworks
- ✅ **Es flexible** - Funciona con sesiones o JWT

### 🤔 ¿Por qué usar Passport?

**Sin Passport:**
```javascript
// Necesitarías implementar manualmente:
- Redirigir a Google
- Manejar códigos de autorización
- Intercambiar códigos por tokens
- Obtener datos del usuario
- Manejar errores OAuth
- Validar tokens
// ¡Cientos de líneas de código complejo!
```

**Con Passport:**
```javascript
// Solo necesitas:
passport.use(new GoogleStrategy(config, callback));
app.get('/auth/google', passport.authenticate('google'));
// ¡Passport maneja toda la complejidad!
```

---

## 🧩 ¿Qué son las Estrategias?

Las **estrategias** son módulos que implementan un método específico de autenticación.

### 📚 Tipos de Estrategias en Nuestro Proyecto:

#### 1. **LocalStrategy** 🏠
```javascript
// Autenticación tradicional: email + password
import { Strategy as LocalStrategy } from 'passport-local';

passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    // Tu lógica de validación aquí
  }
));
```

**Cuándo se usa:** Cuando el usuario completa un formulario de login tradicional.

#### 2. **GoogleStrategy** 🔴
```javascript
// Autenticación OAuth 2.0 con Google
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

passport.use(new GoogleStrategy(
  {
    clientID: 'tu-client-id',
    clientSecret: 'tu-client-secret',
    callbackURL: '/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    // Tu lógica de usuario aquí
  }
));
```

**Cuándo se usa:** Cuando el usuario hace clic en "Login con Google".

### 🔄 ¿Cómo Funciona una Estrategia?

1. **Passport detecta** qué estrategia usar basado en la ruta
2. **La estrategia maneja** el proceso de autenticación específico
3. **Ejecuta el callback** con el resultado (usuario o error)
4. **Passport devuelve** el resultado a tu aplicación

---

## 📦 Dependencias Necesarias

### 🛠️ Dependencias Principales:

```json
{
  "passport": "^0.7.0",
  "passport-local": "^1.0.0",
  "passport-google-oauth20": "^2.0.0",
  "jsonwebtoken": "^9.0.2",
  "bcrypt": "^6.0.0"
}
```

### 📋 ¿Qué hace cada dependencia?

#### 1. **passport** 🔐
```bash
npm install passport
```
- **Qué es:** La biblioteca principal de Passport
- **Qué hace:** Proporciona la infraestructura base para autenticación
- **Incluye:** Middleware de Express, manejo de estrategias, serialización

#### 2. **passport-local** 🏠
```bash
npm install passport-local
```
- **Qué es:** Estrategia para autenticación con usuario/contraseña
- **Qué hace:** Maneja formularios de login tradicionales
- **Usa:** Campos como `username`, `password` (configurable)

#### 3. **passport-google-oauth20** 🔴
```bash
npm install passport-google-oauth20
```
- **Qué es:** Estrategia para Google OAuth 2.0
- **Qué hace:** Maneja todo el flujo OAuth con Google
- **Incluye:** Redirecciones, intercambio de tokens, obtención de perfil

#### 4. **jsonwebtoken** 🎫
```bash
npm install jsonwebtoken
```
- **Qué es:** Biblioteca para crear y verificar JWT tokens
- **Qué hace:** Genera tokens seguros sin necesidad de sesiones
- **Ventaja:** Stateless, escalable, no requiere almacenamiento en servidor

#### 5. **bcrypt** 🔒
```bash
npm install bcrypt
```
- **Qué es:** Biblioteca para hashear contraseñas
- **Qué hace:** Encripta contraseñas de forma segura
- **Por qué:** Las contraseñas nunca se guardan en texto plano

---

## 🚀 Configuración de Google OAuth

### 📝 Paso 1: Crear Proyecto en Google Cloud Console

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un nuevo proyecto o selecciona uno existente
3. Ve a "APIs & Services" > "Library"
4. Busca y habilita "Google+ API"

### 🔧 Paso 2: Configurar OAuth Consent Screen

1. Ve a "APIs & Services" > "OAuth consent screen"
2. Completa la información básica:
   - **Application name:** Tu App
   - **User support email:** tu-email@ejemplo.com
   - **Developer contact info:** tu-email@ejemplo.com

### 🔑 Paso 3: Crear Credenciales OAuth

1. Ve a "APIs & Services" > "Credentials"
2. Clic en "Create Credentials" > "OAuth 2.0 Client IDs"
3. Tipo de aplicación: "Web application"
4. Configurar URLs:

```
Authorized JavaScript origins:
http://localhost:3000

Authorized redirect URIs:
http://localhost:3000/api/auth/google/callback
```

5. **Guardar Client ID y Client Secret** - ¡Los necesitarás en tu .env!

### 📄 Paso 4: Configurar Variables de Entorno

```bash
# .env
GOOGLE_CLIENT_ID=123456789-abcdefghijklmnop.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-tu_secreto_real_aqui
```

---

## 🔄 Cómo Funciona el Flujo Completo

### 📊 Diagrama del Flujo OAuth:

```
1. [Usuario] 
   ↓ Clic "Login con Google"
   
2. [Frontend] 
   ↓ Redirige a: GET /api/auth/google
   
3. [Nuestro Servidor] 
   ↓ Passport redirige a Google
   
4. [Google] 
   ↓ Usuario autoriza → Redirige con código
   
5. [Nuestro Servidor] 
   ↓ GET /api/auth/google/callback
   
6. [Passport] 
   ↓ Intercambia código por tokens
   
7. [Google] 
   ↓ Devuelve access_token + profile
   
8. [Nuestra Estrategia] 
   ↓ Busca/crea usuario en BD
   
9. [Nuestro Servidor] 
   ↓ Genera JWT
   
10. [Frontend] 
    ✅ Recibe JWT + datos de usuario
```

### 🔍 Paso a Paso Detallado:

#### **Paso 1-2: Inicio del Flujo**
```javascript
// Frontend: Usuario hace clic en botón
window.location.href = '/api/auth/google';
```

#### **Paso 3: Passport Redirige a Google**
```javascript
// En nuestras rutas
router.get('/google', 
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
// Passport automáticamente redirige a:
// https://accounts.google.com/oauth/authorize?client_id=...&redirect_uri=...
```

#### **Paso 4-5: Google Procesa y Redirige**
```
Usuario autoriza en Google → Google redirige a:
http://localhost:3000/api/auth/google/callback?code=CODIGO_SECRETO
```

#### **Paso 6-8: Passport Procesa la Respuesta**
```javascript
// Passport automáticamente:
// 1. Extrae el código de la URL
// 2. Hace POST a Google para intercambiar código por tokens
// 3. Usa tokens para obtener perfil del usuario
// 4. Ejecuta nuestra función callback con los datos
```

#### **Paso 9-10: Generamos JWT y Respondemos**
```javascript
// En nuestro callback
router.get('/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id }, JWT_SECRET);
    res.json({ token, user: req.user });
  }
);
```

---

## 🏗️ Estructura del Código

### 📁 Organización de Archivos:

```
BackEnd/
├── src/
│   ├── config/
│   │   └── passport.js          # ⭐ Configuración de estrategias
│   ├── routes/
│   │   └── auth.routes.js       # ⭐ Rutas de autenticación
│   ├── models/
│   │   └── Usuario.js           # Modelo de usuario
│   └── controllers/
│       └── usuario.controller.js # Lógica de negocio
├── index.js                     # ⭐ Configuración principal
├── .env                         # ⭐ Variables de entorno
└── package.json                 # Dependencias
```

### 🔧 Archivos Clave:

#### **index.js** - Configuración Principal
```javascript
import passport from 'passport';
import './src/config/passport.js'; // Cargar estrategias

app.use(passport.initialize()); // Inicializar Passport
app.use('/api/auth', authRoutes); // Montar rutas
```

#### **passport.js** - Estrategias
```javascript
// Aquí definimos CÓMO autenticar
passport.use(new LocalStrategy(...));    // Email/password
passport.use(new GoogleStrategy(...));   // Google OAuth
```

#### **auth.routes.js** - Rutas
```javascript
// Aquí definimos QUÉ rutas están disponibles
router.post('/login', ...);              // POST /api/auth/login
router.get('/google', ...);              // GET /api/auth/google
router.get('/google/callback', ...);     // GET /api/auth/google/callback
```

---

## ⚙️ Configuración Paso a Paso

### 🛠️ 1. Instalar Dependencias

```bash
npm install passport passport-local passport-google-oauth20 jsonwebtoken bcrypt
```

### 📝 2. Configurar Variables de Entorno

```bash
# .env
GOOGLE_CLIENT_ID=tu-client-id-real
GOOGLE_CLIENT_SECRET=tu-client-secret-real
JWT_SECRET=tu-jwt-secret-super-seguro
JWT_EXPIRES_IN=24h
```

### 🔧 3. Configurar Passport (passport.js)

```javascript
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  // Tu lógica aquí
}));
```

### 🚦 4. Crear Rutas (auth.routes.js)

```javascript
import passport from 'passport';

// Iniciar login con Google
router.get('/google', 
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Callback de Google
router.get('/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    // Generar JWT y responder
  }
);
```

### 🏃‍♂️ 5. Inicializar en App Principal (index.js)

```javascript
import passport from 'passport';
import './src/config/passport.js';

app.use(passport.initialize());
app.use('/api/auth', authRoutes);
```

---

## 🧪 Testing y Debugging

### ✅ Verificar Configuración:

#### 1. **Verificar Variables de Entorno**
```javascript
console.log('Google Client ID:', process.env.GOOGLE_CLIENT_ID);
console.log('JWT Secret:', process.env.JWT_SECRET ? 'Configurado' : 'Falta');
```

#### 2. **Probar Ruta de Inicio**
```bash
curl http://localhost:3000/api/auth/google
# Debería redirigir a Google
```

#### 3. **Verificar Callback URL**
- En Google Cloud Console debe coincidir exactamente
- `http://localhost:3000/api/auth/google/callback`

### 🐛 Errores Comunes:

#### **Error: "redirect_uri_mismatch"**
```
Causa: URL de callback no coincide con Google Cloud Console
Solución: Verificar URLs en Google Cloud Console
```

#### **Error: "invalid_client"**
```
Causa: Client ID o Client Secret incorrectos
Solución: Verificar variables en .env
```

#### **Error: "Cannot read property 'id' of undefined"**
```
Causa: req.user es undefined en callback
Solución: Verificar que la estrategia llama done(null, user)
```

### 📊 Logs Útiles:

```javascript
// En la estrategia GoogleStrategy
console.log('Google Profile:', profile);
console.log('Usuario encontrado:', usuario);

// En las rutas
console.log('Usuario después de auth:', req.user);
```

---

## 🎯 URLs Finales del Proyecto

### 🔗 Rutas Disponibles:

```
POST   /api/auth/register        # Registro local
POST   /api/auth/login           # Login local
GET    /api/auth/google          # Iniciar login Google
GET    /api/auth/google/callback # Callback Google
```

### 🌐 Para el Frontend:

```javascript
// Iniciar login con Google
window.location.href = 'http://localhost:3000/api/auth/google';

// El callback devolverá:
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "nombre": "Juan Pérez",
    "email": "juan@gmail.com",
    "proveedor": "google"
  }
}
```

---

## 🚀 Próximos Pasos

1. **✅ Configurar Google Cloud Console**
2. **✅ Probar flujo completo**
3. **🔄 Integrar con Frontend**
4. **🔐 Agregar middleware de autenticación JWT**
5. **📱 Considerar otras estrategias (Facebook, GitHub)**

---

## 📚 Recursos Adicionales

- [Documentación oficial de Passport.js](http://www.passportjs.org/)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [JWT.io - Debugger de tokens](https://jwt.io/)
- [Passport.js Strategies List](http://www.passportjs.org/packages/)

---

**¡Happy Coding! 🚀**

*Esta guía fue creada para el equipo de desarrollo. Si tienes dudas, revisa los comentarios en el código o consulta esta documentación.*
