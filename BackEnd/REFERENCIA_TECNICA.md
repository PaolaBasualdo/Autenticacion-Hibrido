# 🔧 Referencia Técnica: Implementación Passport + Google OAuth

Este archivo contiene ejemplos de código específicos y configuraciones técnicas para implementar Passport.js con Google OAuth en el proyecto.

---

## 📦 Instalación de Dependencias

### Package.json Completo
```json
{
  "name": "backend-autenticacion-hibrido",
  "type": "module",
  "dependencies": {
    "passport": "^0.7.0",
    "passport-local": "^1.0.0", 
    "passport-google-oauth20": "^2.0.0",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^6.0.0",
    "express": "^5.1.0",
    "cors": "^2.8.5",
    "dotenv": "^17.2.1",
    "sequelize": "^6.37.7",
    "mysql2": "^3.14.4"
  }
}
```

### Comando de Instalación
```bash
npm install passport passport-local passport-google-oauth20 jsonwebtoken bcrypt
```

---

## 🔐 Configuración de Variables de Entorno

### Archivo .env
```bash
# Servidor
PORT=3000
NODE_ENV=development

# Base de datos
DB_NAME=mi_proyecto_db
DB_USER=root
DB_PASSWORD=
DB_HOST=localhost
DB_PORT=3306
DB_DIALECT=mysql

# Google OAuth (obtener de Google Cloud Console)
GOOGLE_CLIENT_ID=123456789-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abcdefghijklmnopqrstuvwxyz

# JWT
JWT_SECRET=mi-super-secreto-jwt-cambiar-en-produccion
JWT_EXPIRES_IN=24h
```

### ⚠️ Importante:
- Nunca commitear el archivo `.env` al repositorio
- Agregar `.env` al `.gitignore`
- En producción, usar variables de entorno del servidor/hosting

---

## 🏗️ Implementación Completa

### 1. Configuración Principal (index.js)
```javascript
import express from 'express';
import cors from 'cors';
import passport from 'passport';
import dotenv from 'dotenv';
import sequelize from './src/config/database.js';

// IMPORTANTE: Cargar configuración de Passport ANTES de usarlo
import './src/config/passport.js';

// Importar rutas
import authRoutes from './src/routes/auth.routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares básicos
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Inicializar Passport (SIN sesiones para JWT)
app.use(passport.initialize());

// Montar rutas
app.use('/api/auth', authRoutes);

// Iniciar servidor
const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Conexión a BD establecida');
    
    await sequelize.sync({ force: false });
    console.log('✅ Modelos sincronizados');
    
    app.listen(PORT, () => {
      console.log(`🚀 Servidor en http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Error:', error);
  }
};

startServer();
```

### 2. Configuración de Passport (src/config/passport.js)
```javascript
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcrypt";
import Usuario from "../models/Usuario.js";

// Estrategia Local (email + password)
passport.use(new LocalStrategy(
  { usernameField: 'email' }, 
  async (email, password, done) => {
    try {
      const user = await Usuario.findOne({ where: { email } });
      if (!user) {
        return done(null, false, { message: 'Usuario no encontrado' });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return done(null, false, { message: 'Contraseña incorrecta' });
      }
      
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Estrategia Google OAuth 2.0
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Validar que Google envió email
    if (!profile.emails || !profile.emails[0]) {
      return done(new Error('Email no disponible desde Google'), null);
    }

    // Buscar usuario existente por Google ID
    let usuario = await Usuario.findOne({
      where: { 
        proveedorId: profile.id, 
        proveedor: 'google' 
      }
    });

    if (!usuario) {
      // Crear nuevo usuario si no existe
      usuario = await Usuario.create({
        nombre: profile.displayName,
        email: profile.emails[0].value,
        proveedor: 'google',
        proveedorId: profile.id,
        // password será null para usuarios OAuth
      });
    }

    return done(null, usuario);
  } catch (error) {
    return done(error);
  }
}));

export default passport;
```

### 3. Rutas de Autenticación (src/routes/auth.routes.js)
```javascript
import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import { register, login } from "../controllers/usuario.controller.js";

const router = Router();

// Rutas locales
router.post("/register", register);
router.post("/login", login);

// Iniciar autenticación con Google
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'] 
  })
);

// Callback de Google
router.get('/google/callback',
  passport.authenticate('google', { 
    session: false,
    failureRedirect: '/api/auth/google/error'
  }),
  (req, res) => {
    try {
      // Generar JWT
      const token = jwt.sign(
        { 
          id: req.user.id, 
          email: req.user.email 
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRES_IN || '24h' 
        }
      );

      // Respuesta exitosa
      res.json({
        success: true,
        message: 'Autenticación con Google exitosa',
        token,
        user: {
          id: req.user.id,
          nombre: req.user.nombre,
          email: req.user.email,
          proveedor: req.user.proveedor
        }
      });
    } catch (error) {
      console.error('Error generando JWT:', error);
      res.status(500).json({
        success: false,
        error: 'Error interno del servidor'
      });
    }
  }
);

// Ruta de error para OAuth
router.get('/google/error', (req, res) => {
  res.status(401).json({
    success: false,
    error: 'Error en autenticación con Google'
  });
});

export default router;
```

### 4. Modelo de Usuario (src/models/Usuario.js)
```javascript
import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import bcrypt from "bcrypt";

const Usuario = sequelize.define("Usuario", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  nombre: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: true, // null para usuarios OAuth
  },
  proveedor: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: "local", // 'local' | 'google'
  },
  proveedorId: {
    type: DataTypes.STRING,
    allowNull: true, // ID único del proveedor OAuth
  },
}, {
  tableName: "usuarios",
  timestamps: true,
  hooks: {
    beforeCreate: async (usuario) => {
      if (usuario.password) {
        const salt = await bcrypt.genSalt(10);
        usuario.password = await bcrypt.hash(usuario.password, salt);
      }
    },
    beforeUpdate: async (usuario) => {
      if (usuario.changed("password")) {
        const salt = await bcrypt.genSalt(10);
        usuario.password = await bcrypt.hash(usuario.password, salt);
      }
    },
  },
});

// Método para validar contraseña
Usuario.prototype.validarPassword = async function (passwordPlano) {
  if (!this.password) return false;
  return await bcrypt.compare(passwordPlano, this.password);
};

export default Usuario;
```

---

## 🔍 Middleware de Autenticación JWT

### Crear middleware para proteger rutas
```javascript
// src/middlewares/auth.middleware.js
import jwt from 'jsonwebtoken';
import Usuario from '../models/Usuario.js';

export const verificarJWT = async (req, res, next) => {
  try {
    // Obtener token del header Authorization
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        error: 'Token requerido' 
      });
    }

    const token = authHeader.substring(7); // Remover "Bearer "

    // Verificar token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Buscar usuario en BD
    const usuario = await Usuario.findByPk(decoded.id);
    if (!usuario) {
      return res.status(401).json({ 
        success: false, 
        error: 'Usuario no encontrado' 
      });
    }

    // Agregar usuario a request
    req.user = usuario;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Token inválido' 
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Token expirado' 
      });
    }
    
    console.error('Error verificando JWT:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor' 
    });
  }
};

// Uso en rutas protegidas:
// router.get('/perfil', verificarJWT, (req, res) => {
//   res.json({ user: req.user });
// });
```

---

## 🌐 Configuración de Google Cloud Console

### URLs a configurar:

#### JavaScript Origins:
```
http://localhost:3000
http://localhost:3001
https://tu-dominio.com (producción)
```

#### Authorized Redirect URIs:
```
http://localhost:3000/api/auth/google/callback
https://tu-dominio.com/api/auth/google/callback (producción)
```

### Scopes necesarios:
- `https://www.googleapis.com/auth/userinfo.profile`
- `https://www.googleapis.com/auth/userinfo.email`

---

## 🧪 Testing Manual

### 1. Probar autenticación local:
```bash
# Registro
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"nombre":"Test User","email":"test@test.com","password":"123456"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"123456"}'
```

### 2. Probar Google OAuth:
```bash
# Abrir en navegador:
http://localhost:3000/api/auth/google
```

### 3. Probar ruta protegida:
```bash
curl -H "Authorization: Bearer TU_JWT_TOKEN_AQUI" \
  http://localhost:3000/api/usuarios/perfil
```

---

## 🐛 Debugging Common Issues

### Error: "redirect_uri_mismatch"
```javascript
// Verificar en passport.js:
callbackURL: "/api/auth/google/callback" // Debe coincidir con Google Console

// URL completa en Google Console debe ser:
// http://localhost:3000/api/auth/google/callback
```

### Error: "invalid_client"
```javascript
// Verificar .env:
console.log('Client ID:', process.env.GOOGLE_CLIENT_ID);
console.log('Client Secret:', process.env.GOOGLE_CLIENT_SECRET);
```

### Error: "Cannot read property 'id' of undefined"
```javascript
// En callback de GoogleStrategy, verificar:
console.log('Profile recibido:', profile);
console.log('Usuario creado/encontrado:', usuario);

// En ruta callback, verificar:
console.log('req.user:', req.user);
```

---

## 🚀 Deploy en Producción

### Variables de entorno en producción:
```bash
NODE_ENV=production
GOOGLE_CLIENT_ID=tu-client-id-real
GOOGLE_CLIENT_SECRET=tu-client-secret-real
JWT_SECRET=secreto-super-seguro-aleatorio
JWT_EXPIRES_IN=7d
```

### Actualizar URLs en Google Console:
```
https://tu-dominio.com/api/auth/google/callback
```

### CORS para producción:
```javascript
app.use(cors({
  origin: ['https://tu-frontend.com'],
  credentials: true
}));
```

---

**¡Esta guía técnica complementa la documentación principal!** 🚀
