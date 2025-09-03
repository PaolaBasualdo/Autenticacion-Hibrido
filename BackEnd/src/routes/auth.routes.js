// ============================================================================
// RUTAS DE AUTENTICACIÓN
// ============================================================================
// Este archivo maneja todas las rutas relacionadas con autenticación:
// - Registro e inicio de sesión local (email/password)
// - Autenticación OAuth con Google


import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import { register, login } from "../controllers/auth.controller.js";

const router = Router();

// ============================================================================
// RUTAS DE AUTENTICACIÓN LOCAL (tradicional)
// ============================================================================
// Estas rutas manejan el registro e inicio de sesión con email y contraseña

router.post("/register", register); // Crea usuario nuevo + devuelve token JWT
router.post("/login", login);       // Valida credenciales + devuelve token JWT

// ============================================================================
// RUTAS DE AUTENTICACIÓN CON GOOGLE OAUTH 2.0
// ============================================================================
// Flujo completo de autenticación con Google:
// 1. Usuario hace clic en "Login con Google" en el frontend
// 2. Frontend redirige a: GET /api/auth/google
// 3. Passport redirige al usuario a Google para autenticación
// 4. Usuario autoriza la aplicación en Google
// 5. Google redirige a: GET /api/auth/google/callback
// 6. Passport procesa la respuesta y obtiene datos del usuario
// 7. Nuestra app genera un JWT y lo devuelve

// RUTA 1: Iniciar autenticación con Google
// Cuando el usuario visita esta ruta, Passport automáticamente lo redirige a Google
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'] // Permisos que solicitamos a Google
  })
);

// RUTA 2: Callback de Google - Aquí regresa el usuario después de autenticarse
// Google redirige aquí con un código de autorización que Passport procesa automáticamente
router.get('/google/callback',
  // Passport procesa la respuesta de Google y ejecuta la estrategia GoogleStrategy
  passport.authenticate('google', { 
    session: false // No usar sesiones porque usamos JWT
  }),
  (req, res) => {
    try {
      // En este punto, req.user contiene los datos del usuario devueltos por la estrategia
      // (ya sea un usuario existente o uno recién creado)
      
      // Generar token JWT con la información del usuario
      const token = jwt.sign(
        { 
          id: req.user.id, 
          email: req.user.email 
        }, 
        process.env.JWT_SECRET,                    // Clave secreta para firmar el token
        { 
          expiresIn: process.env.JWT_EXPIRES_IN || '24h' // Token válido por 24 horas
        }
      );
      
      // Devolver respuesta JSON con el token y datos básicos del usuario
      res.json({ 
        success: true,
        message: 'Autenticación con Google exitosa',
        token,           // JWT que el frontend debe guardar y usar en requests futuros
        user: {
          id: req.user.id,
          nombre: req.user.nombre,
          email: req.user.email,
          proveedor: req.user.proveedor  // 'google' para identificar el tipo de cuenta
        }
      });
    } catch (error) {
      console.error('Error generando token JWT:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Error interno del servidor al generar token' 
      });
    }
  }
);

// ============================================================================
// EXPORTAR RUTAS
// ============================================================================
// Estas rutas tenemos que tenerlas en /api/auth en el archivo principal index.js
// URLs finales disponibles:
// - POST /api/auth/register (registro local)
// - POST /api/auth/login (login local)  
// - GET /api/auth/google (iniciar login con Google)
// - GET /api/auth/google/callback (callback de Google)

export default router;
