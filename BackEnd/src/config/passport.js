import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcrypt";
import Usuario from "../models/Usuario.js";

// ============================================================================
// ESTRATEGIA LOCAL: Autenticación tradicional con email y contraseña
// ============================================================================
// Esta estrategia maneja el login cuando el usuario ingresa sus credenciales
// directamente en nuestro formulario (no OAuth)
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    // 1. Buscar usuario en la base de datos por email
    const user = await Usuario.findOne({ where: { email } });
    if (!user) return done(null, false, { message: 'Usuario no encontrado' });
    
    // 2. Comparar la contraseña ingresada con el hash almacenado
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return done(null, false, { message: 'Contraseña incorrecta' });
    
    // 3. Si todo está bien, devolver el usuario
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// ============================================================================
// ESTRATEGIA GOOGLE OAUTH: Autenticación usando cuentas de Google
// ============================================================================
// Esta estrategia maneja el flujo OAuth 2.0 con Google:
// 1. Usuario hace clic en "Login con Google"
// 2. Se redirige a Google para autenticación
// 3. Google valida las credenciales del usuario
// 4. Google redirige de vuelta a nuestra app con un código
// 5. Passport intercambia el código por tokens de acceso
// 6. Passport usa los tokens para obtener el perfil del usuario
// 7. Ejecutamos la función callback de abajo con los datos del perfil

passport.use(
    new GoogleStrategy(
        {
            // Credenciales de la aplicación registrada en Google Cloud Console
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            // URL donde Google enviará al usuario después de la autenticación
            callbackURL: "/api/auth/google/callback",
        },
        // FUNCIÓN CALLBACK: Se ejecuta después de que Google autentica al usuario
        // - accessToken: Token para hacer llamadas a APIs de Google en nombre del usuario
        // - refreshToken: Token para renovar el accessToken cuando expire
        // - profile: Información del perfil del usuario obtenida de Google
        // - done: Función callback para indicar el resultado (éxito/error)
        async (accessToken, refreshToken, profile, done) => { 
            try {
                // Validar que Google nos haya enviado un email
                if (!profile.emails || !profile.emails[0]) {
                    return done(new Error('No se pudo obtener el email de Google'), null);
                }

                // 1. Buscar si ya existe un usuario con este Google ID en nuestra BD
                let usuario = await Usuario.findOne({ 
                    where: { 
                        proveedorId: profile.id, 
                        proveedor: 'google' 
                    } 
                });
                
                // 2. Si el usuario no existe, crear uno nuevo
                if (!usuario) {
                    usuario = await Usuario.create({
                        nombre: profile.displayName,           // Nombre completo de Google
                        email: profile.emails[0].value,       // Email principal de Google
                        proveedor: 'google',                  // Marca que se registró vía Google
                        proveedorId: profile.id,              // ID único de Google
                        // Nota: password será null para usuarios de Google
                    });
                }
                
                // 3. Devolver el usuario encontrado o creado
                done(null, usuario);
            } catch (error) {
                // En caso de error (BD, red, etc.), pasarlo al manejador de errores
                done(error);
            }
        }
    )
);

// ============================================================================
// NOTA IMPORTANTE SOBRE JWT vs SESIONES
// ============================================================================
// En aplicaciones tradicionales, Passport requiere serialización/deserialización
// de usuarios para mantener sesiones. Sin embargo, en nuestro proyecto usamos JWT
// (JSON Web Tokens), que son "stateless" (sin estado).
//
// Con JWT:
// - No necesitamos guardar sesiones en el servidor
// - Toda la información del usuario va en el token
// - No necesitamos serializeUser/deserializeUser
// - El frontend guarda el token y lo envía en cada request
//
// Esto hace nuestra aplicación más escalable y simple de mantener.

export default passport;