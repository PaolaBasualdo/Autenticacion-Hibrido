import express from 'express';
import cors from 'cors';
import passport from 'passport';
import dotenv from 'dotenv';
import sequelize from './src/config/database.js';
import './src/config/passport.js';

// Importar rutas
import authRoutes from './src/routes/auth.routes.js';
import usuarioRoutes from './src/routes/usuario.routes.js';
import indexRoutes from './src/routes/index.routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Inicializar Passport (solo para OAuth)
app.use(passport.initialize());

// Rutas
app.use('/api/auth', authRoutes);
app.use('/api/usuarios', usuarioRoutes);
app.use('/', indexRoutes);

// Sincronizar base de datos y arrancar servidor
const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Conexión a la base de datos establecida correctamente.');
    
    await sequelize.sync({ force: false });
    console.log('✅ Modelos sincronizados con la base de datos.');
    
    app.listen(PORT, () => {
      console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Error al inicializar el servidor:', error);
  }
};

startServer();