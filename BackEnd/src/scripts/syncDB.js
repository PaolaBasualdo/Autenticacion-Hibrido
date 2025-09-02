
import express from "express";
import sequelize from "./src/config/database.js";
import indexRoutes from "./src/routes/index.routes.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para JSON
app.use(express.json());

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("¡Backend funcionando correctamente!");
});

// Montar todas las rutas en /api/v1
app.use("/api", indexRoutes);

async function startServer() {
  try {
    await sequelize.authenticate();
    console.log("✅ Conexión a la base de datos establecida correctamente.");

    
    console.log("📌 Modelos listos, sin sincronización automática.");

    app.listen(PORT, () => {
      console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
      console.log(`📖 API v1: http://localhost:${PORT}/api/v1`);
    });
  } catch (error) {
    console.error("❌ Error al conectar a la base de datos:", error);
  }
}

startServer();
