import { Router } from "express";

// Importar las rutas
import usuarioRoutes from "./usuario.routes.js";
import authRoutes from "./auth.routes.js";

const router = Router();

// Montar rutas
router.use("/usuarios", usuarioRoutes);  // CRUD de usuarios
router.use("/auth", authRoutes);         // login, register, refreshToken

export default router;
