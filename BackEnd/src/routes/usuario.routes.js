import { Router } from "express";
import { getUsuarios, getUsuario, perfilController } from "../controllers/usuario.controller.js";
import { protect } from "../middleware/auth.middleware.js";

const router = Router();

router.get("/perfil", protect, perfilController); // protegida
router.get("/", protect, getUsuarios);           // opcionalmente protegida
router.get("/:id", protect, getUsuario);         // opcionalmente protegida

export default router;
