// src/routes/auth.routes.js
import { Router } from "express";
import { register, login } from "../controllers/usuario.controller.js";

const router = Router();

router.post("/register", register); // crea usuario + devuelve token
router.post("/login", login);       // valida credenciales + devuelve token

export default router;
