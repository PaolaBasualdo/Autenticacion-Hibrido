import jwt from "jsonwebtoken";
import Usuario from "../models/Usuario.js";

export const protect = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.usuario = await Usuario.findByPk(decoded.id, {
        attributes: { exclude: ["password"] },
      });
      if (!req.usuario) {
        return res.status(401).json({ success: false, message: "Usuario no encontrado" });
      }
      next();
    } catch (err) {
      return res.status(401).json({ success: false, message: "Token inválido o expirado" });
    }
  } else {
    return res.status(401).json({ success: false, message: "No autorizado, no hay token" });
  }
};
