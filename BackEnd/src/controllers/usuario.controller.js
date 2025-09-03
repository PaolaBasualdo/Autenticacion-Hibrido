import Usuario from "../models/Usuario.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Perfil del usuario logueado (ruta protegida)
export const perfilController = async (req, res) => {
  res.json({ success: true, data: req.usuario });
};

// Listar todos los usuarios (opcional)
export const getUsuarios = async (req, res) => {
  try {
    const usuarios = await Usuario.findAll({
      attributes: ["id", "nombre", "email", "proveedor", "proveedorId", "createdAt"]
    });
    res.json({ success: true, data: usuarios });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error al obtener usuarios" });
  }
};

// Obtener usuario por ID (opcional)
export const getUsuario = async (req, res) => {
  try {
    const { id } = req.params;
    const usuario = await Usuario.findByPk(id, {
      attributes: ["id", "nombre", "email", "proveedor", "proveedorId", "createdAt"]
    });
    if (!usuario) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
    res.json({ success: true, data: usuario });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error al obtener usuario" });
  }
};


