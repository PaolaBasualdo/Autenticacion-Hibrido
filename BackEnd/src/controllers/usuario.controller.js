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


// Registro de usuario (autenticación local)
export const register = async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    // Verificar si el usuario ya existe
    const existe = await Usuario.findOne({ where: { email } });
    if (existe) {
      return res.status(400).json({ success: false, message: "El email ya está registrado" });
    }
    // Crear usuario (el modelo ya hashea el password)
    const usuario = await Usuario.create({ nombre, email, password, proveedor: "local" });
    // Generar JWT
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "24h" }
    );
    res.status(201).json({
      success: true,
      message: "Usuario registrado correctamente",
      token,
      user: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, proveedor: usuario.proveedor }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error al registrar usuario" });
  }
};

// Login de usuario (autenticación local)
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    // Buscar usuario
    const usuario = await Usuario.findOne({ where: { email } });
    if (!usuario || !usuario.password) {
      return res.status(400).json({ success: false, message: "Credenciales inválidas" });
    }
    // Verificar password
    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) {
      return res.status(400).json({ success: false, message: "Credenciales inválidas" });
    }
    // Generar JWT
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "24h" }
    );
    res.json({
      success: true,
      message: "Login exitoso",
      token,
      user: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, proveedor: usuario.proveedor }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error al iniciar sesión" });
  }
};
