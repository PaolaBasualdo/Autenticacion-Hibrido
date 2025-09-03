import Usuario from "../models/Usuario.js";
import jwt from "jsonwebtoken";

// Generar tokens
const generateTokens = (usuario) => {
  const accessToken = jwt.sign(
    { id: usuario.id },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
  const refreshToken = jwt.sign(
    { id: usuario.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );
  return { accessToken, refreshToken };
};

// Registro local
export const register = async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    const usuarioExistente = await Usuario.findOne({ where: { email } });
    if (usuarioExistente) {
      return res.status(400).json({ success: false, message: "Email ya registrado" });
    }

    const nuevoUsuario = await Usuario.create({ nombre, email, password });

    const tokens = generateTokens(nuevoUsuario);

    res.status(201).json({
      success: true,
      message: "Usuario registrado exitosamente",
      data: tokens
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error al registrar usuario" });
  }
};

// Login local
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const usuario = await Usuario.findOne({ where: { email } });
    if (!usuario) return res.status(401).json({ success: false, message: "Credenciales incorrectas" });

    const isValid = await usuario.validarPassword(password);
    if (!isValid) return res.status(401).json({ success: false, message: "Credenciales incorrectas" });

    const tokens = generateTokens(usuario);

    res.json({ success: true, message: "Login exitoso", data: tokens });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error en login" });
  }
};

// Refresh token
export const refreshToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(401).json({ success: false, message: "Token no proporcionado" });

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const usuario = await Usuario.findByPk(decoded.id);
    if (!usuario) return res.status(401).json({ success: false, message: "Usuario no encontrado" });

    const tokens = generateTokens(usuario);
    res.json({ success: true, message: "Token refrescado", data: tokens });
  } catch (err) {
    console.error(err);
    res.status(401).json({ success: false, message: "Token inválido o expirado" });
  }
};
