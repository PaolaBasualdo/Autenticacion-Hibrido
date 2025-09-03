// Middleware de ejemplo para proteger rutas (puedes personalizarlo)

export const ejemploMiddleware = (req, res, next) => {
  // Aquí puedes poner lógica de autenticación, logging, etc.
  next();
};
