<h2 align="center"> INSTITUTO SUPERIOR SANTA ROSA DE CALAMUCHITA</h2>
<h1 align="center">
💻 Hackaton 2025 - Sistema de Autenticación Híbrido
</h1>
<h3 align="center">
Full-Stack JS: Registro Local + Social (OAuth 2.0)
</h3>

<p align="center">
  <a href="https://github.com/PaolaBasualdo/Hackaton-FullStack-Auth">
    <img src="https://img.shields.io/badge/GitHub-Repo-blue?logo=github" alt="GitHub Repo"/>
  </a>
  <img src="https://img.shields.io/badge/STATUS-IN%20DESARROLLO-yellow" alt="Status"/>
  <img src="https://img.shields.io/badge/Node.js-18+-green?logo=node.js" alt="Node.js"/>
  <img src="https://img.shields.io/badge/React-18+-blue?logo=react" alt="React"/>
  <img src="https://img.shields.io/badge/JWT-Security-orange" alt="JWT"/>
</p>

---

## 📌 Tabla de Contenidos

- [Descripción del proyecto](#descripción-del-proyecto)  
- [Estado del proyecto](#estado-del-proyecto)  
- [Demo / Acceso](#demo--acceso)  
- [Funcionalidades](#funcionalidades)  
- [Tecnologías](#tecnologías)  
- [Instalación](#instalación)  
- [Desarrolladora](#desarrolladora)  

---

## 📖 Descripción del proyecto

Este proyecto es un **sistema de autenticación híbrido** para una tienda de comercio electrónico.  
Permite a los usuarios registrarse y autenticarse mediante:

- **Autenticación local:** Email + contraseña  
- **Autenticación social (OAuth 2.0):** Google (con posibilidad de agregar más)  

Incluye **JWT** para proteger rutas privadas y gestionar sesiones de manera segura.  

El frontend está construido con **React.js**, y el backend con **Node.js + Express**.

---

## 🚧 Estado del proyecto

| Funcionalidad                        | Estado       |
|-------------------------------------|------------|
| Registro y login local               | ✅ Completo |
| Hash de contraseñas con bcryptjs     | ✅ Completo |
| Login con Google OAuth 2.0           | ✅ Parcial  |
| Generación y validación de JWT       | ✅ Completo |
| Rutas privadas en frontend           | ✅ Completo |
| Logout y cierre de sesión            | 🚧 En desarrollo |
| Integración con más proveedores OAuth| 🚧 En desarrollo |

---

## 🎬 Demo / Acceso

- **Frontend:** [Link al frontend](#) *(próximamente)*  
- **Backend:** [Link al backend](#) *(próximamente)*  
- **Repositorio GitHub:** [Hackaton-FullStack-Auth](https://github.com/PaolaBasualdo/Hackaton-FullStack-Auth)

---

## 🔧 Funcionalidades

### Autenticación Local
- Registro de usuarios (nombre, email, contraseña)
- Contraseña hasheada con bcryptjs
- Login validando credenciales
- Generación de token JWT para sesiones seguras

### Autenticación Social (OAuth 2.0)
- Login con Google
- Creación automática de usuario si no existe en DB
- Redirección y callback desde el proveedor

### Gestión de Sesión
- Almacenamiento seguro de token en frontend (localStorage / cookies)
- Rutas privadas protegidas con JWT
- Logout funcional (elimina token del cliente)

### Bonus / Próximamente
- Añadir más proveedores sociales (Facebook, Instagram)
- Mejoras en la UI/UX

---

## 🚀 Tecnologías

**Frontend**
- React.js 18+
- React Router
- Axios / Fetch

**Backend**
- Node.js 18+
- Express.js
- Passport.js (local + OAuth 2.0)
- bcryptjs
- jsonwebtoken
- Base de datos relacional (PostgreSQL / MySQL)

**Herramientas**
- Git & GitHub
- Postman / Insomnia
- Visual Studio Code / IntelliJ IDEA

---

## ⚙️ Instalación

1. Clonar el repositorio  
```bash
git clone https://github.com/PaolaBasualdo/Hackaton-FullStack-Auth.git
