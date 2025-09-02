import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import bcrypt from "bcrypt";

const Usuario = sequelize.define(
  "Usuario",
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    nombre: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: true }, // puede ser null si es social login
    proveedor: {
      type: DataTypes.ENUM("local", "google", "facebook", "instagram"), // Proveedor de autenticación, ENUM para restringir valores
      allowNull: false,
      defaultValue: "local",
      validate: {
    isIn: {
      args: [['local', 'google', 'facebook', 'instagram']],
      msg: 'Proveedor no válido'
    } // Validación para asegurar que el valor esté en el conjunto permitido
    },
    proveedorId: {
      type: DataTypes.STRING, // id que da Google/Facebook
      allowNull: true,
    },
  },
},
  {
    tableName: "usuarios",
    timestamps: true,
    hooks: {
      beforeCreate: async (usuario) => {
        if (usuario.password) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      },
      beforeUpdate: async (usuario) => {
        if (usuario.changed("password")) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      },
    },
  }
);

// Método para validar contraseña
Usuario.prototype.validarPassword = async function (passwordPlano) {
  return await bcrypt.compare(passwordPlano, this.password);
};

export default Usuario;
