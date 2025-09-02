import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import bcrypt from "bcrypt";

const Usuario = sequelize.define(
  "Usuario",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    nombre: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: true, // password puede ser null → eso permite que un usuario exista aunque se registre con Google o Facebook (no hay contraseña local).

    },

    // campos para login social
    proveedor: {
      type: DataTypes.STRING, // indica cómo se registró el usuario (local, google, facebook).
      allowNull: false,
      defaultValue: "local",
    },
    proveedorId: {
      type: DataTypes.STRING, // id que da Google/Facebook guarda el id que devuelve el proveedor
      allowNull: true,
    },
  },
  {
    tableName: "usuarios",
    timestamps: true,
//hooks son funciones que Sequelize ejecuta automáticamente

    hooks: {
      beforeCreate: async (usuario) => {//si el usuario trae un password, lo encripta automáticamente antes de guardarlo.
        if (usuario.password) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      },
      beforeUpdate: async (usuario) => {//si alguien cambia la contraseña, también se vuelve a encriptar.
        if (usuario.changed("password")) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      },//Esto evita olvidarse de hacer el bcrypt en cada controlador. El modelo ya se ocupa.
    },
  }
);

// Método de instancia para validar contraseña
Usuario.prototype.validarPassword = async function (passwordPlano) {
  if (!this.password) return false;
  return await bcrypt.compare(passwordPlano, this.password);
};

//El método validarPassword del modelo encapsula el bcrypt.compare, evita hacerlo en cada controlador

//bcrypt.compare toma el hash y ve si coincide con el password plano.

export default Usuario;
