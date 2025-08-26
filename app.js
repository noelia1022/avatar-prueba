const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });

const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ============================
// CONFIGURACIÓN
// ============================
const config = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || 'secret_key_avatar',
  pg: {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  }
};

// Pool PostgreSQL
const pool = new Pool(config.pg);

// Helpers
async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return result.rows;
  } finally {
    client.release();
  }
}

function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function sendJSON(res, status, data) {
  setCORSHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

async function getBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
  });
}

// ============================
// AUTENTICACIÓN
// ============================
async function authMiddleware(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  
  if (!token) {
    sendJSON(res, 401, { success: false, message: 'Token no proporcionado' });
    return null;
  }
  
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch {
    sendJSON(res, 401, { success: false, message: 'Token inválido o expirado' });
    return null;
  }
}

// ============================
// API HANDLERS
// ============================
const apiHandlers = {
  // ---------- LOGIN ----------
  '/api/login': {
    POST: async (req, res) => {
      const { correo, clave } = await getBody(req);
      if (!correo || !clave) return sendJSON(res, 400, { success: false, message: 'Correo y contraseña requeridos' });

      const usuarios = await query(
        `SELECT u.*, r."NombreRol" 
         FROM "Usuarios" u
         JOIN "Roles" r ON u."RolID" = r."RolID"
         WHERE u."Correo" = $1`, 
        [correo]
      );
      const usuario = usuarios[0];
      if (!usuario) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

      let valid = false;
      if (usuario.Contrasena.startsWith('$2b$')) {
        valid = await bcrypt.compare(clave, usuario.Contrasena);
      } else {
        valid = clave === usuario.Contrasena;
        if (valid) {
          const hash = await bcrypt.hash(clave, 10);
          await query('UPDATE "Usuarios" SET "Contrasena"=$1 WHERE "UsuarioID"=$2', [hash, usuario.UsuarioID]);
        }
      }

      if (!valid) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

      const token = jwt.sign(
        { id: usuario.UsuarioID, nombre: usuario.NombreCompleto, rol: usuario.NombreRol, correo: usuario.Correo },
        config.jwtSecret, { expiresIn: '8h' }
      );

      sendJSON(res, 200, { success: true, token });
    }
  },

  // ---------- USUARIOS ----------
  '/api/usuarios': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const usuarios = await query(
        `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", r."NombreRol", u."Estado"
         FROM "Usuarios" u JOIN "Roles" r ON u."RolID" = r."RolID"`
      );
      sendJSON(res, 200, { success: true, usuarios });
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { NombreCompleto, Correo, Contrasena, RolID, Estado } = await getBody(req);
      const exists = await query('SELECT * FROM "Usuarios" WHERE "Correo"=$1', [Correo]);
      if (exists.length) return sendJSON(res, 400, { success: false, message: 'Correo ya existe' });

      const hash = await bcrypt.hash(Contrasena, 10);
      await query(
        'INSERT INTO "Usuarios" ("NombreCompleto","Correo","Contrasena","RolID","Estado") VALUES ($1,$2,$3,$4,$5)',
        [NombreCompleto, Correo, hash, RolID, Estado ?? true]
      );
      sendJSON(res, 201, { success: true, message: 'Usuario creado' });
    }
  },

  '/api/usuarios/:id': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { NombreCompleto, Correo, RolID, Estado } = await getBody(req);
      await query(
        'UPDATE "Usuarios" SET "NombreCompleto"=$1,"Correo"=$2,"RolID"=$3,"Estado"=$4 WHERE "UsuarioID"=$5',
        [NombreCompleto, Correo, RolID, Estado, id]
      );
      sendJSON(res, 200, { success: true, message: 'Usuario actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('DELETE FROM "Usuarios" WHERE "UsuarioID"=$1', [id]);
      sendJSON(res, 200, { success: true, message: 'Usuario eliminado' });
    }
  },

  // ---------- ROLES ----------
  '/api/roles': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const roles = await query('SELECT * FROM "Roles" ORDER BY "NombreRol"');
      sendJSON(res, 200, { success: true, roles });
    }
  },

  // ---------- PERFIL ----------
  '/api/perfil': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const perfil = await query(
        `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", r."NombreRol"
         FROM "Usuarios" u JOIN "Roles" r ON u."RolID"=r."RolID"
         WHERE u."UsuarioID"=$1`, 
        [user.id]
      );
      sendJSON(res, 200, { success: true, usuario: perfil[0] });
    }
  },

  // ---------- PLANES ----------
  '/api/planes': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const planes = await query('SELECT * FROM "PlanesEstudio" ORDER BY "NombrePlan"');
      sendJSON(res, 200, { success: true, planes });
    },
    POST: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { NombrePlan, AnioInicio, Estado } = await getBody(req);
      await query('INSERT INTO "PlanesEstudio" ("NombrePlan","AnioInicio","Estado") VALUES ($1,$2,$3)',
        [NombrePlan, AnioInicio, Estado ?? true]);
      sendJSON(res, 201, { success: true, message: 'Plan creado' });
    }
  },

  '/api/planes/:id': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { NombrePlan, AnioInicio, Estado } = await getBody(req);
      await query('UPDATE "PlanesEstudio" SET "NombrePlan"=$1,"AnioInicio"=$2,"Estado"=$3 WHERE "PlanID"=$4',
        [NombrePlan, AnioInicio, Estado, id]);
      sendJSON(res, 200, { success: true, message: 'Plan actualizado' });
    }
  },

  '/api/planes/:id/inactivar': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('UPDATE "PlanesEstudio" SET "Estado"=false WHERE "PlanID"=$1', [id]);
      sendJSON(res, 200, { success: true, message: 'Plan inactivado' });
    }
  },

  // ---------- MATERIAS ----------
  '/api/materias': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const materias = await query('SELECT * FROM "Materias" ORDER BY "Nombre"');
      sendJSON(res, 200, { success: true, materias });
    },
    POST: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Codigo, Nombre, Creditos, PlanID } = await getBody(req);
      await query('INSERT INTO "Materias" ("Codigo","Nombre","Creditos","PlanID") VALUES ($1,$2,$3,$4)',
        [Codigo, Nombre, Creditos, PlanID]);
      sendJSON(res, 201, { success: true, message: 'Materia creada' });
    }
  },

  '/api/materias/:codigo': {
    PUT: async (req, res, { codigo }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Nombre, Creditos, PlanID } = await getBody(req);
      await query('UPDATE "Materias" SET "Nombre"=$1,"Creditos"=$2,"PlanID"=$3 WHERE "Codigo"=$4',
        [Nombre, Creditos, PlanID, codigo]);
      sendJSON(res, 200, { success: true, message: 'Materia actualizada' });
    },
    DELETE: async (req, res, { codigo }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('UPDATE "Materias" SET "Estado"=false WHERE "Codigo"=$1', [codigo]);
      sendJSON(res, 200, { success: true, message: 'Materia inactivada' });
    }
  },

  // ---------- ESTUDIANTES ----------
  '/api/estudiantes': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const ests = await query('SELECT * FROM "Estudiantes" WHERE "Estado"=true');
      sendJSON(res, 200, { success: true, estudiantes: ests });
    },
    POST: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
      await query(
        'INSERT INTO "Estudiantes" ("Cedula","Nombre","FechaNacimiento","Correo","Telefono","Estado") VALUES ($1,$2,$3,$4,$5,true)',
        [Cedula, Nombre, FechaNacimiento, Correo, Telefono]
      );
      sendJSON(res, 201, { success: true, message: 'Estudiante creado' });
    }
  },

  '/api/estudiantes/:id': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
      await query(
        'UPDATE "Estudiantes" SET "Cedula"=$1,"Nombre"=$2,"FechaNacimiento"=$3,"Correo"=$4,"Telefono"=$5 WHERE "EstudianteID"=$6',
        [Cedula, Nombre, FechaNacimiento, Correo, Telefono, id]
      );
      sendJSON(res, 200, { success: true, message: 'Estudiante actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('UPDATE "Estudiantes" SET "Estado"=false WHERE "EstudianteID"=$1', [id]);
      sendJSON(res, 200, { success: true, message: 'Estudiante inactivado' });
    }
  },

  '/api/estudiantes/:id/reactivar': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('UPDATE "Estudiantes" SET "Estado"=true WHERE "EstudianteID"=$1', [id]);
      sendJSON(res, 200, { success: true, message: 'Estudiante reactivado' });
    }
  },

  // ---------- PROFESORES ----------
  '/api/profesores': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const profs = await query('SELECT * FROM "Profesores" WHERE "Estado"=true');
      sendJSON(res, 200, { success: true, profesores: profs });
    },
    POST: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Nombre, Correo, Telefono } = await getBody(req);
      await query('INSERT INTO "Profesores" ("Nombre","Correo","Telefono","Estado") VALUES ($1,$2,$3,true)',
        [Nombre, Correo, Telefono]);
      sendJSON(res, 201, { success: true, message: 'Profesor creado' });
    }
  },

  '/api/profesores/:id': {
    PUT: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const { Nombre, Correo, Telefono } = await getBody(req);
      await query('UPDATE "Profesores" SET "Nombre"=$1,"Correo"=$2,"Telefono"=$3 WHERE "ProfesorID"=$4',
        [Nombre, Correo, Telefono, id]);
      sendJSON(res, 200, { success: true, message: 'Profesor actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const user = await authMiddleware(req, res); if (!user) return;
      await query('UPDATE "Profesores" SET "Estado"=false WHERE "ProfesorID"=$1', [id]);
      sendJSON(res, 200, { success: true, message: 'Profesor inactivado' });
    }
  },

  // ---------- PERIODOS ----------
  '/api/periodos': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const per = await query('SELECT * FROM "Periodos" ORDER BY "Anio" DESC');
      sendJSON(res, 200, { success: true, periodos: per });
    }
  },

  // ---------- MATRICULAS ----------
  '/api/matriculas': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res); if (!user) return;
      const mats = await query(
        `SELECT m."MatriculaID", e."Nombre" as Estudiante, p."Nombre" as Periodo
         FROM "Matricula" m
         JOIN "Estudiantes" e ON m."EstudianteID"=e."EstudianteID"
         JOIN "Periodos" p ON m."PeriodoID"=p."PeriodoID"`
      );
      sendJSON(res, 200, { success: true, matriculas: mats });
    }
  }
};

// ============================
// ROUTER
// ============================
const server = http.createServer(async (req, res) => {
  setCORSHeaders(res);
  if (req.method === 'OPTIONS') return res.end();

  const url = req.url.split('?')[0];
  const parts = url.split('/').filter(Boolean);

  let handler = apiHandlers[url];
  let params = {};

  if (!handler) {
    // dynamic routes
    if (parts[1] === 'usuarios' && parts[2]) {
      handler = apiHandlers['/api/usuarios/:id']; params.id = parts[2];
    }
    if (parts[1] === 'planes' && parts[2]) {
      if (parts[3] === 'inactivar') { handler = apiHandlers['/api/planes/:id/inactivar']; params.id = parts[2]; }
      else { handler = apiHandlers['/api/planes/:id']; params.id = parts[2]; }
    }
    if (parts[1] === 'materias' && parts[2]) {
      handler = apiHandlers['/api/materias/:codigo']; params.codigo = parts[2];
    }
    if (parts[1] === 'estudiantes' && parts[2]) {
      if (parts[3] === 'reactivar') { handler = apiHandlers['/api/estudiantes/:id/reactivar']; params.id = parts[2]; }
      else { handler = apiHandlers['/api/estudiantes/:id']; params.id = parts[2]; }
    }
    if (parts[1] === 'profesores' && parts[2]) {
      handler = apiHandlers['/api/profesores/:id']; params.id = parts[2];
    }
  }

  if (handler && handler[req.method]) {
    try {
      await handler[req.method](req, res, params);
    } catch (err) {
      console.error(err);
      sendJSON(res, 500, { success: false, message: 'Error en el servidor' });
    }
  } else {
    sendJSON(res, 404, { success: false, message: 'Ruta no encontrada' });
  }
});

// ============================
// START
// ============================
server.listen(config.port, () => {
  console.log(`Servidor escuchando en puerto ${config.port}`);
});
