const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });

const http = require('http');
const fs = require('fs').promises;
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ============================
// CONFIG
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
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  },
};
const pool = new Pool(config.pg);

// ============================
// HELPERS
// ============================
async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const r = await client.query(sql, params);
    return r.rows;
  } finally {
    client.release();
  }
}

function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function sendJSON(res, status, data) {
  setCORS(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

async function getBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
  });
}

const mime = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
};

async function sendFile(res, filePath) {
  try {
    const buf = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
    res.end(buf);
  } catch {
    sendJSON(res, 404, { success: false, message: 'Archivo no encontrado' });
  }
}

// ============================
// AUTH
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
// API
// ============================
const api = {
  // --- LOGIN ---
  '/api/login': {
    POST: async (req, res) => {
      const { correo, clave } = await getBody(req);
      if (!correo || !clave) return sendJSON(res, 400, { success: false, message: 'Correo y contraseña requeridos' });

      const rows = await query(
        `SELECT u.*, r."NombreRol"
         FROM "Usuarios" u
         JOIN "Roles" r ON u."RolID" = r."RolID"
         WHERE u."Correo" = $1`,
        [correo]
      );
      const u = rows[0];
      if (!u) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

      let ok = false;
      if (u.Contrasena?.startsWith('$2')) {
        ok = await bcrypt.compare(clave, u.Contrasena);
      } else {
        ok = clave === u.Contrasena;
        if (ok) {
          const hash = await bcrypt.hash(clave, 10);
          await query(`UPDATE "Usuarios" SET "Contrasena"=$1 WHERE "UsuarioID"=$2`, [hash, u.UsuarioID]);
        }
      }
      if (!ok) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

      const token = jwt.sign(
        { id: u.UsuarioID, nombre: u.NombreCompleto, rol: u.NombreRol, correo: u.Correo },
        config.jwtSecret,
        { expiresIn: '8h' }
      );
      sendJSON(res, 200, { success: true, token });
    },
  },

  // --- USUARIOS ---
  '/api/usuarios': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", r."NombreRol", u."Estado"
         FROM "Usuarios" u
         JOIN "Roles" r ON u."RolID"=r."RolID"
         ORDER BY u."NombreCompleto"`
      );
      sendJSON(res, 200, { success: true, usuarios: rows });
    },
    POST: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { NombreCompleto, Correo, Contrasena, RolID, Estado } = await getBody(req);
      if (!NombreCompleto || !Correo || !Contrasena || !RolID)
        return sendJSON(res, 400, { success: false, message: 'Campos requeridos' });

      const exists = await query(`SELECT 1 FROM "Usuarios" WHERE "Correo"=$1`, [Correo]);
      if (exists.length) return sendJSON(res, 400, { success: false, message: 'El correo ya existe' });

      const hash = await bcrypt.hash(Contrasena, 10);
      await query(
        `INSERT INTO "Usuarios" ("NombreCompleto","Correo","Contrasena","RolID","Estado")
         VALUES ($1,$2,$3,$4,$5)`,
        [NombreCompleto, Correo, hash, RolID, Estado ?? true]
      );
      sendJSON(res, 201, { success: true, message: 'Usuario creado' });
    },
  },
  '/api/usuarios/:id': {
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { NombreCompleto, Correo, RolID, Estado } = await getBody(req);
      await query(
        `UPDATE "Usuarios" SET "NombreCompleto"=$1,"Correo"=$2,"RolID"=$3,"Estado"=$4 WHERE "UsuarioID"=$5`,
        [NombreCompleto, Correo, RolID, Estado, id]
      );
      sendJSON(res, 200, { success: true, message: 'Usuario actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`DELETE FROM "Usuarios" WHERE "UsuarioID"=$1`, [id]);
      sendJSON(res, 200, { success: true, message: 'Usuario eliminado' });
    },
  },

  // --- ROLES ---
  '/api/roles': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Roles" ORDER BY "NombreRol"`);
      sendJSON(res, 200, { success: true, roles: rows });
    },
  },

  // --- PERFIL ---
  '/api/perfil': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", r."NombreRol"
         FROM "Usuarios" u JOIN "Roles" r ON u."RolID"=r."RolID"
         WHERE u."UsuarioID"=$1`,
        [me.id]
      );
      sendJSON(res, 200, { success: true, usuario: rows[0] });
    },
  },

  // --- PLANES ---
  '/api/planes': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "PlanesEstudio" ORDER BY "NombrePlan"`);
      sendJSON(res, 200, { success: true, planes: rows });
    },
    POST: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { NombrePlan, AnioInicio, Estado } = await getBody(req);
      await query(
        `INSERT INTO "PlanesEstudio" ("NombrePlan","AnioInicio","Estado") VALUES ($1,$2,$3)`,
        [NombrePlan, AnioInicio, Estado ?? true]
      );
      sendJSON(res, 201, { success: true, message: 'Plan creado' });
    },
  },
  '/api/planes/:id': {
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { NombrePlan, AnioInicio, Estado } = await getBody(req);
      await query(
        `UPDATE "PlanesEstudio" SET "NombrePlan"=$1,"AnioInicio"=$2,"Estado"=$3 WHERE "PlanID"=$4`,
        [NombrePlan, AnioInicio, Estado, id]
      );
      sendJSON(res, 200, { success: true, message: 'Plan actualizado' });
    },
  },
  '/api/planes/:id/inactivar': {
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`UPDATE "PlanesEstudio" SET "Estado"=false WHERE "PlanID"=$1`, [id]);
      sendJSON(res, 200, { success: true, message: 'Plan inactivado' });
    },
  },

  // --- MATERIAS ---
  '/api/materias': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT m.*, p."NombrePlan"
         FROM "Materias" m
         LEFT JOIN "PlanesEstudio" p ON m."PlanID"=p."PlanID"
         ORDER BY m."Nombre"`
      );
      sendJSON(res, 200, { success: true, materias: rows });
    },
    POST: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Codigo, Nombre, Creditos, PlanID } = await getBody(req);
      await query(
        `INSERT INTO "Materias" ("Codigo","Nombre","Creditos","PlanID","Estado") VALUES ($1,$2,$3,$4,true)`,
        [Codigo, Nombre, Creditos, PlanID ?? null]
      );
      sendJSON(res, 201, { success: true, message: 'Materia creada' });
    },
  },
  '/api/materias/:codigo': {
    GET: async (req, res, { codigo }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT m.*, p."NombrePlan" 
         FROM "Materias" m 
         LEFT JOIN "PlanesEstudio" p ON m."PlanID"=p."PlanID"
         WHERE m."Codigo"=$1`,
        [codigo]
      );
      if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Materia no encontrada' });
      sendJSON(res, 200, { success: true, materia: rows[0] });
    },
    PUT: async (req, res, { codigo }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Nombre, Creditos, PlanID } = await getBody(req);
      await query(
        `UPDATE "Materias" SET "Nombre"=$1,"Creditos"=$2,"PlanID"=$3 WHERE "Codigo"=$4`,
        [Nombre, Creditos, PlanID ?? null, codigo]
      );
      sendJSON(res, 200, { success: true, message: 'Materia actualizada' });
    },
    DELETE: async (req, res, { codigo }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`UPDATE "Materias" SET "Estado"=false WHERE "Codigo"=$1`, [codigo]);
      sendJSON(res, 200, { success: true, message: 'Materia inactivada' });
    },
  },
  '/api/materias/:codigo/estado': {
    PUT: async (req, res, { codigo }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { activo } = await getBody(req);
      if (typeof activo !== 'boolean')
        return sendJSON(res, 400, { success: false, message: 'activo debe ser true/false' });
      await query(`UPDATE "Materias" SET "Estado"=$1 WHERE "Codigo"=$2`, [activo, codigo]);
      sendJSON(res, 200, { success: true, message: `Materia ${activo ? 'activada' : 'desactivada'}` });
    },
  },

  // --- ESTUDIANTES ---
  '/api/estudiantes': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Estudiantes" WHERE "Estado"=true ORDER BY "Nombre"`);
      sendJSON(res, 200, { success: true, estudiantes: rows });
    },
    POST: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
      if (!Cedula || !Nombre) return sendJSON(res, 400, { success: false, message: 'Cédula y Nombre requeridos' });
      const dup = await query(`SELECT 1 FROM "Estudiantes" WHERE "Cedula"=$1`, [Cedula]);
      if (dup.length) return sendJSON(res, 400, { success: false, message: 'La cédula ya existe' });
      await query(
        `INSERT INTO "Estudiantes" ("Cedula","Nombre","FechaNacimiento","Correo","Telefono","Estado")
         VALUES ($1,$2,$3,$4,$5,true)`,
        [Cedula, Nombre, FechaNacimiento || null, Correo || null, Telefono || null]
      );
      sendJSON(res, 201, { success: true, message: 'Estudiante creado' });
    },
  },
  '/api/estudiantes/inactivos': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Estudiantes" WHERE "Estado"=false ORDER BY "Nombre"`);
      sendJSON(res, 200, { success: true, estudiantes: rows });
    },
  },
  '/api/estudiantes/:id': {
    GET: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Estudiantes" WHERE "EstudianteID"=$1`, [id]);
      if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Estudiante no encontrado' });
      sendJSON(res, 200, { success: true, estudiante: rows[0] });
    },
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
      await query(
        `UPDATE "Estudiantes"
         SET "Cedula"=$1,"Nombre"=$2,"FechaNacimiento"=$3,"Correo"=$4,"Telefono"=$5
         WHERE "EstudianteID"=$6`,
        [Cedula, Nombre, FechaNacimiento || null, Correo || null, Telefono || null, id]
      );
      sendJSON(res, 200, { success: true, message: 'Estudiante actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`UPDATE "Estudiantes" SET "Estado"=false WHERE "EstudianteID"=$1`, [id]);
      sendJSON(res, 200, { success: true, message: 'Estudiante inactivado' });
    },
  },
  '/api/estudiantes/:id/reactivar': {
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`UPDATE "Estudiantes" SET "Estado"=true WHERE "EstudianteID"=$1`, [id]);
      sendJSON(res, 200, { success: true, message: 'Estudiante reactivado' });
    },
  },

  // --- PROFESORES ---
  '/api/profesores': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Profesores" WHERE "Estado"=true ORDER BY "Nombre"`);
      sendJSON(res, 200, { success: true, profesores: rows });
    },
    POST: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Nombre, Correo, Telefono } = await getBody(req);
      await query(
        `INSERT INTO "Profesores" ("Nombre","Correo","Telefono","Estado") VALUES ($1,$2,$3,true)`,
        [Nombre, Correo || null, Telefono || null]
      );
      sendJSON(res, 201, { success: true, message: 'Profesor creado' });
    },
  },
  '/api/profesores/:id': {
    GET: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(`SELECT * FROM "Profesores" WHERE "ProfesorID"=$1`, [id]);
      if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Profesor no encontrado' });
      sendJSON(res, 200, { success: true, profesor: rows[0] });
    },
    PUT: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const { Nombre, Correo, Telefono } = await getBody(req);
      await query(
        `UPDATE "Profesores" SET "Nombre"=$1,"Correo"=$2,"Telefono"=$3 WHERE "ProfesorID"=$4`,
        [Nombre, Correo || null, Telefono || null, id]
      );
      sendJSON(res, 200, { success: true, message: 'Profesor actualizado' });
    },
    DELETE: async (req, res, { id }) => {
      const me = await authMiddleware(req, res); if (!me) return;
      await query(`UPDATE "Profesores" SET "Estado"=false WHERE "ProfesorID"=$1`, [id]);
      sendJSON(res, 200, { success: true, message: 'Profesor inactivado' });
    },
  },

  // --- PERIODOS ---
  '/api/periodos': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT * FROM "Periodos"
         ORDER BY "Anio" DESC,
         CASE WHEN "Nombre"='Primer Semestre' THEN 1
              WHEN "Nombre"='Segundo Semestre' THEN 2
              WHEN "Nombre"='Verano' THEN 3 ELSE 4 END`
      );
      sendJSON(res, 200, { success: true, periodos: rows });
    },
  },

  // --- MATRICULAS ---
  '/api/matriculas': {
    GET: async (req, res) => {
      const me = await authMiddleware(req, res); if (!me) return;
      const rows = await query(
        `SELECT m."MatriculaID",
                e."Nombre" AS "Estudiante",
                p."Nombre" AS "Periodo",
                p."Anio"
         FROM "Matricula" m
         JOIN "Estudiantes" e ON m."EstudianteID"=e."EstudianteID"
         JOIN "Periodos" p ON m."PeriodoID"=p."PeriodoID"
         WHERE m."Estado"='Confirmada'`
      );
      sendJSON(res, 200, { success: true, matriculas: rows });
    },
  },
};

// ============================
// ROUTER (API + ESTÁTICOS)
// ============================
const server = http.createServer(async (req, res) => {
  setCORS(res);
  if (req.method === 'OPTIONS') return res.end();

  const cleanPath = req.url.split('?')[0];
  const parts = cleanPath.split('/').filter(Boolean);

  // --- API routing ---
  let handler = api[cleanPath];
  let params = {};

  if (!handler && parts[0] === 'api') {
    // dinámicas
    if (parts[1] === 'usuarios' && parts[2]) handler = api['/api/usuarios/:id'], (params.id = parts[2]);
    if (parts[1] === 'planes' && parts[2]) {
      if (parts[3] === 'inactivar') handler = api['/api/planes/:id/inactivar'], (params.id = parts[2]);
      else handler = api['/api/planes/:id'], (params.id = parts[2]);
    }
    if (parts[1] === 'materias' && parts[2]) {
      if (parts[3] === 'estado') handler = api['/api/materias/:codigo/estado'], (params.codigo = parts[2]);
      else handler = api['/api/materias/:codigo'], (params.codigo = parts[2]);
    }
    if (parts[1] === 'estudiantes' && parts[2]) {
      if (parts[2] === 'inactivos') handler = api['/api/estudiantes/inactivos'];
      else if (parts[3] === 'reactivar') handler = api['/api/estudiantes/:id/reactivar'], (params.id = parts[2]);
      else handler = api['/api/estudiantes/:id'], (params.id = parts[2]);
    }
    if (parts[1] === 'profesores' && parts[2]) handler = api['/api/profesores/:id'], (params.id = parts[2]);
  }

  if (handler && handler[req.method]) {
    try {
      return await handler[req.method](req, res, params);
    } catch (e) {
      console.error('API error:', e);
      return sendJSON(res, 500, { success: false, message: 'Error en el servidor' });
    }
  }

  // --- Static files (HTML/JS/CSS) ---
  // Archivos que tú subiste están en la raíz del proyecto (login.html, index.html, etc.)
  // Mapeamos rutas amigables:
  const routeToFile = {
    '/': 'login.html',
    '/login': 'login.html',
    '/login.html': 'login.html',
    '/index': 'index.html',
    '/index.html': 'index.html',
    '/agregar_estudiante.html': 'agregar_estudiante.html',
    '/agregar_materia.html': 'agregar_materia.html',
    '/agregar_plan.html': 'agregar_plan.html',
    '/agregar_profesor.html': 'agregar_profesor.html',
    '/agregar_usuario.html': 'agregar_usuario.html',
    '/configuracion.html': 'configuracion.html',
    '/estudiantes.html': 'estudiantes.html',
  };

  const fileName = routeToFile[cleanPath] || (cleanPath.endsWith('.html') ? cleanPath.slice(1) : null);
  if (fileName) {
    const full = path.join(__dirname, fileName);
    return sendFile(res, full);
  }

  // cualquier .js/.css/img bajo la raíz
  if (/\.(js|css|png|jpg|jpeg|gif|ico)$/.test(cleanPath)) {
    const full = path.join(__dirname, decodeURIComponent(cleanPath));
    return sendFile(res, full);
  }

  // Not found
  return sendJSON(res, 404, { success: false, message: 'Ruta no encontrada' });
});

// ============================
// START
// ============================
server.listen(config.port, () => {
  console.log(`Servidor escuchando en puerto ${config.port}`);
});
