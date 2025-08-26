// app.js
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });

const http = require('http');
const { URL } = require('url');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ============================
// CONFIGURACIÓN
// ============================
const config = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || 'secret_key_avatar',
  publicDir: path.join(__dirname, 'public'),
  pg: {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  }
};

// ============================
// CONEXIÓN PG
// ============================
const pool = new Pool(config.pg);
async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return result.rows;
  } finally {
    client.release();
  }
}

// ============================
// HELPERS HTTP
// ============================
function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
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
      try { resolve(data ? JSON.parse(data) : {}); }
      catch { resolve({}); }
    });
  });
}
function contentTypeByExt(ext) {
  return ({
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2'
  })[ext] || 'application/octet-stream';
}
async function sendFile(res, filePath) {
  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': contentTypeByExt(ext) });
    res.end(data);
  } catch (err) {
    sendJSON(res, 404, { success: false, message: 'Archivo no encontrado' });
  }
}

// ============================
// AUTENTICACIÓN (JWT)
// ============================
async function authMiddleware(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) { sendJSON(res, 401, { success: false, message: 'Token no proporcionado' }); return null; }
  try { return jwt.verify(token, config.jwtSecret); }
  catch { sendJSON(res, 401, { success: false, message: 'Token inválido o expirado' }); return null; }
}

// ============================
//
//             A P I S
//
// ============================
const api = {};

// ---------- LOGIN ----------
api['/api/login'] = {
  POST: async (req, res) => {
    const { correo, clave } = await getBody(req);
    if (!correo || !clave) return sendJSON(res, 400, { success: false, message: 'Correo y contraseña requeridos' });

    const users = await query(
      `SELECT u.*, r."NombreRol"
       FROM "Usuarios" u JOIN "Roles" r ON u."RolID" = r."RolID"
       WHERE u."Correo" = $1`, [correo]
    );
    const u = users[0];
    if (!u) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

    let ok = false;
    if (u.Contrasena?.startsWith?.('$2')) {
      ok = await bcrypt.compare(clave, u.Contrasena);
    } else {
      ok = clave === u.Contrasena;
      if (ok) {
        const hash = await bcrypt.hash(clave, 10);
        await query('UPDATE "Usuarios" SET "Contrasena"=$1 WHERE "UsuarioID"=$2', [hash, u.UsuarioID]);
      }
    }
    if (!ok) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

    const token = jwt.sign(
      { id: u.UsuarioID, nombre: u.NombreCompleto, rol: u.NombreRol, correo: u.Correo },
      config.jwtSecret,
      { expiresIn: '8h' }
    );
    sendJSON(res, 200, { success: true, token });
  }
};

// ---------- USUARIOS ----------
api['/api/usuarios'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", u."Estado", r."NombreRol"
       FROM "Usuarios" u JOIN "Roles" r ON u."RolID"=r."RolID"
       ORDER BY u."NombreCompleto"`
    );
    sendJSON(res, 200, { success: true, usuarios: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { NombreCompleto, Correo, Contrasena, RolID, Estado } = await getBody(req);
    if (!NombreCompleto || !Correo || !Contrasena || !RolID)
      return sendJSON(res, 400, { success: false, message: 'Faltan campos' });

    const dup = await query('SELECT 1 FROM "Usuarios" WHERE "Correo"=$1', [Correo]);
    if (dup.length) return sendJSON(res, 400, { success: false, message: 'Correo ya registrado' });

    const hash = await bcrypt.hash(Contrasena, 10);
    await query(
      'INSERT INTO "Usuarios" ("NombreCompleto","Correo","Contrasena","RolID","Estado") VALUES ($1,$2,$3,$4,$5)',
      [NombreCompleto, Correo, hash, RolID, Estado ?? true]
    );
    sendJSON(res, 201, { success: true, message: 'Usuario creado' });
  }
};
api['/api/usuarios/:id'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { NombreCompleto, Correo, RolID, Estado } = await getBody(req);
    await query(
      'UPDATE "Usuarios" SET "NombreCompleto"=$1,"Correo"=$2,"RolID"=$3,"Estado"=$4 WHERE "UsuarioID"=$5',
      [NombreCompleto, Correo, RolID, Estado, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Usuario actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('DELETE FROM "Usuarios" WHERE "UsuarioID"=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Usuario eliminado' });
  }
};

// ---------- ROLES ----------
api['/api/roles'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const roles = await query('SELECT * FROM "Roles" ORDER BY "NombreRol"');
    sendJSON(res, 200, { success: true, roles });
  }
};

// ---------- PERFIL ----------
api['/api/perfil'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT u."UsuarioID", u."NombreCompleto", u."Correo", r."NombreRol"
       FROM "Usuarios" u JOIN "Roles" r ON u."RolID"=r."RolID"
       WHERE u."UsuarioID"=$1`, [me.id]
    );
    sendJSON(res, 200, { success: true, usuario: rows[0] || null });
  }
};

// ---------- PLANES ----------
api['/api/planes'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "PlanesEstudio" ORDER BY "NombrePlan"');
    sendJSON(res, 200, { success: true, planes: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { NombrePlan, AnioInicio, Estado } = await getBody(req);
    if (!NombrePlan || !AnioInicio)
      return sendJSON(res, 400, { success: false, message: 'NombrePlan y AnioInicio requeridos' });
    await query(
      'INSERT INTO "PlanesEstudio" ("NombrePlan","AnioInicio","Estado") VALUES ($1,$2,$3)',
      [NombrePlan, AnioInicio, Estado ?? true]
    );
    sendJSON(res, 201, { success: true, message: 'Plan creado' });
  }
};
api['/api/planes/:id'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { NombrePlan, AnioInicio, Estado } = await getBody(req);
    await query(
      'UPDATE "PlanesEstudio" SET "NombrePlan"=$1,"AnioInicio"=$2,"Estado"=$3 WHERE "PlanID"=$4',
      [NombrePlan, AnioInicio, Estado, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Plan actualizado' });
  }
};
api['/api/planes/:id/inactivar'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE "PlanesEstudio" SET "Estado"=false WHERE "PlanID"=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Plan inactivado' });
  }
};

// ---------- MATERIAS ----------
api['/api/materias'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT m.*, p."NombrePlan"
       FROM "Materias" m LEFT JOIN "PlanesEstudio" p ON m."PlanID"=p."PlanID"
       ORDER BY m."Nombre"`
    );
    sendJSON(res, 200, { success: true, materias: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Codigo, Nombre, Creditos, PlanID } = await getBody(req);
    if (!Codigo || !Nombre || !Creditos)
      return sendJSON(res, 400, { success: false, message: 'Código, Nombre y Créditos requeridos' });
    await query(
      'INSERT INTO "Materias" ("Codigo","Nombre","Creditos","PlanID","Estado") VALUES ($1,$2,$3,$4,true)',
      [Codigo, Nombre, Creditos, PlanID || null]
    );
    sendJSON(res, 201, { success: true, message: 'Materia creada' });
  }
};
api['/api/materias/:codigo'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Materias" WHERE "Codigo"=$1', [p.codigo]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Materia no encontrada' });
    sendJSON(res, 200, { success: true, materia: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Nombre, Creditos, PlanID } = await getBody(req);
    await query(
      'UPDATE "Materias" SET "Nombre"=$1,"Creditos"=$2,"PlanID"=$3 WHERE "Codigo"=$4',
      [Nombre, Creditos, PlanID || null, p.codigo]
    );
    sendJSON(res, 200, { success: true, message: 'Materia actualizada' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE "Materias" SET "Estado"=false WHERE "Codigo"=$1', [p.codigo]);
    sendJSON(res, 200, { success: true, message: 'Materia inactivada' });
  }
};
api['/api/materias/:codigo/estado'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { activo } = await getBody(req);
    if (typeof activo !== 'boolean')
      return sendJSON(res, 400, { success: false, message: 'activo debe ser true/false' });
    await query('UPDATE "Materias" SET "Estado"=$1 WHERE "Codigo"=$2', [activo, p.codigo]);
    sendJSON(res, 200, { success: true, message: `Materia ${activo ? 'activada' : 'desactivada'}` });
  }
};

// ---------- ESTUDIANTES ----------
api['/api/estudiantes'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Estudiantes" WHERE "Estado"=true ORDER BY "Nombre"');
    sendJSON(res, 200, { success: true, estudiantes: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
    if (!Cedula || !Nombre)
      return sendJSON(res, 400, { success: false, message: 'Cédula y Nombre requeridos' });
    const dup = await query('SELECT 1 FROM "Estudiantes" WHERE "Cedula"=$1', [Cedula]);
    if (dup.length) return sendJSON(res, 400, { success: false, message: 'Cédula ya registrada' });
    await query(
      'INSERT INTO "Estudiantes" ("Cedula","Nombre","FechaNacimiento","Correo","Telefono","Estado") VALUES ($1,$2,$3,$4,$5,true)',
      [Cedula, Nombre, FechaNacimiento || null, Correo || null, Telefono || null]
    );
    sendJSON(res, 201, { success: true, message: 'Estudiante creado' });
  }
};
api['/api/estudiantes/:id'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Estudiantes" WHERE "EstudianteID"=$1', [p.id]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Estudiante no encontrado' });
    sendJSON(res, 200, { success: true, estudiante: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Cedula, Nombre, FechaNacimiento, Correo, Telefono } = await getBody(req);
    await query(
      'UPDATE "Estudiantes" SET "Cedula"=$1,"Nombre"=$2,"FechaNacimiento"=$3,"Correo"=$4,"Telefono"=$5 WHERE "EstudianteID"=$6',
      [Cedula, Nombre, FechaNacimiento || null, Correo || null, Telefono || null, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Estudiante actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE "Estudiantes" SET "Estado"=false WHERE "EstudianteID"=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Estudiante inactivado' });
  }
};
api['/api/estudiantes/inactivos'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Estudiantes" WHERE "Estado"=false ORDER BY "Nombre"');
    sendJSON(res, 200, { success: true, estudiantes: rows });
  }
};
api['/api/estudiantes/:id/reactivar'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE "Estudiantes" SET "Estado"=true WHERE "EstudianteID"=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Estudiante reactivado' });
  }
};
api['/api/estudiantes/verificar-cedula'] = {
  GET: async (req, res, _p, urlObj) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const cedula = urlObj.searchParams.get('cedula');
    if (!cedula) return sendJSON(res, 400, { success: false, message: 'Cédula requerida' });
    const rows = await query('SELECT 1 FROM "Estudiantes" WHERE "Cedula"=$1', [cedula]);
    sendJSON(res, 200, { success: true, existe: rows.length > 0 });
  }
};

// ---------- PROFESORES ----------
api['/api/profesores'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Profesores" WHERE "Estado"=true ORDER BY "Nombre"');
    sendJSON(res, 200, { success: true, profesores: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Nombre, Correo, Telefono } = await getBody(req);
    if (!Nombre) return sendJSON(res, 400, { success: false, message: 'Nombre requerido' });
    await query(
      'INSERT INTO "Profesores" ("Nombre","Correo","Telefono","Estado") VALUES ($1,$2,$3,true)',
      [Nombre, Correo || null, Telefono || null]
    );
    sendJSON(res, 201, { success: true, message: 'Profesor creado' });
  }
};
api['/api/profesores/:id'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM "Profesores" WHERE "ProfesorID"=$1', [p.id]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Profesor no encontrado' });
    sendJSON(res, 200, { success: true, profesor: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { Nombre, Correo, Telefono } = await getBody(req);
    await query(
      'UPDATE "Profesores" SET "Nombre"=$1,"Correo"=$2,"Telefono"=$3 WHERE "ProfesorID"=$4',
      [Nombre, Correo || null, Telefono || null, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Profesor actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE "Profesores" SET "Estado"=false WHERE "ProfesorID"=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Profesor inactivado' });
  }
};

// ---------- PERIODOS ----------
api['/api/periodos'] = {
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
  }
};

// ---------- MATRÍCULAS ----------
api['/api/matriculas'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT m."MatriculaID",
              CONCAT(e."Nombre",' - ',e."Cedula") AS "Estudiante",
              p."Nombre" AS "Periodo",
              p."Anio"
       FROM "Matricula" m
       JOIN "Estudiantes" e ON m."EstudianteID"=e."EstudianteID"
       JOIN "Periodos" p ON m."PeriodoID"=p."PeriodoID"
       WHERE m."Estado"='Confirmada'
       ORDER BY m."MatriculaID" DESC`
    );
    sendJSON(res, 200, { success: true, matriculas: rows });
  }
};

// ============================
// ROUTER (API + ESTÁTICOS)
// ============================
const server = http.createServer(async (req, res) => {
  setCORS(res);
  if (req.method === 'OPTIONS') return res.end();

  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const pathname = urlObj.pathname;

  // 1) API
  if (pathname.startsWith('/api/')) {
    let handler = api[pathname];
    let params = {};

    // dinámicas
    const parts = pathname.split('/').filter(Boolean); // ['api','usuarios','123']
    const mapDyn = () => {
      if (parts[1] === 'usuarios' && parts[2]) { handler = api['/api/usuarios/:id']; params.id = parts[2]; }
      if (parts[1] === 'planes' && parts[2]) {
        if (parts[3] === 'inactivar') { handler = api['/api/planes/:id/inactivar']; params.id = parts[2]; }
        else { handler = api['/api/planes/:id']; params.id = parts[2]; }
      }
      if (parts[1] === 'materias' && parts[2]) {
        if (parts[3] === 'estado') { handler = api['/api/materias/:codigo/estado']; params.codigo = parts[2]; }
        else { handler = api['/api/materias/:codigo']; params.codigo = parts[2]; }
      }
      if (parts[1] === 'estudiantes' && parts[2]) {
        if (parts[2] === 'inactivos') handler = api['/api/estudiantes/inactivos'];
        else if (parts[3] === 'reactivar') { handler = api['/api/estudiantes/:id/reactivar']; params.id = parts[2]; }
        else { handler = api['/api/estudiantes/:id']; params.id = parts[2]; }
      }
      if (parts[1] === 'profesores' && parts[2]) { handler = api['/api/profesores/:id']; params.id = parts[2]; }
    };
    if (!handler) mapDyn();

    if (handler && handler[req.method]) {
      try { await handler[req.method](req, res, params, urlObj); }
      catch (e) { console.error(e); sendJSON(res, 500, { success: false, message: 'Error en el servidor' }); }
    } else {
      sendJSON(res, 404, { success: false, message: 'Ruta no encontrada' });
    }
    return;
  }

  // 2) ESTÁTICOS (public/)
  // Seguridad: evitar path traversal
  let filePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  filePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  const abs = path.join(config.publicDir, filePath);
  await sendFile(res, abs);
});

// ============================
// START
// ============================
server.listen(config.port, () => {
  console.log('Servidor escuchando en puerto', config.port);
});
