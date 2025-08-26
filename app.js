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
    const { correo, clave, contrasena, password } = await getBody(req);
    const pass = clave || contrasena || password;   // 👈 acepta los tres nombres

    if (!correo || !pass) {
      return sendJSON(res, 400, { success: false, message: 'Correo y contraseña requeridos' });
    }

    const users = await query(
      `SELECT u.*, r.nombrerol
       FROM usuarios u JOIN roles r ON u.rolid = r.rolid
       WHERE u.correo = $1`, [correo]
    );
    const u = users[0];
    if (!u) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

    let ok = false;
    if (u.contrasena?.startsWith?.('$2')) {
      ok = await bcrypt.compare(pass, u.contrasena);
    } else {
      ok = pass === u.contrasena;
      if (ok) {
        const hash = await bcrypt.hash(pass, 10);
        await query('UPDATE usuarios SET contrasena=$1 WHERE usuarioid=$2', [hash, u.usuarioid]);
      }
    }
    if (!ok) return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });

    const token = jwt.sign(
      { id: u.usuarioid, nombre: u.nombrecompleto, rol: u.nombrerol, correo: u.correo },
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
      `SELECT u.usuarioid, u.nombrecompleto, u.correo, u.estado, r.nombrerol
       FROM usuarios u JOIN roles r ON u.rolid=r.rolid
       ORDER BY u.nombrecompleto`
    );
    sendJSON(res, 200, { success: true, usuarios: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombrecompleto, correo, contrasena, rolid, estado } = await getBody(req);
    if (!nombrecompleto || !correo || !contrasena || !rolid)
      return sendJSON(res, 400, { success: false, message: 'Faltan campos' });

    const dup = await query('SELECT 1 FROM usuarios WHERE correo=$1', [correo]);
    if (dup.length) return sendJSON(res, 400, { success: false, message: 'Correo ya registrado' });

    const hash = await bcrypt.hash(contrasena, 10);
    await query(
      'INSERT INTO usuarios (nombrecompleto, correo, contrasena, rolid, estado) VALUES ($1,$2,$3,$4,$5)',
      [nombrecompleto, correo, hash, rolid, estado ?? true]
    );
    sendJSON(res, 201, { success: true, message: 'Usuario creado' });
  }
};
api['/api/usuarios/:id'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombrecompleto, correo, rolid, estado } = await getBody(req);
    await query(
      'UPDATE usuarios SET nombrecompleto=$1, correo=$2, rolid=$3, estado=$4 WHERE usuarioid=$5',
      [nombrecompleto, correo, rolid, estado, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Usuario actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('DELETE FROM usuarios WHERE usuarioid=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Usuario eliminado' });
  }
};

// ---------- ROLES ----------
api['/api/roles'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const roles = await query('SELECT * FROM roles ORDER BY nombrerol');
    sendJSON(res, 200, { success: true, roles });
  }
};

// ---------- PERFIL ----------
api['/api/perfil'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT u.usuarioid, u.nombrecompleto, u.correo, r.nombrerol
       FROM usuarios u JOIN roles r ON u.rolid=r.rolid
       WHERE u.usuarioid=$1`, [me.id]
    );
    sendJSON(res, 200, { success: true, usuario: rows[0] || null });
  }
};

// ---------- PLANES ----------
api['/api/planes'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM planesestudio ORDER BY nombreplan');
    sendJSON(res, 200, { success: true, planes: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombreplan, anioinicio, estado } = await getBody(req);
    if (!nombreplan || !anioinicio)
      return sendJSON(res, 400, { success: false, message: 'nombreplan y anioinicio requeridos' });
    await query(
      'INSERT INTO planesestudio (nombreplan, anioinicio, estado) VALUES ($1,$2,$3)',
      [nombreplan, anioinicio, estado ?? true]
    );
    sendJSON(res, 201, { success: true, message: 'Plan creado' });
  }
};
api['/api/planes/:id'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombreplan, anioinicio, estado } = await getBody(req);
    await query(
      'UPDATE planesestudio SET nombreplan=$1, anioinicio=$2, estado=$3 WHERE planid=$4',
      [nombreplan, anioinicio, estado, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Plan actualizado' });
  }
};
api['/api/planes/:id/inactivar'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE planesestudio SET estado=false WHERE planid=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Plan inactivado' });
  }
};

// ---------- MATERIAS ----------
api['/api/materias'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT m.*, p.nombreplan
       FROM materias m LEFT JOIN planesestudio p ON m.planid=p.planid
       ORDER BY m.nombre`
    );
    sendJSON(res, 200, { success: true, materias: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { codigo, nombre, creditos, planid } = await getBody(req);
    if (!codigo || !nombre || !creditos)
      return sendJSON(res, 400, { success: false, message: 'Código, Nombre y Créditos requeridos' });
    await query(
      'INSERT INTO materias (codigo, nombre, creditos, planid, estado) VALUES ($1,$2,$3,$4,true)',
      [codigo, nombre, creditos, planid || null]
    );
    sendJSON(res, 201, { success: true, message: 'Materia creada' });
  }
};
api['/api/materias/:codigo'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM materias WHERE codigo=$1', [p.codigo]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Materia no encontrada' });
    sendJSON(res, 200, { success: true, materia: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombre, creditos, planid } = await getBody(req);
    await query(
      'UPDATE materias SET nombre=$1, creditos=$2, planid=$3 WHERE codigo=$4',
      [nombre, creditos, planid || null, p.codigo]
    );
    sendJSON(res, 200, { success: true, message: 'Materia actualizada' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE materias SET estado=false WHERE codigo=$1', [p.codigo]);
    sendJSON(res, 200, { success: true, message: 'Materia inactivada' });
  }
};
api['/api/materias/:codigo/estado'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { activo } = await getBody(req);
    if (typeof activo !== 'boolean')
      return sendJSON(res, 400, { success: false, message: 'activo debe ser true/false' });
    await query('UPDATE materias SET estado=$1 WHERE codigo=$2', [activo, p.codigo]);
    sendJSON(res, 200, { success: true, message: `Materia ${activo ? 'activada' : 'desactivada'}` });
  }
};

// ---------- ESTUDIANTES ----------
api['/api/estudiantes'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM estudiantes WHERE estado=true ORDER BY nombre');
    sendJSON(res, 200, { success: true, estudiantes: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { cedula, nombre, fechanacimiento, correo, telefono } = await getBody(req);
    if (!cedula || !nombre)
      return sendJSON(res, 400, { success: false, message: 'Cédula y Nombre requeridos' });
    const dup = await query('SELECT 1 FROM estudiantes WHERE cedula=$1', [cedula]);
    if (dup.length) return sendJSON(res, 400, { success: false, message: 'Cédula ya registrada' });
    await query(
      'INSERT INTO estudiantes (cedula, nombre, fechanacimiento, correo, telefono, estado) VALUES ($1,$2,$3,$4,$5,true)',
      [cedula, nombre, fechanacimiento || null, correo || null, telefono || null]
    );
    sendJSON(res, 201, { success: true, message: 'Estudiante creado' });
  }
};
api['/api/estudiantes/:id'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM estudiantes WHERE estudianteid=$1', [p.id]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Estudiante no encontrado' });
    sendJSON(res, 200, { success: true, estudiante: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { cedula, nombre, fechanacimiento, correo, telefono } = await getBody(req);
    await query(
      'UPDATE estudiantes SET cedula=$1, nombre=$2, fechanacimiento=$3, correo=$4, telefono=$5 WHERE estudianteid=$6',
      [cedula, nombre, fechanacimiento || null, correo || null, telefono || null, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Estudiante actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE estudiantes SET estado=false WHERE estudianteid=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Estudiante inactivado' });
  }
};
api['/api/estudiantes/inactivos'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM estudiantes WHERE estado=false ORDER BY nombre');
    sendJSON(res, 200, { success: true, estudiantes: rows });
  }
};
api['/api/estudiantes/:id/reactivar'] = {
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE estudiantes SET estado=true WHERE estudianteid=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Estudiante reactivado' });
  }
};
api['/api/estudiantes/verificar-cedula'] = {
  GET: async (req, res, _p, urlObj) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const cedula = urlObj.searchParams.get('cedula');
    if (!cedula) return sendJSON(res, 400, { success: false, message: 'Cédula requerida' });
    const rows = await query('SELECT 1 FROM estudiantes WHERE cedula=$1', [cedula]);
    sendJSON(res, 200, { success: true, existe: rows.length > 0 });
  }
};

// ---------- PROFESORES ----------
// Nota: En tu INSERT inicial no veo la tabla profesores, pero la dejo por si la necesitas
api['/api/profesores'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM profesores WHERE estado=true ORDER BY nombre');
    sendJSON(res, 200, { success: true, profesores: rows });
  },
  POST: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombre, correo, telefono } = await getBody(req);
    if (!nombre) return sendJSON(res, 400, { success: false, message: 'Nombre requerido' });
    await query(
      'INSERT INTO profesores (nombre, correo, telefono, estado) VALUES ($1,$2,$3,true)',
      [nombre, correo || null, telefono || null]
    );
    sendJSON(res, 201, { success: true, message: 'Profesor creado' });
  }
};
api['/api/profesores/:id'] = {
  GET: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query('SELECT * FROM profesores WHERE profesorid=$1', [p.id]);
    if (!rows[0]) return sendJSON(res, 404, { success: false, message: 'Profesor no encontrado' });
    sendJSON(res, 200, { success: true, profesor: rows[0] });
  },
  PUT: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const { nombre, correo, telefono } = await getBody(req);
    await query(
      'UPDATE profesores SET nombre=$1, correo=$2, telefono=$3 WHERE profesorid=$4',
      [nombre, correo || null, telefono || null, p.id]
    );
    sendJSON(res, 200, { success: true, message: 'Profesor actualizado' });
  },
  DELETE: async (req, res, p) => {
    const me = await authMiddleware(req, res); if (!me) return;
    await query('UPDATE profesores SET estado=false WHERE profesorid=$1', [p.id]);
    sendJSON(res, 200, { success: true, message: 'Profesor inactivado' });
  }
};

// ---------- PERIODOS ----------
api['/api/periodos'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT * FROM periodos
       ORDER BY anio DESC,
         CASE WHEN nombre='Primer Semestre' THEN 1
              WHEN nombre='Segundo Semestre' THEN 2
              WHEN nombre='Verano' THEN 3 ELSE 4 END`
    );
    sendJSON(res, 200, { success: true, periodos: rows });
  }
};

// ---------- MATRÍCULAS ----------
api['/api/matriculas'] = {
  GET: async (req, res) => {
    const me = await authMiddleware(req, res); if (!me) return;
    const rows = await query(
      `SELECT m.matriculaid,
              CONCAT(e.nombre,' - ',e.cedula) AS estudiante,
              p.nombre AS periodo,
              p.anio
       FROM matricula m
       JOIN estudiantes e ON m.estudianteid=e.estudianteid
       JOIN periodos p ON m.periodoid=p.periodoid
       WHERE m.estado='Confirmada'
       ORDER BY m.matriculaid DESC`
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