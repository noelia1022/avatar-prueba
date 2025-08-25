const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });

const http = require('http');
const fs = require('fs').promises;
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ============================
// CONFIGURACIÓN
// ============================
const config = {
  port: process.env.PORT || 3000,
  publicDir: path.join(__dirname, 'public'),
  jwtSecret: process.env.JWT_SECRET || 'secret_key_avatar',
  mysql: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'noelia1234',
    database: process.env.DB_NAME || 'avatar',
    waitForConnections: true,
    connectionLimit: 10,
    dateStrings: true,
  }
};
// Pool MySQL
const pool = mysql.createPool(config.mysql);

// Helpers
async function query(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

// Helper para CORS
function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function sendJSON(res, status, data) {
  setCORSHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

async function sendFile(res, filePath) {
  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath);
    const contentTypes = {
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.ico': 'image/x-icon'
    };
    
    res.writeHead(200, { 
      'Content-Type': contentTypes[ext] || 'application/octet-stream'
    });
    res.end(data);
  } catch (error) {
    console.error('Error al servir archivo:', error);
    sendJSON(res, 404, { success: false, message: 'Archivo no encontrado' });
  }
}

async function getBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (error) {
        console.error('Error parsing JSON:', error);
        resolve({});
      }
    });
  });
}

// Middleware de autenticación
async function authMiddleware(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  
  if (!token) {
    sendJSON(res, 401, { success: false, message: 'Token no proporcionado' });
    return null;
  }
  
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (error) {
    console.error('Error validando token:', error);
    sendJSON(res, 401, { success: false, message: 'Token inválido or expirado' });
    return null;
  }
}

// API Handlers
const apiHandlers = {
  // Autenticación
  '/api/login': {
    POST: async (req, res) => {
      try {
        const { correo, clave } = await getBody(req);
        
        if (!correo || !clave) {
          return sendJSON(res, 400, { success: false, message: 'Correo y contraseña requeridos' });
        }

        const [usuario] = await query(`
          SELECT u.*, r.NombreRol 
          FROM Usuarios u
          JOIN Roles r ON u.RolID = r.RolID
          WHERE u.Correo = ?
        `, [correo]);

        if (!usuario) {
          return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });
        }

        let passwordValid = false;
        if (usuario.Contrasena.startsWith('$2b$') || usuario.Contrasena.startsWith('$2a$')) {
          passwordValid = await bcrypt.compare(clave, usuario.Contrasena);
        } else {
          passwordValid = (clave === usuario.Contrasena);
          if (passwordValid) {
            const hashedPassword = await bcrypt.hash(clave, 10);
            await query(
              'UPDATE Usuarios SET Contrasena = ? WHERE UsuarioID = ?',
              [hashedPassword, usuario.UsuarioID]
            );
          }
        }
        
        if (!passwordValid) {
          return sendJSON(res, 401, { success: false, message: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
          { id: usuario.UsuarioID, nombre: usuario.NombreCompleto, rol: usuario.NombreRol, correo: usuario.Correo },
          config.jwtSecret, 
          { expiresIn: '8h' }
        );

        sendJSON(res, 200, { success: true, token });
        
      } catch (error) {
        console.error('Error en login:', error);
        sendJSON(res, 500, { success: false, message: 'Error interno del servidor' });
      }
    }
  },

  // Usuarios
  '/api/usuarios': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const usuarios = await query(`
          SELECT u.UsuarioID, u.NombreCompleto, u.Correo, r.NombreRol, u.Estado
          FROM Usuarios u
          JOIN Roles r ON u.RolID = r.RolID
          ORDER BY u.NombreCompleto
        `);
        sendJSON(res, 200, { success: true, usuarios });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener usuarios' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { NombreCompleto, Correo, Contrasena, RolID, Estado } = await getBody(req);
        
        if (!NombreCompleto || !Correo || !Contrasena || !RolID) {
          return sendJSON(res, 400, { success: false, message: 'Todos los campos son requeridos' });
        }

        // Verificar si el correo ya existe
        const [existente] = await query('SELECT * FROM Usuarios WHERE Correo = ?', [Correo]);
        if (existente) {
          return sendJSON(res, 400, { success: false, message: 'El correo ya está registrado' });
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(Contrasena, 10);

        await query(
          'INSERT INTO Usuarios (NombreCompleto, Correo, Contrasena, RolID, Estado) VALUES (?, ?, ?, ?, ?)',
          [NombreCompleto, Correo, hashedPassword, RolID, Estado || 1]
        );

        sendJSON(res, 201, { success: true, message: 'Usuario creado correctamente' });
      } catch (error) {
        console.error('Error al crear usuario:', error);
        sendJSON(res, 500, { success: false, message: 'Error al crear usuario' });
      }
    }
  },

  '/api/usuarios/:id': {
    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const { NombreCompleto, Correo, RolID, Estado } = await getBody(req);
        
        // Verificar si el correo ya existe en otro usuario
        const [correoExistente] = await query(
          'SELECT * FROM Usuarios WHERE Correo = ? AND UsuarioID != ?',
          [Correo, id]
        );
        
        if (correoExistente) {
          return sendJSON(res, 400, { success: false, message: 'El correo ya está en uso por otro usuario' });
        }

        await query(
          'UPDATE Usuarios SET NombreCompleto = ?, Correo = ?, RolID = ?, Estado = ? WHERE UsuarioID = ?',
          [NombreCompleto, Correo, RolID, Estado, id]
        );

        sendJSON(res, 200, { success: true, message: 'Usuario actualizado correctamente' });
      } catch (error) {
        console.error('Error al actualizar usuario:', error);
        sendJSON(res, 500, { success: false, message: 'Error al actualizar usuario' });
      }
    },

    DELETE: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        await query('DELETE FROM Usuarios WHERE UsuarioID = ?', [id]);
        sendJSON(res, 200, { success: true, message: 'Usuario eliminado correctamente' });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al eliminar usuario' });
      }
    }
  },

  // Roles
  '/api/roles': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const roles = await query('SELECT * FROM Roles ORDER BY NombreRol');
        sendJSON(res, 200, { success: true, roles });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener roles' });
      }
    }
  },

  // Perfil
  '/api/perfil': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const [usuario] = await query(`
          SELECT u.UsuarioID, u.NombreCompleto, u.Correo, r.NombreRol
          FROM Usuarios u
          JOIN Roles r ON u.RolID = r.RolID
          WHERE u.UsuarioID = ?
        `, [user.id]);

        sendJSON(res, 200, { success: true, usuario });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener perfil' });
      }
    }
  },

  // Planes de estudio
  '/api/planes': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const planes = await query('SELECT * FROM PlanesEstudio ORDER BY NombrePlan');
        sendJSON(res, 200, { success: true, planes });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener planes de estudio' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { NombrePlan, AnioInicio, Estado } = await getBody(req);
        
        if (!NombrePlan || !AnioInicio) {
          return sendJSON(res, 400, { 
            success: false, 
            message: 'Nombre del plan y año de inicio son requeridos' 
          });
        }

        // Verificar si ya existe un plan con el mismo nombre
        const [planExistente] = await query(
          'SELECT * FROM PlanesEstudio WHERE NombrePlan = ?', 
          [NombrePlan]
        );
        
        if (planExistente) {
          return sendJSON(res, 400, { 
            success: false, 
            message: 'Ya existe un plan de estudio con ese nombre' 
          });
        }

        await query(
          'INSERT INTO PlanesEstudio (NombrePlan, AnioInicio, Estado) VALUES (?, ?, ?)',
          [NombrePlan, AnioInicio, Estado || 1]
        );

        sendJSON(res, 201, { success: true, message: 'Plan de estudio creado correctamente' });
      } catch (error) {
        console.error('Error al crear plan de estudio:', error);
        sendJSON(res, 500, { success: false, message: 'Error al crear plan de estudio' });
      }
    }
  },

  '/api/planes/:id': {
    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const { NombrePlan, AnioInicio, Estado } = await getBody(req);
        
        if (!NombrePlan || !AnioInicio) {
          return sendJSON(res, 400, { 
            success: false, 
            message: 'Nombre del plan y año de inicio son requeridos' 
          });
        }

        // Verificar si el nombre ya existe en otro plan
        const [planExistente] = await query(
          'SELECT * FROM PlanesEstudio WHERE NombrePlan = ? AND PlanID != ?',
          [NombrePlan, id]
        );
        
        if (planExistente) {
          return sendJSON(res, 400, { 
            success: false, 
            message: 'Ya existe otro plan de estudio con ese nombre' 
          });
        }

        await query(
          'UPDATE PlanesEstudio SET NombrePlan = ?, AnioInicio = ?, Estado = ? WHERE PlanID = ?',
          [NombrePlan, AnioInicio, Estado, id]
        );

        sendJSON(res, 200, { success: true, message: 'Plan de estudio actualizado correctamente' });
      } catch (error) {
        console.error('Error al actualizar plan de estudio:', error);
        sendJSON(res, 500, { success: false, message: 'Error al actualizar plan de estudio' });
      }
    }
  },

  '/api/planes/:id/inactivar': {
    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        
        // En lugar de DELETE, hacemos un UPDATE del estado a inactivo (0)
        await query(
          'UPDATE PlanesEstudio SET Estado = 0 WHERE PlanID = ?',
          [id]
        );
        
        sendJSON(res, 200, { success: true, message: 'Plan de estudio marcado como inactivo correctamente' });
      } catch (error) {
        console.error('Error al marcar plan como inactivo:', error);
        sendJSON(res, 500, { success: false, message: 'Error al marcar plan como inactivo' });
      }
    }
  },

  // Materias
  '/api/materias': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const materias = await query(`
          SELECT m.*, p.NombrePlan 
          FROM Materias m 
          LEFT JOIN PlanesEstudio p ON m.PlanID = p.PlanID 
          ORDER BY m.Nombre
        `);
        sendJSON(res, 200, { success: true, materias });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener materias' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { Codigo, Nombre, Creditos, PlanID } = await getBody(req);
        if (!Codigo || !Nombre || !Creditos) {
          return sendJSON(res, 400, { success: false, message: 'Código, Nombre y Créditos son requeridos' });
        }

        const [existente] = await query('SELECT * FROM Materias WHERE Codigo = ?', [Codigo]);
        if (existente) {
          return sendJSON(res, 400, { success: false, message: 'El código de materia ya existe' });
        }

        await query(
          'INSERT INTO Materias (Codigo, Nombre, Creditos, PlanID) VALUES (?, ?, ?, ?)',
          [Codigo, Nombre, Creditos, PlanID || null]
        );

        sendJSON(res, 201, { success: true, message: 'Materia creada correctamente' });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al crear materia' });
      }
    }
  },

  '/api/materias/:codigo': {
    GET: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { codigo } = params;
        const [materia] = await query(`
          SELECT m.*, p.NombrePlan 
          FROM Materias m 
          LEFT JOIN PlanesEstudio p ON m.PlanID = p.PlanID 
          WHERE m.Codigo = ?
        `, [codigo]);

        if (!materia) {
          return sendJSON(res, 404, { success: false, message: 'Materia no encontrada' });
        }

        sendJSON(res, 200, { success: true, materia });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener materia' });
      }
    },

    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { codigo } = params;
        const { Nombre, Creditos, PlanID } = await getBody(req);

        await query(
          'UPDATE Materias SET Nombre = ?, Creditos = ?, PlanID = ? WHERE Codigo = ?',
          [Nombre, Creditos, PlanID || null, codigo]
        );

        sendJSON(res, 200, { success: true, message: 'Materia actualizada correctamente' });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al actualizar materia' });
      }
    },

    DELETE: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { codigo } = params;
        
        // En lugar de DELETE, actualizamos el estado a inactivo
        await query('UPDATE Materias SET Estado = 0 WHERE Codigo = ?', [codigo]);
        
        sendJSON(res, 200, { success: true, message: 'Materia marcada como inactiva correctamente' });
      } catch (error) {
        console.error('Error al marcar materia como inactiva:', error);
        sendJSON(res, 500, { success: false, message: 'Error al marcar materia como inactiva' });
      }
    }
  },

  // Nuevo endpoint para cambiar estado de materias
  '/api/materias/:codigo/estado': {
    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { codigo } = params;
        const { activo } = await getBody(req);
        
        // Validar que el parámetro activo sea booleano
        if (typeof activo !== 'boolean') {
          return sendJSON(res, 400, { success: false, message: 'El campo "activo" debe ser true or false' });
        }

        // Verificar si la materia existe
        const [materia] = await query('SELECT * FROM Materias WHERE Codigo = ?', [codigo]);
        if (!materia) {
          return sendJSON(res, 404, { success: false, message: 'Materia no encontrada' });
        }

        // Actualizar el estado de la materia
        await query('UPDATE Materias SET Estado = ? WHERE Codigo = ?', [activo ? 1 : 0, codigo]);
        
        sendJSON(res, 200, { 
          success: true, 
          message: `Materia ${activo ? 'activada' : 'desactivada'} correctamente` 
        });
      } catch (error) {
        console.error('Error al cambiar estado de materia:', error);
        sendJSON(res, 500, { success: false, message: 'Error al cambiar estado de materia' });
      }
    }
  },

  // Estudiantes
  '/api/estudiantes': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const estudiantes = await query('SELECT * FROM estudiantes WHERE Estado = 1 ORDER BY Nombre');
        sendJSON(res, 200, { success: true, estudiantes });
      } catch (error) {
        console.error('Error al obtener estudiantes:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener estudiantes' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { cedula, nombre, fechaNacimiento, correo, telefono } = await getBody(req);
        
        if (!cedula || !nombre) {
          return sendJSON(res, 400, { success: false, message: 'Cédula y nombre son requeridos' });
        }

        // Verificar si la cédula ya existe
        const [existente] = await query('SELECT * FROM estudiantes WHERE Cedula = ?', [cedula]);
        if (existente) {
          return sendJSON(res, 400, { success: false, message: 'La cédula ya está registrada' });
        }

        await query(
          'INSERT INTO estudiantes (Cedula, Nombre, FechaNacimiento, Correo, Telefono, Estado) VALUES (?, ?, ?, ?, ?, 1)',
          [cedula, nombre, fechaNacimiento || null, correo || null, telefono || null]
        );

        sendJSON(res, 201, { success: true, message: 'Estudiante creado correctamente' });
      } catch (error) {
        console.error('Error al crear estudiante:', error);
        sendJSON(res, 500, { success: false, message: 'Error al crear estudiante' });
      }
    }
  },

  '/api/estudiantes/:id': {
    GET: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const [estudiante] = await query('SELECT * FROM estudiantes WHERE EstudianteID = ?', [id]);

        if (!estudiante) {
          return sendJSON(res, 404, { success: false, message: 'Estudiante no encontrado' });
        }

        sendJSON(res, 200, { success: true, estudiante });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener estudiante' });
      }
    },

    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const { cedula, nombre, fechaNacimiento, correo, telefono } = await getBody(req);
        
        // Verificar si la cédula ya existe en otro estudiante
        const [cedulaExistente] = await query(
          'SELECT * FROM estudiantes WHERE Cedula = ? AND EstudianteID != ?',
          [cedula, id]
        );
        
        if (cedulaExistente) {
          return sendJSON(res, 400, { success: false, message: 'La cédula ya está en uso por otro estudiante' });
        }

        await query(
          'UPDATE estudiantes SET Cedula = ?, Nombre = ?, FechaNacimiento = ?, Correo = ?, Telefono = ? WHERE EstudianteID = ?',
          [cedula, nombre, fechaNacimiento || null, correo || null, telefono || null, id]
        );

        sendJSON(res, 200, { success: true, message: 'Estudiante actualizado correctamente' });
      } catch (error) {
        console.error('Error al actualizar estudiante:', error);
        sendJSON(res, 500, { success: false, message: 'Error al actualizar estudiante' });
      }
    },

    DELETE: async (req, res, params) => {
      console.log('=== MARCANDO ESTUDIANTE COMO INACTIVO ===');
      
      const user = await authMiddleware(req, res);
      if (!user) {
        console.log('❌ No autenticado');
        return;
      }

      try {
        const { id } = params;
        console.log('ID a marcar como inactivo:', id);
        
        // Verificar si el estudiante existe primero
        const [estudiante] = await query('SELECT * FROM estudiantes WHERE EstudianteID = ?', [id]);
        
        if (!estudiante) {
          console.log('❌ Estudiante no encontrado');
          return sendJSON(res, 404, { success: false, message: 'Estudiante no encontrado' });
        }

        console.log('Marcando como inactivo estudiante:', estudiante.Nombre);
        
        // En lugar de DELETE, hacemos un UPDATE del estado
        await query('UPDATE estudiantes SET Estado = 0 WHERE EstudianteID = ?', [id]);
        
        console.log('✅ Estudiante marcado como inactivo correctamente');
        sendJSON(res, 200, { success: true, message: 'Estudiante marcado como inactivo correctamente' });
        
      } catch (error) {
        console.error('❌ Error al marcar estudiante como inactivo:', error);
        sendJSON(res, 500, { 
          success: false, 
          message: 'Error al marcar estudiante como inactivo: ' + error.message 
        });
      }
    }
  },

  '/api/estudiantes/verificar-cedula': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const cedula = req.query.cedula;
        if (!cedula) {
          return sendJSON(res, 400, { success: false, message: 'Cédula requerida' });
        }

        const [estudiante] = await query('SELECT * FROM estudiantes WHERE Cedula = ?', [cedula]);
        sendJSON(res, 200, { success: true, existe: !!estudiante });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al verificar cédula' });
      }
    }
  },

  // Estudiantes inactivos (opcional)
  '/api/estudiantes/inactivos': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const estudiantes = await query('SELECT * FROM estudiantes WHERE Estado = 0 ORDER BY Nombre');
        sendJSON(res, 200, { success: true, estudiantes });
      } catch (error) {
        console.error('Error al obtener estudiantes inactivos:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener estudiantes inactivos' });
      }
    }
  },

  // Reactivar estudiante (opcional)
  '/api/estudiantes/:id/reactivar': {
    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        await query('UPDATE estudiantes SET Estado = 1 WHERE EstudianteID = ?', [id]);
        sendJSON(res, 200, { success: true, message: 'Estudiante reactivado correctamente' });
      } catch (error) {
        console.error('Error al reactivar estudiante:', error);
        sendJSON(res, 500, { success: false, message: 'Error al reactivar estudiante' });
      }
    }
  },

  // PROFESORES - Implementación corregida
  '/api/profesores': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const profesores = await query('SELECT * FROM profesores WHERE Estado = 1 ORDER BY Nombre');
        sendJSON(res, 200, { success: true, profesores });
      } catch (error) {
        console.error('Error al obtener profesores:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener profesores' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { nombre, correo, telefono } = await getBody(req);
        
        if (!nombre) {
          return sendJSON(res, 400, { success: false, message: 'El nombre es obligatorio' });
        }

        await query(
          'INSERT INTO profesores (Nombre, Correo, Telefono, Estado) VALUES (?, ?, ?, 1)',
          [nombre, correo || null, telefono || null]
        );

        sendJSON(res, 201, { success: true, message: 'Profesor creado correctamente' });
      } catch (error) {
        console.error('Error al crear profesor:', error);
        sendJSON(res, 500, { success: false, message: 'Error al crear profesor' });
      }
    }
  },

  '/api/profesores/:id': {
    GET: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const [profesor] = await query('SELECT * FROM profesores WHERE ProfesorID = ?', [id]);

        if (!profesor) {
          return sendJSON(res, 404, { success: false, message: 'Profesor no encontrado' });
        }

        sendJSON(res, 200, { success: true, profesor });
      } catch (error) {
        sendJSON(res, 500, { success: false, message: 'Error al obtener profesor' });
      }
    },

    PUT: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        const { nombre, correo, telefono } = await getBody(req);

        await query(
          'UPDATE profesores SET Nombre = ?, Correo = ?, Telefono = ? WHERE ProfesorID = ?',
          [nombre, correo || null, telefono || null, id]
        );

        sendJSON(res, 200, { success: true, message: 'Profesor actualizado correctamente' });
      } catch (error) {
        console.error('Error al actualizar profesor:', error);
        sendJSON(res, 500, { success: false, message: 'Error al actualizar profesor' });
      }
    },

    DELETE: async (req, res, params) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { id } = params;
        
        // En lugar de DELETE, marcamos como inactivo
        await query('UPDATE profesores SET Estado = 0 WHERE ProfesorID = ?', [id]);
        
        sendJSON(res, 200, { success: true, message: 'Profesor marcado como inactivo correctamente' });
      } catch (error) {
        console.error('Error al marcar profesor como inactivo:', error);
        sendJSON(res, 500, { 
          success: false, 
          message: 'Error al marcar profesor como inactivo: ' + error.message 
        });
      }
    }
  },

  // Periodos académicos
  '/api/periodos': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const periodos = await query(`
          SELECT * FROM Periodos 
          ORDER BY Anio DESC, 
          CASE 
            WHEN Nombre = 'Primer Semestre' THEN 1
            WHEN Nombre = 'Segundo Semestre' THEN 2
            WHEN Nombre = 'Verano' THEN 3
            ELSE 4
          END
        `);
        sendJSON(res, 200, { success: true, periodos });
      } catch (error) {
        console.error('Error al obtener periodos:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener periodos' });
      }
    }
  },

  // MATRÍCULAS - Endpoint para obtener matrículas confirmadas
  '/api/matriculas': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const matriculas = await query(`
          SELECT m.MatriculaID, 
                 CONCAT(e.Nombre, ' - ', e.Cedula) as Estudiante, 
                 p.Nombre as Periodo, 
                 p.Anio
          FROM matricula m
          INNER JOIN estudiantes e ON m.EstudianteID = e.EstudianteID
          INNER JOIN periodos p ON m.PeriodoID = p.PeriodoID
          WHERE m.Estado = 'Confirmada'
          ORDER BY m.FechaMatricula DESC
        `);
        sendJSON(res, 200, { success: true, matriculas });
      } catch (error) {
        console.error('Error al obtener matrículas:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener matrículas' });
      }
    }
  },

  // API de Pagos
  '/api/pagos': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const pagos = await query(`
          SELECT p.*, 
                 e.Nombre as Estudiante, 
                 e.Cedula,
                 per.Nombre as Periodo, 
                 per.Anio
          FROM pagos p
          INNER JOIN matricula m ON p.MatriculaID = m.MatriculaID
          INNER JOIN estudiantes e ON m.EstudianteID = e.EstudianteID
          INNER JOIN periodos per ON m.PeriodoID = per.PeriodoID
          ORDER BY p.FechaPago DESC
        `);
        sendJSON(res, 200, { success: true, pagos });
      } catch (error) {
        console.error('Error al obtener pagos:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener pagos' });
      }
    },

    POST: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        const { MatriculaID, Monto, FechaPago, MetodoPago } = await getBody(req);
        
        if (!MatriculaID || !Monto || !FechaPago || !MetodoPago) {
          return sendJSON(res, 400, { 
            success: false, 
            message: 'Matrícula, monto, fecha y método de pago son requeridos' 
          });
        }

        await query(
          'INSERT INTO pagos (MatriculaID, Monto, FechaPago, MetodoPago) VALUES (?, ?, ?, ?)',
          [MatriculaID, Monto, FechaPago, MetodoPago]
        );

        sendJSON(res, 201, { success: true, message: 'Pago registrado correctamente' });
      } catch (error) {
        console.error('Error al registrar pago:', error);
        sendJSON(res, 500, { success: false, message: 'Error al registrar pago' });
      }
    }
  },

  // Dashboard - Datos para gráficos y estadísticas
  '/api/dashboard': {
    GET: async (req, res) => {
      const user = await authMiddleware(req, res);
      if (!user) return;

      try {
        // Obtener conteos básicos
        const [estudiantesCount] = await query('SELECT COUNT(*) as total FROM estudiantes WHERE Estado = 1');
        const [profesoresCount] = await query('SELECT COUNT(*) as total FROM profesores WHERE Estado = 1');
        const [materiasCount] = await query('SELECT COUNT(*) as total FROM materias WHERE Estado = 1');
        const [matriculasCount] = await query('SELECT COUNT(*) as total FROM matricula WHERE Estado = "Confirmada"');
        
        // Obtener ingresos del mes actual
        const [ingresosMes] = await query(`
          SELECT COALESCE(SUM(Monto), 0) as total 
          FROM pagos 
          WHERE MONTH(FechaPago) = MONTH(CURRENT_DATE()) 
          AND YEAR(FechaPago) = YEAR(CURRENT_DATE())
        `);
        
        // Obtener estudiantes por periodo (para gráfico)
        const estudiantesPorPeriodo = await query(`
          SELECT p.Nombre as periodo, p.Anio, COUNT(m.MatriculaID) as cantidad
          FROM periodos p
          LEFT JOIN matricula m ON p.PeriodoID = m.PeriodoID AND m.Estado = 'Confirmada'
          GROUP BY p.PeriodoID
          ORDER BY p.Anio DESC, p.Nombre
          LIMIT 5
        `);
        
        // Obtener últimos pagos
        const ultimosPagos = await query(`
          SELECT p.*, e.Nombre as estudiante, per.Nombre as periodo, per.Anio
          FROM pagos p
          INNER JOIN matricula m ON p.MatriculaID = m.MatriculaID
          INNER JOIN estudiantes e ON m.EstudianteID = e.EstudianteID
          INNER JOIN periodos per ON m.PeriodoID = per.PeriodoID
          ORDER BY p.FechaPago DESC
          LIMIT 5
        `);

        sendJSON(res, 200, {
          success: true,
          dashboard: {
            totales: {
              estudiantes: estudiantesCount.total,
              profesores: profesoresCount.total,
              materias: materiasCount.total,
              matriculas: matriculasCount.total,
              ingresosMes: ingresosMes.total
            },
            estudiantesPorPeriodo,
            ultimosPagos
          }
        });
      } catch (error) {
        console.error('Error al obtener datos del dashboard:', error);
        sendJSON(res, 500, { success: false, message: 'Error al obtener datos del dashboard' });
      }
    }
  }
};

// ============================
// SERVER
// ============================
const server = http.createServer(async (req, res) => {
  // Manejar CORS para preflight requests
  if (req.method === 'OPTIONS') {
    setCORSHeaders(res);
    res.writeHead(200);
    res.end();
    return;
  }

  // Servir archivos estáticos
  if (req.method === 'GET' && !req.url.startsWith('/api/')) {
    let filePath = req.url === '/' ? '/index.html' : req.url;
    filePath = path.join(config.publicDir, filePath);
    return sendFile(res, filePath);
  }

  // Manejar API
  if (req.url.startsWith('/api/')) {
    try {
      // Buscar el handler correspondiente
      let handlerFound = null;
      let params = {};
      
      for (const [route, methods] of Object.entries(apiHandlers)) {
        if (methods[req.method]) {
          // Verificar si es una ruta con parámetros
          if (route.includes(':')) {
            const routeParts = route.split('/');
            const urlParts = req.url.split('?')[0].split('/');
            
            if (routeParts.length === urlParts.length) {
              let match = true;
              const routeParams = {};
              
              for (let i = 0; i < routeParts.length; i++) {
                if (routeParts[i].startsWith(':')) {
                  const paramName = routeParts[i].slice(1);
                  routeParams[paramName] = urlParts[i];
                } else if (routeParts[i] !== urlParts[i]) {
                  match = false;
                  break;
                }
              }
              
              if (match) {
                handlerFound = methods[req.method];
                params = routeParams;
                break;
              }
            }
          } else if (req.url.startsWith(route)) {
            handlerFound = methods[req.method];
            break;
          }
        }
      }
      
      if (handlerFound) {
        return await handlerFound(req, res, params);
      } else {
        sendJSON(res, 404, { success: false, message: 'Endpoint no encontrado' });
      }
    } catch (error) {
      console.error('Error en API handler:', error);
      sendJSON(res, 500, { success: false, message: 'Error interno del servidor' });
    }
  } else {
    sendJSON(res, 404, { success: false, message: 'Ruta no encontrada' });
  }
});

// Iniciar servidor
server.listen(config.port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${config.port}`);
});

// Manejo de cierre
process.on('SIGINT', async () => {
  console.log('\nCerrando servidor...');
  await pool.end();
  process.exit(0);
});