require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const db = require('./db');

// Session store: intenta SQLite (persistente), cae a MemoryStore si no está disponible
let sessionStore;
try {
  const SQLiteStore = require('connect-sqlite3')(session);
  sessionStore = new SQLiteStore({ db: 'sessions.db', dir: './' });
  console.log('✓ Sesiones: SQLite (persistente)');
} catch (e) {
  const MemoryStore = require('memorystore')(session);
  sessionStore = new MemoryStore({ checkPeriod: 86400000 }); // limpia cada 24h
  console.log('✓ Sesiones: memoria (fallback)');
}

const app = express();
// Detrás del proxy de Render: necesario para cookies seguras y para detectar HTTPS
app.set('trust proxy', 1);
// Endpoint de salud (monitoreo / mantener despierto el servicio)
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
const PORT = process.env.PORT || 3000;
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

// Config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.json({ limit: '5mb' }));
// Compresión gzip: las páginas pesan ~70% menos y cargan más rápido (clave en conexiones lentas)
try { app.use(require('compression')()); } catch (e) { console.log('compression no disponible (npm install)'); }
// Archivos estáticos con caché de 1 día (el navegador no los re-descarga en cada página)
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d', etag: true }));

// Carpeta de archivos subidos — en el disco persistente de Render (DATA_DIR)
const fs = require('fs');
const DATA_DIR = process.env.DATA_DIR || __dirname;
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
try { fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch (e) {}
app.use('/uploads', express.static(UPLOADS_DIR, {
  setHeaders: (res, filePath) => {
    // Evitar que el navegador "adivine" el tipo (previene XSS por sniffing)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Tipos que podrían ejecutar scripts en el navegador → forzar descarga, no abrir inline
    if (/\.(html?|svg|xml|js|mjs)$/i.test(filePath)) res.setHeader('Content-Disposition', 'attachment');
  }
}));

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'edumax-secret-2024',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30, httpOnly: true, sameSite: 'lax', secure: 'auto' }
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    // Limpiar el nombre: quitar puntos dobles, caracteres raros
    const clean = file.originalname
      .replace(/\.{2,}/g, '.')   // doble punto → simple
      .replace(/[^a-zA-Z0-9.\-_ñÑáéíóúÁÉÍÓÚüÜ ]/g, '_')
      .trim();
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e6);
    cb(null, unique + '-' + clean);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (req, file, cb) => {
    // Aceptar todo — el frontend ya filtra
    cb(null, true);
  }
});

// Middleware global
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.path = req.path;
  if (req.session.user) {
    try {
      const unread = db.prepare('SELECT COUNT(*) as c FROM mensajes WHERE para_id=? AND leido=0').get(req.session.user.id);
      res.locals.mensajesNoLeidos = unread.c;
    } catch (e) { res.locals.mensajesNoLeidos = 0; }
  } else { res.locals.mensajesNoLeidos = 0; }
  next();
});

// ════════════════════════════════════════════════════════════
// HELPERS DE ROBUSTEZ
// ════════════════════════════════════════════════════════════

// Wrapper para rutas async — captura errores y los pasa al handler
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Validar que un ID sea un entero válido
const validId = (id) => {
  const n = parseInt(id);
  return Number.isInteger(n) && n > 0 ? n : null;
};

// Sanitizar string (trim + límite de longitud)
const clean = (str, max = 5000) => {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, max);
};

function auth(roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    if (roles && !roles.includes(req.session.user.rol)) return res.redirect('/');
    next();
  };
}

// ¿El alumno está inscripto en el aula? (control de acceso)
function inscripto(uid, aulaId) {
  return !!db.prepare('SELECT id FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(uid, aulaId);
}

// Registrar una acción sensible en auditoría (nunca rompe el flujo principal)
function auditar(req, accion, detalle) {
  try {
    const u = req.session.user;
    db.prepare('INSERT INTO auditoria (user_id,user_nombre,accion,detalle) VALUES (?,?,?,?)')
      .run(u ? u.id : null, u ? (u.nombre + ' ' + u.apellido) : 'sistema', accion, detalle || null);
  } catch (e) { /* la auditoría no debe interrumpir nada */ }
}

// ===================== AUTH =====================
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.rol === 'admin') return res.redirect('/admin');
  if (req.session.user.rol === 'docente') return res.redirect('/docente');
  return res.redirect('/alumno');
});

app.get('/login', (req, res) => res.render('login', { error: null }));
// Limitador anti fuerza-bruta en login (en memoria): 5 intentos fallidos → 5 min de espera
const loginIntentos = new Map();
function loginBloqueado(ip) {
  const r = loginIntentos.get(ip);
  if (r && r.hasta > Date.now()) return Math.ceil((r.hasta - Date.now()) / 1000);
  return 0;
}
function registrarFallo(ip) {
  const r = loginIntentos.get(ip) || { n: 0, hasta: 0 };
  r.n++;
  if (r.n >= 5) { r.hasta = Date.now() + 5 * 60 * 1000; r.n = 0; }
  loginIntentos.set(ip, r);
}

app.post('/login', wrap(async (req, res) => {
  const ip = req.ip || 'desconocida';
  const espera = loginBloqueado(ip);
  if (espera) return res.render('login', { error: `Demasiados intentos fallidos. Esperá ${Math.ceil(espera / 60)} minuto(s) y probá de nuevo.` });
  const email = clean(req.body.email, 200).toLowerCase();
  const password = req.body.password || '';
  if (!email || !password) {
    return res.render('login', { error: 'Completá email y contraseña' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email=? AND activo=1').get(email);
  if (!user || !await bcrypt.compare(password, user.password)) {
    registrarFallo(ip);
    return res.render('login', { error: 'Email o contraseña incorrectos' });
  }
  loginIntentos.delete(ip);
  req.session.user = { id: user.id, nombre: user.nombre, apellido: user.apellido, email: user.email, rol: user.rol, institucion: user.institucion, materia: user.materia };
  res.redirect('/');
}));

app.get('/registro', (req, res) => res.render('registro', { error: null, datos: {} }));

// Páginas públicas de información (accesibles con o sin sesión)
app.get('/acerca', (req, res) => res.render('info/acerca'));
app.get('/ayuda', (req, res) => res.render('info/ayuda'));
app.get('/contacto', (req, res) => res.render('info/contacto'));
app.get('/terminos', (req, res) => res.render('info/terminos'));
app.post('/registro', wrap(async (req, res) => {
  const nombre = clean(req.body.nombre, 100);
  const apellido = clean(req.body.apellido, 100);
  const email = clean(req.body.email, 200).toLowerCase();
  const password = req.body.password || '';
  const password2 = req.body.password2 || '';
  const rol = ['alumno', 'docente'].includes(req.body.rol) ? req.body.rol : 'alumno';
  const institucion = clean(req.body.institucion, 200);
  const materia = clean(req.body.materia, 200);

  // Para repoblar el formulario si hay error
  const datos = { nombre, apellido, email, rol, institucion, materia };

  // Validaciones
  if (!nombre || !apellido || !email || !password) {
    return res.render('registro', { error: 'Completá todos los campos obligatorios', datos });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.render('registro', { error: 'El email no tiene un formato válido', datos });
  }
  if (password.length < 8) {
    return res.render('registro', { error: 'La contraseña debe tener al menos 8 caracteres', datos });
  }
  if (password !== password2) {
    return res.render('registro', { error: 'Las contraseñas no coinciden', datos });
  }
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
    return res.render('registro', { error: 'Ya existe una cuenta con ese email. ¿Querés iniciar sesión?', datos });

  const hash = await bcrypt.hash(password, 10);
  const r = db.prepare('INSERT INTO users (nombre,apellido,email,password,rol,institucion,materia) VALUES (?,?,?,?,?,?,?)').run(nombre, apellido, email, hash, rol, institucion || null, materia || null);
  req.session.user = { id: r.lastInsertRowid, nombre, apellido, email, rol, institucion, materia };
  res.redirect('/');
}));

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/perfil', auth(), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  res.render('perfil', { perfil: u });
});
app.post('/perfil', auth(), wrap(async (req, res) => {
  const { nombre, apellido, institucion, materia, bio } = req.body;
  db.prepare('UPDATE users SET nombre=?,apellido=?,institucion=?,materia=?,bio=? WHERE id=?').run(nombre, apellido, institucion, materia, bio, req.session.user.id);
  req.session.user = { ...req.session.user, nombre, apellido, institucion, materia };
  res.redirect('/perfil');
}));

// ===================== ADMIN =====================
app.get('/admin', auth(['admin']), (req, res) => {
  const stats = {
    docentes: db.prepare("SELECT COUNT(*) as c FROM users WHERE rol='docente'").get().c,
    alumnos: db.prepare("SELECT COUNT(*) as c FROM users WHERE rol='alumno'").get().c,
    aulas: db.prepare('SELECT COUNT(*) as c FROM aulas').get().c,
    mensajes: db.prepare('SELECT COUNT(*) as c FROM mensajes').get().c,
  };
  const users = db.prepare('SELECT * FROM users ORDER BY creado_en DESC LIMIT 10').all();
  res.render('admin/panel', { stats, users });
});

app.get('/admin/usuarios', auth(['admin']), (req, res) => {
  const porPagina = 50;
  const pagina = Math.max(1, parseInt(req.query.p) || 1);
  const q = clean(req.query.q || '', 100);
  let total, users;
  if (q) {
    const like = '%' + q + '%';
    total = db.prepare('SELECT COUNT(*) as n FROM users WHERE nombre LIKE ? OR apellido LIKE ? OR email LIKE ?').get(like, like, like).n;
    users = db.prepare('SELECT * FROM users WHERE nombre LIKE ? OR apellido LIKE ? OR email LIKE ? ORDER BY rol,apellido LIMIT ? OFFSET ?').all(like, like, like, porPagina, (pagina - 1) * porPagina);
  } else {
    total = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
    users = db.prepare('SELECT * FROM users ORDER BY rol,apellido LIMIT ? OFFSET ?').all(porPagina, (pagina - 1) * porPagina);
  }
  const resetInfo = req.session.resetInfo || null;
  delete req.session.resetInfo;
  res.render('admin/usuarios', { users, resetInfo, total, pagina, paginas: Math.max(1, Math.ceil(total / porPagina)), q });
});

app.get('/admin/auditoria', auth(['admin']), (req, res) => {
  let registros = [];
  try { registros = db.prepare('SELECT * FROM auditoria ORDER BY id DESC LIMIT 200').all(); } catch (e) {}
  res.render('admin/auditoria', { registros });
});

app.post('/admin/usuarios/:id/toggle', auth(['admin']), (req, res) => {
  db.prepare('UPDATE users SET activo=CASE WHEN activo=1 THEN 0 ELSE 1 END WHERE id=?').run(req.params.id);
  res.redirect('/admin/usuarios');
});

app.post('/admin/usuarios/:id/rol', auth(['admin']), (req, res) => {
  db.prepare('UPDATE users SET rol=? WHERE id=?').run(req.body.rol, req.params.id);
  res.redirect('/admin/usuarios');
});

// Generador de contraseña temporal (8 caracteres)
function passTemporal() { return 'Edu' + Math.random().toString(36).slice(-5); }

app.post('/admin/usuarios/:id/reset-password', auth(['admin']), wrap(async (req, res) => {
  const u = db.prepare('SELECT nombre, apellido, email FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.redirect('/admin/usuarios');
  const temp = passTemporal();
  db.prepare('UPDATE users SET password=? WHERE id=?').run(await bcrypt.hash(temp, 10), req.params.id);
  auditar(req, 'reset_password_admin', 'Usuario: ' + u.email);
  req.session.resetInfo = { nombre: u.nombre + ' ' + u.apellido, email: u.email, temp };
  res.redirect('/admin/usuarios');
}));

// ===================== DOCENTE =====================
app.get('/docente', auth(['docente']), (req, res) => {
  const uid = req.session.user.id;
  const aulas = db.prepare('SELECT a.*, (SELECT COUNT(*) FROM inscripciones WHERE aula_id=a.id) as cant FROM aulas a WHERE docente_id=? ORDER BY id DESC').all(uid);
  const pendientes = db.prepare(`
    SELECT e.*, a.titulo as act_titulo, au.nombre as aula_nombre, u.nombre||' '||u.apellido as alumno
    FROM entregas e JOIN actividades a ON e.actividad_id=a.id JOIN aulas au ON a.aula_id=au.id
    JOIN users u ON e.alumno_id=u.id
    WHERE au.docente_id=? AND e.nota IS NULL ORDER BY e.fecha_entrega DESC LIMIT 10
  `).all(uid);
  res.render('docente/panel', { aulas, pendientes });
});

app.get('/docente/aulas/nueva', auth(['docente']), (req, res) => res.render('docente/aula-nueva', { error: null }));
app.post('/docente/aulas/nueva', auth(['docente']), upload.single('imagen'), (req, res) => {
  const { nombre, descripcion, nivel, anio } = req.body;
  const codigo = Math.random().toString(36).substring(2, 8).toUpperCase();
  const imagen = req.file ? req.file.filename : null;
  const r = db.prepare('INSERT INTO aulas (docente_id,nombre,descripcion,nivel,anio,codigo_acceso,imagen) VALUES (?,?,?,?,?,?,?)').run(req.session.user.id, nombre, descripcion, nivel, anio, codigo, imagen);
  // Crear foro general automáticamente
  db.prepare('INSERT INTO foros (aula_id,titulo,descripcion) VALUES (?,?,?)').run(r.lastInsertRowid, 'Foro general', 'Espacio de debate y consultas generales del aula');
  res.redirect('/docente/aulas/' + r.lastInsertRowid);
});

// Borrar aula y todo su contenido (en cascada, transaccional si el motor lo soporta)
app.post('/docente/aulas/:id/eliminar', auth(['docente']), (req, res) => {
  const aulaId = parseInt(req.params.id);
  const aula = db.prepare('SELECT id, nombre FROM aulas WHERE id=? AND docente_id=?').get(aulaId, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const pasos = () => {
    db.prepare('DELETE FROM entregas WHERE actividad_id IN (SELECT id FROM actividades WHERE aula_id=?)').run(aulaId);
    db.prepare('DELETE FROM actividades WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM preguntas WHERE evaluacion_id IN (SELECT id FROM evaluaciones WHERE aula_id=?)').run(aulaId);
    db.prepare('DELETE FROM intentos_eval WHERE evaluacion_id IN (SELECT id FROM evaluaciones WHERE aula_id=?)').run(aulaId);
    db.prepare('DELETE FROM evaluaciones WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM respuestas_foro WHERE hilo_id IN (SELECT id FROM hilos WHERE foro_id IN (SELECT id FROM foros WHERE aula_id=?))').run(aulaId);
    db.prepare('DELETE FROM hilos WHERE foro_id IN (SELECT id FROM foros WHERE aula_id=?)').run(aulaId);
    db.prepare('DELETE FROM foros WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM votos_encuesta WHERE encuesta_id IN (SELECT id FROM encuestas WHERE aula_id=?)').run(aulaId);
    db.prepare('DELETE FROM encuestas WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM contenidos WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM wikis WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM anuncios WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM eventos WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM asistencias WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM inscripciones WHERE aula_id=?').run(aulaId);
    db.prepare('DELETE FROM aulas WHERE id=?').run(aulaId);
  };
  try {
    if (typeof db.transaction === 'function') db.transaction(pasos)();
    else pasos();
    auditar(req, 'eliminar_aula', 'Aula "' + aula.nombre + '" (#' + aulaId + ')');
  } catch (e) { console.error('Error borrando aula:', e.message); }
  res.redirect('/docente');
});

app.get('/docente/aulas/:id', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const tab = req.query.tab || 'contenidos';
  const data = { aula, tab };
  data.resetInfo = req.session.resetInfo || null;
  delete req.session.resetInfo;
  data.contenidos = db.prepare('SELECT * FROM contenidos WHERE aula_id=? ORDER BY orden,id').all(aula.id);
  // Cuántos alumnos vieron cada contenido (alimenta el "X de Y" del Programa)
  try {
    const vistosPorContenido = db.prepare('SELECT contenido_id, COUNT(*) as n FROM contenido_visto WHERE contenido_id IN (SELECT id FROM contenidos WHERE aula_id=?) GROUP BY contenido_id').all(aula.id);
    const mapaVistos = {};
    vistosPorContenido.forEach(v => mapaVistos[v.contenido_id] = v.n);
    data.contenidos.forEach(c => c._vistos = mapaVistos[c.id] || 0);
  } catch (e) { data.contenidos.forEach(c => c._vistos = 0); }
  data.actividades = db.prepare('SELECT a.*, (SELECT COUNT(*) FROM entregas WHERE actividad_id=a.id) as entregas FROM actividades a WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.evaluaciones = db.prepare('SELECT e.*, (SELECT COUNT(*) FROM intentos_eval WHERE evaluacion_id=e.id AND completado=1) as rindieron FROM evaluaciones e WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.foros = db.prepare('SELECT f.*, (SELECT COUNT(*) FROM hilos WHERE foro_id=f.id) as hilos FROM foros f WHERE aula_id=?').all(aula.id);
  data.alumnos = db.prepare('SELECT u.*, i.progreso, i.fecha FROM users u JOIN inscripciones i ON i.alumno_id=u.id WHERE i.aula_id=? ORDER BY u.apellido').all(aula.id);
  data.anuncios = db.prepare("SELECT an.*, u.nombre||' '||u.apellido as autor FROM anuncios an JOIN users u ON an.autor_id=u.id WHERE aula_id=? ORDER BY id DESC").all(aula.id);
  data.wikis = db.prepare('SELECT * FROM wikis WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.encuestas = db.prepare('SELECT * FROM encuestas WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.encuestas.forEach(e => { e.opciones = JSON.parse(e.opciones); e.votos = db.prepare('SELECT opcion, COUNT(*) as c FROM votos_encuesta WHERE encuesta_id=? GROUP BY opcion').all(e.id); });
  data.host = req.get('host');
  data.protocol = req.protocol;
  res.render('docente/aula', data);
});

// Helper: si viene array (campos duplicados ocultos), tomar el primer valor no-vacío
function pickFirst(v) {
  if (Array.isArray(v)) return v.find(x => x && x.length > 0) || null;
  return v || null;
}

// Sanea HTML guardado: elimina scripts, manejadores de eventos y javascript: (mantiene iframes de embeds)
function limpiarHTML(html) {
  if (!html) return html;
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<\/?\s*script\b[^>]*>/gi, '')
    .replace(/\son\w+\s*=\s*"[^"]*"/gi, '')
    .replace(/\son\w+\s*=\s*'[^']*'/gi, '')
    .replace(/\son\w+\s*=\s*[^\s>]+/gi, '')
    .replace(/javascript:/gi, '');
}

// Contenidos
app.post('/docente/aulas/:id/contenidos', auth(['docente']), (req, res, next) => {
  upload.single('archivo')(req, res, (err) => {
    if (err) {
      // Error de multer: archivo muy grande, error de lectura, etc.
      console.error('Error de upload:', err.message);
      return res.redirect('/docente/aulas/' + req.params.id + '?error=' + encodeURIComponent('Error al subir archivo: ' + err.message));
    }
    next();
  });
}, (req, res) => {
  const { tipo, titulo, orden, obligatorio, unidad } = req.body;
  const archivo = req.file ? req.file.filename : null;
  const nombre_original = req.file ? req.file.originalname : null;
  try {
    db.prepare('INSERT INTO contenidos (aula_id,tipo,titulo,cuerpo,archivo,nombre_original,url_externa,orden,embed_html,descripcion,obligatorio,unidad) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').run(
      parseInt(req.params.id),
      tipo || 'texto',
      titulo,
      limpiarHTML(pickFirst(req.body.cuerpo)),
      archivo,
      nombre_original,
      pickFirst(req.body.url_externa),
      parseInt(orden) || 0,
      limpiarHTML(pickFirst(req.body.embed_html)),
      pickFirst(req.body.descripcion),
      obligatorio ? 1 : 0,
      pickFirst(unidad)
    );
    res.redirect('/docente/aulas/' + req.params.id);
  } catch (e) {
    console.error('Error insertando contenido:', e);
    res.status(500).send('Error al guardar: ' + e.message);
  }
});

// ── Editar contenido ──────────────────────────────────────
app.post('/docente/contenidos/:id/editar', auth(['docente']), (req, res, next) => {
  upload.single('archivo')(req, res, (err) => { if (err) return next(err); next(); });
}, (req, res) => {
  const c = db.prepare('SELECT c.*, a.docente_id FROM contenidos c JOIN aulas a ON c.aula_id=a.id WHERE c.id=?').get(req.params.id);
  if (!c || c.docente_id !== req.session.user.id) return res.redirect('/docente');
  const { titulo, descripcion, obligatorio, unidad, orden } = req.body;
  const archivo   = req.file ? req.file.filename    : c.archivo;
  const nomOrig   = req.file ? req.file.originalname : c.nombre_original;
  const urlExt    = pickFirst(req.body.url_externa) || c.url_externa;
  const cuerpo    = limpiarHTML(pickFirst(req.body.cuerpo)      || c.cuerpo);
  const embedHtml = limpiarHTML(pickFirst(req.body.embed_html)  || c.embed_html);
  db.prepare(`UPDATE contenidos SET titulo=?,descripcion=?,obligatorio=?,unidad=?,orden=?,archivo=?,nombre_original=?,url_externa=?,cuerpo=?,embed_html=? WHERE id=?`)
    .run(titulo, descripcion||null, obligatorio?1:0, unidad||null, parseInt(orden)||0, archivo, nomOrig, urlExt, cuerpo, embedHtml, c.id);
  res.redirect('/docente/aulas/' + c.aula_id);
});

// ── Reordenar contenido (subir/bajar) ─────────────────────
app.post('/docente/contenidos/:id/subir', auth(['docente']), (req, res) => {
  const c = db.prepare('SELECT c.*, a.docente_id FROM contenidos c JOIN aulas a ON c.aula_id=a.id WHERE c.id=?').get(req.params.id);
  if (!c || c.docente_id !== req.session.user.id) return res.redirect('/docente');
  const prev = db.prepare('SELECT * FROM contenidos WHERE aula_id=? AND (unidad=? OR (unidad IS NULL AND ? IS NULL)) AND orden < ? ORDER BY orden DESC, id DESC LIMIT 1').get(c.aula_id, c.unidad, c.unidad, c.orden||999);
  if (prev) {
    db.prepare('UPDATE contenidos SET orden=? WHERE id=?').run(prev.orden||0, c.id);
    db.prepare('UPDATE contenidos SET orden=? WHERE id=?').run(c.orden||0, prev.id);
  }
  res.redirect('/docente/aulas/' + c.aula_id);
});
app.post('/docente/contenidos/:id/bajar', auth(['docente']), (req, res) => {
  const c = db.prepare('SELECT c.*, a.docente_id FROM contenidos c JOIN aulas a ON c.aula_id=a.id WHERE c.id=?').get(req.params.id);
  if (!c || c.docente_id !== req.session.user.id) return res.redirect('/docente');
  const next2 = db.prepare('SELECT * FROM contenidos WHERE aula_id=? AND (unidad=? OR (unidad IS NULL AND ? IS NULL)) AND orden > ? ORDER BY orden ASC, id ASC LIMIT 1').get(c.aula_id, c.unidad, c.unidad, c.orden||0);
  if (next2) {
    db.prepare('UPDATE contenidos SET orden=? WHERE id=?').run(next2.orden||0, c.id);
    db.prepare('UPDATE contenidos SET orden=? WHERE id=?').run(c.orden||0, next2.id);
  }
  res.redirect('/docente/aulas/' + c.aula_id);
});

app.post('/docente/contenidos/:id/eliminar', auth(['docente']), (req, res) => {
  const c = db.prepare('SELECT c.*, a.docente_id FROM contenidos c JOIN aulas a ON c.aula_id=a.id WHERE c.id=?').get(req.params.id);
  if (c && c.docente_id === req.session.user.id) {
    db.prepare('DELETE FROM contenidos WHERE id=?').run(req.params.id);
    res.redirect('/docente/aulas/' + c.aula_id + '?tab=contenidos');
  } else res.redirect('/docente');
});

// Actividades
app.get('/docente/aulas/:id/actividades/nueva', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  res.render('docente/actividad-nueva', { aula });
});

app.post('/docente/aulas/:id/actividades', auth(['docente']), (req, res) => {
  const { titulo, descripcion, fecha_entrega, puntaje_max, tipo_entrega } = req.body;
  db.prepare('INSERT INTO actividades (aula_id,titulo,descripcion,fecha_entrega,puntaje_max,tipo_entrega) VALUES (?,?,?,?,?,?)').run(req.params.id, titulo, descripcion, fecha_entrega||null, puntaje_max||10, tipo_entrega||'archivo');
  res.redirect('/docente/aulas/' + req.params.id + '?tab=actividades');
});

app.get('/docente/actividades/:id', auth(['docente']), (req, res) => {
  const act = db.prepare('SELECT a.*, au.nombre as aula_nombre, au.docente_id FROM actividades a JOIN aulas au ON a.aula_id=au.id WHERE a.id=?').get(req.params.id);
  if (!act || act.docente_id !== req.session.user.id) return res.redirect('/docente');
  const entregas = db.prepare('SELECT e.*, u.nombre, u.apellido FROM entregas e JOIN users u ON e.alumno_id=u.id WHERE e.actividad_id=? ORDER BY e.fecha_entrega DESC').all(act.id);
  res.render('docente/actividad-entregas', { act, entregas });
});

app.post('/docente/entregas/:id/calificar', auth(['docente']), (req, res) => {
  const { nota, feedback, redirect_to } = req.body;
  db.prepare('UPDATE entregas SET nota=?,feedback=? WHERE id=?').run(parseFloat(nota), feedback, req.params.id);
  res.redirect(redirect_to || '/docente');
});

// Evaluaciones
app.get('/docente/aulas/:id/evaluaciones/nueva', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  res.render('docente/evaluacion-nueva', { aula });
});

app.post('/docente/aulas/:id/evaluaciones', auth(['docente']), (req, res) => {
  const { titulo, descripcion, intentos_max, tiempo_limite, fecha_desde, fecha_hasta } = req.body;
  const r = db.prepare('INSERT INTO evaluaciones (aula_id,titulo,descripcion,intentos_max,tiempo_limite,fecha_desde,fecha_hasta) VALUES (?,?,?,?,?,?,?)').run(req.params.id, titulo, descripcion, intentos_max||1, tiempo_limite||null, fecha_desde||null, fecha_hasta||null);
  res.redirect('/docente/evaluaciones/' + r.lastInsertRowid + '/preguntas');
});

app.get('/docente/evaluaciones/:id/preguntas', auth(['docente']), (req, res) => {
  const ev = db.prepare('SELECT e.*, a.nombre as aula_nombre, a.docente_id FROM evaluaciones e JOIN aulas a ON e.aula_id=a.id WHERE e.id=?').get(req.params.id);
  if (!ev || ev.docente_id !== req.session.user.id) return res.redirect('/docente');
  const preguntas = db.prepare('SELECT * FROM preguntas WHERE evaluacion_id=? ORDER BY orden').all(ev.id);
  res.render('docente/evaluacion-preguntas', { ev, preguntas });
});

app.post('/docente/evaluaciones/:id/preguntas', auth(['docente']), (req, res) => {
  const { tipo, texto, opciones, respuesta_correcta, puntaje } = req.body;
  const orden = db.prepare('SELECT COUNT(*) as c FROM preguntas WHERE evaluacion_id=?').get(req.params.id).c;
  db.prepare('INSERT INTO preguntas (evaluacion_id,tipo,texto,opciones,respuesta_correcta,puntaje,orden) VALUES (?,?,?,?,?,?,?)').run(req.params.id, tipo, texto, opciones||null, respuesta_correcta, puntaje||1, orden);
  res.redirect('/docente/evaluaciones/' + req.params.id + '/preguntas');
});

app.post('/docente/preguntas/:id/eliminar', auth(['docente']), (req, res) => {
  const p = db.prepare('SELECT p.*, e.aula_id, a.docente_id FROM preguntas p JOIN evaluaciones e ON p.evaluacion_id=e.id JOIN aulas a ON e.aula_id=a.id WHERE p.id=?').get(req.params.id);
  if (p && p.docente_id === req.session.user.id) db.prepare('DELETE FROM preguntas WHERE id=?').run(req.params.id);
  res.redirect('/docente/evaluaciones/' + p.evaluacion_id + '/preguntas');
});

app.get('/docente/evaluaciones/:id/resultados', auth(['docente']), (req, res) => {
  const ev = db.prepare('SELECT e.*, a.nombre as aula_nombre, a.docente_id FROM evaluaciones e JOIN aulas a ON e.aula_id=a.id WHERE e.id=?').get(req.params.id);
  if (!ev || ev.docente_id !== req.session.user.id) return res.redirect('/docente');
  const intentos = db.prepare('SELECT i.*, u.nombre, u.apellido FROM intentos_eval i JOIN users u ON i.alumno_id=u.id WHERE i.evaluacion_id=? AND i.completado=1 ORDER BY i.nota DESC').all(ev.id);
  res.render('docente/evaluacion-resultados', { ev, intentos });
});

// Foros docente
app.post('/docente/aulas/:id/foros', auth(['docente']), (req, res) => {
  db.prepare('INSERT INTO foros (aula_id,titulo,descripcion) VALUES (?,?,?)').run(req.params.id, req.body.titulo, req.body.descripcion);
  res.redirect('/docente/aulas/' + req.params.id + '?tab=foros');
});

// Anuncios
app.post('/docente/aulas/:id/anuncios', auth(['docente']), (req, res) => {
  db.prepare('INSERT INTO anuncios (aula_id,autor_id,titulo,cuerpo) VALUES (?,?,?,?)').run(req.params.id, req.session.user.id, req.body.titulo, req.body.cuerpo);
  res.redirect('/docente/aulas/' + req.params.id + '?tab=anuncios');
});

// Asistencia docente
app.get('/docente/aulas/:id/asistencia', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const fecha = req.query.fecha || new Date().toISOString().split('T')[0];
  const alumnos = db.prepare(`
    SELECT u.*, a.presente FROM users u 
    JOIN inscripciones i ON i.alumno_id=u.id
    LEFT JOIN asistencias a ON a.alumno_id=u.id AND a.aula_id=? AND a.fecha=?
    WHERE i.aula_id=? ORDER BY u.apellido
  `).all(aula.id, fecha, aula.id);
  res.render('docente/asistencia', { aula, alumnos, fecha });
});

app.post('/docente/aulas/:id/asistencia', auth(['docente']), (req, res) => {
  const { fecha, asistencias } = req.body;
  const lista = JSON.parse(asistencias || '[]');
  const upsert = db.prepare('INSERT INTO asistencias (alumno_id,aula_id,fecha,presente) VALUES (?,?,?,?) ON CONFLICT(alumno_id,aula_id,fecha) DO UPDATE SET presente=excluded.presente');
  db.transaction(items => items.forEach(i => upsert.run(i.id, req.params.id, fecha, i.presente ? 1 : 0)))(lista);
  res.redirect('/docente/aulas/' + req.params.id + '/asistencia?fecha=' + fecha);
});

// Calificaciones docente
app.get('/docente/aulas/:id/calificaciones', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const alumnos = db.prepare('SELECT u.* FROM users u JOIN inscripciones i ON i.alumno_id=u.id WHERE i.aula_id=? ORDER BY u.apellido').all(aula.id);
  const actividades = db.prepare('SELECT * FROM actividades WHERE aula_id=?').all(aula.id);
  const evaluaciones = db.prepare('SELECT * FROM evaluaciones WHERE aula_id=?').all(aula.id);
  const entregas = db.prepare('SELECT * FROM entregas WHERE actividad_id IN (SELECT id FROM actividades WHERE aula_id=?)').all(aula.id);
  const intentos = db.prepare('SELECT * FROM intentos_eval WHERE evaluacion_id IN (SELECT id FROM evaluaciones WHERE aula_id=?) AND completado=1').all(aula.id);
  res.render('docente/calificaciones', { aula, alumnos, actividades, evaluaciones, entregas, intentos });
});

// IA docente
app.get('/docente/ia', auth(['docente']), (req, res) => {
  const aulas = db.prepare('SELECT * FROM aulas WHERE docente_id=?').all(req.session.user.id);
  res.render('docente/ia', { respuesta: null, consulta: null, aulas, examGuardado: null });
});

app.post('/docente/ia/generar', auth(['docente']), wrap(async (req, res) => {
  const { tipo, materia, tema, nivel, cantidad, dificultad, extras, aula_id } = req.body;
  const aulas = db.prepare('SELECT * FROM aulas WHERE docente_id=?').all(req.session.user.id);
  if (!anthropic) return res.render('docente/ia', { respuesta: 'API key no configurada. Agregá ANTHROPIC_API_KEY en el .env', consulta: req.body.tipo, aulas, examGuardado: null });
  try {
    const prompt = `Sos un docente experto. Generá un ${tipo} de "${materia}" sobre "${tema}" para ${nivel}. ${cantidad} ejercicios, dificultad ${dificultad}. Incluí encabezado con nombre/curso/fecha/nota, ejercicios numerados con puntaje, tabla de calificación. ${extras||''}`;
    const r = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 2000, messages: [{ role: 'user', content: prompt }] });
    const contenido = r.content[0].text;
    let examGuardado = null;
    if (aula_id) {
      const ins = db.prepare('INSERT INTO evaluaciones (aula_id,titulo,descripcion) VALUES (?,?,?)').run(aula_id, `${tipo} - ${tema}`, contenido);
      examGuardado = ins.lastInsertRowid;
    }
    res.render('docente/ia', { respuesta: contenido, consulta: req.body, aulas, examGuardado });
  } catch(e) { res.render('docente/ia', { respuesta: 'Error: ' + e.message, consulta: req.body, aulas, examGuardado: null }); }
}));

app.post('/docente/ia/asistente', auth(['docente']), wrap(async (req, res) => {
  const aulas = db.prepare('SELECT * FROM aulas WHERE docente_id=?').all(req.session.user.id);
  if (!anthropic) return res.render('docente/ia', { respuesta: 'API key no configurada', consulta: null, aulas, examGuardado: null });
  try {
    const r = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 2000, messages: [{ role: 'user', content: `Sos un asistente para docentes argentinos. Respondé en español rioplatense.\n\n${req.body.consulta}` }] });
    res.render('docente/ia', { respuesta: r.content[0].text, consulta: req.body.consulta, aulas, examGuardado: null });
  } catch(e) { res.render('docente/ia', { respuesta: 'Error: ' + e.message, consulta: null, aulas, examGuardado: null }); }
}));

// ===================== ALUMNO =====================
app.get('/alumno', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const aulas = db.prepare("SELECT a.*, u.nombre||' '||u.apellido as docente, i.progreso FROM aulas a JOIN inscripciones i ON i.aula_id=a.id JOIN users u ON a.docente_id=u.id WHERE i.alumno_id=?").all(uid);
  const pendientes = db.prepare(`
    SELECT ac.*, au.nombre as aula_nombre FROM actividades ac JOIN aulas au ON ac.aula_id=au.id
    JOIN inscripciones i ON i.aula_id=au.id AND i.alumno_id=?
    WHERE ac.visible=1 AND ac.id NOT IN (SELECT actividad_id FROM entregas WHERE alumno_id=?)
    ORDER BY ac.fecha_entrega LIMIT 5
  `).all(uid, uid);
  const anuncios = db.prepare(`
    SELECT an.*, au.nombre as aula_nombre, u.nombre||' '||u.apellido as autor FROM anuncios an
    JOIN aulas au ON an.aula_id=au.id JOIN users u ON an.autor_id=u.id
    JOIN inscripciones i ON i.aula_id=au.id AND i.alumno_id=?
    ORDER BY an.id DESC LIMIT 5
  `).all(uid);
  // Novedades: notas recibidas hace poco
  const notasNuevas = db.prepare(`
    SELECT e.nota, e.feedback, ac.titulo, ac.id as actividad_id, au.nombre as aula_nombre
    FROM entregas e JOIN actividades ac ON e.actividad_id=ac.id JOIN aulas au ON ac.aula_id=au.id
    WHERE e.alumno_id=? AND e.nota IS NOT NULL ORDER BY e.id DESC LIMIT 4
  `).all(uid);
  // Novedades: contenido subido en los últimos 7 días
  const contenidoNuevo = db.prepare(`
    SELECT c.id, c.titulo, c.tipo, au.nombre as aula_nombre FROM contenidos c
    JOIN aulas au ON c.aula_id=au.id
    JOIN inscripciones i ON i.aula_id=au.id AND i.alumno_id=?
    WHERE c.visible=1 AND c.creado_en >= datetime('now','-7 days') ORDER BY c.id DESC LIMIT 5
  `).all(uid);
  res.render('alumno/panel', { aulas, pendientes, anuncios, notasNuevas, contenidoNuevo });
});

app.get('/alumno/inscribirse', auth(['alumno']), (req, res) => res.render('alumno/inscribirse', { error: null, exito: null }));
app.post('/alumno/inscribirse', auth(['alumno']), (req, res) => {
  const aula = db.prepare("SELECT * FROM aulas WHERE codigo_acceso=? AND estado='activa'").get(req.body.codigo?.toUpperCase());
  if (!aula) return res.render('alumno/inscribirse', { error: 'Código inválido o aula inactiva', exito: null });
  const ya = db.prepare('SELECT id FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(req.session.user.id, aula.id);
  if (ya) return res.render('alumno/inscribirse', { error: 'Ya estás inscripto en esta aula', exito: null });
  db.prepare('INSERT INTO inscripciones (alumno_id,aula_id) VALUES (?,?)').run(req.session.user.id, aula.id);
  res.redirect('/alumno/aulas/' + aula.id);
});

app.get('/alumno/aulas/:id', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const insc = db.prepare('SELECT * FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(uid, req.params.id);
  if (!insc) return res.redirect('/alumno');
  const aula = db.prepare("SELECT a.*, u.nombre||' '||u.apellido as docente FROM aulas a JOIN users u ON a.docente_id=u.id WHERE a.id=?").get(req.params.id);
  const tab = req.query.tab || 'contenidos';
  const data = { aula, tab };
  data.contenidos = db.prepare('SELECT * FROM contenidos WHERE aula_id=? AND visible=1 ORDER BY orden,id').all(aula.id);
  data.actividades = db.prepare('SELECT a.*, e.nota, e.id as entrega_id FROM actividades a LEFT JOIN entregas e ON e.actividad_id=a.id AND e.alumno_id=? WHERE a.aula_id=? AND a.visible=1 ORDER BY a.id DESC').all(uid, aula.id);
  data.evaluaciones = db.prepare('SELECT e.*, i.nota as mi_nota, i.id as intento_id FROM evaluaciones e LEFT JOIN intentos_eval i ON i.evaluacion_id=e.id AND i.alumno_id=? AND i.completado=1 WHERE e.aula_id=? AND e.visible=1 ORDER BY e.id DESC').all(uid, aula.id);
  data.foros = db.prepare('SELECT f.*, (SELECT COUNT(*) FROM hilos WHERE foro_id=f.id) as hilos FROM foros f WHERE aula_id=?').all(aula.id);
  data.anuncios = db.prepare("SELECT an.*, u.nombre||' '||u.apellido as autor FROM anuncios an JOIN users u ON an.autor_id=u.id WHERE aula_id=? ORDER BY id DESC").all(aula.id);
  data.wikis = db.prepare('SELECT * FROM wikis WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.encuestas = db.prepare('SELECT * FROM encuestas WHERE aula_id=?').all(aula.id);
  data.encuestas.forEach(e => { e.opciones = JSON.parse(e.opciones); e.votos = db.prepare('SELECT opcion, COUNT(*) as c FROM votos_encuesta WHERE encuesta_id=? GROUP BY opcion').all(e.id); e.miVoto = db.prepare('SELECT opcion FROM votos_encuesta WHERE encuesta_id=? AND alumno_id=?').get(e.id, uid); });
  data.host = req.get('host');
  data.protocol = req.protocol;
  res.render('alumno/aula', data);
});

app.get('/alumno/actividades/:id/entregar', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const act = db.prepare('SELECT a.*, au.nombre as aula_nombre FROM actividades a JOIN aulas au ON a.aula_id=au.id WHERE a.id=?').get(req.params.id);
  const entrega = db.prepare('SELECT * FROM entregas WHERE actividad_id=? AND alumno_id=?').get(req.params.id, uid);
  if (!act || !inscripto(uid, act.aula_id)) return res.redirect('/alumno');
  res.render('alumno/actividad-entregar', { act, entrega });
});

app.post('/alumno/actividades/:id/entregar', auth(['alumno']), upload.single('archivo'), (req, res) => {
  const uid = req.session.user.id;
  const actChk = db.prepare('SELECT aula_id FROM actividades WHERE id=?').get(req.params.id);
  if (!actChk || !inscripto(uid, actChk.aula_id)) return res.redirect('/alumno');
  const archivo = req.file ? req.file.filename : null;
  const nombre_original = req.file ? req.file.originalname : null;
  const ya = db.prepare('SELECT id FROM entregas WHERE actividad_id=? AND alumno_id=?').get(req.params.id, uid);
  if (ya) {
    db.prepare('UPDATE entregas SET archivo=?,nombre_original=?,comentario=?,fecha_entrega=CURRENT_TIMESTAMP WHERE id=?').run(archivo, nombre_original, req.body.comentario, ya.id);
  } else {
    db.prepare('INSERT INTO entregas (actividad_id,alumno_id,archivo,nombre_original,comentario) VALUES (?,?,?,?,?)').run(req.params.id, uid, archivo, nombre_original, req.body.comentario);
  }
  const act = db.prepare('SELECT aula_id FROM actividades WHERE id=?').get(req.params.id);
  res.redirect('/alumno/aulas/' + act.aula_id + '?tab=actividades');
});

app.get('/alumno/evaluaciones/:id/rendir', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const ev = db.prepare('SELECT e.*, a.nombre as aula_nombre FROM evaluaciones e JOIN aulas a ON e.aula_id=a.id WHERE e.id=?').get(req.params.id);
  const intentosHechos = db.prepare('SELECT COUNT(*) as c FROM intentos_eval WHERE evaluacion_id=? AND alumno_id=? AND completado=1').get(req.params.id, uid).c;
  if (!ev || !inscripto(uid, ev.aula_id) || intentosHechos >= ev.intentos_max) return res.redirect('/alumno');
  const preguntas = db.prepare('SELECT * FROM preguntas WHERE evaluacion_id=? ORDER BY orden').all(ev.id);
  preguntas.forEach(p => { if (p.opciones) p.opciones = JSON.parse(p.opciones); });
  res.render('alumno/evaluacion-rendir', { ev, preguntas });
});

app.post('/alumno/evaluaciones/:id/entregar', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const ev = db.prepare('SELECT * FROM evaluaciones WHERE id=?').get(req.params.id);
  if (!ev || !inscripto(uid, ev.aula_id)) return res.redirect('/alumno');
  const preguntas = db.prepare('SELECT * FROM preguntas WHERE evaluacion_id=?').all(ev.id);
  const respuestas = {};
  let puntajeObtenido = 0;
  let puntajeTotal = 0;
  preguntas.forEach(p => {
    puntajeTotal += p.puntaje;
    const resp = req.body['preg_' + p.id] || '';
    respuestas[p.id] = resp;
    if (p.tipo !== 'libre') {
      const correcta = p.respuesta_correcta?.trim().toLowerCase();
      if (resp.trim().toLowerCase() === correcta) puntajeObtenido += p.puntaje;
    }
  });
  const nota = puntajeTotal > 0 ? (puntajeObtenido / puntajeTotal) * 10 : 0;
  db.prepare('INSERT INTO intentos_eval (evaluacion_id,alumno_id,respuestas,nota,puntaje_obtenido,puntaje_total,completado) VALUES (?,?,?,?,?,?,1)').run(ev.id, uid, JSON.stringify(respuestas), Math.round(nota * 100) / 100, puntajeObtenido, puntajeTotal);
  res.redirect('/alumno/evaluaciones/' + ev.id + '/resultado');
});

app.get('/alumno/evaluaciones/:id/resultado', auth(['alumno']), (req, res) => {
  const uid = req.session.user.id;
  const ev = db.prepare('SELECT * FROM evaluaciones WHERE id=?').get(req.params.id);
  if (!ev || !inscripto(uid, ev.aula_id)) return res.redirect('/alumno');
  const intento = db.prepare('SELECT * FROM intentos_eval WHERE evaluacion_id=? AND alumno_id=? AND completado=1 ORDER BY id DESC LIMIT 1').get(req.params.id, uid);
  const preguntas = db.prepare('SELECT * FROM preguntas WHERE evaluacion_id=? ORDER BY orden').all(ev.id);
  preguntas.forEach(p => { if (p.opciones) p.opciones = JSON.parse(p.opciones); });
  const respuestas = intento ? JSON.parse(intento.respuestas || '{}') : {};
  res.render('alumno/evaluacion-resultado', { ev, intento, preguntas, respuestas });
});

// ===================== FOROS (compartido) =====================
app.get('/foros/:id', auth(), (req, res) => {
  const foro = db.prepare('SELECT f.*, a.nombre as aula_nombre, a.docente_id FROM foros f JOIN aulas a ON f.aula_id=a.id WHERE f.id=?').get(req.params.id);
  if (!foro) return res.redirect('/');
  const hilos = db.prepare("SELECT h.*, u.nombre||' '||u.apellido as autor, (SELECT COUNT(*) FROM respuestas_foro WHERE hilo_id=h.id) as respuestas FROM hilos h JOIN users u ON h.autor_id=u.id WHERE h.foro_id=? ORDER BY h.fijado DESC, h.id DESC").all(foro.id);
  res.render('foro', { foro, hilos });
});

app.post('/foros/:id/hilos', auth(), (req, res) => {
  db.prepare('INSERT INTO hilos (foro_id,autor_id,titulo,cuerpo) VALUES (?,?,?,?)').run(req.params.id, req.session.user.id, req.body.titulo, req.body.cuerpo);
  res.redirect('/foros/' + req.params.id);
});

app.get('/foros/hilos/:id', auth(), (req, res) => {
  const hilo = db.prepare("SELECT h.*, u.nombre||' '||u.apellido as autor FROM hilos h JOIN users u ON h.autor_id=u.id WHERE h.id=?").get(req.params.id);
  const foro = db.prepare('SELECT f.*, a.aula_id FROM foros f JOIN aulas a ON f.id=a.id WHERE f.id=?').get(hilo.foro_id) || db.prepare('SELECT * FROM foros WHERE id=?').get(hilo.foro_id);
  const respuestas = db.prepare("SELECT r.*, u.nombre||' '||u.apellido as autor FROM respuestas_foro r JOIN users u ON r.autor_id=u.id WHERE r.hilo_id=? ORDER BY r.id").all(hilo.id);
  res.render('hilo', { hilo, foro, respuestas });
});

app.post('/foros/hilos/:id/responder', auth(), (req, res) => {
  db.prepare('INSERT INTO respuestas_foro (hilo_id,autor_id,cuerpo) VALUES (?,?,?)').run(req.params.id, req.session.user.id, req.body.cuerpo);
  res.redirect('/foros/hilos/' + req.params.id);
});

// ===================== MENSAJERÍA =====================
app.get('/mensajes', auth(), (req, res) => {
  const uid = req.session.user.id;
  const recibidos = db.prepare("SELECT m.*, u.nombre||' '||u.apellido as de_nombre FROM mensajes m JOIN users u ON m.de_id=u.id WHERE m.para_id=? ORDER BY m.id DESC").all(uid);
  const enviados = db.prepare("SELECT m.*, u.nombre||' '||u.apellido as para_nombre FROM mensajes m JOIN users u ON m.para_id=u.id WHERE m.de_id=? ORDER BY m.id DESC").all(uid);
  db.prepare('UPDATE mensajes SET leido=1 WHERE para_id=?').run(uid);
  const usuarios = db.prepare('SELECT id,nombre,apellido,rol FROM users WHERE id!=? AND activo=1 ORDER BY apellido').all(uid);
  res.render('mensajes', { recibidos, enviados, usuarios, tab: req.query.tab||'recibidos' });
});

app.post('/mensajes/enviar', auth(), (req, res) => {
  db.prepare('INSERT INTO mensajes (de_id,para_id,asunto,cuerpo) VALUES (?,?,?,?)').run(req.session.user.id, req.body.para_id, req.body.asunto, req.body.cuerpo);
  res.redirect('/mensajes?tab=enviados');
});

// ===================== CALENDARIO =====================
app.get('/calendario', auth(), (req, res) => {
  const uid = req.session.user.id;
  const user = req.session.user;
  const esDocente = user.rol === 'docente';
  // Eventos cargados a mano
  let eventos = esDocente
    ? db.prepare('SELECT e.*, a.nombre as aula_nombre FROM eventos e LEFT JOIN aulas a ON e.aula_id=a.id WHERE e.creador_id=? OR e.aula_id IN (SELECT id FROM aulas WHERE docente_id=?)').all(uid, uid)
    : db.prepare('SELECT e.*, a.nombre as aula_nombre FROM eventos e LEFT JOIN aulas a ON e.aula_id=a.id WHERE e.aula_id IN (SELECT aula_id FROM inscripciones WHERE alumno_id=?) OR e.creador_id=?').all(uid, uid);
  // Vencimientos automáticos de actividades
  const acts = esDocente
    ? db.prepare('SELECT ac.id, ac.titulo, ac.fecha_entrega, au.nombre as aula_nombre FROM actividades ac JOIN aulas au ON ac.aula_id=au.id WHERE au.docente_id=? AND ac.fecha_entrega IS NOT NULL').all(uid)
    : db.prepare('SELECT ac.id, ac.titulo, ac.fecha_entrega, au.nombre as aula_nombre FROM actividades ac JOIN aulas au ON ac.aula_id=au.id JOIN inscripciones i ON i.aula_id=au.id AND i.alumno_id=? WHERE ac.visible=1 AND ac.fecha_entrega IS NOT NULL').all(uid);
  acts.forEach(a => eventos.push({ titulo: '📝 ' + a.titulo, descripcion: 'Vence la entrega', fecha_inicio: a.fecha_entrega, fecha_fin: null, tipo: 'entrega', aula_nombre: a.aula_nombre, auto: true, link: esDocente ? '/docente/actividades/' + a.id : '/alumno/actividades/' + a.id + '/entregar' }));
  // Vencimientos automáticos de evaluaciones
  const evs = esDocente
    ? db.prepare('SELECT ev.id, ev.titulo, ev.fecha_hasta, au.nombre as aula_nombre FROM evaluaciones ev JOIN aulas au ON ev.aula_id=au.id WHERE au.docente_id=? AND ev.fecha_hasta IS NOT NULL').all(uid)
    : db.prepare('SELECT ev.id, ev.titulo, ev.fecha_hasta, au.nombre as aula_nombre FROM evaluaciones ev JOIN aulas au ON ev.aula_id=au.id JOIN inscripciones i ON i.aula_id=au.id AND i.alumno_id=? WHERE ev.visible=1 AND ev.fecha_hasta IS NOT NULL').all(uid);
  evs.forEach(e => eventos.push({ titulo: '🎯 ' + e.titulo, descripcion: 'Cierra la evaluación', fecha_inicio: e.fecha_hasta, fecha_fin: null, tipo: 'evaluacion', aula_nombre: e.aula_nombre, auto: true, link: esDocente ? '/docente/evaluaciones/' + e.id + '/resultados' : '/alumno/evaluaciones/' + e.id + '/rendir' }));
  // Ordenar todo por fecha
  eventos.sort((a, b) => new Date(a.fecha_inicio) - new Date(b.fecha_inicio));
  const aulas = esDocente ? db.prepare('SELECT * FROM aulas WHERE docente_id=?').all(uid) : db.prepare('SELECT a.* FROM aulas a JOIN inscripciones i ON i.aula_id=a.id WHERE i.alumno_id=?').all(uid);
  res.render('calendario', { eventos, aulas });
});

app.post('/calendario/nuevo', auth(), (req, res) => {
  const { titulo, descripcion, fecha_inicio, fecha_fin, tipo, aula_id } = req.body;
  db.prepare('INSERT INTO eventos (creador_id,aula_id,titulo,descripcion,fecha_inicio,fecha_fin,tipo) VALUES (?,?,?,?,?,?,?)').run(req.session.user.id, aula_id||null, titulo, descripcion, fecha_inicio, fecha_fin||null, tipo||'evento');
  res.redirect('/calendario');
});

// ===================== RECURSOS =====================
app.get('/recursos', auth(), (req, res) => {
  const uid = req.session.user.id;
  const filtro = req.query.filtro || 'todos';
  let recursos;
  if (filtro === 'mios') {
    recursos = db.prepare("SELECT r.*, u.nombre||' '||u.apellido as autor FROM recursos r JOIN users u ON r.autor_id=u.id WHERE r.autor_id=? ORDER BY r.creado_en DESC").all(uid);
  } else if (filtro === 'comunidad') {
    recursos = db.prepare("SELECT r.*, u.nombre||' '||u.apellido as autor FROM recursos r JOIN users u ON r.autor_id=u.id WHERE r.compartido=1 AND r.autor_id!=? ORDER BY r.creado_en DESC").all(uid);
  } else {
    recursos = db.prepare("SELECT r.*, u.nombre||' '||u.apellido as autor FROM recursos r JOIN users u ON r.autor_id=u.id WHERE r.autor_id=? OR r.compartido=1 ORDER BY r.creado_en DESC").all(uid);
  }
  res.render('recursos', { recursos, filtro });
});

app.post('/recursos/nuevo', auth(), upload.single('archivo'), (req, res) => {
  const { titulo, descripcion, materia, nivel, tipo, url_externa, compartido } = req.body;
  const archivo = req.file ? req.file.filename : null;
  const nombre_original = req.file ? req.file.originalname : null;
  db.prepare('INSERT INTO recursos (autor_id,titulo,descripcion,materia,nivel,tipo,archivo,nombre_original,url_externa,compartido) VALUES (?,?,?,?,?,?,?,?,?,?)').run(req.session.user.id, titulo, descripcion, materia, nivel, tipo||'archivo', archivo, nombre_original, url_externa, compartido ? 1 : 0);
  res.redirect('/recursos?filtro=mios');
});

app.post('/recursos/:id/eliminar', auth(), (req, res) => {
  db.prepare('DELETE FROM recursos WHERE id=? AND autor_id=?').run(req.params.id, req.session.user.id);
  res.redirect('/recursos?filtro=mios');
});

app.get('/recursos/:id/descargar', auth(), (req, res) => {
  const r = db.prepare('SELECT * FROM recursos WHERE id=?').get(req.params.id);
  if (!r) return res.redirect('/recursos');
  db.prepare('UPDATE recursos SET descargas=descargas+1 WHERE id=?').run(r.id);
  if (r.archivo) res.download(path.join(UPLOADS_DIR, r.archivo), r.nombre_original);
  else if (r.url_externa) res.redirect(r.url_externa);
  else res.redirect('/recursos');
});

// ===================== WIKIS =====================
app.post('/docente/aulas/:id/wikis', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  db.prepare('INSERT INTO wikis (aula_id,titulo,contenido,autor_id) VALUES (?,?,?,?)').run(aula.id, req.body.titulo, req.body.contenido||'', req.session.user.id);
  res.redirect('/docente/aulas/' + aula.id + '?tab=wikis');
});

app.get('/wikis/:id', auth(), (req, res) => {
  const wiki = db.prepare("SELECT w.*, u.nombre||' '||u.apellido as autor, e.nombre||' '||e.apellido as editor, a.nombre as aula_nombre, a.docente_id FROM wikis w JOIN users u ON w.autor_id=u.id LEFT JOIN users e ON w.editado_por=e.id JOIN aulas a ON w.aula_id=a.id WHERE w.id=?").get(req.params.id);
  if (!wiki) return res.redirect('/');
  res.render('wiki', { wiki });
});

app.get('/wikis/:id/editar', auth(), (req, res) => {
  const wiki = db.prepare('SELECT w.*, a.docente_id, a.id as aula_id FROM wikis w JOIN aulas a ON w.aula_id=a.id WHERE w.id=?').get(req.params.id);
  if (!wiki) return res.redirect('/');
  // Verificar acceso: docente del aula o alumno inscripto
  const uid = req.session.user.id;
  if (req.session.user.rol !== 'docente' || wiki.docente_id !== uid) {
    const insc = db.prepare('SELECT id FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(uid, wiki.aula_id);
    if (!insc && wiki.docente_id !== uid) return res.redirect('/');
  }
  res.render('wiki-editar', { wiki });
});

app.post('/wikis/:id/editar', auth(), (req, res) => {
  db.prepare('UPDATE wikis SET titulo=?,contenido=?,editado_por=?,editado_en=CURRENT_TIMESTAMP WHERE id=?').run(req.body.titulo, req.body.contenido, req.session.user.id, req.params.id);
  res.redirect('/wikis/' + req.params.id);
});

// ===================== ENCUESTAS =====================
app.post('/docente/aulas/:id/encuestas', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const opciones = (req.body.opciones || '').split('\n').map(s => s.trim()).filter(Boolean);
  db.prepare('INSERT INTO encuestas (aula_id,pregunta,opciones,multiple,anonima) VALUES (?,?,?,?,?)').run(aula.id, req.body.pregunta, JSON.stringify(opciones), req.body.multiple ? 1 : 0, req.body.anonima ? 1 : 0);
  res.redirect('/docente/aulas/' + aula.id + '?tab=encuestas');
});

app.post('/encuestas/:id/votar', auth(['alumno']), (req, res) => {
  const enc = db.prepare('SELECT * FROM encuestas WHERE id=?').get(req.params.id);
  if (!enc || enc.cerrada) return res.redirect('/');
  const opcionesSeleccionadas = [].concat(req.body.opcion || []);
  // Si no es múltiple, borrar votos previos
  if (!enc.multiple) db.prepare('DELETE FROM votos_encuesta WHERE encuesta_id=? AND alumno_id=?').run(enc.id, req.session.user.id);
  const ins = db.prepare('INSERT OR IGNORE INTO votos_encuesta (encuesta_id,alumno_id,opcion) VALUES (?,?,?)');
  opcionesSeleccionadas.forEach(op => ins.run(enc.id, req.session.user.id, op));
  res.redirect('back');
});

// ===================== VIDEOLLAMADA =====================
app.post('/docente/aulas/:id/videollamada', auth(['docente']), (req, res) => {
  db.prepare('UPDATE aulas SET videollamada_url=?,videollamada_horario=? WHERE id=? AND docente_id=?').run(req.body.url||null, req.body.horario||null, req.params.id, req.session.user.id);
  res.redirect('/docente/aulas/' + req.params.id);
});

// Docente resetea la contraseña de un alumno inscripto en su aula
app.post('/docente/aulas/:id/alumnos/:alumnoId/reset-password', auth(['docente']), wrap(async (req, res) => {
  const aula = db.prepare('SELECT id FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  const insc = db.prepare('SELECT id FROM inscripciones WHERE aula_id=? AND alumno_id=?').get(req.params.id, req.params.alumnoId);
  if (!aula || !insc) return res.redirect('/docente');
  const u = db.prepare('SELECT nombre, apellido, email FROM users WHERE id=?').get(req.params.alumnoId);
  const temp = passTemporal();
  db.prepare('UPDATE users SET password=? WHERE id=?').run(await bcrypt.hash(temp, 10), req.params.alumnoId);
  auditar(req, 'reset_password_docente', 'Alumno: ' + u.email + ' (aula #' + req.params.id + ')');
  req.session.resetInfo = { nombre: u.nombre + ' ' + u.apellido, email: u.email, temp };
  res.redirect('/docente/aulas/' + req.params.id + '?tab=alumnos');
}));

// ===================== INSCRIBIR ALUMNO MANUALMENTE =====================
app.post('/docente/aulas/:id/inscribir-alumno', auth(['docente']), wrap(async (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const { nombre, apellido, email, password } = req.body;
  let alumno = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!alumno) {
    const pwd = password || 'edumax' + Math.random().toString(36).substring(2,8);
    const hash = await bcrypt.hash(pwd, 10);
    const r = db.prepare('INSERT INTO users (nombre,apellido,email,password,rol) VALUES (?,?,?,?,?)').run(nombre, apellido, email, hash, 'alumno');
    alumno = { id: r.lastInsertRowid, nombre, apellido, email };
    req.session.tempPwd = { email, pwd };
  }
  const ya = db.prepare('SELECT id FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(alumno.id, aula.id);
  if (!ya) db.prepare('INSERT INTO inscripciones (alumno_id,aula_id) VALUES (?,?)').run(alumno.id, aula.id);
  res.redirect('/docente/aulas/' + aula.id + '?tab=alumnos&inscripto=' + alumno.id);
}));

// ===================== VISOR DE ARCHIVOS INTEGRADO =====================
function getYouTubeId(url){
  if(!url) return null;
  const m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|v\/)|youtu\.be\/)([\w-]+)/);
  return m ? m[1] : null;
}
function getVimeoId(url){
  if(!url) return null;
  const m = url.match(/vimeo\.com\/(\d+)/);
  return m ? m[1] : null;
}
function getFileType(filename){
  if(!filename) return 'other';
  const n = filename.toLowerCase();
  if(n.endsWith('.pdf')) return 'pdf';
  if(n.match(/\.(jpg|jpeg|png|gif|webp|svg)$/)) return 'image';
  if(n.match(/\.(mp4|webm|ogv)$/)) return 'video';
  if(n.match(/\.(mp3|wav|ogg|m4a)$/)) return 'audio';
  if(n.match(/\.(docx?|odt|rtf)$/)) return 'word';
  if(n.match(/\.(xlsx?|csv|ods)$/)) return 'excel';
  if(n.match(/\.(pptx?|odp)$/)) return 'powerpoint';
  if(n.match(/\.(txt|md)$/)) return 'text';
  return 'other';
}

app.get('/contenidos/:id/ver', auth(), (req, res) => {
  const c = db.prepare('SELECT c.*, a.nombre as aula_nombre, a.id as aula_id, a.docente_id FROM contenidos c JOIN aulas a ON c.aula_id=a.id WHERE c.id=?').get(req.params.id);
  if (!c) return res.redirect('/');
  const uid = req.session.user.id;
  if (req.session.user.rol === 'docente' && c.docente_id !== uid) return res.redirect('/');
  if (req.session.user.rol === 'alumno') {
    const insc = db.prepare('SELECT id FROM inscripciones WHERE alumno_id=? AND aula_id=?').get(uid, c.aula_id);
    if (!insc) return res.redirect('/');
    // Registrar que este alumno vio este contenido (una sola vez) y recalcular su progreso real
    try {
      db.prepare('INSERT OR IGNORE INTO contenido_visto (contenido_id, alumno_id) VALUES (?,?)').run(c.id, uid);
      const total = db.prepare('SELECT COUNT(*) as n FROM contenidos WHERE aula_id=? AND visible=1').get(c.aula_id).n;
      const vistos = db.prepare('SELECT COUNT(*) as n FROM contenido_visto cv JOIN contenidos co ON cv.contenido_id=co.id WHERE cv.alumno_id=? AND co.aula_id=? AND co.visible=1').get(uid, c.aula_id).n;
      db.prepare('UPDATE inscripciones SET progreso=? WHERE alumno_id=? AND aula_id=?').run(total ? Math.round(vistos / total * 100) : 0, uid, c.aula_id);
    } catch (e) { /* el tracking nunca debe romper la vista */ }
  }
  const fileType = getFileType(c.nombre_original);
  const ytId = c.url_externa ? getYouTubeId(c.url_externa) : null;
  const vimeoId = c.url_externa ? getVimeoId(c.url_externa) : null;
  // Navegación anterior/siguiente
  const allContenidos = db.prepare('SELECT id, titulo FROM contenidos WHERE aula_id=? AND visible=1 ORDER BY orden,id').all(c.aula_id);
  const idx = allContenidos.findIndex(x => x.id === c.id);
  const prev = idx > 0 ? allContenidos[idx-1] : null;
  const next = idx >= 0 && idx < allContenidos.length-1 ? allContenidos[idx+1] : null;
  res.render('contenido-ver', { c, fileType, ytId, vimeoId, host: req.get('host'), backUrl: '/' + (req.session.user.rol === 'docente' ? 'docente' : 'alumno') + '/aulas/' + c.aula_id, prev, next, total: allContenidos.length, current: idx+1 });
});

app.get('/recursos/:id/ver', auth(), (req, res) => {
  const r = db.prepare("SELECT r.*, u.nombre||' '||u.apellido as autor FROM recursos r JOIN users u ON r.autor_id=u.id WHERE r.id=?").get(req.params.id);
  if (!r) return res.redirect('/recursos');
  if (r.compartido !== 1 && r.autor_id !== req.session.user.id) return res.redirect('/recursos');
  const fileType = getFileType(r.nombre_original);
  const ytId = r.url_externa ? getYouTubeId(r.url_externa) : null;
  const vimeoId = r.url_externa ? getVimeoId(r.url_externa) : null;
  res.render('recurso-ver', { r, fileType, ytId, vimeoId, host: req.get('host') });
});

app.get('/docente/aulas/:id/preview', auth(['docente']), (req, res) => {
  const aula = db.prepare('SELECT * FROM aulas WHERE id=? AND docente_id=?').get(req.params.id, req.session.user.id);
  if (!aula) return res.redirect('/docente');
  const uid = req.session.user.id;
  const data = { aula: { ...aula, docente: req.session.user.nombre + ' ' + req.session.user.apellido }, tab: 'contenidos', preview: true };
  data.contenidos = db.prepare('SELECT * FROM contenidos WHERE aula_id=? AND visible=1 ORDER BY orden,id').all(aula.id);
  data.actividades = db.prepare('SELECT a.*, NULL as nota, NULL as entrega_id FROM actividades a WHERE a.aula_id=? AND a.visible=1 ORDER BY a.id DESC').all(aula.id);
  data.evaluaciones = db.prepare('SELECT e.*, NULL as mi_nota, NULL as intento_id FROM evaluaciones e WHERE e.aula_id=? AND e.visible=1 ORDER BY e.id DESC').all(aula.id);
  data.foros = db.prepare('SELECT f.*, (SELECT COUNT(*) FROM hilos WHERE foro_id=f.id) as hilos FROM foros f WHERE aula_id=?').all(aula.id);
  data.anuncios = db.prepare("SELECT an.*, u.nombre||' '||u.apellido as autor FROM anuncios an JOIN users u ON an.autor_id=u.id WHERE aula_id=? ORDER BY id DESC").all(aula.id);
  data.wikis = db.prepare('SELECT * FROM wikis WHERE aula_id=? ORDER BY id DESC').all(aula.id);
  data.encuestas = db.prepare('SELECT * FROM encuestas WHERE aula_id=?').all(aula.id);
  data.encuestas.forEach(e => { e.opciones = JSON.parse(e.opciones); e.votos = []; e.miVoto = null; });
  data.alumnos = [];
  res.render('alumno/aula', data);
});

// ===================== BÚSQUEDA DE USUARIOS por DNI/CUIL/Nombre/Email =====================
app.get('/buscar-usuarios', auth(['docente','admin']), (req, res) => {
  const q = (req.query.q || '').trim();
  let resultados = [];
  if (q) {
    const like = '%' + q + '%';
    resultados = db.prepare(`
      SELECT id, nombre, apellido, email, dni, cuil, telefono, rol, institucion, materia, creado_en
      FROM users 
      WHERE dni LIKE ? OR cuil LIKE ? OR email LIKE ? OR nombre LIKE ? OR apellido LIKE ?
      ORDER BY apellido, nombre LIMIT 50
    `).all(like, like, like, like, like);
  }
  res.render('buscar-usuarios', { q, resultados });
});

// Actualizar perfil para incluir DNI/CUIL/teléfono
app.post('/perfil/datos-personales', auth(), (req, res) => {
  const { dni, cuil, telefono } = req.body;
  db.prepare('UPDATE users SET dni=?, cuil=?, telefono=? WHERE id=?').run(
    dni || null, cuil || null, telefono || null, req.session.user.id
  );
  res.redirect('/perfil');
});

// ════════════════════════════════════════════════════════════
// MANEJO DE ERRORES Y RUTAS NO ENCONTRADAS
// ════════════════════════════════════════════════════════════

// 404 — página no encontrada
app.use((req, res) => {
  res.status(404);
  if (req.accepts('html')) {
    return res.render('error', {
      codigo: 404,
      titulo: 'Página no encontrada',
      mensaje: 'La página que buscás no existe o fue movida.',
      volver: req.session && req.session.user ? '/' : '/login'
    });
  }
  res.json({ error: 'No encontrado' });
});

// Manejador de errores global — captura TODO lo que falle
app.use((err, req, res, next) => {
  console.error('═══ ERROR ═══');
  console.error('Ruta:', req.method, req.path);
  console.error('Mensaje:', err.message);
  console.error('Stack:', err.stack);

  // Errores específicos de Multer (subida de archivos)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).render('error', {
      codigo: 413,
      titulo: 'Archivo muy grande',
      mensaje: 'El archivo supera el límite de 200 MB. Probá comprimirlo o subirlo a Drive y pegá el link.',
      volver: req.get('Referer') || '/'
    });
  }

  res.status(err.status || 500);
  if (req.accepts('html')) {
    return res.render('error', {
      codigo: err.status || 500,
      titulo: 'Algo salió mal',
      mensaje: process.env.NODE_ENV === 'production'
        ? 'Ocurrió un error inesperado. Ya estamos al tanto. Probá de nuevo en unos minutos.'
        : err.message,
      volver: req.get('Referer') || '/'
    });
  }
  res.json({ error: 'Error interno del servidor' });
});

// Capturar errores no manejados para que el servidor no se caiga
process.on('uncaughtException', (err) => {
  console.error('⚠️  Excepción no capturada:', err.message);
  console.error(err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('⚠️  Promesa rechazada sin manejar:', reason);
});

// Respaldo automático de la base: crea una copia consistente diaria y conserva las últimas 7
function backupDB() {
  try {
    const dir = path.join(DATA_DIR, 'backups');
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(dir, 'edumax-' + stamp + '.db');
    if (fs.existsSync(dest)) return; // ya hay backup de hoy
    db.exec("VACUUM INTO '" + dest.replace(/'/g, '') + "'");
    const files = fs.readdirSync(dir).filter(f => f.startsWith('edumax-') && f.endsWith('.db')).sort();
    while (files.length > 7) { try { fs.unlinkSync(path.join(dir, files.shift())); } catch (e) {} }
    console.log('✓ Backup de base creado:', dest);
  } catch (e) { console.error('Backup falló:', e.message); }
}
setTimeout(backupDB, 8000);                       // al arrancar
setInterval(backupDB, 12 * 60 * 60 * 1000);       // cada 12 h

const server = app.listen(PORT, () => console.log(`✓ EduMax v2 en http://localhost:${PORT}`));

// Apagado ordenado
process.on('SIGTERM', () => {
  console.log('SIGTERM recibido, cerrando servidor...');
  server.close(() => { try { db.close(); } catch(e){} process.exit(0); });
});
