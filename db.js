const path = require('path');
const fs = require('fs');

// Directorio de datos persistentes (disco de Render). En local usa la carpeta del proyecto.
const DATA_DIR = process.env.DATA_DIR || __dirname;
// Asegurar que exista
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
const DB_PATH = path.join(DATA_DIR, 'edumax.db');

// Cargar driver SQLite con fallback robusto:
// 1) better-sqlite3 (preferido, usado en producción/Railway)
// 2) node:sqlite nativo (Node 22+) como fallback sin compilación
let db;
try {
  const Database = require('better-sqlite3');
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
} catch (e) {
  const { DatabaseSync } = require('node:sqlite');
  const native = new DatabaseSync(DB_PATH);
  db = {
    _native: native,
    exec: (sql) => native.exec(sql),
    pragma: () => {},
    close: () => native.close(),
    prepare: (sql) => {
      const stmt = native.prepare(sql);
      return {
        run: (...a) => { const r = stmt.run(...a); return { lastInsertRowid: r.lastInsertRowid, changes: r.changes }; },
        get: (...a) => stmt.get(...a),
        all: (...a) => stmt.all(...a),
      };
    },
  };
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    apellido TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    rol TEXT NOT NULL DEFAULT 'alumno',
    institucion TEXT,
    materia TEXT,
    avatar TEXT,
    bio TEXT,
    activo INTEGER DEFAULT 1,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS aulas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    docente_id INTEGER NOT NULL,
    nombre TEXT NOT NULL,
    descripcion TEXT,
    imagen TEXT,
    nivel TEXT,
    anio TEXT,
    codigo_acceso TEXT UNIQUE,
    estado TEXT DEFAULT 'activa',
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (docente_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS inscripciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alumno_id INTEGER NOT NULL,
    aula_id INTEGER NOT NULL,
    fecha DATE DEFAULT (date('now')),
    progreso INTEGER DEFAULT 0,
    UNIQUE(alumno_id, aula_id),
    FOREIGN KEY (alumno_id) REFERENCES users(id),
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS contenidos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    titulo TEXT NOT NULL,
    cuerpo TEXT,
    archivo TEXT,
    nombre_original TEXT,
    url_externa TEXT,
    orden INTEGER DEFAULT 0,
    visible INTEGER DEFAULT 1,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS actividades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT,
    fecha_entrega DATETIME,
    puntaje_max INTEGER DEFAULT 10,
    tipo_entrega TEXT DEFAULT 'archivo',
    visible INTEGER DEFAULT 1,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS entregas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actividad_id INTEGER NOT NULL,
    alumno_id INTEGER NOT NULL,
    archivo TEXT,
    nombre_original TEXT,
    comentario TEXT,
    nota REAL,
    feedback TEXT,
    fecha_entrega DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(actividad_id, alumno_id),
    FOREIGN KEY (actividad_id) REFERENCES actividades(id),
    FOREIGN KEY (alumno_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS evaluaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT,
    intentos_max INTEGER DEFAULT 1,
    tiempo_limite INTEGER,
    fecha_desde DATETIME,
    fecha_hasta DATETIME,
    visible INTEGER DEFAULT 1,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS preguntas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluacion_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    texto TEXT NOT NULL,
    opciones TEXT,
    respuesta_correcta TEXT,
    puntaje INTEGER DEFAULT 1,
    orden INTEGER DEFAULT 0,
    FOREIGN KEY (evaluacion_id) REFERENCES evaluaciones(id)
  );

  CREATE TABLE IF NOT EXISTS intentos_eval (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluacion_id INTEGER NOT NULL,
    alumno_id INTEGER NOT NULL,
    respuestas TEXT,
    nota REAL,
    puntaje_obtenido REAL,
    puntaje_total REAL,
    completado INTEGER DEFAULT 0,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evaluacion_id) REFERENCES evaluaciones(id),
    FOREIGN KEY (alumno_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS foros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS hilos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    foro_id INTEGER NOT NULL,
    autor_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    cuerpo TEXT NOT NULL,
    fijado INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (foro_id) REFERENCES foros(id),
    FOREIGN KEY (autor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS respuestas_foro (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hilo_id INTEGER NOT NULL,
    autor_id INTEGER NOT NULL,
    cuerpo TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hilo_id) REFERENCES hilos(id),
    FOREIGN KEY (autor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS mensajes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    de_id INTEGER NOT NULL,
    para_id INTEGER NOT NULL,
    asunto TEXT,
    cuerpo TEXT NOT NULL,
    leido INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (de_id) REFERENCES users(id),
    FOREIGN KEY (para_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS eventos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER,
    creador_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT,
    fecha_inicio DATETIME NOT NULL,
    fecha_fin DATETIME,
    tipo TEXT DEFAULT 'evento',
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id),
    FOREIGN KEY (creador_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS anuncios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    autor_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    cuerpo TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id),
    FOREIGN KEY (autor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS asistencias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alumno_id INTEGER NOT NULL,
    aula_id INTEGER NOT NULL,
    fecha DATE NOT NULL,
    presente INTEGER DEFAULT 0,
    UNIQUE(alumno_id, aula_id, fecha),
    FOREIGN KEY (alumno_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS recursos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autor_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT,
    materia TEXT,
    nivel TEXT,
    archivo TEXT,
    nombre_original TEXT,
    url_externa TEXT,
    tipo TEXT,
    compartido INTEGER DEFAULT 0,
    descargas INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (autor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS wikis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    contenido TEXT,
    autor_id INTEGER NOT NULL,
    editado_por INTEGER,
    visible INTEGER DEFAULT 1,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    editado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id),
    FOREIGN KEY (autor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS encuestas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aula_id INTEGER NOT NULL,
    pregunta TEXT NOT NULL,
    opciones TEXT NOT NULL,
    multiple INTEGER DEFAULT 0,
    anonima INTEGER DEFAULT 1,
    cerrada INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (aula_id) REFERENCES aulas(id)
  );

  CREATE TABLE IF NOT EXISTS votos_encuesta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encuesta_id INTEGER NOT NULL,
    alumno_id INTEGER NOT NULL,
    opcion TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(encuesta_id, alumno_id, opcion),
    FOREIGN KEY (encuesta_id) REFERENCES encuestas(id),
    FOREIGN KEY (alumno_id) REFERENCES users(id)
  );

  -- Agregar columna videollamada_url a aulas si no existe
`);

// Migración: agregar columna videollamada_url si no existe
try {
  db.prepare("ALTER TABLE aulas ADD COLUMN videollamada_url TEXT").run();
} catch(e) {/* ya existe */}
try {
  db.prepare("ALTER TABLE aulas ADD COLUMN videollamada_horario TEXT").run();
} catch(e) {/* ya existe */}

// Migración: nuevas columnas para contenidos avanzados
try { db.prepare("ALTER TABLE contenidos ADD COLUMN embed_html TEXT").run(); } catch(e) {}
try { db.prepare("ALTER TABLE contenidos ADD COLUMN descripcion TEXT").run(); } catch(e) {}
try { db.prepare("ALTER TABLE contenidos ADD COLUMN obligatorio INTEGER DEFAULT 0").run(); } catch(e) {}
try { db.prepare("ALTER TABLE contenidos ADD COLUMN unidad TEXT").run(); } catch(e) {}

// Migración: DNI y CUIL en usuarios
try { db.prepare("ALTER TABLE users ADD COLUMN dni TEXT").run(); } catch(e) {}
try { db.prepare("ALTER TABLE users ADD COLUMN cuil TEXT").run(); } catch(e) {}
try { db.prepare("ALTER TABLE users ADD COLUMN telefono TEXT").run(); } catch(e) {}

// Registro de auditoría (acciones sensibles: borrados, reseteos de clave, etc.)
try {
  db.exec(`CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_nombre TEXT,
    accion TEXT NOT NULL,
    detalle TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
} catch(e) { console.error('No se pudo crear tabla auditoria:', e.message); }

// Seguimiento de contenidos vistos por alumno (alimenta el "X de Y" del Programa y el progreso real)
try {
  db.exec(`CREATE TABLE IF NOT EXISTS contenido_visto (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contenido_id INTEGER NOT NULL,
    alumno_id INTEGER NOT NULL,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(contenido_id, alumno_id)
  )`);
} catch(e) { console.error('No se pudo crear tabla contenido_visto:', e.message); }

// ════════════════════════════════════════════════════════════
// ÍNDICES — aceleran las consultas más frecuentes
// ════════════════════════════════════════════════════════════
const indices = [
  'CREATE INDEX IF NOT EXISTS idx_contenidos_aula ON contenidos(aula_id)',
  'CREATE INDEX IF NOT EXISTS idx_inscripciones_alumno ON inscripciones(alumno_id)',
  'CREATE INDEX IF NOT EXISTS idx_inscripciones_aula ON inscripciones(aula_id)',
  'CREATE INDEX IF NOT EXISTS idx_aulas_docente ON aulas(docente_id)',
  'CREATE INDEX IF NOT EXISTS idx_mensajes_para ON mensajes(para_id, leido)',
  'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
  'CREATE INDEX IF NOT EXISTS idx_visto_contenido ON contenido_visto(contenido_id)',
  'CREATE INDEX IF NOT EXISTS idx_visto_alumno ON contenido_visto(alumno_id)',
];
for (const idx of indices) {
  try { db.exec(idx); } catch(e) { /* tabla puede no existir aún */ }
}

module.exports = db;
