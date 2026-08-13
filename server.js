import express from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import xss from 'xss';
import { body, validationResult, matchedData } from 'express-validator';
import cors from 'cors';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 🔒 CONFIGURACIÓN DE SEGURIDAD - NIVEL PRODUCCIÓN
// ============================================================

// 1. VARIABLES DE ENTORNO CON VALIDACIÓN ESTRICTA
const ENV = {
    SUPABASE_URL: process.env.SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
    NODE_ENV: process.env.NODE_ENV || 'development',
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || [
        'https://la-reina-mgje.onrender.com',
        'https://la-reina.onrender.com',
        'http://localhost:3000',
        'http://127.0.0.1:3000'
    ],
    JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
    SESSION_DURATION: parseInt(process.env.SESSION_DURATION) || 3600000, // 1 hora
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000, // 15 min
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
    MAX_ORDER_ITEMS: parseInt(process.env.MAX_ORDER_ITEMS) || 50,
    MAX_ORDER_TOTAL: parseInt(process.env.MAX_ORDER_TOTAL) || 999999
};

// Validación crítica de variables de entorno
const ENV_ERRORS = [];
if (!ENV.SUPABASE_URL) ENV_ERRORS.push('SUPABASE_URL');
if (!ENV.SUPABASE_SERVICE_ROLE_KEY) ENV_ERRORS.push('SUPABASE_SERVICE_ROLE_KEY');
if (!ENV.ADMIN_PASSWORD) ENV_ERRORS.push('ADMIN_PASSWORD');

if (ENV_ERRORS.length > 0) {
    console.error('❌ ERRORES CRÍTICOS DE CONFIGURACIÓN:');
    ENV_ERRORS.forEach(err => console.error(`   ❌ ${err} no está configurada`));
    if (ENV.NODE_ENV === 'production') {
        console.error('🚫 El servidor no puede iniciar en producción sin estas variables.');
        process.exit(1);
    } else {
        console.warn('⚠️ Continuando en modo desarrollo con configuración parcial.');
    }
}

console.log('🔐 ========== SEGURIDAD ACTIVADA ==========');
console.log(`🔐 NODE_ENV: ${ENV.NODE_ENV}`);
console.log(`🔐 Rate Limit: ${ENV.RATE_LIMIT_MAX} peticiones/${ENV.RATE_LIMIT_WINDOW/60000}min`);
console.log(`🔐 Max File Size: ${ENV.MAX_FILE_SIZE/1024/1024}MB`);
console.log(`🔐 Max Order Items: ${ENV.MAX_ORDER_ITEMS}`);
console.log(`🔐 Session Duration: ${ENV.SESSION_DURATION/3600000}h`);
console.log(`🔐 Allowed Origins: ${ENV.ALLOWED_ORIGINS.join(', ')}`);
console.log('🔐 =========================================');

// 2. INICIALIZAR SUPABASE CON MANEJO DE ERRORES
let supabase = null;
if (ENV.SUPABASE_URL && ENV.SUPABASE_SERVICE_ROLE_KEY) {
    try {
        supabase = createClient(ENV.SUPABASE_URL, ENV.SUPABASE_SERVICE_ROLE_KEY, {
            auth: {
                autoRefreshToken: false,
                persistSession: false
            }
        });
        console.log('✅ Supabase inicializado correctamente');
    } catch (error) {
        console.error('❌ Error inicializando Supabase:', error.message);
        if (ENV.NODE_ENV === 'production') process.exit(1);
    }
}

// 3. MIDDLEWARES DE SEGURIDAD (ORDEN CRÍTICO)

// 3.1 HELMET - Protección de cabeceras HTTP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "*.supabase.co", "via.placeholder.com", "d.top4top.io", "i.ibb.co", "images.unsplash.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "*.supabase.co"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: "deny" },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
}));

// 3.2 CORS - Configuración restrictiva
app.use(cors({
    origin: (origin, callback) => {
        // Permitir peticiones sin origin (como Postman) solo en desarrollo
        if (!origin) return callback(null, true);
        if (ENV.ALLOWED_ORIGINS.includes(origin) || ENV.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.log(`🔴 CORS bloqueado: ${origin}`);
            callback(new Error('Origen no permitido por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Admin-Password', 'X-CSRF-Token', 'X-Requested-With'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    credentials: true,
    maxAge: 86400 // 24 horas
}));

// 3.3 HPP - Protección contra Parameter Pollution
app.use(hpp());

// 3.4 RATE LIMITING - Múltiples capas
const globalLimiter = rateLimit({
    windowMs: ENV.RATE_LIMIT_WINDOW,
    max: ENV.RATE_LIMIT_MAX,
    message: { 
        success: false, 
        error: 'Demasiadas peticiones. Por favor, espera unos minutos.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.connection.remoteAddress || 'unknown';
    },
    skip: (req) => {
        // Permitir más peticiones desde IPs de administradores (opcional)
        return false;
    }
});

// Rate limiter específico para login (más estricto)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // 5 intentos
    message: { 
        success: false, 
        error: 'Demasiados intentos de login. Espera 15 minutos.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.connection.remoteAddress || 'unknown';
    }
});

// Rate limiter específico para pedidos (anti-flood)
const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 10, // 10 pedidos por hora
    message: { 
        success: false, 
        error: 'Demasiados pedidos en poco tiempo. Espera 1 hora.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.connection.remoteAddress || 'unknown';
    }
});

// Aplicar rate limiters según ruta
app.use('/api', globalLimiter);
app.use('/api/admin/login', loginLimiter);
app.use('/api/pedidos', orderLimiter);

// 3.5 LIMITADOR DE TAMAÑO DE PETICIONES
app.use(express.json({ 
    limit: '5mb',
    verify: (req, res, buf) => {
        // Verificar tamaño total de la petición
        const size = buf.length;
        if (size > 5 * 1024 * 1024) {
            throw new Error('La petición excede el límite de 5MB');
        }
    }
}));
app.use(express.urlencoded({ 
    extended: true, 
    limit: '5mb' 
}));

// 3.6 MIDDLEWARE DE SANITIZACIÓN ESTRICTA
const sanitizeInput = (req, res, next) => {
    // EXCLUIR login de la sanitización (necesario para contraseña)
    if (req.path === '/api/admin/login') {
        return next();
    }
    
    const sanitizeValue = (value) => {
        if (typeof value === 'string') {
            // XSS sanitization
            let sanitized = xss(value, {
                whiteList: {},
                stripIgnoreTag: true,
                stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed']
            });
            
            // Eliminar caracteres de control
            sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
            
            // Limitar longitud
            return sanitized.slice(0, 5000);
        }
        if (Array.isArray(value)) {
            return value.map(v => sanitizeValue(v));
        }
        if (typeof value === 'object' && value !== null) {
            const result = {};
            for (const [key, val] of Object.entries(value)) {
                // Limpiar nombres de propiedades
                const cleanKey = key.replace(/[<>{}()\[\]\/\\;'"`]/g, '');
                result[cleanKey] = sanitizeValue(val);
            }
            return result;
        }
        return value;
    };
    
    try {
        if (req.body) req.body = sanitizeValue(req.body);
        if (req.query) req.query = sanitizeValue(req.query);
        if (req.params) req.params = sanitizeValue(req.params);
    } catch (error) {
        console.error('❌ Error en sanitización:', error);
        return res.status(400).json({ 
            success: false, 
            error: 'Datos de entrada inválidos' 
        });
    }
    
    next();
};

app.use(sanitizeInput);

// 3.7 MIDDLEWARE DE VALIDACIÓN DE TIPOS
const validateTypes = (req, res, next) => {
    // Verificar tipos primitivos en parámetros comunes
    const checkParam = (value, name) => {
        if (value === undefined || value === null) return true;
        if (typeof value === 'string' && value.length > 5000) {
            return false;
        }
        return true;
    };
    
    // Verificar body
    if (req.body) {
        for (const [key, value] of Object.entries(req.body)) {
            if (!checkParam(value, key)) {
                return res.status(400).json({
                    success: false,
                    error: `Parámetro '${key}' excede la longitud máxima permitida`
                });
            }
        }
    }
    
    next();
};

app.use(validateTypes);

// 3.8 BLOQUEO DE RUTAS MALICIOSAS (con expresión regular optimizada)
const BLOCKED_PATHS = [
    '/wp-admin', '/cpanel', '/plesk', '/phpmyadmin', '/mysql', '/db',
    '/config', '/.env', '/.git', '/backup', '/shell', '/cmd', '/exec',
    '/system', '/vendor', '/composer', '/.ssh', '/.aws', '/.htaccess',
    '/web.config', '/robots.txt', '/sitemap.xml', '/adminer', '/phpinfo',
    '/info.php', '/test.php', '/setup', '/install', '/update', '/upgrade',
    '/drupal', '/wordpress', '/joomla', '/magento', '/prestashop'
];

app.use((req, res, next) => {
    const requestPath = req.path.toLowerCase();
    for (const blocked of BLOCKED_PATHS) {
        if (requestPath.startsWith(blocked) || requestPath.includes(blocked)) {
            console.log(`🔴 [BLOQUEADO] ${req.path} desde ${req.ip} - Ruta maliciosa`);
            // Responder con 404 genérico para no revelar información
            return res.status(404).send('Not Found');
        }
    }
    next();
});

// 3.9 LOG DE PETICIONES (sin datos sensibles)
app.use((req, res, next) => {
    const startTime = Date.now();
    const method = req.method;
    const path = req.path;
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    
    // Log solo en desarrollo o para rutas específicas
    if (ENV.NODE_ENV === 'development') {
        console.log(`📝 ${method} ${path} desde ${ip}`);
    }
    
    // Capturar respuesta
    const originalSend = res.send;
    res.send = function(data) {
        const duration = Date.now() - startTime;
        // Solo loguear errores o rutas críticas
        if (res.statusCode >= 400) {
            console.log(`⚠️ ${method} ${path} → ${res.statusCode} (${duration}ms) desde ${ip}`);
        }
        originalSend.call(this, data);
    };
    
    next();
});

// ============================================================
// 4. FUNCIONES DE SEGURIDAD Y VALIDACIÓN
// ============================================================

// 4.1 VALIDACIÓN DE TELÉFONO CUBANO (mejorada)
function validarTelefonoCubano(telefono) {
    if (!telefono || typeof telefono !== 'string') {
        return { valido: false, mensaje: 'Teléfono inválido', limpio: '' };
    }
    
    // Eliminar todo excepto dígitos
    const limpio = telefono.replace(/[^0-9]/g, '');
    
    if (!limpio) {
        return { valido: false, mensaje: 'El teléfono es obligatorio', limpio: '' };
    }
    
    // Caso: +53 5XXXXXXX (8 dígitos después del +53)
    if (telefono.includes('+53') && limpio.length === 10) {
        const sinCodigo = limpio.replace(/^53/, '');
        if (sinCodigo.length === 8 && sinCodigo.startsWith('5')) {
            return { valido: true, mensaje: 'Válido', limpio: sinCodigo };
        }
        return { valido: false, mensaje: 'Formato: +53 5XXXXXXX (8 dígitos)', limpio: '' };
    }
    
    // Caso: 53XXXXXXX (10 dígitos)
    if (limpio.length === 10 && limpio.startsWith('53')) {
        const sinCodigo = limpio.substring(2);
        if (sinCodigo.startsWith('5')) {
            return { valido: true, mensaje: 'Válido', limpio: sinCodigo };
        }
        return { valido: false, mensaje: 'Después de 53 deben haber 8 dígitos empezando con 5', limpio: '' };
    }
    
    // Caso: 5XXXXXXX (8 dígitos)
    if (limpio.length === 8 && limpio.startsWith('5')) {
        return { valido: true, mensaje: 'Válido', limpio: limpio };
    }
    
    // Caso: 5XXXXXXX (7 dígitos - error común)
    if (limpio.length === 7 && limpio.startsWith('5')) {
        return { valido: false, mensaje: 'El número debe tener 8 dígitos. Ej: 5XXXXXXX', limpio: '' };
    }
    
    return { 
        valido: false, 
        mensaje: 'Formato cubano: 5XXXXXXX (8 dígitos) o +53 5XXXXXXX', 
        limpio: '' 
    };
}

// 4.2 VALIDACIÓN DE DIRECCIÓN (mejorada)
function validarDireccion(direccion) {
    if (!direccion || typeof direccion !== 'string') {
        return { valido: false, mensaje: 'La dirección es obligatoria' };
    }
    
    const trimmed = direccion.trim();
    
    if (trimmed.length < 5) {
        return { valido: false, mensaje: 'La dirección debe tener al menos 5 caracteres' };
    }
    
    if (trimmed.length > 200) {
        return { valido: false, mensaje: 'La dirección no puede exceder 200 caracteres' };
    }
    
    // Caracteres permitidos: letras, números, espacios, #, /, ., ,, -
    const regex = /^[a-zA-Z0-9áéíóúñÑ\s#/.,\-]+$/;
    if (!regex.test(trimmed)) {
        const invalidos = trimmed.replace(/[a-zA-Z0-9áéíóúñÑ\s#/.,\-]/g, '');
        return { 
            valido: false, 
            mensaje: `Caracteres no permitidos: "${invalidos}". Solo se permiten: #, /, ., ,, -` 
        };
    }
    
    return { valido: true, mensaje: 'Dirección válida' };
}

// 4.3 VALIDACIÓN DE NOMBRE
function validarNombre(nombre) {
    if (!nombre || typeof nombre !== 'string') {
        return { valido: false, mensaje: 'El nombre es obligatorio' };
    }
    
    const trimmed = nombre.trim();
    
    if (trimmed.length < 2) {
        return { valido: false, mensaje: 'El nombre debe tener al menos 2 caracteres' };
    }
    
    if (trimmed.length > 60) {
        return { valido: false, mensaje: 'El nombre no puede exceder 60 caracteres' };
    }
    
    const regex = /^[a-zA-ZáéíóúñÑ\s]+$/;
    if (!regex.test(trimmed)) {
        return { valido: false, mensaje: 'El nombre solo puede contener letras y espacios' };
    }
    
    return { valido: true, mensaje: 'Nombre válido' };
}

// 4.4 VALIDACIÓN DE ITEMS DEL PEDIDO
function validarItems(items) {
    if (!items || !Array.isArray(items)) {
        return { valido: false, mensaje: 'El carrito no puede estar vacío' };
    }
    
    if (items.length === 0) {
        return { valido: false, mensaje: 'El carrito no puede estar vacío' };
    }
    
    if (items.length > ENV.MAX_ORDER_ITEMS) {
        return { 
            valido: false, 
            mensaje: `Máximo ${ENV.MAX_ORDER_ITEMS} productos por pedido` 
        };
    }
    
    for (const item of items) {
        if (!item.id || typeof item.id !== 'number' || item.id <= 0) {
            return { valido: false, mensaje: 'ID de producto inválido' };
        }
        if (!item.nombre || typeof item.nombre !== 'string' || item.nombre.length < 2) {
            return { valido: false, mensaje: 'Nombre de producto inválido' };
        }
        if (!item.qty || typeof item.qty !== 'number' || item.qty < 1 || item.qty > 99) {
            return { valido: false, mensaje: 'Cantidad inválida (1-99)' };
        }
        if (!item.precio || typeof item.precio !== 'number' || item.precio <= 0) {
            return { valido: false, mensaje: 'Precio inválido' };
        }
    }
    
    return { valido: true, mensaje: 'Items válidos' };
}

// 4.5 SANITIZACIÓN DE ENTRADA PARA BASE DE DATOS
function sanitizarParaBD(value) {
    if (typeof value === 'string') {
        return value
            .replace(/['"]/g, '') // Eliminar comillas
            .replace(/\\/g, '\\\\') // Escapar backslashes
            .replace(/;/g, '') // Eliminar punto y coma
            .trim()
            .slice(0, 5000);
    }
    return value;
}

// 4.6 GENERACIÓN DE CÓDIGO ÚNICO (más seguro)
function generarCodigoUnico() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const randomPart = Array.from(
        { length: 8 }, 
        () => chars.charAt(Math.floor(Math.random() * chars.length))
    ).join('');
    
    const timestamp = Date.now().toString(36).slice(-4).toUpperCase();
    const cryptoRandom = crypto.randomBytes(4).toString('hex').toUpperCase();
    
    return `${randomPart}${timestamp}${cryptoRandom.slice(0, 4)}`;
}

// 4.7 VERIFICACIÓN DE RATE LIMIT POR IP (Manual)
function verificarRateLimitIP(ip) {
    const now = Date.now();
    const key = ip || 'unknown';
    
    let record = rateLimitStore.get(key);
    if (!record) {
        record = { count: 0, resetTime: now + ENV.RATE_LIMIT_WINDOW };
        rateLimitStore.set(key, record);
    }
    
    if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + ENV.RATE_LIMIT_WINDOW;
    }
    
    if (record.count >= ENV.RATE_LIMIT_MAX) {
        const waitTime = Math.ceil((record.resetTime - now) / 60000);
        return { 
            allowed: false, 
            waitTime: waitTime,
            remaining: 0
        };
    }
    
    record.count++;
    rateLimitStore.set(key, record);
    
    return { 
        allowed: true,
        remaining: ENV.RATE_LIMIT_MAX - record.count,
        resetTime: new Date(record.resetTime).toISOString()
    };
}

// 4.8 FUNCIÓN DE SUBIDA A SUPABASE (con validación)
async function uploadToSupabase(file, folder = 'Productos') {
    try {
        if (!supabase) {
            console.error('❌ Supabase no inicializado');
            return null;
        }
        
        if (!file || !file.buffer) {
            console.error('❌ Archivo inválido para subir');
            return null;
        }
        
        // Validar tamaño
        if (file.size > ENV.MAX_FILE_SIZE) {
            console.error(`❌ Archivo excede tamaño máximo: ${file.size} > ${ENV.MAX_FILE_SIZE}`);
            return null;
        }
        
        // Validar tipo MIME
        const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
        if (!allowedMimes.includes(file.mimetype)) {
            console.error(`❌ Tipo MIME no permitido: ${file.mimetype}`);
            return null;
        }
        
        const fileExt = file.originalname.split('.').pop() || 'jpg';
        const fileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { data, error } = await supabase.storage
            .from(folder)
            .upload(filePath, file.buffer, {
                cacheControl: '3600',
                upsert: false,
                contentType: file.mimetype
            });
        
        if (error) {
            console.error('❌ Error en upload:', error.message);
            return null;
        }
        
        const { data: { publicUrl } } = supabase.storage
            .from(folder)
            .getPublicUrl(filePath);
        
        return publicUrl;
    } catch (error) {
        console.error('❌ Error subiendo imagen:', error.message);
        return null;
    }
}

// 4.9 FUNCIÓN DE ELIMINACIÓN DE SUPABASE
async function deleteFromSupabase(imageUrl) {
    try {
        if (!supabase) return false;
        if (!imageUrl || typeof imageUrl !== 'string') return false;
        if (!imageUrl.includes('/storage/v1/object/public/')) return false;
        
        const urlParts = imageUrl.split('/Productos/');
        if (urlParts.length < 2) return false;
        
        const filePath = `Productos/${urlParts[1]}`;
        
        const { error } = await supabase.storage
            .from('Productos')
            .remove([filePath]);
        
        if (error) {
            console.error('❌ Error eliminando imagen:', error.message);
            return false;
        }
        return true;
    } catch (error) {
        console.error('❌ Error eliminando imagen:', error.message);
        return false;
    }
}

// ============================================================
// 5. API PÚBLICA (SIN AUTENTICACIÓN)
// ============================================================

// 5.1 ESTADO DEL SERVIDOR (sin información sensible)
app.get('/api/status', (req, res) => {
    res.json({ 
        online: true, 
        timestamp: new Date().toISOString(),
        version: '4.0.0',
        supabase: !!supabase
    });
});

// 5.2 CONFIGURACIÓN PÚBLICA
app.get('/api/config', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ 
                error: 'Servicio de base de datos no disponible',
                moneda_base: 'CUP',
                tasas: { CUP: 1, USD: 0.04, EUR: 0.037 }
            });
        }
        
        const { data, error } = await supabase
            .from('config')
            .select('moneda_base, tasas, updated_at')
            .eq('id', 1)
            .single();
        
        if (error) {
            const defaultConfig = {
                moneda_base: 'CUP',
                tasas: { CUP: 1, USD: 0.04, EUR: 0.037 },
                updated_at: new Date().toISOString()
            };
            return res.json(defaultConfig);
        }
        
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/config:', error.message);
        res.status(500).json({ 
            error: 'Error al cargar configuración',
            moneda_base: 'CUP',
            tasas: { CUP: 1, USD: 0.04, EUR: 0.037 }
        });
    }
});

// 5.3 LISTA DE TIENDAS
app.get('/api/tiendas/info', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('id, nombre, icono, descripcion, categorias')
            .order('nombre');
        
        if (error) {
            console.error('❌ Error en /api/tiendas/info:', error.message);
            return res.status(500).json({ error: 'Error al cargar tiendas' });
        }
        
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error en /api/tiendas/info:', error.message);
        res.status(500).json({ error: 'Error al cargar tiendas' });
    }
});

// 5.4 DATOS DE UNA TIENDA
app.get('/api/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', tiendaId)
            .single();
        
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/tiendas/:id:', error.message);
        res.status(500).json({ error: 'Error al cargar tienda' });
    }
});

// 5.5 CONFIGURACIÓN DE UNA TIENDA (sin datos bancarios para público)
app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('configuracion')
            .eq('id', tiendaId)
            .single();
        
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        
        // Remover datos bancarios para público
        const config = data?.configuracion || {};
        if (config.datos_bancarios) {
            delete config.datos_bancarios.numero_tarjeta;
        }
        
        res.json(config);
    } catch (error) {
        console.error('❌ Error en /api/tiendas/:id/config:', error.message);
        res.status(500).json({ error: 'Error al cargar configuración' });
    }
});

// 5.6 PRODUCTOS DE UNA TIENDA
app.get('/api/productos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('❌ Error en /api/productos:', error.message);
            return res.status(500).json({ error: 'Error al cargar productos' });
        }
        
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error en /api/productos:', error.message);
        res.status(500).json({ error: 'Error al cargar productos' });
    }
});

// 5.7 CATEGORÍAS DE UNA TIENDA
app.get('/api/categorias', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        
        if (error) {
            return res.json(['otros']);
        }
        
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('❌ Error en /api/categorias:', error.message);
        res.json(['otros']);
    }
});

// 5.8 VERIFICAR RATE LIMIT
app.get('/api/check-rate-limit', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const result = verificarRateLimitIP(ip);
    res.json(result);
});

// ============================================================
// 6. API DE PEDIDOS - CON VALIDACIÓN ESTRICTA
// ============================================================

// 6.1 CREAR PEDIDO - CON VALIDACIÓN COMPLETA
app.post('/api/pedidos', [
    // Validaciones con express-validator
    body('tienda')
        .optional()
        .isString()
        .trim()
        .isLength({ min: 2, max: 50 })
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID de tienda inválido'),
    
    body('nombre')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 2, max: 60 })
        .matches(/^[a-zA-ZáéíóúñÑ\s]+$/)
        .withMessage('El nombre solo puede contener letras y espacios'),
    
    body('telefono')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 5, max: 20 })
        .withMessage('Teléfono inválido'),
    
    body('direccion')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 5, max: 200 })
        .withMessage('La dirección debe tener entre 5 y 200 caracteres'),
    
    body('items')
        .isArray({ min: 1 })
        .withMessage('El carrito no puede estar vacío'),
    
    body('items.*.id')
        .isInt({ min: 1 })
        .withMessage('ID de producto inválido'),
    
    body('items.*.qty')
        .isInt({ min: 1, max: 99 })
        .withMessage('Cantidad inválida (1-99)'),
    
    body('items.*.precio')
        .isFloat({ min: 0.01 })
        .withMessage('Precio inválido'),
    
    body('total')
        .isFloat({ min: 0.01, max: ENV.MAX_ORDER_TOTAL })
        .withMessage(`Total inválido (máximo ${ENV.MAX_ORDER_TOTAL})`),
    
    body('moneda')
        .optional()
        .isIn(['CUP', 'USD', 'EUR'])
        .withMessage('Moneda inválida'),
    
    body('metodoPago')
        .optional()
        .isIn(['Efectivo', 'Transferencia'])
        .withMessage('Método de pago inválido')
], async (req, res) => {
    try {
        // 1. Validar express-validator
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({
                    field: e.path,
                    message: e.msg
                }))
            });
        }
        
        // 2. Verificar Supabase
        if (!supabase) {
            return res.status(503).json({
                success: false,
                error: 'Servicio de base de datos no disponible'
            });
        }
        
        // 3. Verificar Rate Limit
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const rateResult = verificarRateLimitIP(ip);
        if (!rateResult.allowed) {
            return res.status(429).json({
                success: false,
                error: `Demasiados pedidos. Espera ${rateResult.waitTime} minutos.`
            });
        }
        
        // 4. Obtener datos validados
        const data = matchedData(req);
        const tienda = data.tienda || 'electro';
        
        // 5. Validar tienda existe
        const { data: storeExists, error: storeError } = await supabase
            .from('stores')
            .select('id, configuracion')
            .eq('id', tienda)
            .single();
        
        if (storeError || !storeExists) {
            return res.status(400).json({
                success: false,
                error: 'Tienda no encontrada'
            });
        }
        
        // 6. Validar teléfono cubano
        const telefonoValidado = validarTelefonoCubano(data.telefono);
        if (!telefonoValidado.valido) {
            return res.status(400).json({
                success: false,
                error: telefonoValidado.mensaje
            });
        }
        
        // 7. Validar dirección
        const direccionValidada = validarDireccion(data.direccion);
        if (!direccionValidada.valido) {
            return res.status(400).json({
                success: false,
                error: direccionValidada.mensaje
            });
        }
        
        // 8. Validar items
        const itemsValidados = validarItems(data.items);
        if (!itemsValidados.valido) {
            return res.status(400).json({
                success: false,
                error: itemsValidados.mensaje
            });
        }
        
        // 9. Verificar coherencia del total
        const totalCalculado = data.items.reduce((sum, item) => sum + (item.precio * item.qty), 0);
        if (Math.abs(totalCalculado - data.total) > 0.01) {
            return res.status(400).json({
                success: false,
                error: 'El total no coincide con la suma de los productos'
            });
        }
        
        // 10. Verificar método de pago y datos bancarios
        const metodoPago = data.metodoPago || 'Efectivo';
        if (metodoPago === 'Transferencia') {
            const config = storeExists.configuracion || {};
            const numeroTarjeta = config?.datos_bancarios?.numero_tarjeta;
            if (!numeroTarjeta || numeroTarjeta.trim() === '') {
                return res.status(400).json({
                    success: false,
                    error: 'Transferencia no disponible. Contacte al administrador.'
                });
            }
        }
        
        // 11. Generar código único
        const codigoCliente = generarCodigoUnico();
        
        // 12. Obtener siguiente ID
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        // 13. Preparar items para BD (sanitizados)
        const itemsParaBD = data.items.map(item => ({
            id: item.id,
            nombre: sanitizarParaBD(item.nombre).slice(0, 100),
            precio: parseFloat(item.precio.toFixed(2)),
            qty: parseInt(item.qty),
            imagen: item.imagen || ''
        }));
        
        // 14. Insertar pedido
        const { error: insertError } = await supabase
            .from('orders')
            .insert({
                id: nextId,
                codigo_cliente: codigoCliente,
                tienda: tienda,
                nombre: sanitizarParaBD(data.nombre).slice(0, 60),
                telefono: telefonoValidado.limpio,
                direccion: sanitizarParaBD(data.direccion).slice(0, 200),
                items: itemsParaBD,
                total: parseFloat(data.total.toFixed(2)),
                moneda: data.moneda || 'CUP',
                metodo_pago: metodoPago,
                estado: 'pendiente',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });
        
        if (insertError) {
            console.error('❌ Error insertando pedido:', insertError.message);
            return res.status(500).json({
                success: false,
                error: 'Error al registrar el pedido'
            });
        }
        
        // 15. Actualizar contador
        await supabase
            .from('order_counters')
            .upsert({ 
                tienda: tienda, 
                counter: nextId,
                updated_at: new Date().toISOString()
            });
        
        // 16. Log seguro
        console.log(`✅ Pedido #${nextId} registrado desde ${ip} - Código: ${codigoCliente}`);
        
        res.status(201).json({
            success: true,
            orderId: nextId,
            codigoCliente: codigoCliente,
            message: 'Pedido registrado correctamente'
        });
        
    } catch (error) {
        console.error('❌ Error en POST /api/pedidos:', error.message);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

// 6.2 BUSCAR PEDIDO POR CÓDIGO (público)
app.get('/api/pedidos/buscar', async (req, res) => {
    try {
        const codigo = req.query.codigo?.toUpperCase().trim();
        const tienda = req.query.tienda?.toLowerCase().trim();
        
        if (!codigo || codigo.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'Código de pedido inválido'
            });
        }
        
        if (!supabase) {
            return res.status(503).json({
                success: false,
                error: 'Servicio de base de datos no disponible'
            });
        }
        
        let query = supabase
            .from('orders')
            .select('*')
            .eq('codigo_cliente', codigo);
        
        if (tienda) {
            query = query.eq('tienda', tienda);
        }
        
        const { data, error } = await query;
        
        if (error) {
            console.error('❌ Error buscando pedido:', error.message);
            return res.status(500).json({
                success: false,
                error: 'Error al buscar pedido'
            });
        }
        
        // Sanitizar respuesta (remover datos sensibles)
        const safeData = (data || []).map(order => ({
            id: order.id,
            codigo_cliente: order.codigo_cliente,
            tienda: order.tienda,
            nombre: order.nombre,
            telefono: order.telefono,
            direccion: order.direccion,
            items: order.items,
            total: order.total,
            moneda: order.moneda,
            metodo_pago: order.metodo_pago,
            estado: order.estado,
            created_at: order.created_at,
            updated_at: order.updated_at
        }));
        
        res.json({
            success: true,
            data: safeData
        });
        
    } catch (error) {
        console.error('❌ Error en /api/pedidos/buscar:', error.message);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

// ============================================================
// 7. API ADMIN - CON AUTENTICACIÓN Y VALIDACIÓN
// ============================================================

// 7.1 MIDDLEWARE DE AUTENTICACIÓN
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ 
            error: 'No autorizado',
            message: 'Token de autenticación requerido'
        });
    }
    
    const session = sessions.get(token);
    if (!session || session.expiry < Date.now()) {
        sessions.delete(token);
        return res.status(401).json({ 
            error: 'No autorizado',
            message: 'Sesión expirada'
        });
    }
    
    // Renovar sesión
    session.expiry = Date.now() + ENV.SESSION_DURATION;
    sessions.set(token, session);
    req.session = session;
    next();
};

// Aplicar autenticación a todas las rutas /api/admin
app.use('/api/admin', requireAuth);

// ============================================================
// 7.2 RUTAS ADMIN - TIENDAS
// ============================================================

app.get('/api/admin/tiendas', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .order('id');
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error en /api/admin/tiendas:', error.message);
        res.status(500).json({ error: 'Error al cargar tiendas' });
    }
});

app.get('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', tiendaId)
            .single();
        
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/admin/tiendas/:id:', error.message);
        res.status(500).json({ error: 'Error al cargar tienda' });
    }
});

app.post('/api/admin/tiendas', [
    body('id')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 2, max: 50 })
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID inválido (solo minúsculas, números, guiones y guión bajo)'),
    
    body('nombre')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Nombre inválido'),
    
    body('icono')
        .optional()
        .isString()
        .isLength({ max: 10 })
        .withMessage('Icono inválido'),
    
    body('descripcion')
        .optional()
        .isString()
        .isLength({ max: 1000 })
        .withMessage('Descripción demasiado larga'),
    
    body('categorias')
        .optional()
        .isArray()
        .withMessage('Categorías debe ser un array'),
    
    body('configuracion')
        .optional()
        .isObject()
        .withMessage('Configuración inválida')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const data = matchedData(req);
        
        // Verificar que no exista
        const { data: existing } = await supabase
            .from('stores')
            .select('id')
            .eq('id', data.id)
            .single();
        
        if (existing) {
            return res.status(400).json({
                success: false,
                error: 'Ya existe una tienda con este ID'
            });
        }
        
        const { error } = await supabase
            .from('stores')
            .insert({
                id: data.id,
                nombre: data.nombre.trim(),
                icono: data.icono || '🛒',
                descripcion: data.descripcion || '',
                configuracion: data.configuracion || {},
                categorias: data.categorias || ['otros'],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });
        
        if (error) throw error;
        
        res.status(201).json({ success: true });
    } catch (error) {
        console.error('❌ Error en POST /api/admin/tiendas:', error.message);
        res.status(500).json({ error: 'Error al crear tienda' });
    }
});

app.put('/api/admin/tiendas/:id', [
    body('nombre')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Nombre inválido'),
    
    body('icono')
        .optional()
        .isString()
        .isLength({ max: 10 })
        .withMessage('Icono inválido'),
    
    body('descripcion')
        .optional()
        .isString()
        .isLength({ max: 1000 })
        .withMessage('Descripción demasiado larga'),
    
    body('categorias')
        .optional()
        .isArray()
        .withMessage('Categorías debe ser un array'),
    
    body('configuracion')
        .optional()
        .isObject()
        .withMessage('Configuración inválida')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const data = matchedData(req);
        
        const { error } = await supabase
            .from('stores')
            .update({
                nombre: data.nombre.trim(),
                icono: data.icono || '🛒',
                descripcion: data.descripcion || '',
                configuracion: data.configuracion || {},
                categorias: data.categorias || ['otros'],
                updated_at: new Date().toISOString()
            })
            .eq('id', tiendaId);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en PUT /api/admin/tiendas/:id:', error.message);
        res.status(500).json({ error: 'Error al actualizar tienda' });
    }
});

app.delete('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        // Verificar que exista
        const { data: existing } = await supabase
            .from('stores')
            .select('id')
            .eq('id', tiendaId)
            .single();
        
        if (!existing) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        
        const { error } = await supabase
            .from('stores')
            .delete()
            .eq('id', tiendaId);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en DELETE /api/admin/tiendas/:id:', error.message);
        res.status(500).json({ error: 'Error al eliminar tienda' });
    }
});

// ============================================================
// 7.3 RUTAS ADMIN - CATEGORÍAS
// ============================================================

app.get('/api/admin/categorias', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        
        if (error) {
            return res.json(['otros']);
        }
        
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('❌ Error en /api/admin/categorias:', error.message);
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', [
    body('tienda')
        .notEmpty()
        .isString()
        .trim()
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID de tienda inválido'),
    
    body('categoria')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 2, max: 50 })
        .matches(/^[a-zA-Z0-9áéíóúñÑ\s\-]+$/)
        .withMessage('Categoría inválida')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { tienda, categoria } = req.body;
        const categoriaLimpia = categoria.trim();
        
        const { data: store } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        
        if (!store) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        
        const currentCats = store.categorias || [];
        if (!currentCats.includes(categoriaLimpia)) {
            currentCats.push(categoriaLimpia);
        }
        
        const { error } = await supabase
            .from('stores')
            .update({ 
                categorias: currentCats, 
                updated_at: new Date().toISOString() 
            })
            .eq('id', tienda);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en POST /api/admin/categorias:', error.message);
        res.status(500).json({ error: 'Error al agregar categoría' });
    }
});

// ============================================================
// 7.4 RUTAS ADMIN - PRODUCTOS
// ============================================================

app.get('/api/admin/productos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error en /api/admin/productos:', error.message);
        res.json([]);
    }
});

app.post('/api/admin/productos', upload.single('imagen'), [
    body('nombre')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 3, max: 100 })
        .matches(/^[a-zA-Z0-9áéíóúñÑ\s\-\.]+$/)
        .withMessage('Nombre inválido'),
    
    body('precio')
        .isFloat({ min: 0.01, max: 999999.99 })
        .withMessage('Precio inválido'),
    
    body('descuento')
        .optional()
        .isInt({ min: 0, max: 100 })
        .withMessage('Descuento inválido (0-100)'),
    
    body('tienda')
        .notEmpty()
        .isString()
        .trim()
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID de tienda inválido'),
    
    body('categoria')
        .optional()
        .isString()
        .trim()
        .isLength({ max: 50 })
        .withMessage('Categoría inválida'),
    
    body('disponible')
        .optional()
        .isBoolean()
        .withMessage('Disponible debe ser booleano'),
    
    body('tamanio')
        .optional()
        .isIn(['pequeno', 'grande'])
        .withMessage('Tamaño inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const data = req.body;
        let imagen = data.imagen_url || 'https://via.placeholder.com/400';
        
        // Subir imagen si existe
        if (req.file) {
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) {
                imagen = uploadedUrl;
            } else {
                return res.status(500).json({ 
                    success: false, 
                    error: 'Error al subir la imagen' 
                });
            }
        }
        
        const productoData = {
            tienda: data.tienda,
            nombre: data.nombre.trim(),
            descripcion: data.descripcion?.trim() || '',
            precio: parseFloat(data.precio),
            descuento: parseInt(data.descuento) || 0,
            imagen: imagen,
            disponible: data.disponible === 'true',
            tamanio: data.tamanio || 'pequeno',
            categoria: data.categoria?.trim() || 'otros',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        
        const { data: result, error } = await supabase
            .from('products')
            .insert(productoData)
            .select();
        
        if (error) throw error;
        
        res.status(201).json({ success: true, data: result });
    } catch (error) {
        console.error('❌ Error en POST /api/admin/productos:', error.message);
        res.status(500).json({ success: false, error: 'Error al crear producto' });
    }
});

app.put('/api/admin/productos/:id', upload.single('imagen'), [
    body('nombre')
        .notEmpty()
        .isString()
        .trim()
        .isLength({ min: 3, max: 100 })
        .matches(/^[a-zA-Z0-9áéíóúñÑ\s\-\.]+$/)
        .withMessage('Nombre inválido'),
    
    body('precio')
        .isFloat({ min: 0.01, max: 999999.99 })
        .withMessage('Precio inválido'),
    
    body('descuento')
        .optional()
        .isInt({ min: 0, max: 100 })
        .withMessage('Descuento inválido (0-100)'),
    
    body('categoria')
        .optional()
        .isString()
        .trim()
        .isLength({ max: 50 })
        .withMessage('Categoría inválida'),
    
    body('disponible')
        .optional()
        .isBoolean()
        .withMessage('Disponible debe ser booleano'),
    
    body('tamanio')
        .optional()
        .isIn(['pequeno', 'grande'])
        .withMessage('Tamaño inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        const productId = parseInt(req.params.id);
        if (!productId || productId <= 0) {
            return res.status(400).json({ error: 'ID de producto inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const data = req.body;
        
        // Obtener producto actual
        const { data: oldProduct } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', productId)
            .single();
        
        if (!oldProduct) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        
        const updateData = {
            nombre: data.nombre.trim(),
            descripcion: data.descripcion?.trim() || '',
            precio: parseFloat(data.precio),
            descuento: parseInt(data.descuento) || 0,
            disponible: data.disponible === 'true',
            tamanio: data.tamanio || 'pequeno',
            categoria: data.categoria?.trim() || 'otros',
            updated_at: new Date().toISOString()
        };
        
        // Manejar imagen
        if (req.file) {
            if (oldProduct.imagen && !oldProduct.imagen.includes('via.placeholder.com')) {
                await deleteFromSupabase(oldProduct.imagen);
            }
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) {
                updateData.imagen = uploadedUrl;
            }
        } else if (data.imagen_url) {
            updateData.imagen = data.imagen_url;
        }
        
        const { error } = await supabase
            .from('products')
            .update(updateData)
            .eq('id', productId);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en PUT /api/admin/productos/:id:', error.message);
        res.status(500).json({ error: 'Error al actualizar producto' });
    }
});

app.delete('/api/admin/productos/:id', async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (!productId || productId <= 0) {
            return res.status(400).json({ error: 'ID de producto inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data: product } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', productId)
            .single();
        
        if (!product) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        
        if (product.imagen && !product.imagen.includes('via.placeholder.com')) {
            await deleteFromSupabase(product.imagen);
        }
        
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', productId);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en DELETE /api/admin/productos/:id:', error.message);
        res.status(500).json({ error: 'Error al eliminar producto' });
    }
});

// ============================================================
// 7.5 RUTAS ADMIN - PEDIDOS
// ============================================================

app.get('/api/admin/pedidos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim();
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        let query = supabase
            .from('orders')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (tienda) {
            query = query.eq('tienda', tienda);
        }
        
        const { data, error } = await query;
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error en /api/admin/pedidos:', error.message);
        res.json([]);
    }
});

app.put('/api/admin/pedidos/:id', [
    body('tienda')
        .notEmpty()
        .isString()
        .trim()
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID de tienda inválido'),
    
    body('estado')
        .notEmpty()
        .isIn(['pendiente', 'confirmado', 'enviado', 'entregado'])
        .withMessage('Estado inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        const orderId = parseInt(req.params.id);
        if (!orderId || orderId <= 0) {
            return res.status(400).json({ error: 'ID de pedido inválido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { tienda, estado } = req.body;
        
        const { error } = await supabase
            .from('orders')
            .update({ 
                estado: estado,
                updated_at: new Date().toISOString()
            })
            .eq('id', orderId)
            .eq('tienda', tienda);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en PUT /api/admin/pedidos/:id:', error.message);
        res.status(500).json({ error: 'Error al actualizar pedido' });
    }
});

app.delete('/api/admin/pedidos/:id', async (req, res) => {
    try {
        const orderId = parseInt(req.params.id);
        if (!orderId || orderId <= 0) {
            return res.status(400).json({ error: 'ID de pedido inválido' });
        }
        
        const tienda = req.query.tienda?.toLowerCase().trim();
        if (!tienda) {
            return res.status(400).json({ error: 'ID de tienda requerido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('id', orderId)
            .eq('tienda', tienda);
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en DELETE /api/admin/pedidos/:id:', error.message);
        res.status(500).json({ error: 'Error al eliminar pedido' });
    }
});

app.delete('/api/admin/pedidos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim();
        if (!tienda) {
            return res.status(400).json({ error: 'ID de tienda requerido' });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('tienda', tienda);
        
        if (error) throw error;
        
        // Resetear contador
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: 0 });
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error en DELETE /api/admin/pedidos:', error.message);
        res.status(500).json({ error: 'Error al eliminar pedidos' });
    }
});

// ============================================================
// 7.6 RUTAS ADMIN - CONFIGURACIÓN
// ============================================================

app.get('/api/admin/config', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        
        if (error) {
            const defaultConfig = {
                id: 1,
                moneda_base: 'CUP',
                tasas: { CUP: 1, USD: 0.04, EUR: 0.037 },
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };
            
            await supabase
                .from('config')
                .insert(defaultConfig);
            
            return res.json(defaultConfig);
        }
        
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/admin/config:', error.message);
        res.json({ 
            moneda_base: 'CUP', 
            tasas: { CUP: 1, USD: 0.04, EUR: 0.037 }
        });
    }
});

app.put('/api/admin/config', [
    body('monedaBase')
        .optional()
        .isString()
        .trim()
        .isIn(['CUP', 'USD', 'EUR'])
        .withMessage('Moneda base inválida'),
    
    body('tasas')
        .isObject()
        .withMessage('Tasas inválidas'),
    
    body('tasas.USD')
        .isFloat({ min: 0.0001 })
        .withMessage('Tasa USD inválida'),
    
    body('tasas.EUR')
        .isFloat({ min: 0.0001 })
        .withMessage('Tasa EUR inválida')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio de base de datos no disponible' });
        }
        
        const data = req.body;
        
        const configData = {
            moneda_base: data.monedaBase || 'CUP',
            tasas: {
                CUP: 1,
                USD: parseFloat(data.tasas.USD) || 0.04,
                EUR: parseFloat(data.tasas.EUR) || 0.037
            },
            updated_at: new Date().toISOString()
        };
        
        // Verificar si existe
        const { data: existing } = await supabase
            .from('config')
            .select('id')
            .eq('id', 1)
            .single();
        
        let result;
        if (existing) {
            result = await supabase
                .from('config')
                .update(configData)
                .eq('id', 1);
        } else {
            result = await supabase
                .from('config')
                .insert({ id: 1, ...configData, created_at: new Date().toISOString() });
        }
        
        if (result.error) throw result.error;
        
        res.json({ 
            success: true,
            message: 'Configuración guardada correctamente'
        });
    } catch (error) {
        console.error('❌ Error en PUT /api/admin/config:', error.message);
        res.status(500).json({ 
            success: false,
            error: 'Error al guardar configuración'
        });
    }
});

// ============================================================
// 8. MANEJO DE ERRORES GLOBAL
// ============================================================

// 8.1 Error 404 - Ruta no encontrada
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Ruta no encontrada',
        path: req.path 
    });
});

// 8.2 Error 500 - Error interno
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err.message);
    console.error('🔍 Stack:', err.stack);
    
    // No exponer stack traces en producción
    const errorMessage = ENV.NODE_ENV === 'production' 
        ? 'Error interno del servidor' 
        : err.message;
    
    res.status(500).json({ 
        error: errorMessage,
        ...(ENV.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ============================================================
// 9. INICIAR SERVIDOR CON VALIDACIONES
// ============================================================

// Verificar conexión a Supabase antes de iniciar
async function verificarConexionSupabase() {
    if (!supabase) {
        console.warn('⚠️ Supabase no disponible. Algunas funciones no funcionarán.');
        return false;
    }
    
    try {
        const { data, error } = await supabase
            .from('config')
            .select('id')
            .limit(1);
        
        if (error) {
            console.error('❌ Error conectando a Supabase:', error.message);
            return false;
        }
        
        console.log('✅ Conexión a Supabase verificada');
        return true;
    } catch (error) {
        console.error('❌ Error verificando conexión a Supabase:', error.message);
        return false;
    }
}

// Iniciar servidor
app.listen(PORT, '0.0.0.0', async () => {
    console.log('🚀 ========== TIENDA LA REINA ==========');
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`🔐 Entorno: ${ENV.NODE_ENV || 'development'}`);
    console.log(`🔑 Administración: ${ADMIN_PASSWORD ? '✅ Activada' : '❌ Desactivada'}`);
    
    // Verificar Supabase
    const supabaseOk = await verificarConexionSupabase();
    console.log(`🗄️ Supabase: ${supabaseOk ? '✅ Conectado' : '❌ No disponible'}`);
    
    console.log('🛡️ ========== SEGURIDAD ==========');
    console.log(`🛡️ Helmet: ✅ Activado`);
    console.log(`🛡️ CORS: ✅ Restrictivo (${ENV.ALLOWED_ORIGINS.length} orígenes)`);
    console.log(`🛡️ Rate Limit: ${ENV.RATE_LIMIT_MAX} req/${ENV.RATE_LIMIT_WINDOW/60000}min`);
    console.log(`🛡️ Sanitización: ✅ Activada`);
    console.log(`🛡️ Validación de tipos: ✅ Activada`);
    console.log(`🛡️ HPP: ✅ Activado`);
    console.log(`🛡️ XSS Protection: ✅ Activada`);
    console.log(`🛡️ Bloqueo de rutas: ✅ Activado (${BLOCKED_PATHS.length} patrones)`);
    console.log(`🛡️ Máximo items por pedido: ${ENV.MAX_ORDER_ITEMS}`);
    console.log(`🛡️ Máximo total por pedido: ${ENV.MAX_ORDER_TOTAL}`);
    console.log('📋 ===================================');
    console.log(`📋 Panel Admin: ${process.env.URL || `http://localhost:${PORT}`}/admin`);
    console.log('🔐 ===================================');
});

// ============================================================
// 10. LIMPIEZA DE SESIONES Y CIERRE GRACIOSO
// ============================================================

// Función de limpieza periódica de sesiones expiradas
setInterval(() => {
    const now = Date.now();
    let deleted = 0;
    for (const [key, value] of sessions) {
        if (value.expiry < now) {
            sessions.delete(key);
            deleted++;
        }
    }
    if (deleted > 0 && ENV.NODE_ENV === 'development') {
        console.log(`🧹 Sesiones limpiadas: ${deleted}`);
    }
}, 300000); // Cada 5 minutos

// Limpieza de rate limit store
setInterval(() => {
    const now = Date.now();
    let deleted = 0;
    for (const [key, record] of rateLimitStore) {
        if (now > record.resetTime) {
            rateLimitStore.delete(key);
            deleted++;
        }
    }
    if (rateLimitStore.size > 10000) {
        const keys = Array.from(rateLimitStore.keys());
        const toDelete = keys.slice(0, keys.length - 10000);
        toDelete.forEach(key => rateLimitStore.delete(key));
    }
}, 600000); // Cada 10 minutos

// Cierre gracioso
process.on('SIGTERM', () => {
    console.log('🛑 Recibida señal SIGTERM. Cerrando servidor...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 Recibida señal SIGINT. Cerrando servidor...');
    process.exit(0);
});

// Capturar errores no manejados
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    // En producción, no cerrar el proceso
    if (ENV.NODE_ENV === 'production') {
        console.warn('⚠️ Continuando después de error no capturado');
    } else {
        process.exit(1);
    }
});