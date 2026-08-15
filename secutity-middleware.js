import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import hpp from 'hpp';
import xss from 'xss';
import { body, validationResult } from 'express-validator';
import path from 'path';
import crypto from 'crypto';

// ============================================
// MIDDLEWARE DE SEGURIDAD DE ALTO NIVEL
// ============================================

// 1. HELMET - Protección de cabeceras
export const helmetMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "*.supabase.co", "via.placeholder.com", "d.top4top.io", "i.ibb.co", "images.unsplash.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "*.supabase.co"],
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: "deny" },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true,
});

// 2. CORS - Configuración restrictiva
export const corsMiddleware = cors({
    origin: process.env.ALLOWED_ORIGINS ? 
        process.env.ALLOWED_ORIGINS.split(',') : 
        ['https://la-reina-mgje.onrender.com', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Admin-Password'],
    credentials: true,
    maxAge: 86400
});

// 3. RATE LIMITING - Protección contra DDoS
export const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, intente más tarde' },
    standardHeaders: true,
    legacyHeaders: false,
});

export const strictRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { error: 'Límite de intentos excedido' },
});

// 4. HPP - Protección contra Parameter Pollution
export const hppMiddleware = hpp();

// 5. SANITIZACIÓN DE ENTRADA (EXCLUYE PASSWORD)
export const sanitizeInput = (req, res, next) => {
    // EXCLUIR login de la sanitización
    if (req.path === '/api/admin/login') {
        return next();
    }
    
    const sanitizeObject = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            // EXCLUIR 'password' de la sanitización
            if (key === 'password' || key === 'contraseña') {
                sanitized[key] = value;
                continue;
            }
            
            if (typeof value === 'string') {
                sanitized[key] = xss(value.trim(), {
                    whiteList: [],
                    stripIgnoreTag: true,
                    stripIgnoreTagBody: ['script']
                }).slice(0, 5000);
            } else if (Array.isArray(value)) {
                sanitized[key] = value.map(v => typeof v === 'string' ? 
                    xss(v.trim()).slice(0, 5000) : v);
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    };

    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.params) req.params = sanitizeObject(req.params);
    next();
};

// 6. VALIDACIÓN DE PRODUCTOS
export const validateProduct = [
    body('nombre').trim().isLength({ min: 3, max: 100 })
        .withMessage('El nombre debe tener entre 3 y 100 caracteres')
        .matches(/^[a-zA-Z0-9áéíóúñÑ\s\-\.]+$/)
        .withMessage('El nombre contiene caracteres no permitidos'),
    
    body('precio').isFloat({ min: 0.01, max: 999999.99 })
        .withMessage('El precio debe ser entre 0.01 y 999,999.99'),
    
    body('descripcion').optional()
        .isLength({ max: 5000 })
        .withMessage('La descripción no puede exceder 5000 caracteres'),
    
    body('descuento').optional().isInt({ min: 0, max: 100 })
        .withMessage('El descuento debe ser entre 0 y 100%'),
    
    body('tienda').trim().isLength({ min: 1, max: 50 })
        .withMessage('Tienda inválida')
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('ID de tienda solo permite minúsculas, números, guiones y guión bajo'),
    
    body('categoria').optional().isLength({ max: 50 })
        .withMessage('Categoría muy larga'),
    
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        next();
    }
];

// 7. VALIDACIÓN DE TIENDAS
export const validateStore = [
    body('id').trim().isLength({ min: 2, max: 50 })
        .withMessage('El ID debe tener entre 2 y 50 caracteres')
        .matches(/^[a-z0-9\-_]+$/)
        .withMessage('Solo minúsculas, números, guiones y guión bajo'),
    
    body('nombre').trim().isLength({ min: 2, max: 100 })
        .withMessage('El nombre debe tener entre 2 y 100 caracteres'),
    
    body('icono').optional().isLength({ max: 10 }),
    
    body('descripcion').optional().isLength({ max: 1000 }),
    
    body('categorias').optional().isArray().withMessage('Categorías debe ser un array'),
    
    body('configuracion.envio.costo').optional().isFloat({ min: 0 })
        .withMessage('El costo de envío debe ser un número positivo'),
    
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        next();
    }
];

// 8. VALIDACIÓN DE PEDIDOS
export const validateOrder = [
    body('nombre').trim().isLength({ min: 2, max: 100 })
        .withMessage('Nombre inválido')
        .matches(/^[a-zA-ZáéíóúñÑ\s]+$/)
        .withMessage('El nombre solo puede contener letras y espacios'),
    
    body('telefono').trim().isLength({ min: 5, max: 20 })
        .withMessage('Teléfono inválido')
        .matches(/^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/)
        .withMessage('Formato de teléfono inválido'),
    
    body('direccion').trim().isLength({ min: 5, max: 500 })
        .withMessage('La dirección debe tener entre 5 y 500 caracteres'),
    
    body('items').isArray({ min: 1 }).withMessage('El carrito no puede estar vacío'),
    
    body('items.*.id').isNumeric().withMessage('ID de producto inválido'),
    body('items.*.qty').isInt({ min: 1, max: 99 })
        .withMessage('Cantidad inválida'),
    
    body('total').isFloat({ min: 0.01 })
        .withMessage('Total inválido'),
    
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
            });
        }
        next();
    }
];

// 9. VALIDACIÓN DE ARCHIVOS SUBIDOS
export const validateFileUpload = (req, res, next) => {
    if (!req.file) {
        return next();
    }

    const file = req.file;
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg'];

    if (!allowedMimeTypes.includes(file.mimetype)) {
        return res.status(400).json({ 
            success: false, 
            error: 'Tipo de archivo no permitido. Solo imágenes JPG, PNG, WEBP, GIF, SVG' 
        });
    }

    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
        return res.status(400).json({ 
            success: false, 
            error: 'Extensión de archivo no permitida' 
        });
    }

    if (file.size > 5 * 1024 * 1024) {
        return res.status(400).json({ 
            success: false, 
            error: 'El archivo excede el límite de 5MB' 
        });
    }

    const header = file.buffer.toString('hex', 0, 4);
    const imageSignatures = {
        'ffd8': 'jpeg',
        '89504e47': 'png',
        '47494638': 'gif',
        '52494646': 'webp',
        '3c3f786d': 'svg',
        '3c737667': 'svg'
    };

    let isValidImage = false;
    for (const [sig, type] of Object.entries(imageSignatures)) {
        if (header.startsWith(sig)) {
            isValidImage = true;
            break;
        }
    }

    if (!isValidImage) {
        return res.status(400).json({ 
            success: false, 
            error: 'El archivo no parece ser una imagen válida' 
        });
    }

    file.originalname = file.originalname
        .replace(/[^a-zA-Z0-9.\-]/g, '_')
        .slice(0, 100);

    next();
};

// 10. TOKEN CSRF
let csrfTokens = new Map();

export const generateCsrfToken = (req, res, next) => {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000;
    csrfTokens.set(token, { expires, ip: req.ip });
    req.csrfToken = token;
    res.cookie('XSRF-TOKEN', token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    next();
};

export const validateCsrfToken = (req, res, next) => {
    const token = req.headers['x-xsrf-token'] || req.body._csrf;
    if (!token) {
        return res.status(403).json({ error: 'Token CSRF requerido' });
    }

    const stored = csrfTokens.get(token);
    if (!stored) {
        return res.status(403).json({ error: 'Token CSRF inválido' });
    }

    if (stored.expires < Date.now()) {
        csrfTokens.delete(token);
        return res.status(403).json({ error: 'Token CSRF expirado' });
    }

    if (csrfTokens.size > 100) {
        const now = Date.now();
        for (const [key, value] of csrfTokens) {
            if (value.expires < now) csrfTokens.delete(key);
        }
    }

    next();
};

// 11. LOG DE SEGURIDAD
export const securityLog = (req, message, level = 'info') => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        method: req.method,
        path: req.path,
        level,
        message,
        userAgent: req.get('user-agent')
    };
    console.log(`[SECURITY] ${JSON.stringify(logEntry)}`);
};

// 12. FILTRO DE SQL INJECTION (EXCLUYE PASSWORD)
export const sqlInjectionFilter = (req, res, next) => {
    // Excluir login de la verificación SQL
    if (req.path === '/api/admin/login') {
        return next();
    }
    
    const dangerous = ['SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'EXEC', 'UNION', ';--', '/*', '*/'];
    const checkValue = (value) => {
        if (typeof value === 'string') {
            const upper = value.toUpperCase();
            for (const term of dangerous) {
                if (upper.includes(term)) return true;
            }
        }
        return false;
    };

    const checkObject = (obj) => {
        if (!obj || typeof obj !== 'object') return false;
        for (const [key, value] of Object.entries(obj)) {
            // EXCLUIR password de la verificación SQL
            if (key === 'password' || key === 'contraseña') continue;
            if (checkValue(key) || checkValue(value)) return true;
            if (typeof value === 'object' && value !== null) {
                if (checkObject(value)) return true;
            }
        }
        return false;
    };

    if (checkObject(req.body) || checkObject(req.query) || checkObject(req.params)) {
        securityLog(req, 'Posible inyección SQL detectada', 'error');
        return res.status(403).json({ error: 'Solicitud bloqueada por razones de seguridad' });
    }

    next();
};

// 13. PROTECCIÓN CONTRA ATAQUES DE FUERZA BRUTA
export const bruteForceProtection = {
    attempts: new Map(),
    maxAttempts: 5,
    blockTime: 300000,

    check: (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const record = bruteForceProtection.attempts.get(ip);

        if (record) {
            if (record.blocked && record.blockedUntil > now) {
                securityLog(req, `IP ${ip} bloqueada por múltiples intentos fallidos`, 'error');
                return res.status(429).json({ 
                    error: 'Demasiados intentos. Espera 5 minutos antes de intentar nuevamente.' 
                });
            }
            if (record.blocked && record.blockedUntil <= now) {
                bruteForceProtection.attempts.delete(ip);
            }
        }

        next();
    },

    recordAttempt: (ip, success) => {
        const record = bruteForceProtection.attempts.get(ip) || { attempts: 0, blocked: false, blockedUntil: 0 };
        
        if (success) {
            bruteForceProtection.attempts.delete(ip);
            return;
        }

        record.attempts += 1;
        if (record.attempts >= bruteForceProtection.maxAttempts) {
            record.blocked = true;
            record.blockedUntil = Date.now() + bruteForceProtection.blockTime;
            record.attempts = 0;
        }
        bruteForceProtection.attempts.set(ip, record);
    }
};