import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import hpp from 'hpp';
import xss from 'xss';
import path from 'path';

// ============================================
// MIDDLEWARE DE SEGURIDAD MEJORADO
// ============================================

// 1. HELMET - Configuración más permisiva
export const helmetMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "*.supabase.co", "via.placeholder.com", "i.ibb.co", "d.top4top.io"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "*.supabase.co"],
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
});

// 2. CORS - Configuración mejorada para Render
export const corsMiddleware = cors({
    origin: function(origin, callback) {
        // Permitir solicitudes sin origen (curl, Postman, etc.)
        if (!origin) {
            return callback(null, true);
        }
        
        // Orígenes permitidos desde variables de entorno o por defecto
        const allowedOrigins = process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',') 
            : [
                'https://la-reina-mgje.onrender.com',
                'http://localhost:3000',
                'http://localhost:3001',
                'http://localhost:3002',
                'https://*.onrender.com'
            ];
        
        // Verificar si el origen está permitido
        const isAllowed = allowedOrigins.some(allowed => {
            if (allowed.includes('*')) {
                const pattern = allowed.replace('*', '.*');
                return new RegExp(pattern).test(origin);
            }
            return allowed === origin;
        });
        
        if (isAllowed || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.log(`❌ CORS bloqueado para: ${origin}`);
            callback(null, false);
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'Admin-Password',
        'Accept',
        'Origin',
        'X-Requested-With',
        'X-HTTP-Method-Override',
        'X-Forwarded-For'
    ],
    exposedHeaders: ['Authorization'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 200
});

// 3. RATE LIMITING
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

// 4. HPP
export const hppMiddleware = hpp();

// 5. SANITIZACIÓN DE ENTRADA MEJORADA
export const sanitizeInput = (req, res, next) => {
    // Excluir rutas de login para no interferir con la autenticación
    const excludePaths = ['/api/admin/login', '/api/pedidos'];
    if (excludePaths.some(p => req.path === p)) {
        return next();
    }
    
    const sanitizeObject = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        if (Buffer.isBuffer(obj)) return obj;
        
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            // No sanitizar contraseñas
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
                sanitized[key] = value.map(v => 
                    typeof v === 'string' ? 
                        xss(v.trim()).slice(0, 5000) : 
                        (typeof v === 'object' && v !== null ? sanitizeObject(v) : v)
                );
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    };

    try {
        if (req.body) req.body = sanitizeObject(req.body);
        if (req.query) req.query = sanitizeObject(req.query);
        if (req.params) req.params = sanitizeObject(req.params);
    } catch (error) {
        console.error('Error sanitizando entrada:', error);
    }
    next();
};

// 6. VALIDACIÓN DE INVENTARIO
export const validateInventory = (req, res, next) => {
    const { product_id, variant_name, stock, sku, price_adjustment } = req.body;
    const errors = [];
    
    if (!product_id || isNaN(parseInt(product_id)) || parseInt(product_id) < 1) {
        errors.push({ field: 'product_id', message: 'ID de producto inválido' });
    }
    if (!variant_name || variant_name.trim().length < 1 || variant_name.trim().length > 50) {
        errors.push({ field: 'variant_name', message: 'El nombre de la variante es requerido (1-50 caracteres)' });
    }
    if (stock === undefined || isNaN(parseInt(stock)) || parseInt(stock) < 0) {
        errors.push({ field: 'stock', message: 'El stock debe ser un número positivo' });
    }
    if (price_adjustment !== undefined && isNaN(parseFloat(price_adjustment))) {
        errors.push({ field: 'price_adjustment', message: 'Ajuste de precio inválido' });
    }
    if (sku !== undefined && sku.length > 50) {
        errors.push({ field: 'sku', message: 'SKU muy largo (máximo 50 caracteres)' });
    }
    
    if (errors.length > 0) {
        return res.status(400).json({ success: false, errors });
    }
    next();
};

// 7. VALIDACIÓN DE PRODUCTOS MEJORADA
export const validateProduct = (req, res, next) => {
    const { nombre, precio, descripcion, images, has_variants } = req.body;
    const errors = [];
    
    if (!nombre || nombre.trim().length < 2 || nombre.trim().length > 100) {
        errors.push({ field: 'nombre', message: 'El nombre debe tener entre 2 y 100 caracteres' });
    }
    if (!precio || isNaN(parseFloat(precio)) || parseFloat(precio) < 0.01 || parseFloat(precio) > 999999.99) {
        errors.push({ field: 'precio', message: 'El precio debe ser entre 0.01 y 999,999.99' });
    }
    if (descripcion !== undefined && descripcion.length > 5000) {
        errors.push({ field: 'descripcion', message: 'La descripción no puede exceder 5000 caracteres' });
    }
    if (images !== undefined && !Array.isArray(images) && typeof images !== 'string') {
        errors.push({ field: 'images', message: 'images debe ser un array de URLs o una cadena' });
    }
    if (has_variants !== undefined && typeof has_variants !== 'boolean' && has_variants !== 'true' && has_variants !== 'false') {
        errors.push({ field: 'has_variants', message: 'has_variants debe ser booleano' });
    }
    
    if (errors.length > 0) {
        return res.status(400).json({ success: false, errors });
    }
    next();
};

// 8. FILTRO SQL INJECTION MEJORADO
export const sqlInjectionFilter = (req, res, next) => {
    // Excluir rutas de login y pedidos
    const excludePaths = ['/api/admin/login', '/api/pedidos'];
    if (excludePaths.some(p => req.path === p)) {
        return next();
    }
    
    const dangerous = [
        'SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 
        'EXEC', 'UNION', ';--', '/*', '*/', 'ALTER', 
        'CREATE', 'TRUNCATE', 'MERGE', 'REPLACE'
    ];
    
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
        if (Buffer.isBuffer(obj)) return false;
        
        for (const [key, value] of Object.entries(obj)) {
            if (key === 'password' || key === 'contraseña') continue;
            if (checkValue(key) || checkValue(value)) return true;
            if (typeof value === 'object' && value !== null) {
                if (checkObject(value)) return true;
            }
        }
        return false;
    };

    try {
        if (checkObject(req.body) || checkObject(req.query) || checkObject(req.params)) {
            console.log(`🔴 Posible inyección SQL detectada en ${req.path} desde ${req.ip}`);
            return res.status(403).json({ error: 'Solicitud bloqueada por razones de seguridad' });
        }
    } catch (error) {
        console.error('Error en sqlInjectionFilter:', error);
    }
    next();
};

// 9. PROTECCIÓN CONTRA FUERZA BRUTA
export const bruteForceProtection = {
    attempts: new Map(),
    maxAttempts: 5,
    blockTime: 300000,

    check: (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        const now = Date.now();
        const record = bruteForceProtection.attempts.get(ip);

        if (record) {
            if (record.blocked && record.blockedUntil > now) {
                const waitTime = Math.ceil((record.blockedUntil - now) / 60000);
                return res.status(429).json({ 
                    error: `Demasiados intentos. Espera ${waitTime} minutos antes de intentar nuevamente.` 
                });
            }
            if (record.blocked && record.blockedUntil <= now) {
                bruteForceProtection.attempts.delete(ip);
            }
        }
        next();
    },

    recordAttempt: (ip, success) => {
        if (!ip) return;
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
            console.log(`🔒 IP ${ip} bloqueada por ${bruteForceProtection.blockTime/60000} minutos`);
        }
        bruteForceProtection.attempts.set(ip, record);
    }
};

// 10. VALIDACIÓN DE ARCHIVOS MEJORADA
export const validateFileUpload = (req, res, next) => {
    if (!req.file && (!req.files || req.files.length === 0)) return next();

    const files = req.files || [req.file];
    const errors = [];

    for (const file of files) {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg'];

        if (!allowedMimeTypes.includes(file.mimetype)) {
            errors.push(`Tipo de archivo no permitido: ${file.originalname}. Solo JPG, PNG, WEBP, GIF, SVG`);
            continue;
        }

        const ext = path.extname(file.originalname).toLowerCase();
        if (!allowedExtensions.includes(ext)) {
            errors.push(`Extensión no permitida: ${file.originalname}`);
            continue;
        }

        if (file.size > 5 * 1024 * 1024) {
            errors.push(`Archivo excede 5MB: ${file.originalname}`);
            continue;
        }

        // Verificar firma de imagen
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
        for (const [sig] of Object.entries(imageSignatures)) {
            if (header.startsWith(sig)) {
                isValidImage = true;
                break;
            }
        }

        if (!isValidImage) {
            errors.push(`Archivo no es una imagen válida: ${file.originalname}`);
        }

        // Sanitizar nombre
        file.originalname = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_').slice(0, 100);
    }

    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            errors: errors 
        });
    }
    next();
};

// 11. LOG DE SEGURIDAD
export const securityLog = (req, message, level = 'info') => {
    console.log(`[SECURITY] ${new Date().toISOString()} | ${req.ip} | ${req.method} ${req.path} | ${level} | ${message}`);
};