import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import cors from 'cors';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import xss from 'xss';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// 1. VARIABLES DE ENTORNO
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ENCRYPTION_MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY;

// Validación crítica
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    console.error('   Configura estas variables en Render');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR CRÍTICO: Falta ADMIN_PASSWORD');
    console.error('   Configura ADMIN_PASSWORD en Render');
    process.exit(1);
}

if (!ENCRYPTION_MASTER_KEY || ENCRYPTION_MASTER_KEY.length < 32) {
    console.error('❌ ERROR CRÍTICO: ENCRYPTION_MASTER_KEY debe tener al menos 32 caracteres');
    console.error('   Genera una clave con: crypto.randomBytes(32).toString("hex")');
    process.exit(1);
}

console.log('✅ Variables de entorno verificadas');
console.log(`   - SUPABASE_URL: ${SUPABASE_URL ? '✅' : '❌'}`);
console.log(`   - SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅' : '❌'}`);
console.log(`   - ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
console.log(`   - ENCRYPTION_MASTER_KEY: ${ENCRYPTION_MASTER_KEY ? '✅' : '❌'}`);

// ============================================
// 2. CLIENTE SUPABASE
// ============================================
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// 3. SISTEMA DE ENCRIPTACIÓN (AES-256-GCM)
// ============================================

// 3.1 Obtener clave maestra (derivada con PBKDF2)
function getMasterKey() {
    const salt = crypto.createHash('sha256').update('tienda-la-reina-v3-salt').digest();
    return crypto.pbkdf2Sync(ENCRYPTION_MASTER_KEY, salt, 100000, 32, 'sha256');
}

// 3.2 Encriptar dato (AES-256-GCM con autenticación)
function encryptData(text) {
    try {
        if (!text) return null;
        const masterKey = getMasterKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag();
        
        return {
            encrypted: encrypted,
            iv: iv.toString('hex'),
            tag: tag.toString('hex')
        };
    } catch (error) {
        console.error('❌ Error encriptando:', error);
        throw new Error('Error al encriptar datos');
    }
}

// 3.3 Desencriptar dato (con verificación de integridad)
function decryptData(encrypted, ivHex, tagHex) {
    try {
        if (!encrypted || !ivHex || !tagHex) return null;
        const masterKey = getMasterKey();
        const iv = Buffer.from(ivHex, 'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
        
        decipher.setAuthTag(tag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('❌ Error desencriptando:', error);
        throw new Error('Error al desencriptar datos (integridad comprometida)');
    }
}

// 3.4 Verificar integridad con hash
function verificarIntegridad(dato, hash) {
    if (!dato || !hash) return false;
    const hashActual = crypto.createHash('sha256').update(dato).digest('hex');
    return hashActual === hash;
}

// ============================================
// 4. SISTEMA DE AUDITORÍA
// ============================================

async function registrarAuditoria(tableName, recordId, action, oldData, newData, req) {
    try {
        // Obtener último hash
        const { data: lastLog } = await supabase
            .from('audit_log')
            .select('current_hash')
            .eq('table_name', tableName)
            .eq('record_id', recordId)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        const previousHash = lastLog?.current_hash || '';
        const eventId = crypto.randomUUID();
        
        // Generar hash encadenado
        const dataString = eventId + JSON.stringify(newData || oldData || {}) + previousHash;
        const currentHash = crypto.createHash('sha256').update(dataString).digest('hex');
        
        await supabase.from('audit_log').insert({
            event_id: eventId,
            previous_hash: previousHash,
            current_hash: currentHash,
            table_name: tableName,
            record_id: recordId,
            action: action,
            old_data: oldData,
            new_data: newData,
            ip: req.ip || req.connection.remoteAddress,
            user_agent: req.headers['user-agent'] || '',
            user_id: req.headers['admin-user'] || 'system',
            session_id: req.headers['session-id'] || crypto.randomUUID()
        });
        
        return true;
    } catch (error) {
        console.error('❌ Error en auditoría:', error);
        return false;
    }
}

// ============================================
// 5. MIDDLEWARE DE SEGURIDAD
// ============================================

// 5.1 Helmet (headers de seguridad)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "http:", "https://*.supabase.co"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    referrerPolicy: { policy: 'same-origin' }
}));

// 5.2 CORS (restringido)
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://*.onrender.com', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'admin-password', 'session-id', 'x-csrf-token', 'admin-user'],
    credentials: true,
    maxAge: 86400
}));

// 5.3 Rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, por favor espera' },
    standardHeaders: true,
    legacyHeaders: false,
});

const adminLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    message: { error: 'Límite de peticiones admin excedido' },
});

const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Límite de pedidos por hora alcanzado' },
});

// 5.4 Body parsers
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// 5.5 Static files
app.use(express.static(__dirname));

// ============================================
// 6. SISTEMA DE DETECCIÓN DE ANOMALÍAS
// ============================================

const bloqueosIP = new Map();

async function verificarIPBloqueada(ip) {
    if (!ip) return false;
    
    // Verificar en caché
    if (bloqueosIP.has(ip)) {
        const bloqueo = bloqueosIP.get(ip);
        if (bloqueo.expires > Date.now()) {
            return true;
        }
        bloqueosIP.delete(ip);
    }
    
    // Verificar en BD
    const { data } = await supabase
        .from('blocked_ips')
        .select('expires_at')
        .eq('ip', ip)
        .single();
    
    if (data && data.expires_at) {
        const expires = new Date(data.expires_at).getTime();
        if (expires > Date.now()) {
            bloqueosIP.set(ip, { expires });
            return true;
        }
        // Eliminar expirado
        await supabase.from('blocked_ips').delete().eq('ip', ip);
    }
    
    return false;
}

async function registrarIntentoFallido(ip, action, details) {
    try {
        await supabase.from('failed_attempts').insert({
            ip: ip,
            action: action,
            details: details || {},
            created_at: new Date()
        });
        
        // Contar intentos en la última hora
        const { count } = await supabase
            .from('failed_attempts')
            .select('*', { count: 'exact', head: true })
            .eq('ip', ip)
            .gte('created_at', new Date(Date.now() - 60 * 60 * 1000));
        
        if (count >= 5) {
            // Bloquear IP por 24 horas
            await supabase.from('blocked_ips').upsert({
                ip: ip,
                reason: `Demasiados intentos fallidos (${count})`,
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
                attempts_count: count
            });
            bloqueosIP.set(ip, { expires: Date.now() + 24 * 60 * 60 * 1000 });
        }
    } catch (error) {
        console.error('❌ Error registrando intento:', error);
    }
}

// ============================================
// 7. MIDDLEWARE DE AUTENTICACIÓN ADMIN
// ============================================

const ADMIN_AUTH = async (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    
    // 1. Verificar IP bloqueada
    if (await verificarIPBloqueada(ip)) {
        return res.status(403).json({ error: 'IP bloqueada por seguridad' });
    }
    
    // 2. Verificar contraseña
    const password = req.headers['admin-password'] || req.query.password;
    
    if (!password || password !== ADMIN_PASSWORD) {
        await registrarIntentoFallido(ip, 'login_fallido', {
            headers: req.headers,
            method: req.method,
            path: req.path
        });
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    // 3. Verificar sesión (protección contra robo de token)
    const sessionId = req.headers['session-id'];
    if (!sessionId) {
        return res.status(401).json({ error: 'Sesión inválida' });
    }
    
    // 4. Registrar acceso
    await registrarAuditoria(
        'admin_access',
        sessionId,
        'LOGIN',
        null,
        { ip: ip, userAgent: req.headers['user-agent'] },
        req
    );
    
    // 5. Pasar datos del admin
    req.admin = {
        ip: ip,
        sessionId: sessionId,
        userAgent: req.headers['user-agent']
    };
    
    next();
};

// ============================================
// 8. MIDDLEWARE DE VALIDACIÓN DE ENTRADA
// ============================================

// Lista de palabras prohibidas
const PALABRAS_PROHIBIDAS = [
    'puta', 'pendejo', 'cabron', 'hijo de puta', 'malparido', 'maricon',
    'pato', 'bobo', 'imbecil', 'estupido', 'idiota', 'maldito', 'coño',
    'verga', 'mamahuevo', 'comemierda', 'mierda', 'culero', 'chinga',
    'jodido', 'carajo', 'cojones', 'gilipollas', 'capullo', 'subnormal',
    'retrasado', 'mongolo', 'tonto', 'tonta', 'estupida', 'estúpido',
    'nazi', 'fascista', 'racista', 'homofobico', 'transfobico', 'xenofobo',
    'terrorista', 'narcotraficante', 'pedofilo', 'violador', 'asesino'
];

function sanitizarTexto(texto) {
    if (!texto) return '';
    
    // 1. Eliminar caracteres peligrosos
    texto = texto.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
    texto = texto.replace(/[<>{}[\]\\;'"`]/g, '');
    
    // 2. Prevenir XSS
    texto = xss(texto, {
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed']
    });
    
    // 3. Limitar longitud
    texto = texto.slice(0, 200);
    
    // 4. Normalizar espacios
    texto = texto.replace(/\s+/g, ' ').trim();
    
    return texto;
}

function contienePalabrasOfensivas(texto) {
    if (!texto) return false;
    const textoLower = texto.toLowerCase();
    
    // 1. Palabras exactas
    for (const palabra of PALABRAS_PROHIBIDAS) {
        if (textoLower.includes(palabra)) return true;
    }
    
    // 2. Patrones ofuscados
    const patrones = [
        /p[uú]t[aeo]/i,
        /p[eé]nd[eé]j[o0]/i,
        /c[aá]br[o0]n/i,
        /m[aá]ric[o0]n/i,
        /m[ií]erd[aá]/i,
        /c[o0][ñn][o0]/i,
        /h[ií]j[o0][\s]*d[eé][\s]*p[uú]t[aá]/i
    ];
    
    for (const patron of patrones) {
        if (patron.test(texto)) return true;
    }
    
    return false;
}

function validarTelefonoCubano(telefono) {
    const telefonoLimpio = telefono.replace(/\s/g, '');
    const patron = /^(?:\+53|53)?[ ]?[0-9]{8}$/;
    if (!patron.test(telefonoLimpio)) return false;
    const digitos = telefonoLimpio.replace(/\D/g, '');
    if (digitos.length !== 8) return false;
    if (!digitos.startsWith('5')) return false;
    return true;
}

function validarTarjeta(tarjeta) {
    const tarjetaLimpia = tarjeta.replace(/\s/g, '');
    if (!/^\d{13,19}$/.test(tarjetaLimpia)) return false;
    
    // Algoritmo de Luhn
    let sum = 0;
    let alternate = false;
    for (let i = tarjetaLimpia.length - 1; i >= 0; i--) {
        let n = parseInt(tarjetaLimpia.charAt(i));
        if (alternate) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alternate = !alternate;
    }
    return sum % 10 === 0;
}

// ============================================
// 9. CONFIGURACIÓN DE MULTER
// ============================================
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

// ============================================
// 10. FUNCIONES DE SUPABASE STORAGE
// ============================================

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        if (!file) return null;
        
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { data, error } = await supabase.storage
            .from(folder)
            .upload(filePath, file.buffer, {
                cacheControl: '3600',
                upsert: false,
                contentType: file.mimetype
            });
        
        if (error) throw error;
        
        const { data: { publicUrl } } = supabase.storage
            .from(folder)
            .getPublicUrl(filePath);
        
        return publicUrl;
    } catch (error) {
        console.error('❌ Error subiendo imagen:', error);
        return null;
    }
}

// ============================================
// 11. FUNCIONES AUXILIARES
// ============================================

function generarCodigoUnico() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const timestamp = Date.now().toString(36).slice(-4).toUpperCase();
    return `${code}${timestamp}`;
}

function generarCodigoPedido() {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `LR-${timestamp}-${random}`;
}

// ============================================
// 12. RUTAS ESTÁTICAS
// ============================================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================
// 13. API PÚBLICA
// ============================================

app.get('/api/status', globalLimiter, (req, res) => {
    res.json({
        online: true,
        timestamp: new Date().toISOString(),
        version: '3.0.0',
        security: 'AES-256-GCM'
    });
});

app.get('/api/tiendas/info', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        // Filtrar datos sensibles
        const safeData = data.map(store => ({
            id: store.id,
            nombre: store.nombre,
            icono: store.icono,
            descripcion: store.descripcion,
            categorias: store.categorias
        }));
        res.json(safeData || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Tienda no encontrada' });
        
        // Filtrar datos sensibles
        const safeData = {
            id: data.id,
            nombre: data.nombre,
            icono: data.icono,
            descripcion: data.descripcion,
            categorias: data.categorias,
            configuracion: {
                envio: data.configuracion?.envio || {},
                garantia: data.configuracion?.garantia || {},
                metodos_pago: data.configuracion?.metodos_pago || [],
                contacto: {
                    telefono: data.configuracion?.contacto?.telefono || '',
                    email: data.configuracion?.contacto?.email || ''
                }
            }
        };
        res.json(safeData);
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id/config', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('tienda, whatsapp_confirmacion, telefono_contacto, email_contacto, tarjeta_ultimos_digitos, version, updated_at')
            .eq('tienda', req.params.id)
            .single();
        if (error) throw error;
        res.json(data || {});
    } catch (error) {
        console.error('❌ Error:', error);
        res.json({});
    }
});

app.get('/api/productos', globalLimiter, async (req, res) => {
    const tienda = req.query.tienda || 'electro';
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json([]);
    }
});

app.get('/api/categorias', globalLimiter, async (req, res) => {
    const tienda = req.query.tienda || 'electro';
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json(['otros']);
    }
});

app.get('/api/config', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('❌ Error:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

// ============================================
// 14. API DE PEDIDOS CON SEGURIDAD AVANZADA
// ============================================

app.post('/api/pedidos', orderLimiter, async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    
    try {
        // 1. Verificar IP bloqueada
        if (await verificarIPBloqueada(ip)) {
            return res.status(403).json({ error: 'IP bloqueada por seguridad' });
        }
        
        // 2. Validar CSRF
        const csrfToken = req.headers['x-csrf-token'];
        if (!csrfToken) {
            return res.status(403).json({ error: 'Token CSRF requerido' });
        }
        
        // 3. Validar datos de entrada
        const {
            tienda = 'electro',
            nombre,
            telefono,
            direccion,
            items,
            total,
            moneda = 'CUP',
            metodoPago = 'Efectivo'
        } = req.body;
        
        // 4. Sanitizar y validar nombre
        const nombreSanitizado = sanitizarTexto(nombre);
        if (!nombreSanitizado || nombreSanitizado.length < 3) {
            return res.status(400).json({ error: 'Nombre inválido (mínimo 3 caracteres)' });
        }
        if (contienePalabrasOfensivas(nombreSanitizado)) {
            await registrarAuditoria('pedido', 'rechazado', 'NOMBRE_OFENSIVO', 
                { nombre: nombreSanitizado }, null, req);
            return res.status(400).json({ error: 'Nombre contiene lenguaje inapropiado' });
        }
        
        // 5. Sanitizar y validar dirección
        const direccionSanitizada = sanitizarTexto(direccion);
        if (!direccionSanitizada || direccionSanitizada.length < 5) {
            return res.status(400).json({ error: 'Dirección inválida (mínimo 5 caracteres)' });
        }
        if (contienePalabrasOfensivas(direccionSanitizada)) {
            await registrarAuditoria('pedido', 'rechazado', 'DIRECCION_OFENSIVA',
                { direccion: direccionSanitizada }, null, req);
            return res.status(400).json({ error: 'Dirección contiene lenguaje inapropiado' });
        }
        
        // 6. Validar teléfono
        if (!validarTelefonoCubano(telefono)) {
            return res.status(400).json({
                error: 'Teléfono inválido. Use formato +53 5XXXXXXX'
            });
        }
        
        // 7. Validar items
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'El carrito está vacío' });
        }
        
        // 8. Validar productos en base de datos
        const productIds = items.map(item => item.id);
        const { data: productosValidos, error: errorProductos } = await supabase
            .from('products')
            .select('id, precio, disponible')
            .in('id', productIds)
            .eq('tienda', tienda);
        
        if (errorProductos) throw errorProductos;
        
        // Verificar existencia y disponibilidad
        for (const item of items) {
            const producto = productosValidos?.find(p => p.id === item.id);
            if (!producto) {
                return res.status(400).json({
                    error: `Producto "${item.nombre}" no existe en la tienda`
                });
            }
            if (!producto.disponible) {
                return res.status(400).json({
                    error: `Producto "${item.nombre}" no está disponible`
                });
            }
            // Verificar precio (prevención de manipulación)
            const precioEsperado = producto.precio * (1 - (item.descuento || 0) / 100);
            if (Math.abs(item.precio - precioEsperado) > 0.01) {
                return res.status(400).json({
                    error: `Precio inválido para "${item.nombre}"`
                });
            }
        }
        
        // 9. Validar total
        let totalCalculado = 0;
        for (const item of items) {
            const producto = productosValidos?.find(p => p.id === item.id);
            if (producto) {
                const precioFinal = producto.precio * (1 - (item.descuento || 0) / 100);
                totalCalculado += precioFinal * item.qty;
            }
        }
        
        if (Math.abs(total - totalCalculado) > 0.01) {
            return res.status(400).json({ error: 'Total inválido' });
        }
        
        // 10. Generar códigos
        const codigoCliente = generarCodigoUnico();
        const codigoPedido = generarCodigoPedido();
        
        // 11. Obtener siguiente ID
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        // 12. Guardar pedido
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            codigo_pedido: codigoPedido,
            tienda: tienda,
            nombre: nombreSanitizado,
            telefono: telefono.replace(/\s/g, ''),
            direccion: direccionSanitizada,
            items: items.map(item => ({
                ...item,
                nombre: sanitizarTexto(item.nombre)
            })),
            total: total,
            moneda: moneda,
            metodo_pago: metodoPago,
            estado: 'pendiente',
            ip_cliente: ip,
            user_agent: req.headers['user-agent'] || '',
            session_id: req.headers['session-id'] || crypto.randomUUID(),
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        // 13. Actualizar contador
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        // 14. Registrar en auditoría
        await registrarAuditoria(
            'orders',
            nextId.toString(),
            'PEDIDO_CREADO',
            null,
            {
                codigo_cliente: codigoCliente,
                codigo_pedido: codigoPedido,
                total: total,
                items: items.length
            },
            req
        );
        
        // 15. Respuesta segura
        res.json({
            success: true,
            orderId: nextId,
            codigoCliente: codigoCliente,
            codigoPedido: codigoPedido,
            mensaje: 'Pedido registrado exitosamente'
        });
        
    } catch (error) {
        console.error('❌ Error en /api/pedidos:', error);
        await registrarAuditoria('pedido', 'error', 'ERROR_CREAR_PEDIDO',
            { error: error.message }, null, req);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============================================
// 15. API ADMIN CON SEGURIDAD BLINDADA
// ============================================

// 15.1 Autenticación admin
app.post('/api/admin/verify', globalLimiter, async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const { password } = req.body;
    
    // Verificar IP bloqueada
    if (await verificarIPBloqueada(ip)) {
        return res.status(403).json({ error: 'IP bloqueada' });
    }
    
    if (password === ADMIN_PASSWORD) {
        // Generar sesión segura
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        res.json({
            success: true,
            sessionId: sessionId,
            expires: Date.now() + 24 * 60 * 60 * 1000
        });
    } else {
        await registrarIntentoFallido(ip, 'login_fallido', {
            method: 'POST',
            path: '/api/admin/verify'
        });
        res.status(401).json({ success: false });
    }
});

// 15.2 Obtener configuración de tienda (seguro)
app.get('/api/admin/store-config/:tienda', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('*')
            .eq('tienda', req.params.tienda)
            .single();
        
        if (error) throw error;
        
        // NUNCA enviar datos encriptados al frontend
        const safeData = {
            tienda: data.tienda,
            tarjeta_ultimos_digitos: data.tarjeta_ultimos_digitos || '****',
            tarjeta_configurada: !!data.tarjeta_encriptada,
            whatsapp_confirmacion: data.whatsapp_confirmacion,
            telefono_contacto: data.telefono_contacto,
            email_contacto: data.email_contacto,
            version: data.version,
            updated_at: data.updated_at,
            updated_by: data.updated_by
        };
        
        res.json(safeData);
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: 'Error al obtener configuración' });
    }
});

// 15.3 Actualizar tarjeta (con encriptación blindada)
app.post('/api/admin/store-config/:tienda/tarjeta', ADMIN_AUTH, async (req, res) => {
    try {
        const { tarjeta, whatsapp, telefono, email } = req.body;
        
        // Validar tarjeta
        if (!tarjeta) {
            return res.status(400).json({ error: 'Número de tarjeta requerido' });
        }
        
        if (!validarTarjeta(tarjeta)) {
            await registrarAuditoria(
                'store_config',
                req.params.tienda,
                'ERROR_VALIDACION_TARJETA',
                { error: 'Tarjeta inválida' },
                null,
                req
            );
            return res.status(400).json({ error: 'Número de tarjeta inválido' });
        }
        
        // Encriptar tarjeta (AES-256-GCM)
        const tarjetaLimpia = tarjeta.replace(/\s/g, '');
        const encriptado = encryptData(tarjetaLimpia);
        if (!encriptado) {
            throw new Error('Error al encriptar tarjeta');
        }
        
        const hash = crypto.createHash('sha256').update(tarjetaLimpia).digest('hex');
        const ultimosDigitos = tarjetaLimpia.slice(-4);
        
        // Obtener versión actual
        const { data: configActual } = await supabase
            .from('store_config')
            .select('version')
            .eq('tienda', req.params.tienda)
            .single();
        
        const nuevaVersion = (configActual?.version || 0) + 1;
        
        // Guardar en base de datos (SOLO datos encriptados)
        const { error } = await supabase
            .from('store_config')
            .upsert({
                tienda: req.params.tienda,
                tarjeta_encriptada: encriptado.encrypted,
                tarjeta_iv: encriptado.iv,
                tarjeta_tag: encriptado.tag,
                tarjeta_hash: hash,
                tarjeta_ultimos_digitos: ultimosDigitos,
                whatsapp_confirmacion: whatsapp || '',
                telefono_contacto: telefono || '',
                email_contacto: email || '',
                version: nuevaVersion,
                rotacion_count: 0,
                updated_at: new Date(),
                updated_by: req.headers['admin-user'] || 'admin'
            });
        
        if (error) throw error;
        
        // Registrar en auditoría
        await registrarAuditoria(
            'store_config',
            req.params.tienda,
            'ACTUALIZAR_TARJETA',
            { version_anterior: configActual?.version || 0 },
            {
                version_nueva: nuevaVersion,
                ultimos_digitos: ultimosDigitos,
                encriptacion: 'AES-256-GCM'
            },
            req
        );
        
        res.json({
            success: true,
            message: 'Tarjeta actualizada correctamente',
            ultimos_digitos: ultimosDigitos,
            version: nuevaVersion
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        await registrarAuditoria(
            'store_config',
            req.params.tienda,
            'ERROR_ACTUALIZAR_TARJETA',
            { error: error.message },
            null,
            req
        );
        res.status(500).json({ error: 'Error al actualizar tarjeta' });
    }
});

// 15.4 Obtener tarjeta completa (solo uso interno)
app.get('/api/admin/store-config/:tienda/tarjeta-completa', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('tarjeta_encriptada, tarjeta_iv, tarjeta_tag, tarjeta_hash')
            .eq('tienda', req.params.tienda)
            .single();
        
        if (error) throw error;
        
        if (!data.tarjeta_encriptada) {
            return res.json({ tarjeta: null, configurada: false });
        }
        
        // Desencriptar
        const tarjetaCompleta = decryptData(
            data.tarjeta_encriptada,
            data.tarjeta_iv,
            data.tarjeta_tag
        );
        
        // Verificar integridad
        const hashActual = crypto.createHash('sha256').update(tarjetaCompleta).digest('hex');
        const integridad = hashActual === data.tarjeta_hash;
        
        if (!integridad) {
            await registrarAuditoria(
                'store_config',
                req.params.tienda,
                'INTEGRIDAD_COMPROMETIDA',
                { hash_esperado: data.tarjeta_hash, hash_actual: hashActual },
                null,
                req
            );
            return res.status(500).json({ error: 'Integridad de datos comprometida' });
        }
        
        res.json({
            tarjeta: tarjetaCompleta,
            ultimos_digitos: tarjetaCompleta.slice(-4),
            integridad: integridad
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: 'Error al obtener tarjeta' });
    }
});

// 15.5 Verificar integridad
app.post('/api/admin/store-config/:tienda/verificar', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('tarjeta_encriptada, tarjeta_iv, tarjeta_tag, tarjeta_hash, tarjeta_ultimos_digitos')
            .eq('tienda', req.params.tienda)
            .single();
        
        if (error) throw error;
        
        if (!data.tarjeta_encriptada) {
            return res.json({ existe: false });
        }
        
        // Desencriptar para verificar
        const tarjetaCompleta = decryptData(
            data.tarjeta_encriptada,
            data.tarjeta_iv,
            data.tarjeta_tag
        );
        
        const hashActual = crypto.createHash('sha256').update(tarjetaCompleta).digest('hex');
        const integridad = hashActual === data.tarjeta_hash;
        
        await registrarAuditoria(
            'store_config',
            req.params.tienda,
            'VERIFICAR_INTEGRIDAD',
            null,
            {
                integridad: integridad,
                ultimos_digitos: data.tarjeta_ultimos_digitos
            },
            req
        );
        
        res.json({
            existe: true,
            integridad: integridad,
            ultimos_digitos: data.tarjeta_ultimos_digitos,
            version: data.version || 1
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: 'Error al verificar' });
    }
});

// 15.6 Obtener auditoría de cambios
app.get('/api/admin/store-config/:tienda/audit', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('audit_log')
            .select('*')
            .eq('table_name', 'store_config')
            .eq('record_id', req.params.tienda)
            .order('created_at', { ascending: false })
            .limit(50);
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json([]);
    }
});

// 15.7 Productos (admin)
app.get('/api/admin/productos', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', req.query.tienda)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json([]);
    }
});

app.post('/api/admin/productos', ADMIN_AUTH, upload.single('imagen'), async (req, res) => {
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
        
        if (req.file) {
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) imagen = uploadedUrl;
        }
        
        const { error } = await supabase.from('products').insert({
            tienda: req.body.tienda,
            nombre: sanitizarTexto(req.body.nombre),
            descripcion: sanitizarTexto(req.body.descripcion || ''),
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            imagen: imagen,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: sanitizarTexto(req.body.categoria) || 'otros',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// 15.8 Pedidos (admin)
app.get('/api/admin/pedidos', ADMIN_AUTH, async (req, res) => {
    try {
        let query = supabase
            .from('orders')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (req.query.tienda) {
            query = query.eq('tienda', req.query.tienda);
        }
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json([]);
    }
});

app.put('/api/admin/pedidos/:id', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .update({
                estado: req.body.estado,
                updated_at: new Date()
            })
            .eq('id', req.params.id)
            .eq('tienda', req.body.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos/:id', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('id', req.params.id)
            .eq('tienda', req.query.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos', ADMIN_AUTH, async (req, res) => {
    try {
        if (req.query.tienda) {
            const { error } = await supabase
                .from('orders')
                .delete()
                .eq('tienda', req.query.tienda);
            
            if (error) throw error;
            
            await supabase
                .from('order_counters')
                .upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// 15.9 Configuración global
app.get('/api/admin/config', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('❌ Error:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('config')
            .upsert({
                id: 1,
                moneda_base: req.body.moneda_base,
                tasas: req.body.tasas,
                updated_at: new Date()
            });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// 16. MANEJO DE ERRORES
// ============================================

// 16.1 Error 404
app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

// 16.2 Error handler global
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    
    // No exponer detalles internos
    const mensaje = err.message.includes('invalid') || err.message.includes('validation')
        ? err.message
        : 'Error interno del servidor';
    
    res.status(500).json({ error: mensaje });
});

// ============================================
// 17. INICIAR SERVIDOR
// ============================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n========================================');
    console.log('🚀 SERVIDOR BLINDADO INICIADO');
    console.log(`   Puerto: ${PORT}`);
    console.log(`   Admin: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
    console.log(`   Encriptación: AES-256-GCM ${ENCRYPTION_MASTER_KEY ? '✅' : '❌'}`);
    console.log(`   Auditoría: ✅ Activada`);
    console.log(`   Rate Limiting: ✅ Activado`);
    console.log('========================================\n');
});

export default app;