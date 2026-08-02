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

// Validación de variables
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR: Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR: Falta ADMIN_PASSWORD');
    process.exit(1);
}

if (!ENCRYPTION_MASTER_KEY || ENCRYPTION_MASTER_KEY.length < 32) {
    console.error('❌ ERROR: ENCRYPTION_MASTER_KEY debe tener al menos 32 caracteres');
    process.exit(1);
}

console.log('✅ Variables de entorno verificadas');

// ============================================
// 2. CLIENTE SUPABASE
// ============================================
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// 3. SISTEMA DE ENCRIPTACIÓN
// ============================================
function getMasterKey() {
    const salt = crypto.createHash('sha256').update('tienda-la-reina-v3').digest();
    return crypto.pbkdf2Sync(ENCRYPTION_MASTER_KEY, salt, 100000, 32, 'sha256');
}

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
        throw new Error('Error al desencriptar datos');
    }
}

// ============================================
// 4. MIDDLEWARE DE SEGURIDAD
// ============================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "https://*.supabase.co"],
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

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://*.onrender.com', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'admin-password', 'session-id', 'x-csrf-token'],
    credentials: true
}));

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, por favor espera' }
});

const adminLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    message: { error: 'Límite de peticiones admin excedido' }
});

const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Límite de pedidos por hora alcanzado' }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(__dirname));

// ============================================
// 5. MIDDLEWARE DE AUTENTICACIÓN ADMIN
// ============================================

const ADMIN_AUTH = async (req, res, next) => {
    const password = req.headers['admin-password'] || req.query.password;
    
    if (!password || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    const sessionId = req.headers['session-id'];
    if (!sessionId) {
        return res.status(401).json({ error: 'Sesión inválida' });
    }
    
    req.admin = {
        sessionId: sessionId,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent']
    };
    
    next();
};

// ============================================
// 6. FUNCIONES DE VALIDACIÓN
// ============================================

const PALABRAS_PROHIBIDAS = [
    'puta', 'pendejo', 'cabron', 'hijo de puta', 'malparido', 'maricon',
    'pato', 'bobo', 'imbecil', 'estupido', 'idiota', 'maldito', 'coño',
    'verga', 'mamahuevo', 'comemierda', 'mierda', 'culero', 'chinga',
    'jodido', 'carajo', 'cojones', 'gilipollas', 'capullo', 'subnormal',
    'retrasado', 'mongolo', 'tonto', 'tonta', 'estupida', 'estúpido',
    'nazi', 'fascista', 'racista', 'homofobico', 'transfobico', 'xenofobo'
];

function sanitizarTexto(texto) {
    if (!texto) return '';
    texto = texto.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
    texto = texto.replace(/[<>{}[\]\\;'"`]/g, '');
    texto = xss(texto, { stripIgnoreTag: true, stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'] });
    texto = texto.slice(0, 200);
    texto = texto.replace(/\s+/g, ' ').trim();
    return texto;
}

function contienePalabrasOfensivas(texto) {
    if (!texto) return false;
    const textoLower = texto.toLowerCase();
    for (const palabra of PALABRAS_PROHIBIDAS) {
        if (textoLower.includes(palabra)) return true;
    }
    const patrones = [/p[uú]t[aeo]/i, /p[eé]nd[eé]j[o0]/i, /c[aá]br[o0]n/i, /m[aá]ric[o0]n/i];
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
    let sum = 0, alternate = false;
    for (let i = tarjetaLimpia.length - 1; i >= 0; i--) {
        let n = parseInt(tarjetaLimpia.charAt(i));
        if (alternate) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
        alternate = !alternate;
    }
    return sum % 10 === 0;
}

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
// 7. FUNCIONES DE SUPABASE STORAGE
// ============================================
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

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
        const { data: { publicUrl } } = supabase.storage.from(folder).getPublicUrl(filePath);
        return publicUrl;
    } catch (error) {
        console.error('❌ Error subiendo imagen:', error);
        return null;
    }
}

// ============================================
// 8. RUTAS ESTÁTICAS
// ============================================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================
// 9. API PÚBLICA
// ============================================

app.get('/api/status', globalLimiter, (req, res) => {
    res.json({ online: true, timestamp: new Date().toISOString(), version: '3.0.0' });
});

app.get('/api/tiendas/info', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
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

// ✅ RUTA PÚBLICA - DEVUELVE EL NÚMERO COMPLETO DE TARJETA
app.get('/api/tiendas/:id/tarjeta-completa', globalLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('tarjeta_encriptada, tarjeta_iv, tarjeta_tag, tarjeta_ultimos_digitos')
            .eq('tienda', req.params.id)
            .single();

        if (error) {
            // Si no hay configuración, devolver null
            return res.json({ 
                tarjeta: null, 
                configurada: false,
                ultimos_digitos: null,
                mensaje: 'No hay tarjeta configurada'
            });
        }

        if (!data.tarjeta_encriptada) {
            return res.json({ 
                tarjeta: null, 
                configurada: false,
                ultimos_digitos: null,
                mensaje: 'No hay tarjeta configurada'
            });
        }

        // Desencriptar el número completo
        const tarjetaCompleta = decryptData(
            data.tarjeta_encriptada,
            data.tarjeta_iv,
            data.tarjeta_tag
        );

        // ✅ DEVOLVER EL NÚMERO COMPLETO PARA EL CLIENTE
        res.json({
            tarjeta: tarjetaCompleta,
            configurada: true,
            ultimos_digitos: data.tarjeta_ultimos_digitos || tarjetaCompleta.slice(-4),
            mensaje: 'Número de tarjeta disponible'
        });

    } catch (error) {
        console.error('❌ Error en /api/tiendas/:id/tarjeta-completa:', error);
        res.status(500).json({ 
            error: 'Error al obtener tarjeta',
            tarjeta: null,
            configurada: false
        });
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
        const safeData = {
            tienda: data?.tienda || req.params.id,
            whatsapp_confirmacion: data?.whatsapp_confirmacion || '',
            telefono_contacto: data?.telefono_contacto || '',
            email_contacto: data?.email_contacto || '',
            tarjeta_ultimos_digitos: data?.tarjeta_ultimos_digitos || null,
            tarjeta_configurada: !!data?.tarjeta_ultimos_digitos,
            version: data?.version || 1,
            updated_at: data?.updated_at || null
        };
        res.json(safeData);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json({ tienda: req.params.id, tarjeta_configurada: false });
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
// 10. API DE PEDIDOS
// ============================================

app.post('/api/pedidos', orderLimiter, async (req, res) => {
    try {
        const { tienda = 'electro', nombre, telefono, direccion, items, total, moneda = 'CUP', metodoPago = 'Efectivo' } = req.body;
        
        const nombreSanitizado = sanitizarTexto(nombre);
        if (!nombreSanitizado || nombreSanitizado.length < 3) {
            return res.status(400).json({ error: 'Nombre inválido (mínimo 3 caracteres)' });
        }
        if (contienePalabrasOfensivas(nombreSanitizado)) {
            return res.status(400).json({ error: 'Nombre contiene lenguaje inapropiado' });
        }
        
        const direccionSanitizada = sanitizarTexto(direccion);
        if (!direccionSanitizada || direccionSanitizada.length < 5) {
            return res.status(400).json({ error: 'Dirección inválida (mínimo 5 caracteres)' });
        }
        if (contienePalabrasOfensivas(direccionSanitizada)) {
            return res.status(400).json({ error: 'Dirección contiene lenguaje inapropiado' });
        }
        
        if (!validarTelefonoCubano(telefono)) {
            return res.status(400).json({ error: 'Teléfono inválido. Use formato +53 5XXXXXXX' });
        }
        
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'El carrito está vacío' });
        }
        
        const productIds = items.map(item => item.id);
        const { data: productosValidos, error: errorProductos } = await supabase
            .from('products')
            .select('id, precio, disponible')
            .in('id', productIds)
            .eq('tienda', tienda);
        
        if (errorProductos) throw errorProductos;
        
        let totalCalculado = 0;
        for (const item of items) {
            const producto = productosValidos?.find(p => p.id === item.id);
            if (!producto) {
                return res.status(400).json({ error: `Producto "${item.nombre}" no existe` });
            }
            if (!producto.disponible) {
                return res.status(400).json({ error: `Producto "${item.nombre}" no disponible` });
            }
            const precioEsperado = producto.precio * (1 - (item.descuento || 0) / 100);
            if (Math.abs(item.precio - precioEsperado) > 0.01) {
                return res.status(400).json({ error: `Precio inválido para "${item.nombre}"` });
            }
            totalCalculado += precioEsperado * item.qty;
        }
        
        if (Math.abs(total - totalCalculado) > 0.01) {
            return res.status(400).json({ error: 'Total inválido' });
        }
        
        const codigoCliente = generarCodigoUnico();
        const codigoPedido = generarCodigoPedido();
        
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            codigo_pedido: codigoPedido,
            tienda: tienda,
            nombre: nombreSanitizado,
            telefono: telefono.replace(/\s/g, ''),
            direccion: direccionSanitizada,
            items: items.map(item => ({ ...item, nombre: sanitizarTexto(item.nombre) })),
            total: total,
            moneda: moneda,
            metodo_pago: metodoPago,
            estado: 'pendiente',
            ip_cliente: req.ip || req.connection.remoteAddress,
            user_agent: req.headers['user-agent'] || '',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        await supabase.from('order_counters').upsert({ tienda: tienda, counter: nextId });
        
        res.json({
            success: true,
            orderId: nextId,
            codigoCliente: codigoCliente,
            codigoPedido: codigoPedido,
            mensaje: 'Pedido registrado exitosamente'
        });
        
    } catch (error) {
        console.error('❌ Error en /api/pedidos:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============================================
// 11. API ADMIN
// ============================================

app.post('/api/admin/verify', globalLimiter, async (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        res.json({ success: true, sessionId: sessionId, expires: Date.now() + 24 * 60 * 60 * 1000 });
    } else {
        res.status(401).json({ success: false });
    }
});

app.get('/api/admin/tiendas', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/tiendas', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').insert({
            id: req.body.id?.toLowerCase().trim(),
            nombre: req.body.nombre?.trim(),
            icono: req.body.icono || '🛒',
            descripcion: req.body.descripcion || '',
            configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros'],
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

app.put('/api/admin/tiendas/:id', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('stores')
            .update({
                nombre: req.body.nombre,
                icono: req.body.icono,
                descripcion: req.body.descripcion,
                configuracion: req.body.configuracion,
                categorias: req.body.categorias,
                updated_at: new Date()
            })
            .eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/tiendas/:id', ADMIN_AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/categorias', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.query.tienda)
            .single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('❌ Error:', error);
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', ADMIN_AUTH, async (req, res) => {
    try {
        const { data: store } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.body.tienda)
            .single();
        const currentCats = store?.categorias || [];
        if (!currentCats.includes(req.body.categoria)) {
            currentCats.push(req.body.categoria);
        }
        const { error } = await supabase
            .from('stores')
            .update({ categorias: currentCats, updated_at: new Date() })
            .eq('id', req.body.tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// 11.1 Productos (admin)
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
        const { error } = await supabase.from('products').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// 11.2 Pedidos (admin)
app.get('/api/admin/pedidos', ADMIN_AUTH, async (req, res) => {
    try {
        let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
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
            .update({ estado: req.body.estado, updated_at: new Date() })
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
            const { error } = await supabase.from('orders').delete().eq('tienda', req.query.tienda);
            if (error) throw error;
            await supabase.from('order_counters').upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// 11.3 Configuración de tienda (admin) - CRUD completo
app.get('/api/admin/store-config/:tienda', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('store_config')
            .select('*')
            .eq('tienda', req.params.tienda)
            .single();

        if (error) {
            // Si no existe, devolver datos vacíos
            return res.json({
                tienda: req.params.tienda,
                tarjeta_ultimos_digitos: '****',
                tarjeta_configurada: false,
                whatsapp_confirmacion: '',
                telefono_contacto: '',
                email_contacto: '',
                version: 0,
                updated_at: null,
                updated_by: null
            });
        }

        const safeData = {
            tienda: data.tienda,
            tarjeta_ultimos_digitos: data.tarjeta_ultimos_digitos || '****',
            tarjeta_configurada: !!data.tarjeta_encriptada,
            whatsapp_confirmacion: data.whatsapp_confirmacion || '',
            telefono_contacto: data.telefono_contacto || '',
            email_contacto: data.email_contacto || '',
            version: data.version || 0,
            updated_at: data.updated_at,
            updated_by: data.updated_by
        };

        res.json(safeData);
    } catch (error) {
        console.error('❌ Error en /api/admin/store-config/:tienda:', error);
        res.status(500).json({ error: 'Error al obtener configuración' });
    }
});

// ✅ GUARDAR TARJETA (admin) - La tarjeta se encripta y se guarda
app.post('/api/admin/store-config/:tienda/tarjeta', ADMIN_AUTH, async (req, res) => {
    try {
        const { tarjeta, whatsapp, telefono, email } = req.body;

        if (!tarjeta) {
            return res.status(400).json({ error: 'Número de tarjeta requerido' });
        }

        if (!validarTarjeta(tarjeta)) {
            return res.status(400).json({ error: 'Número de tarjeta inválido' });
        }

        // Limpiar y encriptar la tarjeta
        const tarjetaLimpia = tarjeta.replace(/\s/g, '');
        const encriptado = encryptData(tarjetaLimpia);
        const hash = crypto.createHash('sha256').update(tarjetaLimpia).digest('hex');
        const ultimosDigitos = tarjetaLimpia.slice(-4);

        // Obtener versión actual
        const { data: configActual } = await supabase
            .from('store_config')
            .select('version')
            .eq('tienda', req.params.tienda)
            .single();

        const nuevaVersion = (configActual?.version || 0) + 1;

        // Guardar en base de datos
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
                updated_at: new Date(),
                updated_by: req.headers['admin-user'] || 'admin'
            });

        if (error) throw error;

        res.json({
            success: true,
            message: 'Tarjeta actualizada correctamente',
            ultimos_digitos: ultimosDigitos,
            version: nuevaVersion
        });

    } catch (error) {
        console.error('❌ Error en /api/admin/store-config/:tienda/tarjeta:', error);
        res.status(500).json({ error: 'Error al actualizar tarjeta' });
    }
});

// 11.4 Configuración global
app.get('/api/admin/config', ADMIN_AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
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
                moneda_base: req.body.moneda_base || 'CUP',
                tasas: req.body.tasas || { CUP: 1, USD: 0.04, EUR: 0.037 },
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
// 12. MANEJO DE ERRORES
// ============================================

app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================
// 13. INICIAR SERVIDOR
// ============================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n========================================');
    console.log('🚀 SERVIDOR INICIADO CORRECTAMENTE');
    console.log(`   Puerto: ${PORT}`);
    console.log(`   Admin: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
    console.log(`   Encriptación: AES-256-GCM ${ENCRYPTION_MASTER_KEY ? '✅' : '❌'}`);
    console.log('========================================');
    console.log('📌 RUTAS DISPONIBLES:');
    console.log('   - /api/tiendas/:id/tarjeta-completa → Número COMPLETO para clientes');
    console.log('   - /api/admin/store-config/:tienda/tarjeta → Solo ADMIN puede modificar');
    console.log('========================================\n');
});

export default app;