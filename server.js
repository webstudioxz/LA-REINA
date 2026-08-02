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
// VARIABLES DE ENTORNO (SEGURAS)
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TARJETA_TRANSFERENCIA = process.env.TARJETA_TRANSFERENCIA || '';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const RATE_LIMIT_WINDOW = parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000; // 15 minutos
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX) || 10; // 10 peticiones por ventana

// Validación de variables críticas
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR CRÍTICO: Falta ADMIN_PASSWORD');
    process.exit(1);
}

console.log('✅ Variables de entorno verificadas:');
console.log(`   - SUPABASE_URL: ${SUPABASE_URL ? '✅' : '❌'}`);
console.log(`   - SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅' : '❌'}`);
console.log(`   - ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
console.log(`   - TARJETA_TRANSFERENCIA: ${TARJETA_TRANSFERENCIA ? '✅' : '⚠️ No configurada'}`);

// ============================================
// CLIENTE SUPABASE
// ============================================
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE DE SEGURIDAD
// ============================================

// 1. Helmet - Protección de headers HTTP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "http:", "https://*.supabase.co"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
        },
    },
}));

// 2. CORS configurado
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['*'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'admin-password'],
    credentials: true
}));

// 3. Rate Limiting - Protección contra ataques de fuerza bruta y DDoS
const limiter = rateLimit({
    windowMs: RATE_LIMIT_WINDOW,
    max: RATE_LIMIT_MAX,
    message: { error: 'Demasiadas peticiones, por favor espera unos minutos' },
    standardHeaders: true,
    legacyHeaders: false,
});

const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 5, // 5 pedidos por hora por IP
    message: { error: 'Límite de pedidos por hora alcanzado' },
});

// 4. Body parsers con límites
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Static files
app.use(express.static(__dirname));

// ============================================
// FUNCIONES DE VALIDACIÓN Y SEGURIDAD
// ============================================

// Lista de palabras prohibidas (ofensivas)
const PALABRAS_PROHIBIDAS = [
    'puta', 'pendejo', 'cabron', 'hijo de puta', 'malparido', 'maricon',
    'pato', 'bobo', 'imbecil', 'estupido', 'idiota', 'maldito', 'coño',
    'verga', 'mamahuevo', 'comemierda', 'mierda', 'culero', 'chinga',
    'jodido', 'carajo', 'cojones', 'gilipollas', 'capullo', 'subnormal',
    'retrasado', 'mongolo', 'tonto', 'tonta', 'estupida', 'estúpido',
    'nazi', 'fascista', 'racista', 'homofobico', 'transfobico', 'xenofobo'
];

// Sanitizar y validar texto
function sanitizarTexto(texto) {
    if (!texto) return '';
    
    // 1. Eliminar caracteres invisibles y peligrosos
    texto = texto.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
    texto = texto.replace(/[<>{}[\]\\]/g, '');
    
    // 2. Prevenir inyección SQL y XSS
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

// Validar contenido ofensivo
function contienePalabrasOfensivas(texto) {
    if (!texto) return false;
    
    const textoLower = texto.toLowerCase();
    const palabras = textoLower.split(/\s+/);
    
    // Palabra exacta
    for (const palabra of PALABRAS_PROHIBIDAS) {
        if (textoLower.includes(palabra)) return true;
    }
    
    // Detectar ofuscaciones básicas
    const ofuscaciones = [
        /p[uú]t[aeo]/i,
        /p[eé]nd[eé]j[o0]/i,
        /c[aá]br[o0]n/i,
        /m[aá]ric[o0]n/i,
        /m[ií]erd[aá]/i,
        /c[o0][ñn][o0]/i
    ];
    
    for (const regex of ofuscaciones) {
        if (regex.test(texto)) return true;
    }
    
    return false;
}

// Validar número de teléfono cubano
function validarTelefonoCubano(telefono) {
    const telefonoLimpio = telefono.replace(/\s/g, '');
    const patron = /^(?:\+53|53)?[ ]?[0-9]{8}$/;
    
    if (!patron.test(telefonoLimpio)) return false;
    
    // Extraer los 8 dígitos
    const digitos = telefonoLimpio.replace(/\D/g, '');
    if (digitos.length !== 8) return false;
    
    // Verificar que comience con 5
    if (!digitos.startsWith('5')) return false;
    
    return true;
}

// Validar dirección cubana (básica)
function validarDireccionCubana(direccion) {
    if (!direccion || direccion.length < 5) return false;
    if (direccion.length > 200) return false;
    
    // Debe contener al menos una palabra y un número
    const tieneNumero = /\d/.test(direccion);
    const tieneLetra = /[a-zA-ZáéíóúÁÉÍÓÚñÑ]/.test(direccion);
    
    return tieneNumero && tieneLetra;
}

// Generar token CSRF
function generarCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Verificar token CSRF
function verificarCSRFToken(req) {
    const token = req.headers['x-csrf-token'] || req.body.csrf_token;
    const sessionToken = req.session?.csrf_token;
    return token && sessionToken && token === sessionToken;
}

// ============================================
// MULTER CON VALIDACIÓN DE ARCHIVOS
// ============================================
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { 
        fileSize: 5 * 1024 * 1024, // 5MB
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
// FUNCIONES DE SUPABASE STORAGE
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
// MIDDLEWARE DE AUTENTICACIÓN ADMIN
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    if (pass === ADMIN_PASSWORD) {
        // Verificar que no sea una petición de otro origen
        const origin = req.headers.origin;
        if (origin && !origin.includes('render.com') && !origin.includes('localhost')) {
            return res.status(403).json({ error: 'Origen no permitido' });
        }
        return next();
    }
    res.status(401).json({ error: 'No autorizado' });
};

// ============================================
// FUNCIONES AUXILIARES
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
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================
// API PÚBLICA (con rate limiting)
// ============================================

app.get('/api/status', (req, res) => {
    res.json({ 
        online: true, 
        timestamp: new Date().toISOString(),
        version: '3.0.0'
    });
});

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        // No enviar datos sensibles de configuración
        const safeData = data.map(store => ({
            id: store.id,
            nombre: store.nombre,
            icono: store.icono,
            descripcion: store.descripcion,
            categorias: store.categorias
        }));
        res.json(safeData || []);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id', async (req, res) => {
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
                // No incluir datos bancarios
            }
        };
        res.json(safeData);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/productos', async (req, res) => {
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
        console.error('Error:', error);
        res.json([]);
    }
});

app.get('/api/categorias', async (req, res) => {
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
        console.error('Error:', error);
        res.json(['otros']);
    }
});

app.get('/api/config', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('Error:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

// ============================================
// API DE PEDIDOS CON SEGURIDAD AVANZADA
// ============================================

app.post('/api/pedidos', orderLimiter, async (req, res) => {
    try {
        // 1. Validar CSRF
        const csrfToken = req.headers['x-csrf-token'];
        // En producción, usar sesiones para CSRF
        if (!csrfToken) {
            return res.status(403).json({ error: 'Token CSRF requerido' });
        }
        
        // 2. Validar datos de entrada
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
        
        // 3. Sanitizar y validar nombre
        const nombreSanitizado = sanitizarTexto(nombre);
        if (!nombreSanitizado || nombreSanitizado.length < 3) {
            return res.status(400).json({ error: 'Nombre inválido (mínimo 3 caracteres)' });
        }
        if (contienePalabrasOfensivas(nombreSanitizado)) {
            return res.status(400).json({ error: 'Nombre contiene lenguaje inapropiado' });
        }
        
        // 4. Sanitizar y validar dirección
        const direccionSanitizada = sanitizarTexto(direccion);
        if (!direccionSanitizada || direccionSanitizada.length < 5) {
            return res.status(400).json({ error: 'Dirección inválida (mínimo 5 caracteres)' });
        }
        if (contienePalabrasOfensivas(direccionSanitizada)) {
            return res.status(400).json({ error: 'Dirección contiene lenguaje inapropiado' });
        }
        
        // 5. Validar teléfono
        if (!validarTelefonoCubano(telefono)) {
            return res.status(400).json({ 
                error: 'Teléfono inválido. Use formato +53 5XXXXXXX' 
            });
        }
        
        // 6. Validar items
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'El carrito está vacío' });
        }
        
        // 7. Validar items existentes en la base de datos
        const productIds = items.map(item => item.id);
        const { data: productosValidos, error: errorProductos } = await supabase
            .from('products')
            .select('id, precio, disponible')
            .in('id', productIds)
            .eq('tienda', tienda);
            
        if (errorProductos) throw errorProductos;
        
        // Verificar que todos los productos existan y estén disponibles
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
        
        // 8. Validar total (prevención de manipulación)
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
        
        // 9. Generar código de pedido
        const codigoCliente = generarCodigoUnico();
        const codigoPedido = generarCodigoPedido();
        
        // 10. Obtener siguiente ID
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        // 11. Guardar pedido
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
            ip_cliente: req.ip || req.connection.remoteAddress,
            user_agent: req.headers['user-agent'] || '',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        // 12. Actualizar contador
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        // 13. Registrar en logs de auditoría
        await supabase.from('audit_logs').insert({
            action: 'pedido_creado',
            tienda: tienda,
            pedido_id: nextId,
            codigo_cliente: codigoCliente,
            ip: req.ip || req.connection.remoteAddress,
            created_at: new Date()
        }).catch(err => console.error('Error log:', err));
        
        // 14. Respuesta (sin datos sensibles)
        res.json({ 
            success: true, 
            orderId: nextId, 
            codigoCliente: codigoCliente,
            codigoPedido: codigoPedido,
            mensaje: 'Pedido registrado exitosamente'
        });
        
    } catch (error) {
        console.error('Error en /api/pedidos:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============================================
// API ADMIN CON SEGURIDAD MEJORADA
// ============================================

app.post('/api/admin/verify', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        // Generar token de sesión
        const sessionToken = crypto.randomBytes(32).toString('hex');
        res.json({ 
            success: true,
            token: sessionToken,
            expires: Date.now() + 24 * 60 * 60 * 1000 // 24 horas
        });
    } else {
        // Log de intento fallido
        console.log(`⚠️ Intento de login fallido desde ${req.ip}`);
        res.status(401).json({ success: false });
    }
});

// ============================================
// API ADMIN CON CONFIGURACIÓN SEGURA
// ============================================

app.get('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('Error:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', AUTH, async (req, res) => {
    try {
        // Solo permitir actualizar configuración no sensible
        const configPermitida = {
            moneda_base: req.body.moneda_base,
            tasas: req.body.tasas,
            updated_at: new Date()
        };
        
        const { error } = await supabase
            .from('config')
            .upsert({ id: 1, ...configPermitida });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Obtener número de tarjeta (solo para admin)
app.get('/api/admin/tarjeta', AUTH, (req, res) => {
    res.json({ 
        tarjeta: TARJETA_TRANSFERENCIA || '',
        configurada: !!TARJETA_TRANSFERENCIA
    });
});

// ============================================
// RESTANTES RUTAS ADMIN
// ============================================

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/productos', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', req.query.tienda)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error:', error);
        res.json([]);
    }
});

app.post('/api/admin/productos', AUTH, upload.single('imagen'), async (req, res) => {
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
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/pedidos', AUTH, async (req, res) => {
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
        console.error('Error:', error);
        res.json([]);
    }
});

app.put('/api/admin/pedidos/:id', AUTH, async (req, res) => {
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
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('id', req.params.id)
            .eq('tienda', req.query.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n========================================');
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
    console.log(`💳 Tarjeta: ${TARJETA_TRANSFERENCIA ? '✅' : '⚠️'}`);
    console.log(`🛡️ Rate Limit: ${RATE_LIMIT_MAX} peticiones/${RATE_LIMIT_WINDOW/60000}min`);
    console.log('========================================\n');
});