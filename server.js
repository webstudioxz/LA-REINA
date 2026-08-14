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
// 🔑 CONTRASEÑA ADMIN - FIJA PARA PRUEBAS
// ============================================================

// ⚠️ CONTRASEÑA FIJA: 1988
const ADMIN_PASSWORD = '1988';

console.log('🔐 ========== SEGURIDAD ACTIVADA ==========');
console.log(`🔐 ADMIN_PASSWORD: ${ADMIN_PASSWORD ? `✅ Configurada (${ADMIN_PASSWORD})` : '❌ NO CONFIGURADA'}`);
console.log('🔐 =========================================');

// ============================================================
// SUPABASE
// ============================================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
let supabase = null;

if (supabaseUrl && supabaseKey) {
    try {
        supabase = createClient(supabaseUrl, supabaseKey, {
            auth: { autoRefreshToken: false, persistSession: false }
        });
        console.log('✅ Supabase inicializado');
    } catch (error) {
        console.error('❌ Error inicializando Supabase:', error.message);
    }
} else {
    console.warn('⚠️ Supabase no configurado');
}

// ============================================================
// SESIONES EN MEMORIA
// ============================================================

const sessions = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [key, value] of sessions) {
        if (value.expiry < now) sessions.delete(key);
    }
}, 300000);

// ============================================================
// MIDDLEWARES
// ============================================================

// Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "*.supabase.co", "via.placeholder.com", "d.top4top.io", "i.ibb.co", "images.unsplash.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "*.supabase.co"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        const allowed = ['https://la-reina-mgje.onrender.com', 'https://la-reina.onrender.com', 'http://localhost:3000', 'http://localhost:10000'];
        if (allowed.includes(origin) || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            callback(new Error('Origen no permitido'));
        }
    },
    credentials: true
}));

app.use(hpp());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Rate Limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { success: false, error: 'Demasiadas peticiones.' },
    skip: (req) => req.path === '/api/admin/login'
});
app.use('/api', limiter);

// ============================================================
// RUTAS ESTÁTICAS
// ============================================================

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin.html', (req, res) => {
    res.redirect('/admin');
});

// ============================================================
// SANITIZACIÓN SIMPLE
// ============================================================

app.use((req, res, next) => {
    if (req.path === '/api/admin/login') return next();
    
    const sanitize = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        for (const key of Object.keys(obj)) {
            if (typeof obj[key] === 'string') {
                obj[key] = obj[key].replace(/[<>]/g, '').trim().slice(0, 5000);
            } else if (typeof obj[key] === 'object') {
                sanitize(obj[key]);
            }
        }
        return obj;
    };
    
    try {
        if (req.body) sanitize(req.body);
        if (req.query) sanitize(req.query);
        if (req.params) sanitize(req.params);
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos' });
    }
    next();
});

// ============================================================
// API PÚBLICAS
// ============================================================

app.get('/api/status', (req, res) => {
    res.json({ online: true, timestamp: new Date().toISOString() });
});

app.get('/api/config', async (req, res) => {
    try {
        if (!supabase) {
            return res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
        }
        const { data, error } = await supabase.from('config').select('moneda_base, tasas').eq('id', 1).single();
        if (error) {
            return res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
        }
        res.json(data);
    } catch (error) {
        res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.get('/api/tiendas/info', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('id, nombre, icono, descripcion, categorias').order('nombre');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar tiendas' });
    }
});

app.get('/api/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('*').eq('id', tiendaId).single();
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar tienda' });
    }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('configuracion').eq('id', tiendaId).single();
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        const config = data?.configuracion || {};
        if (config.datos_bancarios) {
            delete config.datos_bancarios.numero_tarjeta;
        }
        res.json(config);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar configuración' });
    }
});

app.get('/api/productos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('products').select('*').eq('tienda', tienda).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar productos' });
    }
});

app.get('/api/categorias', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('categorias').eq('id', tienda).single();
        if (error) {
            return res.json(['otros']);
        }
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        res.json(['otros']);
    }
});

// ============================================================
// 🔑 LOGIN ADMIN - CON CONTRASEÑA FIJA 1988
// ============================================================

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    
    console.log('🔐 ========== INTENTO DE LOGIN ==========');
    console.log(`🔐 IP: ${ip}`);
    console.log(`🔐 Password ingresada: ${password ? '***' : '(vacía)'}`);
    console.log(`🔐 Password esperada: ${ADMIN_PASSWORD}`);
    console.log(`🔐 Coinciden: ${password === ADMIN_PASSWORD}`);
    console.log('🔐 =======================================');
    
    if (!password) {
        return res.status(400).json({ success: false, error: 'Contraseña requerida' });
    }
    
    // ✅ Comparación exacta - SIN trim() para evitar problemas
    if (password === ADMIN_PASSWORD) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Date.now() + 86400000; // 24 horas
        sessions.set(token, { expiry, ip, createdAt: Date.now() });
        
        console.log(`✅ LOGIN EXITOSO desde ${ip}`);
        console.log(`✅ Token: ${token.substring(0, 16)}...`);
        
        res.json({ 
            success: true, 
            token: token, 
            expires: expiry 
        });
    } else {
        console.log(`🔴 LOGIN FALLIDO desde ${ip}`);
        res.status(401).json({ 
            success: false, 
            error: 'Contraseña incorrecta' 
        });
    }
});

// ============================================================
// VERIFICAR SESIÓN
// ============================================================

app.get('/api/admin/verify-session', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    console.log(`🔐 Verificando sesión: ${token ? token.substring(0, 16) + '...' : 'sin token'}`);
    
    if (!token) {
        return res.status(401).json({ valid: false });
    }
    
    const session = sessions.get(token);
    if (!session) {
        console.log('🔴 Sesión no encontrada');
        return res.status(401).json({ valid: false });
    }
    
    if (session.expiry < Date.now()) {
        console.log('🔴 Sesión expirada');
        sessions.delete(token);
        return res.status(401).json({ valid: false });
    }
    
    // Renovar
    session.expiry = Date.now() + 86400000;
    sessions.set(token, session);
    
    console.log('✅ Sesión válida');
    res.json({ valid: true });
});

// ============================================================
// LOGOUT
// ============================================================

app.post('/api/admin/logout', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
        sessions.delete(token);
        console.log('👋 Logout');
    }
    res.json({ success: true });
});

// ============================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================================

const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    const session = sessions.get(token);
    if (!session || session.expiry < Date.now()) {
        sessions.delete(token);
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    session.expiry = Date.now() + 86400000;
    sessions.set(token, session);
    next();
};

app.use('/api/admin', requireAuth);

// ============================================================
// RUTAS ADMIN - TIENDAS
// ============================================================

app.get('/api/admin/tiendas', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('*').order('id');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar tiendas' });
    }
});

app.get('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('*').eq('id', tiendaId).single();
        if (error) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Error al cargar tienda' });
    }
});

app.post('/api/admin/tiendas', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const data = req.body;
        const { data: existing } = await supabase.from('stores').select('id').eq('id', data.id).single();
        if (existing) {
            return res.status(400).json({ success: false, error: 'Ya existe una tienda con este ID' });
        }
        const { error } = await supabase.from('stores').insert({
            id: data.id,
            nombre: data.nombre,
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
        res.status(500).json({ error: 'Error al crear tienda' });
    }
});

app.put('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const data = req.body;
        const { error } = await supabase.from('stores').update({
            nombre: data.nombre,
            icono: data.icono || '🛒',
            descripcion: data.descripcion || '',
            configuracion: data.configuracion || {},
            categorias: data.categorias || ['otros'],
            updated_at: new Date().toISOString()
        }).eq('id', tiendaId);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar tienda' });
    }
});

app.delete('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const tiendaId = req.params.id?.toLowerCase().trim();
        if (!tiendaId || !/^[a-z0-9\-_]+$/.test(tiendaId)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { error } = await supabase.from('stores').delete().eq('id', tiendaId);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar tienda' });
    }
});

// ============================================================
// RUTAS ADMIN - CATEGORÍAS
// ============================================================

app.get('/api/admin/categorias', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('stores').select('categorias').eq('id', tienda).single();
        if (error) {
            return res.json(['otros']);
        }
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { tienda, categoria } = req.body;
        const { data: store } = await supabase.from('stores').select('categorias').eq('id', tienda).single();
        if (!store) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }
        const currentCats = store.categorias || [];
        if (!currentCats.includes(categoria)) {
            currentCats.push(categoria);
        }
        const { error } = await supabase.from('stores').update({ categorias: currentCats }).eq('id', tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al agregar categoría' });
    }
});

// ============================================================
// RUTAS ADMIN - PRODUCTOS
// ============================================================

app.get('/api/admin/productos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim() || 'electro';
        if (!/^[a-z0-9\-_]+$/.test(tienda)) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('products').select('*').eq('tienda', tienda).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.json([]);
    }
});

app.post('/api/admin/productos', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const data = req.body;
        const productoData = {
            tienda: data.tienda,
            nombre: data.nombre,
            descripcion: data.descripcion || '',
            precio: parseFloat(data.precio),
            descuento: parseInt(data.descuento) || 0,
            imagen: data.imagen_url || 'https://via.placeholder.com/400',
            disponible: data.disponible === 'true',
            tamanio: data.tamanio || 'pequeno',
            categoria: data.categoria || 'otros',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        const { error } = await supabase.from('products').insert(productoData);
        if (error) throw error;
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al crear producto' });
    }
});

app.put('/api/admin/productos/:id', async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (!productId || productId <= 0) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const data = req.body;
        const updateData = {
            nombre: data.nombre,
            descripcion: data.descripcion || '',
            precio: parseFloat(data.precio),
            descuento: parseInt(data.descuento) || 0,
            disponible: data.disponible === 'true',
            tamanio: data.tamanio || 'pequeno',
            categoria: data.categoria || 'otros',
            updated_at: new Date().toISOString()
        };
        if (data.imagen_url) {
            updateData.imagen = data.imagen_url;
        }
        const { error } = await supabase.from('products').update(updateData).eq('id', productId);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar producto' });
    }
});

app.delete('/api/admin/productos/:id', async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (!productId || productId <= 0) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { error } = await supabase.from('products').delete().eq('id', productId);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar producto' });
    }
});

// ============================================================
// RUTAS ADMIN - PEDIDOS
// ============================================================

app.get('/api/admin/pedidos', async (req, res) => {
    try {
        const tienda = req.query.tienda?.toLowerCase().trim();
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (tienda) {
            query = query.eq('tienda', tienda);
        }
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.json([]);
    }
});

app.put('/api/admin/pedidos/:id', async (req, res) => {
    try {
        const orderId = parseInt(req.params.id);
        if (!orderId || orderId <= 0) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { tienda, estado } = req.body;
        const { error } = await supabase.from('orders').update({ estado: estado }).eq('id', orderId).eq('tienda', tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar pedido' });
    }
});

app.delete('/api/admin/pedidos/:id', async (req, res) => {
    try {
        const orderId = parseInt(req.params.id);
        if (!orderId || orderId <= 0) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        const tienda = req.query.tienda?.toLowerCase().trim();
        if (!tienda) {
            return res.status(400).json({ error: 'ID de tienda requerido' });
        }
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { error } = await supabase.from('orders').delete().eq('id', orderId).eq('tienda', tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
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
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { error } = await supabase.from('orders').delete().eq('tienda', tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar pedidos' });
    }
});

// ============================================================
// RUTAS ADMIN - CONFIGURACIÓN
// ============================================================

app.get('/api/admin/config', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
        if (error) {
            const defaultConfig = {
                id: 1,
                moneda_base: 'CUP',
                tasas: { CUP: 1, USD: 0.04, EUR: 0.037 },
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };
            await supabase.from('config').insert(defaultConfig);
            return res.json(defaultConfig);
        }
        res.json(data);
    } catch (error) {
        res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({ error: 'Servicio no disponible' });
        }
        const data = req.body;
        const configData = {
            moneda_base: data.monedaBase || 'CUP',
            tasas: { CUP: 1, USD: data.tasas?.USD || 0.04, EUR: data.tasas?.EUR || 0.037 },
            updated_at: new Date().toISOString()
        };
        const { data: existing } = await supabase.from('config').select('id').eq('id', 1).single();
        if (existing) {
            await supabase.from('config').update(configData).eq('id', 1);
        } else {
            await supabase.from('config').insert({ id: 1, ...configData, created_at: new Date().toISOString() });
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar configuración' });
    }
});

// ============================================================
// 404 - RUTA NO ENCONTRADA
// ============================================================

app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

// ============================================================
// MANEJO DE ERRORES
// ============================================================

app.use((err, req, res, next) => {
    console.error('❌ Error:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 ========== TIENDA LA REINA ==========');
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`🔑 Contraseña Admin: ${ADMIN_PASSWORD}`);
    console.log(`📋 Panel Admin: http://localhost:${PORT}/admin`);
    console.log('🔐 ===================================');
});