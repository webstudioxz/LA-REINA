import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('ERROR: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}
if (!ADMIN_PASSWORD) {
    console.error('ERROR: Falta ADMIN_PASSWORD');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// SEGURIDAD: HELMET
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// SEGURIDAD: RATE LIMITING
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Demasiadas solicitudes. Intenta mas tarde.' },
    standardHeaders: true,
    legacyHeaders: false
});

const orderLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Demasiados pedidos. Espera un momento.' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Demasiados intentos de login.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(generalLimiter);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(__dirname));

// MULTER
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowed.includes(file.mimetype)) return cb(null, true);
        cb(new Error('Solo se permiten imagenes (JPG, PNG, WebP, GIF)'));
    }
});

// VALIDACIONES BLINDADAS
function sanitizar(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>'"&]/g, '').trim();
}

function validarTelefono(tel) {
    const clean = tel.replace(/[\s\-\(\)\.]/g, '');
    const digits = clean.replace(/^\+/, '');
    if (!digits || !/^\d+$/.test(digits)) return false;
    if (/^(\d)\1{7,}$/.test(digits)) return false;
    if (/^(012|123|234|345|456|567|678|789|890)/.test(digits) && digits.length <= 11) return false;
    if (digits.length === 8 && /^[567]\d{7}$/.test(digits)) return true;
    if (digits.length === 10 && digits.startsWith('53')) {
        const local = digits.substring(2);
        if (/^[567]\d{7}$/.test(local)) return true;
    }
    if (digits.length === 11 && digits.startsWith('535')) {
        const local = digits.substring(3);
        if (/^[567]\d{7}$/.test(local)) return true;
    }
    return false;
}

function validarNombre(nombre) {
    const clean = sanitizar(nombre);
    if (!clean) return false;
    const words = clean.split(/\s+/).filter(w => w.length > 0);
    if (words.length < 2) return false;
    for (const word of words) {
        if (word.length < 2) return false;
        if (!/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ']+$/.test(word)) return false;
        if (/^(.)\1{3,}$/.test(word)) return false;
        const lower = word.toLowerCase();
        const kb = ['asdf', 'qwer', 'zxcv', 'hjkl', 'fghj'];
        if (kb.some(p => lower.includes(p)) && word.length <= 5) return false;
    }
    return true;
}

function validarDireccion(dir) {
    const clean = sanitizar(dir);
    if (!clean || clean.length < 10) return false;
    if (!/\d/.test(clean)) return false;
    if (!/[a-zA-ZáéíóúÁÉÍÓÚñÑ]/.test(clean)) return false;
    const noSpaces = clean.replace(/\s/g, '');
    if (/^(.)\1{6,}$/.test(noSpaces)) return false;
    const lower = clean.toLowerCase();
    const gibberish = ['mmm', 'xxx', 'aaa', 'zzz', 'asdf', 'qwer'];
    if (gibberish.some(g => lower.includes(g) && clean.length < 20)) return false;
    return true;
}

function validarItemsPedidos(items) {
    if (!Array.isArray(items) || items.length === 0) return false;
    for (const item of items) {
        if (!item.id || !item.nombre || typeof item.precio !== 'number' || typeof item.qty !== 'number') return false;
        if (item.qty < 1 || item.precio < 0) return false;
    }
    return true;
}

// SUBIDA/ELIMINACION IMAGENES
async function uploadToSupabase(file, folder = 'Productos') {
    try {
        const ext = file.originalname.split('.').pop().toLowerCase();
        const name = `${Date.now()}-${Math.random().toString(36).substring(2, 10)}.${ext}`;
        const { data, error } = await supabase.storage.from(folder).upload(name, file.buffer, {
            cacheControl: '3600', upsert: false, contentType: file.mimetype
        });
        if (error) return null;
        const { data: { publicUrl } } = supabase.storage.from(folder).getPublicUrl(name);
        return publicUrl;
    } catch { return null; }
}

async function deleteFromSupabase(imageUrl) {
    try {
        if (!imageUrl || !imageUrl.includes('/storage/v1/object/public/')) return;
        const parts = imageUrl.split('/Productos/');
        if (parts.length < 2) return;
        await supabase.storage.from('Productos').remove([`Productos/${parts[1]}`]);
    } catch { }
}

// AUTH MIDDLEWARE
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    if (pass === ADMIN_PASSWORD) return next();
    res.status(401).json({ error: 'No autorizado' });
};

function generarCodigoUnico() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code + Date.now().toString(36).slice(-4).toUpperCase();
}

// RUTAS ESTATICAS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// API PUBLICA
app.get('/api/status', (req, res) => res.json({ online: true, ts: Date.now() }));

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('id, nombre, icono');
        if (error) throw error;
        res.json(data || []);
    } catch { res.json([]); }
});

app.get('/api/tiendas/:id', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').eq('id', req.params.id).single();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'No encontrada' });
        res.json(data);
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const { data } = await supabase.from('stores').select('configuracion').eq('id', req.params.id).single();
        res.json(data?.configuracion || {});
    } catch { res.json({}); }
});

app.get('/api/productos', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('id, nombre, descripcion, precio, descuento, imagen, disponible, tamanio, categoria')
            .eq('tienda', req.query.tienda || 'electro')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch { res.json([]); }
});

app.get('/api/categorias', async (req, res) => {
    try {
        const { data } = await supabase.from('stores').select('categorias').eq('id', req.query.tienda || 'electro').single();
        res.json(data?.categorias || ['otros']);
    } catch { res.json(['otros']); }
});

app.get('/api/config', async (req, res) => {
    try {
        const { data } = await supabase.from('config').select('*').eq('id', 1).single();
        res.json(data || { moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch { res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } }); }
});

// CREAR PEDIDO — VALIDACION BLINDADA + SIN RACE CONDITION
app.post('/api/pedidos', orderLimiter, async (req, res) => {
    try {
        const tienda = sanitizar(req.body.tienda || 'electro');
        const nombre = req.body.nombre;
        const telefono = req.body.telefono;
        const direccion = req.body.direccion;
        const items = req.body.items;
        const total = parseFloat(req.body.total) || 0;
        const moneda = sanitizar(req.body.moneda || 'CUP');
        const metodoPago = sanitizar(req.body.metodoPago || 'Efectivo');

        const errores = [];
        if (!validarNombre(nombre)) errores.push('Nombre invalido. Minimo nombre y apellido, solo letras.');
        if (!validarTelefono(telefono)) errores.push('Telefono invalido. Formato: 5XXXXXXXX (8 digitos) o +53 5XXXXXXXX.');
        if (!validarDireccion(direccion)) errores.push('Direccion invalida. Minimo 10 caracteres, debe incluir numero y calle.');
        if (!validarItemsPedidos(items)) errores.push('Los productos del carrito son invalidos.');
        if (total <= 0) errores.push('El total debe ser mayor a 0.');
        if (!['Efectivo', 'Transferencia'].includes(metodoPago)) errores.push('Metodo de pago no valido.');

        if (errores.length > 0) return res.status(400).json({ success: false, errores });

        const codigoCliente = generarCodigoUnico();

        const { data: resultado, error: rpcError } = await supabase.rpc('crear_pedido_seguro', {
            p_codigo_cliente: codigoCliente,
            p_tienda: tienda,
            p_nombre: sanitizar(nombre),
            p_telefono: telefono.replace(/[\s\-\(\)\.]/g, ''),
            p_direccion: sanitizar(direccion),
            p_items: items.map(i => ({
                id: i.id, nombre: sanitizar(i.nombre),
                precio: Number(i.precio), qty: Number(i.qty),
                imagen: String(i.imagen || '')
            })),
            p_total: total, p_moneda: moneda, p_metodo_pago: metodoPago
        });

        if (rpcError) throw rpcError;
        if (!resultado?.success) return res.status(400).json({ success: false, errores: [resultado?.error || 'Error al crear pedido'] });

        res.json({
            success: true,
            orderId: resultado.orderId,
            orderNumber: resultado.orderNumber,
            codigoCliente: resultado.codigoCliente
        });
    } catch (error) {
        console.error('Error en /api/pedidos:', error.message);
        res.status(500).json({ success: false, errores: ['Error interno del servidor. Intenta de nuevo.'] });
    }
});

// API ADMIN
app.post('/api/admin/verify', loginLimiter, (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) return res.json({ success: true });
    res.status(401).json({ success: false });
});

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').eq('id', req.params.id).single();
        if (error) throw error;
        res.json(data);
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.post('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').insert({
            id: sanitizar(req.body.id?.toLowerCase()),
            nombre: sanitizar(req.body.nombre),
            icono: sanitizar(req.body.icono || '🛒'),
            descripcion: sanitizar(req.body.descripcion || ''),
            configuracion: req.body.configuracion || {},
            categorias: (req.body.categorias || ['otros']).map(c => sanitizar(c.toLowerCase())),
            created_at: new Date(), updated_at: new Date()
        });
        if (error) throw error;
        res.json({ success: true });
    } catch (e) {
        const msg = e.message?.includes('duplicate') ? 'Ya existe una tienda con ese ID' : 'Error al crear tienda';
        res.status(400).json({ error: msg });
    }
});

app.put('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').update({
            nombre: sanitizar(req.body.nombre),
            icono: sanitizar(req.body.icono),
            descripcion: sanitizar(req.body.descripcion),
            configuracion: req.body.configuracion,
            categorias: (req.body.categorias || []).map(c => sanitizar(c.toLowerCase())),
            updated_at: new Date()
        }).eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.delete('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data } = await supabase.from('stores').select('categorias').eq('id', req.query.tienda).single();
        res.json(data?.categorias || ['otros']);
    } catch { res.json(['otros']); }
});

app.post('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data: store } = await supabase.from('stores').select('categorias').eq('id', req.body.tienda).single();
        const cats = store?.categorias || [];
        const nueva = sanitizar(req.body.categoria.toLowerCase());
        if (!cats.includes(nueva)) cats.push(nueva);
        const { error } = await supabase.from('stores').update({ categorias: cats, updated_at: new Date() }).eq('id', req.body.tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/admin/productos', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').select('*').eq('tienda', req.query.tienda).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch { res.json([]); }
});

app.post('/api/admin/productos', AUTH, upload.single('imagen'), async (req, res) => {
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
        if (req.file) {
            const url = await uploadToSupabase(req.file);
            if (!url) return res.status(500).json({ success: false, error: 'Error al subir imagen' });
            imagen = url;
        }
        const { data, error } = await supabase.from('products').insert({
            tienda: sanitizar(req.body.tienda),
            nombre: sanitizar(req.body.nombre),
            descripcion: sanitizar(req.body.descripcion || ''),
            precio: parseFloat(req.body.precio) || 0,
            descuento: parseInt(req.body.descuento) || 0,
            imagen, disponible: req.body.disponible === 'true',
            tamanio: sanitizar(req.body.tamanio || 'pequeno'),
            categoria: sanitizar(req.body.categoria || 'otros'),
            created_at: new Date(), updated_at: new Date()
        }).select();
        if (error) throw error;
        res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, error: 'Error al crear producto' }); }
});

app.put('/api/admin/productos/:id', AUTH, upload.single('imagen'), async (req, res) => {
    try {
        const { data: old } = await supabase.from('products').select('imagen').eq('id', req.params.id).single();
        const upd = {
            nombre: sanitizar(req.body.nombre),
            descripcion: sanitizar(req.body.descripcion),
            precio: parseFloat(req.body.precio) || 0,
            descuento: parseInt(req.body.descuento) || 0,
            disponible: req.body.disponible === 'true',
            tamanio: sanitizar(req.body.tamanio),
            categoria: sanitizar(req.body.categoria),
            updated_at: new Date()
        };
        if (req.file) {
            if (old?.imagen && !old.imagen.includes('via.placeholder.com')) await deleteFromSupabase(old.imagen);
            const url = await uploadToSupabase(req.file);
            if (url) upd.imagen = url;
        } else if (req.body.imagen_url) {
            upd.imagen = req.body.imagen_url;
        }
        const { error } = await supabase.from('products').update(upd).eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
        const { data: p } = await supabase.from('products').select('imagen').eq('id', req.params.id).single();
        if (p?.imagen && !p.imagen.includes('via.placeholder.com')) await deleteFromSupabase(p.imagen);
        const { error } = await supabase.from('products').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        let q = supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (req.query.tienda) q = q.eq('tienda', req.query.tienda);
        const { data, error } = await q;
        if (error) throw error;
        res.json(data || []);
    } catch { res.json([]); }
});

app.put('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('orders').update({ estado: sanitizar(req.body.estado), updated_at: new Date() }).eq('id', req.params.id).eq('tienda', req.body.tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.delete('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('orders').delete().eq('id', req.params.id).eq('tienda', req.query.tienda);
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.delete('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        if (req.query.tienda) {
            await supabase.from('orders').delete().eq('tienda', req.query.tienda);
            await supabase.from('order_counters').upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.get('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { data } = await supabase.from('config').select('*').eq('id', 1).single();
        res.json(data || { moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch { res.json({ moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } }); }
});

app.put('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('config').upsert({ id: 1, ...req.body, updated_at: new Date() });
        if (error) throw error;
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Error interno' }); }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tienda La Reina v4.0 — Puerto ${PORT}`);
    console.log(`Seguridad: Helmet + Rate Limiting activos`);
});