import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import { body, query, param, validationResult } from 'express-validator';
import xss from 'xss';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// VARIABLES DE ENTORNO
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ Falta ADMIN_PASSWORD');
    process.exit(1);
}

console.log('🔐 ADMIN_PASSWORD configurada:', ADMIN_PASSWORD.length, 'caracteres');

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// SEGURIDAD HELMET
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'admin-password'],
    maxAge: 86400
}));

// ============================================
// RATE LIMITING
// ============================================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Demasiadas solicitudes' },
    standardHeaders: true,
    legacyHeaders: false
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { error: 'Demasiados intentos' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(globalLimiter);

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname, {
    maxAge: '1h',
    etag: true,
    lastModified: true
}));

// ============================================
// VALIDADORES
// ============================================
const validarPedido = [
    body('tienda').trim().isString().notEmpty().escape(),
    body('nombre').trim().isString().isLength({ min: 3, max: 100 }).matches(/^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s'-]+$/),
    body('telefono').trim().isString().matches(/^\+?[0-9]{8,15}$/),
    body('direccion').trim().isString().isLength({ min: 10, max: 300 }),
    body('items').isArray({ min: 1 }),
    body('items.*.id').isInt(),
    body('items.*.qty').isInt({ min: 1, max: 99 }),
    body('total').isFloat({ min: 0 }),
    body('metodoPago').isIn(['Efectivo', 'Transferencia'])
];

const validarProducto = [
    body('tienda').trim().isString().notEmpty(),
    body('nombre').trim().isString().isLength({ min: 2, max: 200 }),
    body('precio').isFloat({ min: 0, max: 99999999 }),
    body('categoria').trim().isString()
];

// ============================================
// MULTER CONFIGURACIÓN
// ============================================
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Solo imágenes JPG, PNG, WebP y GIF'));
        }
    }
});

// ============================================
// FUNCIONES UTILITARIAS
// ============================================
async function uploadToSupabase(file, folder = 'Productos') {
    try {
        const fileExt = file.originalname.split('.').pop().toLowerCase();
        const fileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;

        const { error } = await supabase.storage
            .from(folder)
            .upload(filePath, file.buffer, {
                cacheControl: '31536000',
                upsert: false,
                contentType: file.mimetype
            });

        if (error) throw error;

        const { data: { publicUrl } } = supabase.storage
            .from(folder)
            .getPublicUrl(filePath);

        return publicUrl;
    } catch (error) {
        console.error('Error upload:', error);
        return null;
    }
}

async function deleteFromSupabase(imageUrl) {
    try {
        if (!imageUrl?.includes('/storage/v1/object/public/')) return false;
        const urlParts = imageUrl.split('/Productos/');
        if (urlParts.length < 2) return false;
        const filePath = `Productos/${urlParts[1]}`;
        await supabase.storage.from('Productos').remove([filePath]);
        return true;
    } catch (error) {
        console.error('Error delete:', error);
        return false;
    }
}

function generarCodigoUnico() {
    return crypto.randomBytes(6).toString('hex').toUpperCase() +
           Date.now().toString(36).slice(-4).toUpperCase();
}

function sanitizarTexto(texto) {
    if (!texto) return '';
    return xss(texto.trim());
}

function validarTelefono(telefono) {
    const limpio = telefono.replace(/[\s\-\(\)]/g, '');
    return /^\+?[0-9]{8,15}$/.test(limpio) ? limpio : null;
}

// ============================================
// MIDDLEWARE AUTH (CORREGIDO)
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    
    if (!pass) {
        return res.status(401).json({ error: 'No autorizado - falta contraseña' });
    }
    
    if (pass === ADMIN_PASSWORD) {
        return next();
    }
    
    console.log('❌ AUTH fallido - password recibida:', pass.length, 'caracteres, esperada:', ADMIN_PASSWORD.length, 'caracteres');
    res.status(401).json({ error: 'No autorizado' });
};

// ============================================
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// También servir admin.html por si acceden directamente
app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// ============================================
// API PÚBLICA
// ============================================

app.get('/api/status', (req, res) => {
    res.json({ online: true, timestamp: Date.now() });
});

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('id, nombre, icono, descripcion');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error /api/tiendas/info:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id', [
    param('id').isString().notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'ID inválido' });

        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error || !data) return res.status(404).json({ error: 'Tienda no encontrada' });
        res.json(data);
    } catch (error) {
        console.error('Error /api/tiendas/:id:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id/config', [
    param('id').isString().notEmpty()
], async (req, res) => {
    try {
        const { data } = await supabase
            .from('stores')
            .select('configuracion')
            .eq('id', req.params.id)
            .single();
        res.json(data?.configuracion || {});
    } catch {
        res.json({});
    }
});

app.get('/api/productos', [
    query('tienda').optional().isString()
], async (req, res) => {
    try {
        const tienda = sanitizarTexto(req.query.tienda) || 'electro';
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .eq('disponible', true)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch {
        res.json([]);
    }
});

app.get('/api/categorias', [
    query('tienda').optional().isString()
], async (req, res) => {
    try {
        const tienda = sanitizarTexto(req.query.tienda) || 'electro';
        const { data } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        res.json(data?.categorias || ['otros']);
    } catch {
        res.json(['otros']);
    }
});

app.get('/api/config', async (req, res) => {
    try {
        const { data } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch {
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.post('/api/pedidos', strictLimiter, validarPedido, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Datos inválidos', details: errors.array() });
        }

        const tienda = sanitizarTexto(req.body.tienda);
        const nombre = sanitizarTexto(req.body.nombre);
        const telefono = validarTelefono(req.body.telefono);
        const direccion = sanitizarTexto(req.body.direccion);
        const metodoPago = sanitizarTexto(req.body.metodoPago);
        const items = req.body.items;
        const total = parseFloat(req.body.total);

        if (!telefono) {
            return res.status(400).json({ error: 'Teléfono inválido' });
        }

        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();

        const nextId = (counterData?.counter || 0) + 1;
        const codigoCliente = generarCodigoUnico();

        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda,
            nombre,
            telefono,
            direccion,
            items,
            total,
            moneda: 'CUP',
            metodo_pago: metodoPago,
            estado: 'pendiente',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        });

        if (insertError) {
            if (insertError.code === '23505') {
                return res.status(409).json({ error: 'Conflicto, intente de nuevo' });
            }
            throw insertError;
        }

        await supabase
            .from('order_counters')
            .upsert({ tienda, counter: nextId });

        res.json({
            success: true,
            orderId: nextId,
            codigoCliente
        });
    } catch (error) {
        console.error('Error pedido:', error);
        res.status(500).json({ error: 'Error al procesar pedido' });
    }
});

// ============================================
// API ADMIN
// ============================================

// VERIFICAR CONTRASEÑA - CORREGIDO
app.post('/api/admin/verify', strictLimiter, (req, res) => {
    const { password } = req.body;
    
    console.log('🔐 Intento de login - Password recibida:', password ? 'SÍ (' + password.length + ' caracteres)' : 'NO');
    console.log('🔐 ADMIN_PASSWORD configurada:', ADMIN_PASSWORD ? 'SÍ (' + ADMIN_PASSWORD.length + ' caracteres)' : 'NO');
    
    if (!password || typeof password !== 'string') {
        return res.status(400).json({ success: false, error: 'Contraseña requerida' });
    }
    
    // Comparación directa (segura porque usamos HTTPS)
    if (password === ADMIN_PASSWORD) {
        console.log('✅ Login exitoso');
        res.json({ success: true });
    } else {
        console.log('❌ Contraseña incorrecta');
        res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
    }
});

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').order('created_at');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error /api/admin/tiendas:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/admin/tiendas/:id', AUTH, param('id').isString(), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Error /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.post('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').insert({
            id: sanitizarTexto(req.body.id?.toLowerCase()),
            nombre: sanitizarTexto(req.body.nombre),
            icono: sanitizarTexto(req.body.icono) || '🛒',
            descripcion: sanitizarTexto(req.body.descripcion) || '',
            configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros'],
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error POST /api/admin/tiendas:', error);
        res.status(500).json({ error: 'Error al crear tienda' });
    }
});

app.put('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('stores')
            .update({
                nombre: sanitizarTexto(req.body.nombre),
                icono: sanitizarTexto(req.body.icono),
                descripcion: sanitizarTexto(req.body.descripcion),
                configuracion: req.body.configuracion,
                categorias: req.body.categorias,
                updated_at: new Date().toISOString()
            })
            .eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error PUT /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: 'Error al actualizar' });
    }
});

app.delete('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        await supabase.from('stores').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error DELETE /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

app.get('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.query.tienda)
            .single();
        res.json(data?.categorias || ['otros']);
    } catch {
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data: store } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.body.tienda)
            .single();

        const currentCats = store?.categorias || [];
        const nuevaCat = sanitizarTexto(req.body.categoria);
        if (!currentCats.includes(nuevaCat)) {
            currentCats.push(nuevaCat);
        }

        await supabase
            .from('stores')
            .update({ categorias: currentCats, updated_at: new Date().toISOString() })
            .eq('id', req.body.tienda);

        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Error' });
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
    } catch {
        res.json([]);
    }
});

app.post('/api/admin/productos', AUTH, upload.single('imagen'), async (req, res) => {
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';

        if (req.file) {
            const uploadedUrl = await uploadToSupabase(req.file);
            if (uploadedUrl) imagen = uploadedUrl;
        }

        const { error } = await supabase.from('products').insert({
            tienda: sanitizarTexto(req.body.tienda),
            nombre: sanitizarTexto(req.body.nombre),
            descripcion: sanitizarTexto(req.body.descripcion || ''),
            precio: parseFloat(req.body.precio) || 0,
            descuento: parseInt(req.body.descuento) || 0,
            imagen,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: sanitizarTexto(req.body.categoria) || 'otros',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        });

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error POST producto:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/productos/:id', AUTH, upload.single('imagen'), async (req, res) => {
    try {
        const updateData = {
            nombre: sanitizarTexto(req.body.nombre),
            descripcion: sanitizarTexto(req.body.descripcion),
            precio: parseFloat(req.body.precio) || 0,
            descuento: parseInt(req.body.descuento) || 0,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio,
            categoria: sanitizarTexto(req.body.categoria),
            updated_at: new Date().toISOString()
        };

        if (req.file) {
            const { data: oldProduct } = await supabase
                .from('products')
                .select('imagen')
                .eq('id', req.params.id)
                .single();
            if (oldProduct?.imagen) await deleteFromSupabase(oldProduct.imagen);
            const uploadedUrl = await uploadToSupabase(req.file);
            if (uploadedUrl) updateData.imagen = uploadedUrl;
        }

        await supabase.from('products').update(updateData).eq('id', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error PUT producto:', error);
        res.status(500).json({ error: 'Error al actualizar' });
    }
});

app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
        const { data: product } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', req.params.id)
            .single();
        if (product?.imagen) await deleteFromSupabase(product.imagen);
        await supabase.from('products').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error DELETE producto:', error);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

app.get('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (req.query.tienda) query = query.eq('tienda', req.query.tienda);
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch {
        res.json([]);
    }
});

app.put('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        await supabase
            .from('orders')
            .update({ estado: req.body.estado, updated_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .eq('tienda', req.body.tienda);
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Error' });
    }
});

app.delete('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        await supabase
            .from('orders')
            .delete()
            .eq('id', req.params.id)
            .eq('tienda', req.query.tienda);
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Error' });
    }
});

app.delete('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        if (req.query.tienda) {
            await supabase.from('orders').delete().eq('tienda', req.query.tienda);
            await supabase.from('order_counters').upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Error' });
    }
});

app.get('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { data } = await supabase.from('config').select('*').eq('id', 1).single();
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch {
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', AUTH, async (req, res) => {
    try {
        await supabase.from('config').upsert({ id: 1, ...req.body, updated_at: new Date().toISOString() });
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Error' });
    }
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('Error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'Archivo muy grande (máx 5MB)' });
    }
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

// ============================================
// INICIAR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor en puerto ${PORT}`);
    console.log(`🔐 Admin password configurada: ${ADMIN_PASSWORD ? '✅ SÍ (' + ADMIN_PASSWORD.length + ' caracteres)' : '❌ NO'}`);
    console.log(`🗄️ Supabase: ${SUPABASE_URL}`);
});