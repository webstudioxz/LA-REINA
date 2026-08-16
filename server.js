import express from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

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

// Validación CRÍTICA
if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR CRÍTICO: ADMIN_PASSWORD no está configurada');
    process.exit(1);
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

console.log('🔍 ========== DIAGNÓSTICO ==========');
console.log(`🔍 SUPABASE_URL: ${SUPABASE_URL ? '✅' : '❌'}`);
console.log(`🔍 ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
console.log('🔍 =================================');

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// SESIONES EN MEMORIA
// ============================================
const sessions = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [key, value] of sessions) {
        if (value.expiry < now) sessions.delete(key);
    }
}, 300000);

// ============================================
// RATE LIMITING POR IP (Anti-DDoS)
// ============================================
const rateLimitStore = new Map();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;

setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of rateLimitStore) {
        if (now > record.resetTime) {
            rateLimitStore.delete(ip);
        }
    }
    if (rateLimitStore.size > 10000) {
        const keys = Array.from(rateLimitStore.keys());
        for (let i = 0; i < keys.length - 10000; i++) {
            rateLimitStore.delete(keys[i]);
        }
    }
}, 60000);

// ============================================
// MIDDLEWARE BASE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// ============================================
// 🛡️ BLOQUEO DE RUTAS SOSPECHOSAS
// ============================================
app.use((req, res, next) => {
    const blockedPaths = [
        '/wp-admin', '/cpanel', '/plesk', '/phpmyadmin',
        '/mysql', '/db', '/config', '/.env', '/.git',
        '/backup', '/shell', '/cmd', '/exec', '/system',
        '/vendor', '/composer', '/.ssh', '/.aws',
        '/.htaccess', '/web.config', '/robots.txt', '/sitemap.xml'
    ];
    
    const requestPath = req.path.toLowerCase();
    if (blockedPaths.some(path => requestPath.startsWith(path))) {
        console.log(`🔴 [BLOQUEADO] ${req.path} desde ${req.ip}`);
        return res.status(404).send('Not Found');
    }
    next();
});

// ============================================
// RUTAS ESTÁTICAS - CORREGIDAS
// ============================================

// Servir archivos estáticos desde el directorio raíz
app.use(express.static(__dirname));

// Ruta principal - sirve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Ruta admin - sirve admin.html
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Redireccionar /admin.html a /admin
app.get('/admin.html', (req, res) => {
    res.redirect('/admin');
});

// ============================================
// LOGIN
// ============================================
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
    console.log('🔐 ========== LOGIN ==========');
    console.log(`🔐 IP: ${req.ip}`);
    console.log(`🔐 Password recibida: "${password}"`);
    console.log(`🔐 ADMIN_PASSWORD: "${ADMIN_PASSWORD}"`);
    console.log(`🔐 Coinciden: ${password === ADMIN_PASSWORD}`);
    console.log('🔐 ============================');
    
    if (!password) {
        return res.status(400).json({ 
            success: false, 
            error: 'Contraseña requerida' 
        });
    }
    
    if (password === ADMIN_PASSWORD) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Date.now() + 3600000;
        
        sessions.set(token, { 
            expiry, 
            ip: req.ip,
            createdAt: Date.now()
        });
        
        console.log(`✅ Login exitoso desde ${req.ip}`);
        res.json({ 
            success: true, 
            token: token,
            expires: expiry 
        });
    } else {
        console.log(`🔴 Login fallido desde ${req.ip}`);
        res.status(401).json({ 
            success: false, 
            error: 'Contraseña incorrecta' 
        });
    }
});

// ============================================
// RATE LIMIT CHECK (Anti-DDoS)
// ============================================
app.get('/api/check-rate-limit', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    let record = rateLimitStore.get(ip);
    if (!record) {
        record = { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
        rateLimitStore.set(ip, record);
    }
    
    if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + RATE_LIMIT_WINDOW;
    }
    
    if (record.count >= RATE_LIMIT_MAX) {
        const waitTime = Math.ceil((record.resetTime - now) / 60000);
        return res.json({ 
            allowed: false, 
            waitTime: waitTime,
            message: `Límite excedido. Espera ${waitTime} minutos.`
        });
    }
    
    record.count++;
    rateLimitStore.set(ip, record);
    
    res.json({ 
        allowed: true,
        remaining: RATE_LIMIT_MAX - record.count,
        resetTime: new Date(record.resetTime).toISOString()
    });
});

// ============================================
// VERIFICAR SESIÓN
// ============================================
app.get('/api/admin/verify-session', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ valid: false });
    }
    
    const session = sessions.get(token);
    if (!session || session.expiry < Date.now()) {
        sessions.delete(token);
        return res.status(401).json({ valid: false });
    }
    
    session.expiry = Date.now() + 3600000;
    sessions.set(token, session);
    res.json({ valid: true });
});

app.post('/api/admin/logout', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
        sessions.delete(token);
        console.log(`👋 Logout desde ${req.ip}`);
    }
    res.json({ success: true });
});

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (token && sessions.has(token)) {
        const session = sessions.get(token);
        if (session.expiry > Date.now()) {
            session.expiry = Date.now() + 3600000;
            sessions.set(token, session);
            return next();
        }
        sessions.delete(token);
    }
    
    console.log(`🔴 Intento no autorizado a ${req.path} desde ${req.ip}`);
    return res.status(401).json({ 
        error: 'No autorizado',
        message: 'Debes iniciar sesión para acceder a esta sección'
    });
};

app.use('/api/admin', requireAuth);

// ============================================
// CONFIGURACIÓN DE MULTER
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 5 * 1024 * 1024 }
});

// ============================================
// FUNCIONES AUXILIARES
// ============================================

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { data, error } = await supabase.storage
            .from(folder)
            .upload(filePath, file.buffer, {
                cacheControl: '3600',
                upsert: false,
                contentType: file.mimetype
            });
        
        if (error) {
            console.error('❌ Error en upload:', error);
            return null;
        }
        
        const { data: { publicUrl } } = supabase.storage
            .from(folder)
            .getPublicUrl(filePath);
        
        return publicUrl;
    } catch (error) {
        console.error('❌ Error subiendo imagen:', error);
        return null;
    }
}

async function deleteFromSupabase(imageUrl) {
    try {
        if (!imageUrl || !imageUrl.includes('/storage/v1/object/public/')) return false;
        
        const urlParts = imageUrl.split('/Productos/');
        if (urlParts.length < 2) return false;
        
        const filePath = `Productos/${urlParts[1]}`;
        
        const { error } = await supabase.storage
            .from('Productos')
            .remove([filePath]);
        
        if (error) throw error;
        return true;
    } catch (error) {
        console.error('❌ Error eliminando imagen:', error);
        return false;
    }
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

// ============================================
// API PÚBLICA
// ============================================

app.get('/api/status', (req, res) => res.json({ online: true }));

app.get('/api/config', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        
        if (error) {
            const defaultConfig = {
                moneda_base: 'CUP',
                tasas: {
                    CUP: 1,
                    USD: 0.04,
                    EUR: 0.037
                },
                updated_at: new Date().toISOString()
            };
            return res.json(defaultConfig);
        }
        
        res.json(data || { moneda_base: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('Error en /api/config:', error);
        res.json({ 
            moneda_base: 'CUP', 
            tasas: { 
                CUP: 1, 
                USD: 0.04, 
                EUR: 0.037 
            },
            updated_at: new Date().toISOString()
        });
    }
});

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/tiendas/info:', error);
        res.status(500).json({ error: error.message });
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
        res.json(data);
    } catch (error) {
        console.error('Error en /api/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('configuracion')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        res.json(data?.configuracion || {});
    } catch (error) {
        console.error('Error en /api/tiendas/:id/config:', error);
        res.json({});
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
        console.error('Error en /api/productos:', error);
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
        console.error('Error en /api/categorias:', error);
        res.json(['otros']);
    }
});

// ============================================
// API PEDIDOS - CORREGIDA (SIN 'ip' Y SIN 'user_agent')
// ============================================
app.post('/api/pedidos', async (req, res) => {
    try {
        console.log('📦 ========== NUEVO PEDIDO ==========');
        console.log('📦 Tienda:', req.body.tienda);
        console.log('📦 Nombre:', req.body.nombre);
        console.log('📦 Teléfono:', req.body.telefono);
        console.log('📦 Total:', req.body.total);
        console.log('📦 Items:', req.body.items?.length || 0);
        
        const tienda = req.body.tienda || 'electro';
        const codigoCliente = generarCodigoUnico();
        
        const ip = req.ip || req.connection.remoteAddress;
        let record = rateLimitStore.get(ip);
        if (!record) {
            record = { count: 0, resetTime: Date.now() + RATE_LIMIT_WINDOW };
            rateLimitStore.set(ip, record);
        }
        
        if (Date.now() > record.resetTime) {
            record.count = 0;
            record.resetTime = Date.now() + RATE_LIMIT_WINDOW;
        }
        
        if (record.count >= RATE_LIMIT_MAX) {
            return res.status(429).json({ 
                success: false, 
                error: 'Demasiados pedidos. Espera unos minutos.' 
            });
        }
        
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        // ============================================
        // INSERT CORREGIDO - SIN 'ip' Y SIN 'user_agent'
        // ============================================
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda: tienda,
            nombre: req.body.nombre?.slice(0, 60),
            telefono: req.body.telefono?.slice(0, 20),
            direccion: req.body.direccion?.slice(0, 200),
            items: req.body.items || [],
            total: req.body.total || 0,
            moneda: req.body.moneda || 'CUP',
            metodo_pago: req.body.metodoPago || 'Efectivo',
            estado: 'pendiente',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) {
            console.error('❌ Error insertando pedido:', insertError);
            throw insertError;
        }
        
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        record.count++;
        rateLimitStore.set(ip, record);
        
        console.log('✅ Pedido #' + nextId + ' registrado con código: ' + codigoCliente);
        console.log('📦 =====================================\n');
        
        res.json({ 
            success: true, 
            orderId: nextId, 
            codigoCliente: codigoCliente 
        });
    } catch (error) {
        console.error('❌ Error en /api/pedidos:', error);
        res.status(500).json({ 
            success: false,
            error: error.message || 'Error interno del servidor' 
        });
    }
});

// ============================================
// API ADMIN
// ============================================

app.get('/api/admin/tiendas', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/admin/tiendas:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Error en /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/tiendas', async (req, res) => {
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
        console.error('Error en POST /api/admin/tiendas:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/tiendas/:id', async (req, res) => {
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
        console.error('Error en PUT /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/tiendas/:id', async (req, res) => {
    try {
        const { error } = await supabase
            .from('stores')
            .delete()
            .eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/categorias', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.query.tienda)
            .single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('Error en /api/admin/categorias:', error);
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', async (req, res) => {
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
        console.error('Error en POST /api/admin/categorias:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/productos', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', req.query.tienda)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/admin/productos:', error);
        res.json([]);
    }
});

app.post('/api/admin/productos', upload.single('imagen'), async (req, res) => {
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
        
        if (req.file) {
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) {
                imagen = uploadedUrl;
            } else {
                return res.status(500).json({ error: 'Error al subir la imagen a Supabase' });
            }
        }
        
        const productoData = {
            tienda: req.body.tienda,
            nombre: req.body.nombre,
            descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            imagen: imagen,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros',
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const { data, error } = await supabase
            .from('products')
            .insert(productoData)
            .select();
        
        if (error) throw error;
        res.json({ success: true, data: data });
        
    } catch (error) {
        console.error('❌ ERROR:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/admin/productos/:id', upload.single('imagen'), async (req, res) => {
    try {
        const { data: oldProduct } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', req.params.id)
            .single();
        
        const updateData = {
            nombre: req.body.nombre,
            descripcion: req.body.descripcion,
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio,
            categoria: req.body.categoria,
            updated_at: new Date()
        };
        
        if (req.file) {
            if (oldProduct?.imagen && !oldProduct.imagen.includes('via.placeholder.com')) {
                await deleteFromSupabase(oldProduct.imagen);
            }
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) updateData.imagen = uploadedUrl;
        } else if (req.body.imagen_url) {
            updateData.imagen = req.body.imagen_url;
        }
        
        const { error } = await supabase
            .from('products')
            .update(updateData)
            .eq('id', req.params.id);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/productos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', async (req, res) => {
    try {
        const { data: product } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', req.params.id)
            .single();
        
        if (product?.imagen && !product.imagen.includes('via.placeholder.com')) {
            await deleteFromSupabase(product.imagen);
        }
        
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/productos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/pedidos', async (req, res) => {
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
        console.error('Error en /api/admin/pedidos:', error);
        res.json([]);
    }
});

app.get('/api/admin/pedidos/buscar', async (req, res) => {
    try {
        const { codigo, tienda } = req.query;
        
        if (!codigo) {
            return res.status(400).json({ 
                success: false, 
                error: 'Se requiere un código de pedido' 
            });
        }
        
        let query = supabase
            .from('orders')
            .select('*')
            .eq('codigo_cliente', codigo.toUpperCase())
            .order('created_at', { ascending: false });
        
        if (tienda) {
            query = query.eq('tienda', tienda);
        }
        
        const { data, error } = await query;
        
        if (error) throw error;
        
        res.json({ 
            success: true, 
            data: data || [] 
        });
    } catch (error) {
        console.error('Error en /api/admin/pedidos/buscar:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

app.put('/api/admin/pedidos/:id', async (req, res) => {
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
        console.error('Error en PUT /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos/:id', async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('id', req.params.id)
            .eq('tienda', req.query.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos', async (req, res) => {
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
        console.error('Error en DELETE /api/admin/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// CONFIGURACIÓN ADMIN
// ============================================
app.get('/api/admin/config', async (req, res) => {
    try {
        console.log('📊 Cargando configuración...');
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        
        if (error) {
            console.log('⚠️ No hay configuración, creando por defecto...');
            const defaultConfig = {
                id: 1,
                moneda_base: 'CUP',
                tasas: {
                    CUP: 1,
                    USD: 0.04,
                    EUR: 0.037
                },
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };
            
            const { error: insertError } = await supabase
                .from('config')
                .insert(defaultConfig);
            
            if (insertError) {
                console.log('⚠️ No se pudo crear configuración por defecto:', insertError);
            }
            
            return res.json(defaultConfig);
        }
        
        console.log('📊 Configuración cargada:', data);
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/admin/config:', error);
        res.json({ 
            moneda_base: 'CUP', 
            tasas: { 
                CUP: 1, 
                USD: 0.04, 
                EUR: 0.037 
            }
        });
    }
});

app.put('/api/admin/config', async (req, res) => {
    try {
        console.log('💾 Guardando configuración:', req.body);
        
        const { monedaBase, tasas } = req.body;
        
        if (!tasas || tasas.USD <= 0 || tasas.EUR <= 0) {
            return res.status(400).json({ 
                success: false,
                error: 'Las tasas deben ser mayores a 0' 
            });
        }
        
        const configData = {
            moneda_base: monedaBase || 'CUP',
            tasas: {
                CUP: 1,
                USD: parseFloat(tasas.USD) || 0.04,
                EUR: parseFloat(tasas.EUR) || 0.037
            },
            updated_at: new Date().toISOString()
        };
        
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
        
        if (result.error) {
            console.error('❌ Error en Supabase:', result.error);
            throw result.error;
        }
        
        console.log('✅ Configuración guardada correctamente');
        res.json({ 
            success: true,
            message: 'Configuración guardada correctamente',
            data: configData
        });
    } catch (error) {
        console.error('❌ Error en PUT /api/admin/config:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ============================================
// MANEJO DE RUTAS NO ENCONTRADAS (404)
// ============================================
app.use((req, res) => {
    // Si la ruta comienza con /api, devolver JSON
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ 
            success: false, 
            error: 'API endpoint no encontrado' 
        });
    }
    // Para rutas no API, devolver página 404 HTML
    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>404 - Página no encontrada</title>
            <style>
                body {
                    font-family: 'Inter', system-ui, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    background: #f8fafc;
                }
                .container {
                    text-align: center;
                    padding: 40px;
                }
                h1 {
                    font-size: 6rem;
                    margin: 0;
                    background: linear-gradient(135deg, #4f46e5, #8b5cf6);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                h2 {
                    color: #1e293b;
                    margin: 8px 0;
                }
                p {
                    color: #64748b;
                    margin: 16px 0;
                }
                a {
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #4f46e5, #8b5cf6);
                    color: white;
                    text-decoration: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: transform 0.2s;
                }
                a:hover {
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>404</h1>
                <h2>Página no encontrada</h2>
                <p>Lo sentimos, la página que buscas no existe.</p>
                <a href="/">Volver al inicio</a>
            </div>
        </body>
        </html>
    `);
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    
    // Si la ruta comienza con /api, devolver JSON
    if (req.path.startsWith('/api/')) {
        return res.status(500).json({ 
            success: false,
            error: process.env.NODE_ENV === 'production' 
                ? 'Error interno del servidor' 
                : err.message 
        });
    }
    
    // Para rutas no API, devolver HTML
    res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Error - Tienda La Reina</title>
            <style>
                body {
                    font-family: 'Inter', system-ui, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    background: #f8fafc;
                }
                .container {
                    text-align: center;
                    padding: 40px;
                }
                h1 {
                    font-size: 4rem;
                    margin: 0;
                    color: #ef4444;
                }
                h2 {
                    color: #1e293b;
                    margin: 8px 0;
                }
                p {
                    color: #64748b;
                    margin: 16px 0;
                }
                a {
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #4f46e5, #8b5cf6);
                    color: white;
                    text-decoration: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: transform 0.2s;
                }
                a:hover {
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚠️</h1>
                <h2>Error del servidor</h2>
                <p>Lo sentimos, ha ocurrido un error interno.</p>
                <a href="/">Volver al inicio</a>
            </div>
        </body>
        </html>
    `);
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Tienda La Reina corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin password: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ No configurada'}`);
    console.log(`🔒 Autenticación obligatoria en /api/admin/*: ✅ Activada`);
    console.log(`🗄️ Supabase conectado: ${SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`📸 Usando bucket: 'Productos'`);
    console.log(`🛡️ Bloqueo de rutas sospechosas: ✅ Activado`);
    console.log(`🛡️ Rate Limiting (${RATE_LIMIT_MAX} pedidos/hora): ✅ Activado`);
    console.log(`📋 Panel Admin: ${process.env.URL || 'https://la-reina-mgje.onrender.com'}/admin`);
    console.log(`📦 Pedidos: SIN 'ip' y SIN 'user_agent' (corregido)`);
    console.log(`📊 Config: usando 'moneda_base' (corregido)`);
    console.log(`📁 Archivos servidos desde: ${__dirname}`);
    console.log('========================================');
});