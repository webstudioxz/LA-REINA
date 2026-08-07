import express from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// ============================================
// CARGAR VARIABLES DE ENTORNO
// ============================================
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// VARIABLES DE ENTORNO CON FALLBACK
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
// FALLBACK: Si no está en variables de entorno, usar valor por defecto
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';

// ============================================
// LOGS DE DIAGNÓSTICO (CRÍTICOS)
// ============================================
console.log('🔍 ========== DIAGNÓSTICO DE ENTORNO ==========');
console.log(`🔍 SUPABASE_URL: ${SUPABASE_URL ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`🔍 SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`🔍 ADMIN_PASSWORD: ${ADMIN_PASSWORD && ADMIN_PASSWORD !== 'Admin123!' ? '✅ Configurada en variables de entorno' : '⚠️ Usando valor por defecto (Admin123!)'}`);
console.log(`🔍 ADMIN_PASSWORD longitud: ${ADMIN_PASSWORD ? ADMIN_PASSWORD.length : 0} caracteres`);
console.log(`🔍 NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
console.log('🔍 ============================================');

// ============================================
// VALIDACIÓN DE VARIABLES CRÍTICAS
// ============================================
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    console.error('❌ Por favor, configura estas variables en Render o en .env');
    process.exit(1);
}

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
        '/login', '/admin', '/wp-admin', '/cpanel',
        '/plesk', '/phpmyadmin', '/mysql', '/db',
        '/config', '/.env', '/.git', '/backup',
        '/shell', '/cmd', '/exec', '/system',
        '/vendor', '/composer', '/.ssh', '/.aws',
        '/.htaccess', '/web.config', '/robots.txt', '/sitemap.xml'
    ];
    
    const requestPath = req.path.toLowerCase();
    if (blockedPaths.some(path => requestPath.startsWith(path))) {
        console.log(`🔴 [BLOQUEADO] Acceso a ${req.path} desde ${req.ip}`);
        return res.status(404).send('Not Found');
    }
    next();
});

// ============================================
// ENDPOINT DE DIAGNÓSTICO (SEGURO)
// ============================================
app.get('/api/admin/test-env', (req, res) => {
    const hasPassword = !!ADMIN_PASSWORD && ADMIN_PASSWORD !== 'Admin123!';
    const passwordLength = ADMIN_PASSWORD ? ADMIN_PASSWORD.length : 0;
    
    res.json({
        hasPassword: hasPassword,
        passwordLength: passwordLength,
        isDefault: ADMIN_PASSWORD === 'Admin123!',
        message: hasPassword ? '✅ ADMIN_PASSWORD cargada correctamente' : '⚠️ ADMIN_PASSWORD usa valor por defecto (Admin123!)'
    });
});

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const adminPass = req.headers['admin-password'] || req.query.password;
    
    if (token && sessions.has(token)) {
        const session = sessions.get(token);
        if (session.expiry > Date.now()) {
            session.expiry = Date.now() + 3600000;
            sessions.set(token, session);
            return next();
        }
        sessions.delete(token);
    }
    
    if (adminPass && adminPass === ADMIN_PASSWORD) {
        const newToken = crypto.randomBytes(32).toString('hex');
        sessions.set(newToken, { 
            expiry: Date.now() + 3600000,
            ip: req.ip 
        });
        req.sessionToken = newToken;
        return next();
    }
    
    console.log(`🔴 Intento de acceso no autorizado a ${req.path} desde ${req.ip}`);
    return res.status(401).json({ 
        error: 'No autorizado', 
        message: 'Debes iniciar sesión para acceder a esta sección' 
    });
};

app.use('/api/admin', requireAuth);

// ============================================
// RUTAS DE AUTENTICACIÓN (CON LOGS DETALLADOS)
// ============================================
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
    console.log(`🔐 Intento de login desde ${req.ip}`);
    console.log(`🔐 Contraseña recibida: ${password ? '***' : '(vacía)'}`);
    console.log(`🔐 ADMIN_PASSWORD configurada: ${ADMIN_PASSWORD ? '✅ Sí' : '❌ No'}`);
    
    if (!password) {
        return res.status(400).json({ success: false, error: 'Contraseña requerida' });
    }
    
    // Limpiar espacios en blanco
    const cleanPassword = password.trim();
    const cleanAdminPassword = ADMIN_PASSWORD ? ADMIN_PASSWORD.trim() : '';
    
    // Comparación segura
    if (cleanPassword === cleanAdminPassword) {
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
        res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
    }
});

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
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================
// API PÚBLICA
// ============================================
app.get('/api/status', (req, res) => res.json({ online: true }));

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
        console.error('Error en /api/config:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.post('/api/pedidos', async (req, res) => {
    try {
        const tienda = req.body.tienda || 'electro';
        const codigoCliente = generarCodigoUnico();
        
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();
        
        const nextId = (counterData?.counter || 0) + 1;
        
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda: tienda,
            nombre: req.body.nombre,
            telefono: req.body.telefono,
            direccion: req.body.direccion,
            items: req.body.items || [],
            total: req.body.total || 0,
            moneda: req.body.moneda || 'CUP',
            metodo_pago: req.body.metodoPago || 'Efectivo',
            estado: 'pendiente',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        res.json({ 
            success: true, 
            orderId: nextId, 
            codigoCliente: codigoCliente 
        });
    } catch (error) {
        console.error('Error en /api/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

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
        
        console.log(`📸 Subiendo a Supabase: bucket '${folder}', ruta '${filePath}'`);
        
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
        
        console.log('✅ Imagen subida:', publicUrl);
        return publicUrl;
    } catch (error) {
        console.error('❌ Error subiendo imagen a Supabase:', error);
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
        console.log('🗑️ Imagen eliminada:', filePath);
        return true;
    } catch (error) {
        console.error('❌ Error eliminando imagen de Supabase:', error);
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
// API ADMIN (TODAS PROTEGIDAS)
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
    console.log('========== CREANDO PRODUCTO ==========');
    console.log('Tienda:', req.body.tienda);
    console.log('Nombre:', req.body.nombre);
    console.log('Precio:', req.body.precio);
    
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
        
        if (req.file) {
            console.log('📸 Subiendo imagen a Supabase (bucket: Productos)...');
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) {
                imagen = uploadedUrl;
                console.log('✅ Imagen subida correctamente');
            } else {
                console.error('❌ Error: uploadToSupabase devolvió null');
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
        
        console.log('💾 Insertando en Supabase (tabla products)...');
        const { data, error } = await supabase
            .from('products')
            .insert(productoData)
            .select();
        
        if (error) {
            console.error('❌ ERROR DE SUPABASE:', error);
            return res.status(500).json({ success: false, error: error.message });
        }
        
        console.log('✅ Producto creado exitosamente:', data);
        console.log('========== FIN CREAR PRODUCTO ==========\n');
        res.json({ success: true, data: data });
        
    } catch (error) {
        console.error('❌ ERROR GENERAL:', error);
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

app.get('/api/admin/config', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        console.error('Error en /api/admin/config:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', async (req, res) => {
    try {
        const configData = {
            monedaBase: req.body.monedaBase || 'CUP',
            tasas: {
                CUP: 1,
                USD: req.body.tasas?.USD || 0.04,
                EUR: req.body.tasas?.EUR || 0.037
            },
            updated_at: new Date()
        };
        
        if (configData.tasas.USD <= 0 || configData.tasas.EUR <= 0) {
            return res.status(400).json({ error: 'Las tasas deben ser mayores a 0' });
        }
        
        const { error } = await supabase
            .from('config')
            .upsert({ 
                id: 1, 
                ...configData
            });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/config:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    res.status(500).json({ 
        error: process.env.NODE_ENV === 'production' 
            ? 'Error interno del servidor' 
            : err.message 
    });
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Tienda La Reina corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin password: ${ADMIN_PASSWORD && ADMIN_PASSWORD !== 'Admin123!' ? '✅ Configurada en variables de entorno' : '⚠️ Usando valor por defecto (Admin123!)'}`);
    console.log(`🔒 Autenticación obligatoria en /api/admin/*: ✅ Activada`);
    console.log(`🗄️ Supabase conectado: ${SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`📸 Usando bucket: 'Productos'`);
    console.log(`🛡️ Bloqueo de rutas sospechosas: ✅ Activado`);
    console.log(`📋 Variables de entorno: ${process.env.NODE_ENV === 'production' ? '🟢 Producción' : '🟡 Desarrollo'}`);
    console.log(`📋 Para probar: https://${process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'}/api/admin/test-env`);
});