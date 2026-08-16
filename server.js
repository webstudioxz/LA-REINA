import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';
import {
    helmetMiddleware,
    corsMiddleware,
    rateLimiter,
    hppMiddleware,
    sanitizeInput,
    sqlInjectionFilter,
    validateProduct,
    validateInventory,
    bruteForceProtection,
    validateFileUpload
} from './security-middleware.js';

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

if (!ADMIN_PASSWORD || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Variables de entorno faltantes');
    console.error('❌ ADMIN_PASSWORD:', ADMIN_PASSWORD ? '✅ Configurada' : '❌ Faltante');
    console.error('❌ SUPABASE_URL:', SUPABASE_URL ? '✅ Configurada' : '❌ Faltante');
    console.error('❌ SUPABASE_SERVICE_ROLE_KEY:', SUPABASE_SERVICE_ROLE_KEY ? '✅ Configurada' : '❌ Faltante');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// RATE LIMITING POR IP PARA PEDIDOS
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
}, 60000);

// ============================================
// MIDDLEWARE BASE
// ============================================
app.use(helmetMiddleware);
app.use(corsMiddleware);
app.use(hppMiddleware);
app.use(rateLimiter);
app.use(sqlInjectionFilter);
app.use(sanitizeInput);
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(__dirname));

// ============================================
// BLOQUEO DE RUTAS SOSPECHOSAS
// ============================================
app.use((req, res, next) => {
    const blockedPaths = [
        '/wp-admin', '/cpanel', '/plesk', '/phpmyadmin',
        '/mysql', '/db', '/config', '/.env', '/.git',
        '/backup', '/shell', '/cmd', '/exec', '/system',
        '/vendor', '/composer', '/.ssh', '/.aws',
        '/.htaccess', '/web.config', '/robots.txt', '/sitemap.xml',
        '/xmlrpc.php', '/.env.local', '/.env.production'
    ];
    
    const requestPath = req.path.toLowerCase();
    if (blockedPaths.some(path => requestPath.startsWith(path))) {
        console.log(`🔴 [BLOQUEADO] ${req.path} desde ${req.ip}`);
        return res.status(404).send('Not Found');
    }
    next();
});

// ============================================
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================
// CONFIGURACIÓN DE MULTER
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'), false);
        }
    }
});

// ============================================
// FUNCIONES AUXILIARES
// ============================================

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        if (!file || !file.buffer) return null;
        
        const fileExt = file.originalname.split('.').pop() || 'jpg';
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { data, error } = await supabase.storage
            .from(folder)
            .upload(filePath, file.buffer, {
                cacheControl: '3600',
                upsert: false,
                contentType: file.mimetype || 'image/jpeg'
            });
        
        if (error) {
            console.error('❌ Error en upload a Supabase:', error);
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
// TOKEN SIMPLE (SIN JWT - SOLO RANDOM)
// ============================================
const activeTokens = new Map();

function generateSimpleToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN MEJORADO
// ============================================
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    console.log(`🔑 Verificando token: ${token ? token.substring(0, 20) + '...' : 'No token'}`);
    console.log(`🔑 Tokens activos: ${activeTokens.size}`);
    
    if (!token) {
        console.log('❌ No hay token en la solicitud');
        return res.status(401).json({ 
            error: 'No autorizado',
            message: 'Token no proporcionado'
        });
    }
    
    const tokenData = activeTokens.get(token);
    if (!tokenData) {
        console.log('❌ Token no encontrado en memoria');
        return res.status(401).json({ 
            error: 'No autorizado',
            message: 'Token inválido'
        });
    }
    
    if (Date.now() < tokenData.expires) {
        console.log('✅ Token válido, expira en:', new Date(tokenData.expires).toISOString());
        return next();
    } else {
        activeTokens.delete(token);
        console.log('❌ Token expirado');
        return res.status(401).json({ 
            error: 'No autorizado',
            message: 'Token expirado'
        });
    }
};

// ============================================
// LOGIN (PÚBLICO - SIN AUTENTICACIÓN) MEJORADO
// ============================================
app.post('/api/admin/login', bruteForceProtection.check, async (req, res) => {
    const { password } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    
    console.log('🔐 ========== LOGIN ==========');
    console.log(`🔐 IP: ${ip}`);
    console.log(`🔐 Password recibida: ${password ? '***' : 'vacía'}`);
    console.log(`🔐 ADMIN_PASSWORD configurada: ${ADMIN_PASSWORD ? '✅ Sí' : '❌ No'}`);
    console.log(`🔐 Longitud admin password: ${ADMIN_PASSWORD ? ADMIN_PASSWORD.length : 0}`);
    console.log(`🔐 URL: ${req.protocol}://${req.get('host')}${req.originalUrl}`);
    console.log('🔐 ============================');
    
    if (!password) {
        return res.status(400).json({ 
            success: false, 
            error: 'Contraseña requerida' 
        });
    }
    
    // Limpiar espacios y comparar
    const cleanPassword = password.trim();
    const cleanAdminPassword = ADMIN_PASSWORD ? ADMIN_PASSWORD.trim() : '';
    
    console.log(`🔐 Comparando longitud: ${cleanPassword.length} vs ${cleanAdminPassword.length}`);
    console.log(`🔐 Coinciden exactamente: ${cleanPassword === cleanAdminPassword}`);
    
    if (cleanPassword === cleanAdminPassword) {
        bruteForceProtection.recordAttempt(ip, true);
        
        const token = generateSimpleToken();
        const expiresAt = Date.now() + 3600000; // 1 hora
        activeTokens.set(token, {
            expires: expiresAt,
            ip: ip,
            created: Date.now()
        });
        
        console.log(`✅ Login exitoso desde ${ip}`);
        console.log(`✅ Token: ${token.substring(0, 20)}...`);
        console.log(`✅ Expira: ${new Date(expiresAt).toISOString()}`);
        console.log(`✅ Tokens activos: ${activeTokens.size}`);
        
        res.json({ 
            success: true, 
            token: token,
            expires: expiresAt
        });
    } else {
        bruteForceProtection.recordAttempt(ip, false);
        console.log(`🔴 Login fallido desde ${ip} - Contraseña incorrecta`);
        res.status(401).json({ 
            success: false, 
            error: 'Contraseña incorrecta' 
        });
    }
});

// ============================================
// VERIFICAR SESIÓN
// ============================================
app.get('/api/admin/verify-session', requireAuth, (req, res) => {
    res.json({ valid: true });
});

// ============================================
// LOGOUT
// ============================================
app.post('/api/admin/logout', requireAuth, (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
        activeTokens.delete(token);
        console.log(`👋 Logout - Token eliminado. Tokens restantes: ${activeTokens.size}`);
    }
    res.json({ success: true });
});

// ============================================
// PRODUCTOS (PROTEGIDOS)
// ============================================

app.get('/api/admin/productos', requireAuth, async (req, res) => {
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

app.post('/api/admin/productos', requireAuth, upload.array('imagenes', 10), validateFileUpload, validateProduct, async (req, res) => {
    try {
        console.log('📦 Creando producto:', req.body.nombre);
        
        let images = ['https://via.placeholder.com/400'];
        
        if (req.files && req.files.length > 0) {
            const uploadedUrls = [];
            for (const file of req.files) {
                const uploadedUrl = await uploadToSupabase(file, 'Productos');
                if (uploadedUrl) {
                    uploadedUrls.push(uploadedUrl);
                }
            }
            if (uploadedUrls.length > 0) {
                images = uploadedUrls;
            }
        } else if (req.body.images) {
            try {
                if (typeof req.body.images === 'string') {
                    images = JSON.parse(req.body.images);
                } else if (Array.isArray(req.body.images)) {
                    images = req.body.images;
                }
            } catch {
                images = [req.body.images];
            }
        }
        
        const productoData = {
            tienda: req.body.tienda,
            nombre: req.body.nombre.trim(),
            descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            images: images,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros',
            has_variants: req.body.has_variants === 'true',
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const { data, error } = await supabase
            .from('products')
            .insert(productoData)
            .select();
        
        if (error) throw error;
        console.log('✅ Producto creado:', data[0].id);
        res.json({ success: true, data: data });
        
    } catch (error) {
        console.error('❌ ERROR en POST producto:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/admin/productos/:id', requireAuth, upload.array('imagenes', 10), validateFileUpload, validateProduct, async (req, res) => {
    try {
        console.log('📦 Actualizando producto:', req.params.id);
        
        const { data: oldProduct } = await supabase
            .from('products')
            .select('images')
            .eq('id', req.params.id)
            .single();
        
        let images = oldProduct?.images || ['https://via.placeholder.com/400'];
        
        if (req.files && req.files.length > 0) {
            const uploadedUrls = [];
            for (const file of req.files) {
                const uploadedUrl = await uploadToSupabase(file, 'Productos');
                if (uploadedUrl) {
                    uploadedUrls.push(uploadedUrl);
                }
            }
            if (uploadedUrls.length > 0) {
                // Eliminar imágenes antiguas
                for (const oldImage of images) {
                    if (!oldImage.includes('via.placeholder.com')) {
                        await deleteFromSupabase(oldImage);
                    }
                }
                images = uploadedUrls;
            }
        } else if (req.body.images) {
            try {
                if (typeof req.body.images === 'string') {
                    images = JSON.parse(req.body.images);
                } else if (Array.isArray(req.body.images)) {
                    images = req.body.images;
                }
            } catch {
                images = [req.body.images];
            }
        }
        
        const updateData = {
            nombre: req.body.nombre.trim(),
            descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            images: images,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros',
            has_variants: req.body.has_variants === 'true',
            updated_at: new Date()
        };
        
        const { error } = await supabase
            .from('products')
            .update(updateData)
            .eq('id', req.params.id);
        
        if (error) throw error;
        console.log('✅ Producto actualizado:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ ERROR en PUT producto:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', requireAuth, async (req, res) => {
    try {
        console.log('🗑️ Eliminando producto:', req.params.id);
        
        const { data: product } = await supabase
            .from('products')
            .select('images')
            .eq('id', req.params.id)
            .single();
        
        if (product?.images) {
            for (const image of product.images) {
                if (!image.includes('via.placeholder.com')) {
                    await deleteFromSupabase(image);
                }
            }
        }
        
        await supabase
            .from('inventory')
            .delete()
            .eq('product_id', req.params.id);
        
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);
        
        if (error) throw error;
        console.log('✅ Producto eliminado:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ ERROR en DELETE producto:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// INVENTARIO (PROTEGIDO)
// ============================================

app.get('/api/admin/inventory/:productId', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('inventory')
            .select('*')
            .eq('product_id', req.params.productId)
            .order('is_default', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/admin/inventory/:productId:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/inventory', requireAuth, validateInventory, async (req, res) => {
    try {
        const { product_id, variant_name, sku, stock, price_adjustment, is_default } = req.body;
        
        console.log('📦 Creando variante:', variant_name, 'para producto:', product_id);
        
        const { data: existing } = await supabase
            .from('inventory')
            .select('id')
            .eq('product_id', product_id)
            .eq('variant_name', variant_name)
            .single();
        
        let result;
        if (existing) {
            result = await supabase
                .from('inventory')
                .update({
                    sku: sku || '',
                    stock: parseInt(stock) || 0,
                    price_adjustment: parseFloat(price_adjustment) || 0,
                    is_default: is_default === true || is_default === 'true',
                    updated_at: new Date()
                })
                .eq('id', existing.id);
        } else {
            result = await supabase
                .from('inventory')
                .insert({
                    product_id,
                    variant_name: variant_name.trim(),
                    sku: sku || '',
                    stock: parseInt(stock) || 0,
                    price_adjustment: parseFloat(price_adjustment) || 0,
                    is_default: is_default === true || is_default === 'true'
                });
        }
        
        if (result.error) throw result.error;
        
        await supabase
            .from('products')
            .update({ has_variants: true, updated_at: new Date() })
            .eq('id', product_id);
        
        console.log('✅ Variante creada/actualizada');
        res.json({ success: true });
    } catch (error) {
        console.error('Error en POST /api/admin/inventory:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/inventory/:id', requireAuth, async (req, res) => {
    try {
        const { stock, price_adjustment } = req.body;
        console.log('📦 Actualizando variante:', req.params.id);
        
        const { error } = await supabase
            .from('inventory')
            .update({ 
                stock: parseInt(stock) || 0,
                price_adjustment: parseFloat(price_adjustment) || 0,
                updated_at: new Date()
            })
            .eq('id', req.params.id);
        
        if (error) throw error;
        console.log('✅ Variante actualizada:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/inventory/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/inventory/:id', requireAuth, async (req, res) => {
    try {
        console.log('🗑️ Eliminando variante:', req.params.id);
        const { error } = await supabase
            .from('inventory')
            .delete()
            .eq('id', req.params.id);
        
        if (error) throw error;
        console.log('✅ Variante eliminada');
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/inventory/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// TIENDAS (PROTEGIDAS)
// ============================================

app.get('/api/admin/tiendas', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/admin/tiendas:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/tiendas/:id', requireAuth, async (req, res) => {
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

app.post('/api/admin/tiendas', requireAuth, async (req, res) => {
    try {
        const storeId = req.body.id?.toLowerCase().trim();
        if (!storeId) {
            return res.status(400).json({ error: 'ID de tienda requerido' });
        }
        
        const { error } = await supabase.from('stores').insert({
            id: storeId,
            nombre: req.body.nombre?.trim() || storeId,
            icono: req.body.icono || '🛒',
            descripcion: req.body.descripcion || '',
            configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros'],
            created_at: new Date(),
            updated_at: new Date()
        });
        if (error) throw error;
        console.log('✅ Tienda creada:', storeId);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en POST /api/admin/tiendas:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/tiendas/:id', requireAuth, async (req, res) => {
    try {
        const { error } = await supabase
            .from('stores')
            .update({
                nombre: req.body.nombre?.trim(),
                icono: req.body.icono,
                descripcion: req.body.descripcion,
                configuracion: req.body.configuracion,
                categorias: req.body.categorias,
                updated_at: new Date()
            })
            .eq('id', req.params.id);
        if (error) throw error;
        console.log('✅ Tienda actualizada:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/tiendas/:id', requireAuth, async (req, res) => {
    try {
        const { error } = await supabase
            .from('stores')
            .delete()
            .eq('id', req.params.id);
        if (error) throw error;
        console.log('🗑️ Tienda eliminada:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// CATEGORÍAS (PROTEGIDAS)
// ============================================

app.get('/api/admin/categorias', requireAuth, async (req, res) => {
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

app.post('/api/admin/categorias', requireAuth, async (req, res) => {
    try {
        const { data: store } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.body.tienda)
            .single();
        
        const currentCats = store?.categorias || [];
        const newCat = req.body.categoria?.toLowerCase().trim();
        if (!newCat) {
            return res.status(400).json({ error: 'Categoría requerida' });
        }
        if (!currentCats.includes(newCat)) {
            currentCats.push(newCat);
        }
        
        const { error } = await supabase
            .from('stores')
            .update({ categorias: currentCats, updated_at: new Date() })
            .eq('id', req.body.tienda);
        
        if (error) throw error;
        console.log('✅ Categoría agregada:', newCat);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en POST /api/admin/categorias:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// PEDIDOS (PROTEGIDOS)
// ============================================

app.get('/api/admin/pedidos', requireAuth, async (req, res) => {
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

app.put('/api/admin/pedidos/:id', requireAuth, async (req, res) => {
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
        console.log('✅ Pedido actualizado:', req.params.id, '->', req.body.estado);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos/:id', requireAuth, async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .delete()
            .eq('id', req.params.id)
            .eq('tienda', req.query.tienda);
        
        if (error) throw error;
        console.log('🗑️ Pedido eliminado:', req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos', requireAuth, async (req, res) => {
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
            
            console.log('🗑️ Todos los pedidos eliminados para:', req.query.tienda);
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/pedidos/buscar', requireAuth, async (req, res) => {
    try {
        const codigo = req.query.codigo?.toUpperCase().trim();
        const tienda = req.query.tienda;
        
        if (!codigo) {
            return res.status(400).json({ 
                success: false, 
                error: 'Código de pedido requerido' 
            });
        }
        
        let query = supabase
            .from('orders')
            .select('*')
            .ilike('codigo_cliente', `%${codigo}%`)
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

// ============================================
// CONFIGURACIÓN (PROTEGIDA)
// ============================================

app.get('/api/admin/config', requireAuth, async (req, res) => {
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
                stock_alert_threshold: 5,
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
        
        console.log('📊 Configuración cargada');
        res.json(data);
    } catch (error) {
        console.error('❌ Error en /api/admin/config:', error);
        res.json({ 
            moneda_base: 'CUP', 
            tasas: { 
                CUP: 1, 
                USD: 0.04, 
                EUR: 0.037 
            },
            stock_alert_threshold: 5
        });
    }
});

app.put('/api/admin/config', requireAuth, async (req, res) => {
    try {
        console.log('💾 Guardando configuración...');
        
        const { monedaBase, tasas, stock_alert_threshold } = req.body;
        
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
            stock_alert_threshold: parseInt(stock_alert_threshold) || 5,
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
// API PÚBLICA (SIN AUTENTICACIÓN)
// ============================================

app.get('/api/status', (req, res) => res.json({ online: true, timestamp: Date.now() }));

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
                stock_alert_threshold: 5,
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
            stock_alert_threshold: 5,
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
// API PEDIDOS (PÚBLICA) MEJORADA
// ============================================

app.post('/api/pedidos', async (req, res) => {
    try {
        console.log('📦 ========== NUEVO PEDIDO ==========');
        
        const tienda = req.body.tienda || 'electro';
        const codigoCliente = generarCodigoUnico();
        
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
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
            console.log(`⚠️ Rate limit excedido para IP: ${ip}`);
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
        
        // Validar items
        const items = req.body.items || [];
        if (!items.length) {
            return res.status(400).json({
                success: false,
                error: 'El carrito está vacío'
            });
        }
        
        // Verificar stock para cada item
        for (const item of items) {
            if (item.variant_id) {
                const { data: variant } = await supabase
                    .from('inventory')
                    .select('stock')
                    .eq('id', item.variant_id)
                    .single();
                
                if (variant && variant.stock < item.qty) {
                    return res.status(400).json({
                        success: false,
                        error: `Stock insuficiente para ${item.nombre}. Disponible: ${variant.stock}`
                    });
                }
            }
        }
        
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda: tienda,
            nombre: req.body.nombre?.slice(0, 60) || 'Cliente',
            telefono: req.body.telefono?.slice(0, 20) || '',
            direccion: req.body.direccion?.slice(0, 200) || '',
            items: items,
            total: parseFloat(req.body.total) || 0,
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
        
        // Actualizar stock
        for (const item of items) {
            if (item.variant_id) {
                await supabase.rpc('decrement_stock', {
                    p_variant_id: item.variant_id,
                    p_quantity: item.qty
                });
            }
        }
        
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        record.count++;
        rateLimitStore.set(ip, record);
        
        console.log(`✅ Pedido #${nextId} registrado con código: ${codigoCliente}`);
        console.log(`📦 Items: ${items.length}, Total: ${req.body.total} ${req.body.moneda || 'CUP'}`);
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
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(400).json({ error: 'El archivo excede el límite de 5MB' });
        }
        if (err.code === 'LIMIT_UNEXPECTED_FILE') {
            return res.status(400).json({ error: 'Demasiados archivos' });
        }
        return res.status(400).json({ error: err.message });
    }
    
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
    console.log('\n========================================');
    console.log(`🚀 Tienda La Reina corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin password: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ No configurada'}`);
    console.log(`🔒 Autenticación con tokens en memoria: ✅ Activado`);
    console.log(`🗄️ Supabase conectado: ${SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`📸 Usando bucket: 'Productos'`);
    console.log(`🛡️ Bloqueo de rutas sospechosas: ✅ Activado`);
    console.log(`📋 Panel Admin: ${process.env.URL || `http://localhost:${PORT}`}/admin`);
    console.log('========================================\n');
});