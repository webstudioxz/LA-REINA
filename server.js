import express from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import hpp from 'hpp';
import NodeCache from 'node-cache';
import { SitemapStream, streamToPromise } from 'sitemap';
import { createGzip } from 'zlib';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// CACHÉ EN MEMORIA
// ============================================
const cache = new NodeCache({
    stdTTL: 300,
    checkperiod: 60,
    maxKeys: 1000
});

// ============================================
// VARIABLES DE ENTORNO
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SITE_URL = process.env.URL || 'https://la-reina-mgje.onrender.com';

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR CRÍTICO: ADMIN_PASSWORD no está configurada');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE DE SEGURIDAD Y RENDIMIENTO
// ============================================

app.use(compression({
    level: 9,
    threshold: 1024
}));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:", "*.supabase.co", "via.placeholder.com", "d.top4top.io", "i.ibb.co", "images.unsplash.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "*.supabase.co"],
        }
    }
}));

app.use(cors({
    origin: [SITE_URL, 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Admin-Password'],
    credentials: true
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones' }
});
app.use('/api', limiter);

app.use(hpp());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// CACHE HEADERS PARA ARCHIVOS ESTÁTICOS
// ============================================
const staticOptions = {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=3600');
        } else if (filePath.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|webp)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
        }
    },
    maxAge: '1d'
};

app.use(express.static(__dirname, staticOptions));

// ============================================
// ROBOTS.TXT
// ============================================
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send(`
User-agent: *
Allow: /
Disallow: /api/
Disallow: /admin/
Sitemap: ${SITE_URL}/sitemap.xml
Host: ${SITE_URL}
    `.trim());
});

// ============================================
// SITEMAP.XML
// ============================================
app.get('/sitemap.xml', async (req, res) => {
    try {
        const { data: products } = await supabase
            .from('products')
            .select('id, tienda, updated_at')
            .order('updated_at', { ascending: false })
            .limit(500);

        const { data: stores } = await supabase
            .from('stores')
            .select('id, updated_at');

        const smStream = new SitemapStream({
            hostname: SITE_URL,
            cacheTime: 600000
        });

        smStream.write({
            url: '/',
            changefreq: 'daily',
            priority: 1.0,
            lastmod: new Date().toISOString()
        });

        if (stores) {
            stores.forEach(store => {
                smStream.write({
                    url: `/?tienda=${store.id}`,
                    changefreq: 'daily',
                    priority: 0.9,
                    lastmod: store.updated_at || new Date().toISOString()
                });
            });
        }

        if (products) {
            products.forEach(product => {
                smStream.write({
                    url: `/producto/${product.id}`,
                    changefreq: 'weekly',
                    priority: 0.7,
                    lastmod: product.updated_at || new Date().toISOString()
                });
            });
        }

        smStream.end();

        const sitemap = await streamToPromise(smStream);
        const gzipped = await new Promise((resolve, reject) => {
            createGzip()
                .on('data', chunk => resolve(chunk))
                .on('error', reject)
                .end(sitemap);
        });

        res.header('Content-Type', 'application/gzip');
        res.header('Content-Encoding', 'gzip');
        res.send(gzipped);

    } catch (error) {
        console.error('Error generando sitemap:', error);
        res.status(500).json({ error: 'Error generando sitemap' });
    }
});

// ============================================
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin.html', (req, res) => {
    res.redirect('/admin');
});

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
// RATE LIMITING POR IP
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
// BLOQUEO DE RUTAS SOSPECHOSAS
// ============================================
app.use((req, res, next) => {
    const blockedPaths = [
        '/wp-admin', '/cpanel', '/plesk', '/phpmyadmin',
        '/mysql', '/db', '/config', '/.env', '/.git',
        '/backup', '/shell', '/cmd', '/exec', '/system',
        '/vendor', '/composer', '/.ssh', '/.aws',
        '/.htaccess', '/web.config'
    ];
    
    const requestPath = req.path.toLowerCase();
    if (blockedPaths.some(path => requestPath.startsWith(path))) {
        return res.status(404).send('Not Found');
    }
    next();
});

// ============================================
// LOGIN
// ============================================
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
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
        
        res.json({ 
            success: true, 
            token: token,
            expires: expiry 
        });
    } else {
        res.status(401).json({ 
            success: false, 
            error: 'Contraseña incorrecta' 
        });
    }
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

app.get('/api/status', (req, res) => {
    res.json({ online: true, timestamp: new Date().toISOString() });
});

app.get('/api/config', async (req, res) => {
    const cacheKey = 'config';
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

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
            cache.set(cacheKey, defaultConfig);
            return res.json(defaultConfig);
        }
        
        cache.set(cacheKey, data);
        res.json(data);
    } catch (error) {
        console.error('Error en /api/config:', error);
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

app.get('/api/tiendas/info', async (req, res) => {
    const cacheKey = 'tiendas_info';
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        cache.set(cacheKey, data || []);
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/tiendas/info:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/tiendas/:id', async (req, res) => {
    const cacheKey = `tienda_${req.params.id}`;
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

    try {
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Tienda no encontrada' });
        cache.set(cacheKey, data);
        res.json(data);
    } catch (error) {
        console.error('Error en /api/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    const cacheKey = `tienda_config_${req.params.id}`;
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

    try {
        const { data, error } = await supabase
            .from('stores')
            .select('configuracion')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        const config = data?.configuracion || {};
        cache.set(cacheKey, config);
        res.json(config);
    } catch (error) {
        console.error('Error en /api/tiendas/:id/config:', error);
        res.json({});
    }
});

app.get('/api/productos', async (req, res) => {
    const tienda = req.query.tienda || 'electro';
    const cacheKey = `productos_${tienda}`;
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .order('created_at', { ascending: false });
        if (error) throw error;
        cache.set(cacheKey, data || []);
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/productos:', error);
        res.json([]);
    }
});

app.get('/api/categorias', async (req, res) => {
    const tienda = req.query.tienda || 'electro';
    const cacheKey = `categorias_${tienda}`;
    let cached = cache.get(cacheKey);
    if (cached) {
        return res.json(cached);
    }

    try {
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', tienda)
            .single();
        if (error) throw error;
        const cats = data?.categorias || ['otros'];
        cache.set(cacheKey, cats);
        res.json(cats);
    } catch (error) {
        console.error('Error en /api/categorias:', error);
        res.json(['otros']);
    }
});

// ============================================
// API PEDIDOS
// ============================================
app.post('/api/pedidos', async (req, res) => {
    try {
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
        cache.del('tiendas_info');
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
        cache.del(`tienda_${req.params.id}`);
        cache.del(`tienda_config_${req.params.id}`);
        cache.del('tiendas_info');
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
        cache.del(`tienda_${req.params.id}`);
        cache.del(`tienda_config_${req.params.id}`);
        cache.del('tiendas_info');
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
        cache.del(`categorias_${req.body.tienda}`);
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
                return res.status(500).json({ error: 'Error al subir la imagen' });
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
        cache.del(`productos_${req.body.tienda}`);
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
            .select('imagen, tienda')
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
        if (oldProduct?.tienda) {
            cache.del(`productos_${oldProduct.tienda}`);
        }
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
            .select('imagen, tienda')
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
        if (product?.tienda) {
            cache.del(`productos_${product.tienda}`);
        }
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
        const { data, error } = await supabase
            .from('config')
            .select('*')
            .eq('id', 1)
            .single();
        
        if (error) {
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
            return res.json(defaultConfig);
        }
        
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
        
        if (result.error) throw result.error;
        
        cache.del('config');
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
// MANEJO DE ERRORES
// ============================================
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ 
            success: false, 
            error: 'API endpoint no encontrado' 
        });
    }
    res.status(404).sendFile(path.join(__dirname, '404.html'));
});

app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    if (req.path.startsWith('/api/')) {
        return res.status(500).json({ 
            success: false,
            error: process.env.NODE_ENV === 'production' 
                ? 'Error interno del servidor' 
                : err.message 
        });
    }
    res.status(500).sendFile(path.join(__dirname, '404.html'));
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Tienda La Reina corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin password: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
    console.log(`📊 Caché activado: ✅`);
    console.log(`🗜️ Compresión GZIP: ✅`);
    console.log(`📋 Panel Admin: ${SITE_URL}/admin`);
    console.log(`📄 Sitemap: ${SITE_URL}/sitemap.xml`);
    console.log('========================================');
});