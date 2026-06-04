import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// VARIABLES DE ENTORNO
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Validar variables
console.log('🔍 Verificando variables de entorno:');
console.log(`SUPABASE_URL: ${SUPABASE_URL ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ FALTA'}`);

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    console.error('Por favor, configura estas variables en Render:');
    console.error('  1. SUPABASE_URL - URL de tu proyecto Supabase');
    console.error('  2. SUPABASE_SERVICE_ROLE_KEY - Clave service_role de Supabase');
    process.exit(1);
}

// Crear cliente de Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Logging de peticiones
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// ============================================
// MULTER PARA SUBIDA DE IMÁGENES
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 5 * 1024 * 1024 }
});

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
        
        if (error) throw error;
        
        const { data: { publicUrl } } = supabase.storage
            .from(folder)
            .getPublicUrl(filePath);
        
        return publicUrl;
    } catch (error) {
        console.error('Error subiendo imagen:', error);
        return null;
    }
}

// ============================================
// AUTENTICACIÓN
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    if (pass === ADMIN_PASSWORD) return next();
    res.status(401).json({ error: 'No autorizado' });
};

// ============================================
// RUTAS PÚBLICAS
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/api/status', (req, res) => res.json({ online: true, timestamp: Date.now() }));

// Obtener todas las tiendas (público)
app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('id, nombre, icono, descripcion');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en /api/tiendas/info:', error);
        res.json([]);
    }
});

// Obtener una tienda específica
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

// Obtener configuración de una tienda
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

// Obtener productos por tienda
app.get('/api/productos', async (req, res) => {
    const tienda = req.query.tienda;
    if (!tienda) return res.json([]);
    
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

// Obtener categorías por tienda
app.get('/api/categorias', async (req, res) => {
    const tienda = req.query.tienda;
    if (!tienda) return res.json(['otros']);
    
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

// Obtener configuración global
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

// Crear pedido
app.post('/api/pedidos', async (req, res) => {
    try {
        const { tienda, nombre, telefono, direccion, items, total, moneda, metodoPago } = req.body;
        
        if (!tienda || !nombre || !telefono || !direccion || !items || !items.length) {
            return res.status(400).json({ error: 'Faltan datos obligatorios' });
        }
        
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
            nombre: nombre.trim(),
            telefono: telefono.trim(),
            direccion: direccion.trim(),
            items: items,
            total: total,
            moneda: moneda || 'CUP',
            metodo_pago: metodoPago || 'Efectivo',
            estado: 'pendiente',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        await supabase
            .from('order_counters')
            .upsert({ tienda: tienda, counter: nextId });
        
        res.json({ success: true, orderId: nextId, codigoCliente: codigoCliente });
        
    } catch (error) {
        console.error('Error en /api/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

function generarCodigoUnico() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const timestamp = Date.now().toString(36).slice(-4).toUpperCase();
    return `${code}-${timestamp}`;
}

// ============================================
// RUTAS ADMIN (PROTEGIDAS)
// ============================================

app.post('/api/admin/verify', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
    }
});

// Obtener todas las tiendas (admin)
app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').order('created_at', { ascending: true });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en GET /api/admin/tiendas:', error);
        res.status(500).json({ error: error.message });
    }
});

// Obtener una tienda específica (admin)
app.get('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Error en GET /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// Crear tienda (admin)
app.post('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const slug = req.body.id?.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
        
        if (!slug) {
            return res.status(400).json({ error: 'ID de tienda inválido' });
        }
        
        const { error } = await supabase.from('stores').insert({
            id: slug,
            nombre: req.body.nombre?.trim() || slug,
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

// Actualizar tienda (admin)
app.put('/api/admin/tiendas/:id', AUTH, async (req, res) => {
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

// Eliminar tienda (admin)
app.delete('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/tiendas/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// Obtener categorías (admin)
app.get('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stores')
            .select('categorias')
            .eq('id', req.query.tienda)
            .single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        console.error('Error en GET /api/admin/categorias:', error);
        res.json(['otros']);
    }
});

// Agregar categoría (admin)
app.post('/api/admin/categorias', AUTH, async (req, res) => {
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

// Obtener productos (admin)
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
        console.error('Error en GET /api/admin/productos:', error);
        res.json([]);
    }
});

// Crear producto (admin)
app.post('/api/admin/productos', AUTH, upload.single('imagen'), async (req, res) => {
    try {
        let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
        
        if (req.file) {
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) imagen = uploadedUrl;
        }
        
        const { error } = await supabase.from('products').insert({
            tienda: req.body.tienda,
            nombre: req.body.nombre?.trim(),
            descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            imagen: imagen,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en POST /api/admin/productos:', error);
        res.status(500).json({ error: error.message });
    }
});

// Actualizar producto (admin)
app.put('/api/admin/productos/:id', AUTH, upload.single('imagen'), async (req, res) => {
    try {
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

// Eliminar producto (admin)
app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
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

// Obtener pedidos (admin)
app.get('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (req.query.tienda) query = query.eq('tienda', req.query.tienda);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error en GET /api/admin/pedidos:', error);
        res.json([]);
    }
});

// Actualizar estado de pedido (admin)
app.put('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('orders')
            .update({ estado: req.body.estado, updated_at: new Date() })
            .eq('id', req.params.id)
            .eq('tienda', req.body.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// Eliminar un pedido (admin)
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
        console.error('Error en DELETE /api/admin/pedidos/:id:', error);
        res.status(500).json({ error: error.message });
    }
});

// Eliminar todos los pedidos de una tienda (admin)
app.delete('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        if (req.query.tienda) {
            await supabase.from('orders').delete().eq('tienda', req.query.tienda);
            await supabase.from('order_counters').upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error en DELETE /api/admin/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

// Obtener configuración global (admin)
app.get('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Error en GET /api/admin/config:', error);
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

// Actualizar configuración global (admin)
app.put('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('config')
            .upsert({ id: 1, ...req.body, updated_at: new Date() });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error en PUT /api/admin/config:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║     🚀 TIENDA LA REINA - SERVIDOR INICIADO                 ║
╠════════════════════════════════════════════════════════════╣
║  Puerto: ${PORT}                                            ║
║  Admin Password: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ No configurada'}      ║
║  Supabase: ${SUPABASE_URL ? '✅ Conectado' : '❌ No conectado'}                 ║
╠════════════════════════════════════════════════════════════╣
║  URLs:                                                     ║
║  - Frontend: http://localhost:${PORT}/?tienda=electro        ║
║  - Admin:    http://localhost:${PORT}/admin.html            ║
╚════════════════════════════════════════════════════════════╝
    `);
});