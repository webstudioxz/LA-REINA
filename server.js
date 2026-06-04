import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';

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
    console.error('❌ ERROR: Faltan SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR: Falta ADMIN_PASSWORD');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE DE SEGURIDAD
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://", "http://", "https://via.placeholder.com", "https://images.unsplash.com", "https://d.top4top.io", "https://i.ibb.co", "https://*.supabase.co"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "https://*.supabase.co", "https://*.onrender.com"],
        },
    },
}));

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Rate limiting para prevenir ataques de fuerza bruta
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, intenta de nuevo en 15 minutos' }
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Demasiados intentos de login, intenta de nuevo en 1 hora' }
});
app.post('/api/admin/verify', authLimiter);

// ============================================
// VALIDACIONES ANTIFRAUDE
// ============================================

// 1. Validación de teléfono (sin números consecutivos ni repetidos)
function validarTelefono(telefono) {
    const numeros = telefono.replace(/\D/g, '');
    
    if (numeros.length < 8 || numeros.length > 15) {
        return { valido: false, error: 'El teléfono debe tener entre 8 y 15 dígitos' };
    }
    
    // Detectar números repetidos: 11111111
    if (/^(\d)\1+$/.test(numeros)) {
        return { valido: false, error: 'Número de teléfono no válido (dígitos repetidos)' };
    }
    
    // Detectar consecutivos simples: 12345678, 87654321
    let consecutivoCreciente = true;
    let consecutivoDecreciente = true;
    for (let i = 1; i < numeros.length; i++) {
        if (parseInt(numeros[i]) !== parseInt(numeros[i-1]) + 1) consecutivoCreciente = false;
        if (parseInt(numeros[i]) !== parseInt(numeros[i-1]) - 1) consecutivoDecreciente = false;
    }
    
    if (consecutivoCreciente || consecutivoDecreciente) {
        return { valido: false, error: 'Número de teléfono no válido (secuencia consecutiva)' };
    }
    
    // Detectar patrones comunes falsos
    const patronesFalsos = [
        /^12345/, /^54321/, /^0000/, /^9999/,
        /^(\d{2})\1+/, // patrones como 121212
    ];
    
    for (const patron of patronesFalsos) {
        if (patron.test(numeros)) {
            return { valido: false, error: 'Número de teléfono no válido' };
        }
    }
    
    return { valido: true, numeros };
}

// 2. Validación de dirección falsa
function validarDireccion(direccion) {
    const direccionLimpia = direccion.trim().toLowerCase();
    
    const patronesFalsos = [
        /^[0-9]+$/,
        /^([a-z])\1{4,}$/i,
        /^([0-9a-z])\1{4,}$/i,
        /^(sin numero|s\/n|ninguna|ninguno|no aplica|n\/a|desconocido)$/i,
        /^(calle|street|direccion|domicilio|address)\s*$/i,
        /^\s*$/,
        /^(qwerty|asdfgh|zxcvbn)/i,
        /^(test|prueba|ejemplo|demo)$/i
    ];
    
    for (const patron of patronesFalsos) {
        if (patron.test(direccionLimpia)) {
            return { valido: false, error: 'Dirección no válida. Ingrese una dirección real (calle, número, municipio)' };
        }
    }
    
    if (!/\d/.test(direccionLimpia) || !/[a-záéíóúñ]/i.test(direccionLimpia)) {
        return { valido: false, error: 'La dirección debe incluir calle y número' };
    }
    
    if (direccionLimpia.length < 10) {
        return { valido: false, error: 'La dirección es demasiado corta. Ingrese una dirección completa' };
    }
    
    return { valido: true };
}

// 3. Validación de nombre (evitar nombres falsos)
function validarNombre(nombre) {
    const nombreLimpio = nombre.trim();
    
    if (nombreLimpio.length < 3) {
        return { valido: false, error: 'El nombre debe tener al menos 3 caracteres' };
    }
    
    const nombresFalsos = [
        /^test/i, /^prueba/i, /^anon/i, /^usuario/i, /^cliente/i,
        /^[a-z]\1+$/i, /^([a-z]{2})\1+$/i
    ];
    
    for (const patron of nombresFalsos) {
        if (patron.test(nombreLimpio)) {
            return { valido: false, error: 'Nombre no válido' };
        }
    }
    
    return { valido: true };
}

// ============================================
// CONFIGURACIÓN DE MULTER
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

async function deleteFromSupabase(imageUrl) {
    try {
        if (!imageUrl || !imageUrl.includes('/storage/v1/object/public/')) return false;
        
        const match = imageUrl.match(/\/Productos\/(.+)$/);
        if (!match) return false;
        
        const filePath = `Productos/${match[1]}`;
        const { error } = await supabase.storage.from('Productos').remove([filePath]);
        
        if (error) throw error;
        return true;
    } catch (error) {
        console.error('Error eliminando imagen:', error);
        return false;
    }
}

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    if (pass === ADMIN_PASSWORD) return next();
    res.status(401).json({ error: 'No autorizado' });
};

// ============================================
// FUNCIÓN PARA GENERAR CÓDIGO ÚNICO
// ============================================
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
// RUTAS PÚBLICAS
// ============================================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/api/status', (req, res) => res.json({ online: true, timestamp: Date.now() }));

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('id, nombre, icono, descripcion');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
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
        res.json(data);
    } catch (error) {
        res.status(404).json({ error: 'Tienda no encontrada' });
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
        res.json({});
    }
});

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
        res.json([]);
    }
});

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
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

// ============================================
// RUTA DE PEDIDOS CON VALIDACIONES ANTIFRAUDE
// ============================================
app.post('/api/pedidos', async (req, res) => {
    try {
        const { tienda, nombre, telefono, direccion, items, total, moneda, metodoPago } = req.body;
        
        if (!tienda || !nombre || !telefono || !direccion || !items || !items.length) {
            return res.status(400).json({ error: 'Faltan datos obligatorios' });
        }
        
        // VALIDACIONES ANTIFRAUDE
        const nombreValid = validarNombre(nombre);
        if (!nombreValid.valido) {
            return res.status(400).json({ error: nombreValid.error });
        }
        
        const telefonoValid = validarTelefono(telefono);
        if (!telefonoValid.valido) {
            return res.status(400).json({ error: telefonoValid.error });
        }
        
        const direccionValid = validarDireccion(direccion);
        if (!direccionValid.valido) {
            return res.status(400).json({ error: direccionValid.error });
        }
        
        // Verificar stock disponible antes de procesar
        for (const item of items) {
            const { data: product } = await supabase
                .from('products')
                .select('disponible, nombre')
                .eq('id', item.id)
                .eq('tienda', tienda)
                .single();
            
            if (!product || product.disponible !== true) {
                return res.status(400).json({ 
                    error: `"${item.nombre}" no está disponible actualmente` 
                });
            }
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
            telefono: telefonoValid.numeros,
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
        
        res.json({ 
            success: true, 
            orderId: nextId, 
            codigoCliente: codigoCliente 
        });
        
    } catch (error) {
        console.error('Error en /api/pedidos:', error);
        res.status(500).json({ error: 'Error al procesar el pedido' });
    }
});

// ============================================
// RUTAS ADMIN (protegidas)
// ============================================

app.post('/api/admin/verify', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
    }
});

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').insert({
            id: req.body.id?.toLowerCase().trim().replace(/[^a-z0-9_-]/g, ''),
            nombre: req.body.nombre?.trim(),
            icono: req.body.icono || '🛒',
            descripcion: req.body.descripcion || '',
            configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros']
        });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
        if (!currentCats.includes(req.body.categoria)) {
            currentCats.push(req.body.categoria);
        }
        
        const { error } = await supabase
            .from('stores')
            .update({ categorias: currentCats })
            .eq('id', req.body.tienda);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
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
            nombre: req.body.nombre?.trim(),
            descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0,
            imagen: imagen,
            disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros'
        });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
            const { data: old } = await supabase.from('products').select('imagen').eq('id', req.params.id).single();
            if (old?.imagen && !old.imagen.includes('placeholder')) {
                await deleteFromSupabase(old.imagen);
            }
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) updateData.imagen = uploadedUrl;
        } else if (req.body.imagen_url) {
            updateData.imagen = req.body.imagen_url;
        }
        
        const { error } = await supabase.from('products').update(updateData).eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
        const { data: product } = await supabase.from('products').select('imagen').eq('id', req.params.id).single();
        if (product?.imagen && !product.imagen.includes('placeholder')) {
            await deleteFromSupabase(product.imagen);
        }
        
        const { error } = await supabase.from('products').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (req.query.tienda) query = query.eq('tienda', req.query.tienda);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.json([]);
    }
});

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
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos', AUTH, async (req, res) => {
    try {
        if (req.query.tienda) {
            await supabase.from('orders').delete().eq('tienda', req.query.tienda);
            await supabase.from('order_counters').upsert({ tienda: req.query.tienda, counter: 0 });
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

app.put('/api/admin/config', AUTH, async (req, res) => {
    try {
        const { error } = await supabase
            .from('config')
            .upsert({ id: 1, ...req.body, updated_at: new Date() });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`🔐 Admin password: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ No configurada'}`);
    console.log(`🗄️ Supabase: ${SUPABASE_URL ? '✅ Conectado' : '❌ No conectado'}`);
    console.log(`\n📍 URLs disponibles:`);
    console.log(`   - Frontend: http://localhost:${PORT}/?tienda=electro`);
    console.log(`   - Admin: http://localhost:${PORT}/admin.html`);
    console.log(`\n✅ Tienda La Reina lista para usar\n`);
});