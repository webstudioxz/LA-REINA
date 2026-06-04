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
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123456';

console.log('🔍 Verificando variables de entorno:');
console.log(`SUPABASE_URL: ${SUPABASE_URL ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ FALTA'}`);

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Faltan variables de Supabase');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// ============================================
// VALIDACIONES BACKEND
// ============================================

// Validación de teléfono con código de país
function validarTelefonoBackend(telefono) {
    const match = telefono.match(/^\+(\d{1,3})(\d+)$/);
    if (!match) {
        return { valido: false, error: 'Formato inválido. Use +CódigoPaísNúmero (ej: +5351234567)' };
    }
    
    const codigoPais = match[1];
    const numeroLocal = match[2];
    
    const longitudesValidas = {
        '53': 8, '1': 10, '34': 9, '52': 10, '56': 9, '54': 10,
        '57': 10, '51': 9, '58': 10, '593': 9, '591': 8, '595': 9,
        '598': 8, '507': 8, '506': 8, '503': 8, '504': 8, '505': 8
    };
    
    const longitudEsperada = longitudesValidas[codigoPais];
    if (longitudEsperada && numeroLocal.length !== longitudEsperada) {
        return { valido: false, error: `El número debe tener ${longitudEsperada} dígitos para +${codigoPais}` };
    }
    
    if (/^(\d)\1{5,}$/.test(numeroLocal)) {
        return { valido: false, error: 'Número no válido (dígitos repetidos)' };
    }
    
    return { valido: true, codigoPais, numeroLocal };
}

// Validación de dirección con formato calle # número
function validarDireccionBackend(direccion) {
    const direccionLimpia = direccion.trim();
    
    if (direccionLimpia.length < 10) {
        return { valido: false, error: 'Dirección demasiado corta. Use: Calle # Número, Municipio' };
    }
    
    const patronesFalsos = [
        /^[0-9]+$/, /^[a-z\s]{1,5}$/i, /^(test|prueba|demo|ninguna|n\/a)$/i,
        /^([a-záéíóúñ])\1{4,}$/i, /^(sin numero|s\/n|sin número)$/i
    ];
    
    for (const patron of patronesFalsos) {
        if (patron.test(direccionLimpia.toLowerCase())) {
            return { valido: false, error: 'Dirección no válida. Use: Calle # Número, Municipio' };
        }
    }
    
    const patronNumero = /[#\#]?\s*(\d+)|N[oó]\.?\s*(\d+)|\bnúmero\s*(\d+)/i;
    const numeroMatch = direccionLimpia.match(patronNumero);
    
    if (!numeroMatch) {
        return { valido: false, error: 'La dirección debe incluir un número de casa. Ejemplo: "Calle 23 # 456"' };
    }
    
    const numeroCasa = numeroMatch[1] || numeroMatch[2] || numeroMatch[3];
    if (!numeroCasa || numeroCasa === '0') {
        return { valido: false, error: 'Número de casa no válido' };
    }
    
    const palabras = direccionLimpia.split(/\s+/);
    const tieneCalle = palabras.some(p => p.length > 2 && !/^\d+$/.test(p) && !/^[#\#]/.test(p));
    
    if (!tieneCalle) {
        return { valido: false, error: 'Especifique el nombre de la calle o avenida' };
    }
    
    return { valido: true, numeroCasa, direccionCompleta: direccionLimpia };
}

// ============================================
// MULTER PARA IMÁGENES
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { error } = await supabase.storage.from(folder).upload(filePath, file.buffer, {
            cacheControl: '3600',
            contentType: file.mimetype
        });
        
        if (error) throw error;
        
        const { data: { publicUrl } } = supabase.storage.from(folder).getPublicUrl(filePath);
        return publicUrl;
    } catch (error) {
        console.error('Error subiendo imagen:', error);
        return null;
    }
}

// ============================================
// AUTENTICACIÓN ADMIN
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    if (pass === ADMIN_PASSWORD) return next();
    res.status(401).json({ error: 'No autorizado' });
};

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
        res.json([]);
    }
});

app.get('/api/tiendas/:id', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').eq('id', req.params.id).single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(404).json({ error: 'Tienda no encontrada' });
    }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('configuracion').eq('id', req.params.id).single();
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
        const { data, error } = await supabase.from('products').select('*').eq('tienda', tienda).order('created_at', { ascending: false });
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
        const { data, error } = await supabase.from('stores').select('categorias').eq('id', tienda).single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        res.json(['otros']);
    }
});

app.get('/api/config', async (req, res) => {
    try {
        const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
        if (error) throw error;
        res.json(data || { monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    } catch (error) {
        res.json({ monedaBase: 'CUP', tasas: { CUP: 1, USD: 0.04, EUR: 0.037 } });
    }
});

// CREAR PEDIDO CON VALIDACIONES
app.post('/api/pedidos', async (req, res) => {
    try {
        const { tienda, nombre, telefono, direccion, items, total, moneda, metodoPago } = req.body;
        
        if (!tienda || !nombre || !telefono || !direccion || !items || !items.length) {
            return res.status(400).json({ error: 'Faltan datos obligatorios' });
        }
        
        // Validar teléfono
        const telefonoValid = validarTelefonoBackend(telefono);
        if (!telefonoValid.valido) {
            return res.status(400).json({ error: telefonoValid.error });
        }
        
        // Validar dirección
        const direccionValid = validarDireccionBackend(direccion);
        if (!direccionValid.valido) {
            return res.status(400).json({ error: direccionValid.error });
        }
        
        // Verificar stock
        for (const item of items) {
            const { data: product } = await supabase
                .from('products')
                .select('disponible, nombre')
                .eq('id', item.id)
                .eq('tienda', tienda)
                .single();
            
            if (!product || product.disponible !== true) {
                return res.status(400).json({ error: `"${item.nombre}" no está disponible` });
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
            telefono: telefonoValid.numeroLocal,
            codigo_pais: telefonoValid.codigoPais,
            telefono_completo: telefono,
            direccion: direccionValid.direccionCompleta,
            numero_casa: direccionValid.numeroCasa,
            items: items,
            total: total,
            moneda: moneda || 'CUP',
            metodo_pago: metodoPago || 'Efectivo',
            estado: 'pendiente',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        
        await supabase.from('order_counters').upsert({ tienda: tienda, counter: nextId });
        
        res.json({ success: true, orderId: nextId, codigoCliente: codigoCliente });
        
    } catch (error) {
        console.error('Error en /api/pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// RUTAS ADMIN (PROTEGIDAS)
// ============================================

app.post('/api/admin/verify', (req, res) => {
    const { password } = req.body;
    res.json({ success: password === ADMIN_PASSWORD });
});

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').order('created_at', { ascending: true });
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').eq('id', req.params.id).single();
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const slug = req.body.id?.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
        if (!slug) return res.status(400).json({ error: 'ID inválido' });
        
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
        await supabase.from('stores').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('categorias').eq('id', req.query.tienda).single();
        if (error) throw error;
        res.json(data?.categorias || ['otros']);
    } catch (error) {
        res.json(['otros']);
    }
});

app.post('/api/admin/categorias', AUTH, async (req, res) => {
    try {
        const { data: store } = await supabase.from('stores').select('categorias').eq('id', req.body.tienda).single();
        const currentCats = store?.categorias || [];
        if (!currentCats.includes(req.body.categoria)) currentCats.push(req.body.categoria);
        
        await supabase.from('stores').update({ categorias: currentCats, updated_at: new Date() }).eq('id', req.body.tienda);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/productos', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').select('*').eq('tienda', req.query.tienda).order('created_at', { ascending: false });
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
            categoria: req.body.categoria || 'otros',
            created_at: new Date(),
            updated_at: new Date()
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
            const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
            if (uploadedUrl) updateData.imagen = uploadedUrl;
        } else if (req.body.imagen_url) {
            updateData.imagen = req.body.imagen_url;
        }
        
        await supabase.from('products').update(updateData).eq('id', req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/productos/:id', AUTH, async (req, res) => {
    try {
        await supabase.from('products').delete().eq('id', req.params.id);
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
        await supabase.from('orders').update({ estado: req.body.estado, updated_at: new Date() }).eq('id', req.params.id).eq('tienda', req.body.tienda);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/pedidos/:id', AUTH, async (req, res) => {
    try {
        await supabase.from('orders').delete().eq('id', req.params.id).eq('tienda', req.query.tienda);
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
        await supabase.from('config').upsert({ id: 1, ...req.body, updated_at: new Date() });
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
    console.log(`   - Admin: http://localhost:${PORT}/admin.html\n`);
});