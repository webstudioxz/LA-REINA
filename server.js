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

console.log('🔍 Verificando variables:');
console.log(`SUPABASE_URL: ${SUPABASE_URL ? '✅' : '❌'}`);
console.log(`SUPABASE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅' : '❌'}`);
console.log(`ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅' : '❌'}`);

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR: Faltan variables de Supabase');
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
// LISTA COMPLETA DE PAÍSES DISPONIBLES
// ============================================
const PAISES_DISPONIBLES = {
    '53': { nombre: 'Cuba', bandera: '🇨🇺', codigo: '53', digitos: 8, ejemplo: '5XXXXXXX' },
    '1': { nombre: 'Estados Unidos', bandera: '🇺🇸', codigo: '1', digitos: 10, ejemplo: '2125551234' },
    '34': { nombre: 'España', bandera: '🇪🇸', codigo: '34', digitos: 9, ejemplo: '612345678' },
    '52': { nombre: 'México', bandera: '🇲🇽', codigo: '52', digitos: 10, ejemplo: '5512345678' },
    '56': { nombre: 'Chile', bandera: '🇨🇱', codigo: '56', digitos: 9, ejemplo: '912345678' },
    '54': { nombre: 'Argentina', bandera: '🇦🇷', codigo: '54', digitos: 10, ejemplo: '9112345678' },
    '57': { nombre: 'Colombia', bandera: '🇨🇴', codigo: '57', digitos: 10, ejemplo: '3123456789' },
    '51': { nombre: 'Perú', bandera: '🇵🇪', codigo: '51', digitos: 9, ejemplo: '912345678' },
    '58': { nombre: 'Venezuela', bandera: '🇻🇪', codigo: '58', digitos: 10, ejemplo: '4123456789' },
    '593': { nombre: 'Ecuador', bandera: '🇪🇨', codigo: '593', digitos: 9, ejemplo: '991234567' },
    '591': { nombre: 'Bolivia', bandera: '🇧🇴', codigo: '591', digitos: 8, ejemplo: '71234567' },
    '595': { nombre: 'Paraguay', bandera: '🇵🇾', codigo: '595', digitos: 9, ejemplo: '981234567' },
    '598': { nombre: 'Uruguay', bandera: '🇺🇾', codigo: '598', digitos: 8, ejemplo: '91234567' },
    '507': { nombre: 'Panamá', bandera: '🇵🇦', codigo: '507', digitos: 8, ejemplo: '61234567' },
    '506': { nombre: 'Costa Rica', bandera: '🇨🇷', codigo: '506', digitos: 8, ejemplo: '61234567' },
    '503': { nombre: 'El Salvador', bandera: '🇸🇻', codigo: '503', digitos: 8, ejemplo: '71234567' },
    '504': { nombre: 'Honduras', bandera: '🇭🇳', codigo: '504', digitos: 8, ejemplo: '91234567' },
    '505': { nombre: 'Nicaragua', bandera: '🇳🇮', codigo: '505', digitos: 8, ejemplo: '81234567' }
};

// ============================================
// VALIDACIONES
// ============================================
function validarTelefonoBackend(telefono, paisesActivos) {
    const match = telefono.match(/^\+(\d{1,4})(\d+)$/);
    if (!match) {
        return { valido: false, error: 'Formato inválido. Use +CódigoPaísNúmero' };
    }
    
    const codigoPais = match[1];
    const numeroLocal = match[2];
    
    const paisInfo = paisesActivos.find(p => p.codigo === codigoPais);
    if (!paisInfo) {
        return { valido: false, error: `Código de país +${codigoPais} no está habilitado` };
    }
    
    if (numeroLocal.length !== paisInfo.digitos) {
        return { valido: false, error: `El número debe tener ${paisInfo.digitos} dígitos para ${paisInfo.nombre}` };
    }
    
    if (/^(\d)\1{5,}$/.test(numeroLocal)) {
        return { valido: false, error: 'Número no válido (dígitos repetidos)' };
    }
    
    return { valido: true, codigoPais, numeroLocal, paisInfo };
}

function validarDireccionBackend(direccion) {
    const direccionLimpia = direccion.trim();
    if (direccionLimpia.length < 10) {
        return { valido: false, error: 'Dirección muy corta. Use: Calle # Número' };
    }
    
    const patronNumero = /[#\#]?\s*(\d+)|N[oó]\.?\s*(\d+)|\bnúmero\s*(\d+)/i;
    const numeroMatch = direccionLimpia.match(patronNumero);
    
    if (!numeroMatch) {
        return { valido: false, error: 'Incluya el número de casa. Ej: "Calle 23 # 456"' };
    }
    
    const palabras = direccionLimpia.split(/\s+/);
    const tieneCalle = palabras.some(p => p.length > 2 && !/^\d+$/.test(p) && !/^[#\#]/.test(p));
    
    if (!tieneCalle) {
        return { valido: false, error: 'Especifique el nombre de la calle' };
    }
    
    return { valido: true };
}

function generarCodigoUnico() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `${code}-${Date.now().toString(36).slice(-4).toUpperCase()}`;
}

// ============================================
// MULTER
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        const { error } = await supabase.storage.from(folder).upload(filePath, file.buffer, { contentType: file.mimetype });
        if (error) throw error;
        const { data: { publicUrl } } = supabase.storage.from(folder).getPublicUrl(filePath);
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
app.get('/api/status', (req, res) => res.json({ online: true }));

app.get('/api/tiendas/info', async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('id, nombre, icono, descripcion, paises_activos');
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
        const { data, error } = await supabase.from('stores').select('configuracion, paises_activos').eq('id', req.params.id).single();
        if (error) throw error;
        res.json({ configuracion: data?.configuracion || {}, paises_activos: data?.paises_activos || ['53'] });
    } catch (error) {
        res.json({ configuracion: {}, paises_activos: ['53'] });
    }
});

app.get('/api/paises', async (req, res) => {
    const tienda = req.query.tienda;
    if (!tienda) return res.json([]);
    try {
        const { data, error } = await supabase.from('stores').select('paises_activos').eq('id', tienda).single();
        if (error) throw error;
        const paisesActivos = data?.paises_activos || ['53'];
        const paisesInfo = paisesActivos.map(codigo => PAISES_DISPONIBLES[codigo]).filter(p => p);
        res.json(paisesInfo);
    } catch (error) {
        res.json([PAISES_DISPONIBLES['53']]);
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

app.post('/api/pedidos', async (req, res) => {
    try {
        const { tienda, nombre, telefono, direccion, items, total, moneda, metodoPago } = req.body;
        
        if (!tienda || !nombre || !telefono || !direccion || !items || !items.length) {
            return res.status(400).json({ error: 'Faltan datos' });
        }
        
        // Obtener países activos de la tienda
        const { data: tiendaData } = await supabase.from('stores').select('paises_activos').eq('id', tienda).single();
        const paisesActivos = tiendaData?.paises_activos?.map(c => PAISES_DISPONIBLES[c]) || [PAISES_DISPONIBLES['53']];
        
        const telefonoValid = validarTelefonoBackend(telefono, paisesActivos);
        if (!telefonoValid.valido) {
            return res.status(400).json({ error: telefonoValid.error });
        }
        
        const direccionValid = validarDireccionBackend(direccion);
        if (!direccionValid.valido) {
            return res.status(400).json({ error: direccionValid.error });
        }
        
        for (const item of items) {
            const { data: product } = await supabase.from('products').select('disponible').eq('id', item.id).eq('tienda', tienda).single();
            if (!product || product.disponible !== true) {
                return res.status(400).json({ error: `"${item.nombre}" no disponible` });
            }
        }
        
        const codigoCliente = generarCodigoUnico();
        const { data: counterData } = await supabase.from('order_counters').select('counter').eq('tienda', tienda).single();
        const nextId = (counterData?.counter || 0) + 1;
        
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId, codigo_cliente: codigoCliente, tienda: tienda,
            nombre: nombre.trim(), telefono: telefonoValid.numeroLocal, codigo_pais: telefonoValid.codigoPais,
            telefono_completo: telefono, direccion: direccion.trim(),
            items: items, total: total, moneda: moneda || 'CUP', metodo_pago: metodoPago || 'Efectivo',
            estado: 'pendiente', created_at: new Date(), updated_at: new Date()
        });
        
        if (insertError) throw insertError;
        await supabase.from('order_counters').upsert({ tienda: tienda, counter: nextId });
        
        res.json({ success: true, orderId: nextId, codigoCliente: codigoCliente });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// RUTAS ADMIN
// ============================================
app.post('/api/admin/verify', (req, res) => {
    res.json({ success: req.body.password === ADMIN_PASSWORD });
});

app.get('/api/admin/tiendas', AUTH, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*').order('created_at');
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
            id: slug, nombre: req.body.nombre?.trim() || slug, icono: req.body.icono || '🛒',
            descripcion: req.body.descripcion || '', configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros'], paises_activos: req.body.paises_activos || ['53'],
            created_at: new Date(), updated_at: new Date()
        });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').update({
            nombre: req.body.nombre, icono: req.body.icono, descripcion: req.body.descripcion,
            configuracion: req.body.configuracion, categorias: req.body.categorias,
            paises_activos: req.body.paises_activos, updated_at: new Date()
        }).eq('id', req.params.id);
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
        const cats = store?.categorias || [];
        if (!cats.includes(req.body.categoria)) cats.push(req.body.categoria);
        await supabase.from('stores').update({ categorias: cats, updated_at: new Date() }).eq('id', req.body.tienda);
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
            const uploaded = await uploadToSupabase(req.file, 'Productos');
            if (uploaded) imagen = uploaded;
        }
        const { error } = await supabase.from('products').insert({
            tienda: req.body.tienda, nombre: req.body.nombre?.trim(), descripcion: req.body.descripcion || '',
            precio: parseFloat(req.body.precio), descuento: parseInt(req.body.descuento) || 0,
            imagen: imagen, disponible: req.body.disponible === 'true', tamanio: req.body.tamanio || 'pequeno',
            categoria: req.body.categoria || 'otros', created_at: new Date(), updated_at: new Date()
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
            nombre: req.body.nombre, descripcion: req.body.descripcion, precio: parseFloat(req.body.precio),
            descuento: parseInt(req.body.descuento) || 0, disponible: req.body.disponible === 'true',
            tamanio: req.body.tamanio, categoria: req.body.categoria, updated_at: new Date()
        };
        if (req.file) {
            const uploaded = await uploadToSupabase(req.file, 'Productos');
            if (uploaded) updateData.imagen = uploaded;
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

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Servidor en puerto ${PORT}`);
    console.log(`🔐 Admin: ${ADMIN_PASSWORD ? '✅' : '❌'}`);
    console.log(`🗄️ Supabase: ${SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`\n📍 http://localhost:${PORT}/?tienda=electro\n`);
});