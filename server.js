import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import fs from 'fs';

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
console.log(`SUPABASE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? '✅ Configurada' : '❌ FALTA'}`);
console.log(`ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '✅ Configurada' : '❌ FALTA'}`);

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ ERROR CRÍTICO: Faltan variables de Supabase');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(__dirname));

// ============================================
// LISTA COMPLETA DE PAÍSES DISPONIBLES
// ============================================
const PAISES_COMPLETOS = {
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
// VALIDACIONES BACKEND (SEGURIDAD)
// ============================================
function validarSeguridadNumeroBackend(numero, paisInfo) {
    if (!/^\d+$/.test(numero)) {
        return { valido: false, error: 'El número solo debe contener dígitos' };
    }
    
    if (numero.length !== paisInfo.digitos) {
        return { valido: false, error: `El número debe tener ${paisInfo.digitos} dígitos` };
    }
    
    if (/^(\d)\1+$/.test(numero)) {
        return { valido: false, error: 'Número no válido (dígitos repetidos)' };
    }
    
    let consecutivoCreciente = true;
    let consecutivoDecreciente = true;
    for (let i = 1; i < numero.length; i++) {
        if (parseInt(numero[i]) !== parseInt(numero[i-1]) + 1) consecutivoCreciente = false;
        if (parseInt(numero[i]) !== parseInt(numero[i-1]) - 1) consecutivoDecreciente = false;
    }
    
    if (consecutivoCreciente || consecutivoDecreciente) {
        return { valido: false, error: 'Número no válido (secuencia consecutiva)' };
    }
    
    const patronesFalsos = [/^12345/, /^54321/, /^0000/, /^9999/, /^(\d{2})\1+/, /^0+$/, /^9+$/];
    for (const patron of patronesFalsos) {
        if (patron.test(numero)) {
            return { valido: false, error: 'Número de teléfono no válido' };
        }
    }
    
    if (paisInfo.codigo === '53' && !numero.startsWith('5')) {
        return { valido: false, error: 'En Cuba, los números móviles comienzan con 5 (50-59)' };
    }
    
    return { valido: true };
}

// En server.js, reemplazar la función validarTelefonoBackend con esta versión corregida:

function validarTelefonoBackend(telefono, paisesActivos) {
    // Limpiar el teléfono (solo dígitos)
    let telefonoLimpio = telefono.replace(/\D/g, '');
    
    console.log('📞 Validando teléfono (backend):', telefono);
    console.log('📞 Limpio:', telefonoLimpio);
    console.log('🌍 Países activos:', paisesActivos.map(p => ({ codigo: p.codigo, digitos: p.digitos })));
    
    let codigoPais = null;
    let numeroLocal = null;
    let paisEncontrado = null;
    
    // ORDEN IMPORTANTE: Probar códigos más largos primero (ej: 591 antes que 59 o 5)
    const paisesOrdenados = [...paisesActivos].sort((a, b) => b.codigo.length - a.codigo.length);
    
    // Método 1: Buscar coincidencia exacta de código al inicio
    for (const pais of paisesOrdenados) {
        const codStr = String(pais.codigo);
        if (telefonoLimpio.startsWith(codStr)) {
            const resto = telefonoLimpio.substring(codStr.length);
            // Verificar que el resto tenga la cantidad correcta de dígitos
            if (resto.length === pais.digitos) {
                codigoPais = codStr;
                numeroLocal = resto;
                paisEncontrado = pais;
                console.log(`✅ Método 1: código ${codStr}, local ${numeroLocal} (${pais.digitos} dígitos)`);
                break;
            }
        }
    }
    
    // Método 2: El teléfono podría venir con + (ya manejado por frontend, pero por si acaso)
    if (!codigoPais && telefono.includes('+')) {
        const match = telefono.match(/\+(\d{1,4})(\d+)/);
        if (match) {
            const posibleCodigo = match[1];
            const posibleNumero = match[2];
            const pais = paisesActivos.find(p => String(p.codigo) === posibleCodigo);
            if (pais && posibleNumero.length === pais.digitos) {
                codigoPais = posibleCodigo;
                numeroLocal = posibleNumero;
                paisEncontrado = pais;
                console.log(`✅ Método 2 (+): código ${codigoPais}, local ${numeroLocal}`);
            }
        }
    }
    
    // Método 3: Si no se encontró, usar el país por defecto (el primero activo)
    if (!codigoPais && paisesActivos.length > 0) {
        const paisDefault = paisesActivos[0];
        if (telefonoLimpio.length === paisDefault.digitos) {
            codigoPais = String(paisDefault.codigo);
            numeroLocal = telefonoLimpio;
            paisEncontrado = paisDefault;
            console.log(`✅ Método 3 (default): código ${codigoPais}, local ${numeroLocal}`);
        }
    }
    
    // Si aún no se encontró, mostrar error
    if (!codigoPais || !numeroLocal || !paisEncontrado) {
        const opciones = paisesActivos.map(p => `+${p.codigo} (${p.digitos} dígitos, ej: ${p.ejemplo})`).join(', ');
        console.log('❌ No se pudo validar teléfono');
        return { 
            valido: false, 
            error: `Número inválido. Use formato: ${opciones}` 
        };
    }
    
    // Validar seguridad del número local
    const seguridad = validarSeguridadNumeroBackend(numeroLocal, paisEncontrado);
    if (!seguridad.valido) {
        return { valido: false, error: seguridad.error };
    }
    
    const telefonoCompleto = `+${codigoPais}${numeroLocal}`;
    console.log('✅ Teléfono válido (backend):', telefonoCompleto);
    
    return { 
        valido: true, 
        codigoPais, 
        numeroLocal, 
        paisInfo: paisEncontrado,
        telefonoCompleto
    };
}


function validarDireccionBackend(direccion) {
    const direccionLimpia = direccion.trim();
    if (direccionLimpia.length < 10 || direccionLimpia.length > 200) {
        return { valido: false, error: 'Dirección debe tener entre 10 y 200 caracteres' };
    }
    
    const patronesFalsos = [
        /^[0-9]+$/, /^[a-z\s]{1,5}$/i, /^(test|prueba|demo|ninguna)$/i,
        /^([a-záéíóúñ])\1{4,}$/i, /^(sin numero|s\/n|sin número)$/i,
        /^(qwerty|asdfgh|zxcvbn)/i, /^(calle|avenida)$/i
    ];
    
    for (const patron of patronesFalsos) {
        if (patron.test(direccionLimpia.toLowerCase())) {
            return { valido: false, error: 'Dirección no válida' };
        }
    }
    
    const patronNumero = /[#\#]?\s*(\d+)|N[oó]\.?\s*(\d+)|\bnúmero\s*(\d+)/i;
    if (!patronNumero.test(direccionLimpia)) {
        return { valido: false, error: 'Incluya el número de casa. Ejemplo: "Calle 23 # 456"' };
    }
    
    return { valido: true };
}

function validarNombreBackend(nombre) {
    const nombreLimpio = nombre.trim();
    if (nombreLimpio.length < 3 || nombreLimpio.length > 100) {
        return { valido: false, error: 'Nombre debe tener entre 3 y 100 caracteres' };
    }
    
    const nombresFalsos = [/^test/i, /^prueba/i, /^anon/i, /^usuario/i, /^cliente/i, /^[a-z]\1+$/i, /^\d+$/, /^(admin|root|user)$/i];
    for (const patron of nombresFalsos) {
        if (patron.test(nombreLimpio)) {
            return { valido: false, error: 'Nombre no válido' };
        }
    }
    
    if (!nombreLimpio.includes(' ')) {
        return { valido: false, error: 'Ingrese nombre completo (nombre y apellido)' };
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

function validateOrderData(req, res, next) {
    const { items } = req.body;
    
    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: 'Carrito vacío' });
    }
    
    if (items.length > 50) {
        return res.status(400).json({ error: 'Demasiados productos' });
    }
    
    for (const item of items) {
        if (!item.id || !item.nombre || !item.precio || !item.qty) {
            return res.status(400).json({ error: 'Datos de producto inválidos' });
        }
        
        if (item.qty < 1 || item.qty > 99) {
            return res.status(400).json({ error: 'Cantidad no válida' });
        }
        
        if (item.precio < 0 || item.precio > 1000000) {
            return res.status(400).json({ error: 'Precio no válido' });
        }
    }
    
    next();
}

// ============================================
// RUTAS PÚBLICAS
// ============================================
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).send('Error: index.html no encontrado');
    }
});

app.get('/admin.html', (req, res) => {
    const adminPath = path.join(__dirname, 'admin.html');
    if (fs.existsSync(adminPath)) {
        res.sendFile(adminPath);
    } else {
        res.status(404).send('Error: admin.html no encontrado');
    }
});

app.get('/api/status', (req, res) => res.json({ online: true, timestamp: Date.now() }));

// ============================================
// API DE TIENDAS
// ============================================
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
    
    if (!tienda) {
        return res.json([{ codigo: '53', nombre: 'Cuba', bandera: '🇨🇺', digitos: 8, ejemplo: '5XXXXXXX' }]);
    }
    
    try {
        const { data, error } = await supabase.from('stores').select('paises_activos').eq('id', tienda).single();
        
        if (error) {
            console.error('Error fetching store países:', error);
            return res.json([{ codigo: '53', nombre: 'Cuba', bandera: '🇨🇺', digitos: 8, ejemplo: '5XXXXXXX' }]);
        }
        
        let paisesActivos = data?.paises_activos || ['53'];
        
        if (typeof paisesActivos === 'string') {
            try {
                paisesActivos = JSON.parse(paisesActivos);
            } catch(e) {
                paisesActivos = ['53'];
            }
        }
        
        if (!Array.isArray(paisesActivos)) {
            paisesActivos = ['53'];
        }
        
        const paisesInfo = paisesActivos.map(codigo => {
            const codStr = String(codigo).trim();
            const pais = PAISES_COMPLETOS[codStr];
            if (pais) {
                return {
                    codigo: pais.codigo,
                    nombre: pais.nombre,
                    bandera: pais.bandera,
                    digitos: pais.digitos,
                    ejemplo: pais.ejemplo
                };
            }
            return null;
        }).filter(p => p !== null);
        
        if (paisesInfo.length === 0) {
            return res.json([{ codigo: '53', nombre: 'Cuba', bandera: '🇨🇺', digitos: 8, ejemplo: '5XXXXXXX' }]);
        }
        
        res.json(paisesInfo);
    } catch (error) {
        console.error('Error en /api/paises:', error);
        res.json([{ codigo: '53', nombre: 'Cuba', bandera: '🇨🇺', digitos: 8, ejemplo: '5XXXXXXX' }]);
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

// ============================================
// CREAR PEDIDO CON VALIDACIONES
// ============================================
app.post('/api/pedidos', validateOrderData, async (req, res) => {
    try {
        const { tienda, nombre, telefono, direccion, items, total, moneda, metodoPago } = req.body;
        
        if (!tienda || !nombre || !telefono || !direccion || !items || !items.length) {
            return res.status(400).json({ error: 'Faltan datos obligatorios' });
        }
        
        const nombreValid = validarNombreBackend(nombre);
        if (!nombreValid.valido) {
            return res.status(400).json({ error: nombreValid.error });
        }
        
        const { data: tiendaData, error: tiendaError } = await supabase.from('stores').select('paises_activos').eq('id', tienda).single();
        
        if (tiendaError) {
            console.error('Error obteniendo tienda:', tiendaError);
            return res.status(400).json({ error: 'Tienda no encontrada' });
        }
        
        let paisesActivosCodigos = tiendaData?.paises_activos || ['53'];
        
        if (typeof paisesActivosCodigos === 'string') {
            try {
                paisesActivosCodigos = JSON.parse(paisesActivosCodigos);
            } catch(e) {
                paisesActivosCodigos = ['53'];
            }
        }
        
        if (!Array.isArray(paisesActivosCodigos) || paisesActivosCodigos.length === 0) {
            paisesActivosCodigos = ['53'];
        }
        
        const paisesActivos = paisesActivosCodigos.map(c => PAISES_COMPLETOS[String(c)]).filter(p => p);
        
        if (paisesActivos.length === 0) {
            paisesActivos.push(PAISES_COMPLETOS['53']);
        }
        
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
                return res.status(400).json({ error: `"${item.nombre}" no está disponible` });
            }
        }
        
        const codigoCliente = generarCodigoUnico();
        
        const { data: counterData } = await supabase.from('order_counters').select('counter').eq('tienda', tienda).single();
        const nextId = (counterData?.counter || 0) + 1;
        
        const telefonoCompleto = `+${telefonoValid.codigoPais}${telefonoValid.numeroLocal}`;
        
        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda: tienda,
            nombre: nombre.trim(),
            telefono: telefonoValid.numeroLocal,
            codigo_pais: telefonoValid.codigoPais,
            telefono_completo: telefonoCompleto,
            direccion: direccion.trim(),
            items: items,
            total: total,
            moneda: moneda || 'CUP',
            metodo_pago: metodoPago || 'Efectivo',
            estado: 'pendiente',
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (insertError) {
            console.error('Error insertando pedido:', insertError);
            throw insertError;
        }
        
        if (counterData) {
            await supabase.from('order_counters').update({ counter: nextId }).eq('tienda', tienda);
        } else {
            await supabase.from('order_counters').insert({ tienda: tienda, counter: nextId });
        }
        
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
        
        const paisesActivos = Array.isArray(req.body.paises_activos) ? req.body.paises_activos : ['53'];
        
        const { error } = await supabase.from('stores').insert({
            id: slug,
            nombre: req.body.nombre?.trim() || slug,
            icono: req.body.icono || '🛒',
            descripcion: req.body.descripcion || '',
            configuracion: req.body.configuracion || {},
            categorias: req.body.categorias || ['otros'],
            paises_activos: paisesActivos,
            created_at: new Date(),
            updated_at: new Date()
        });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error creando tienda:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/tiendas/:id', AUTH, async (req, res) => {
    try {
        const paisesActivos = Array.isArray(req.body.paises_activos) ? req.body.paises_activos : ['53'];
        
        const { error } = await supabase.from('stores').update({
            nombre: req.body.nombre,
            icono: req.body.icono,
            descripcion: req.body.descripcion,
            configuracion: req.body.configuracion,
            categorias: req.body.categorias,
            paises_activos: paisesActivos,
            updated_at: new Date()
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