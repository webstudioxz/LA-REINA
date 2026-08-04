import express from 'express';
import multer from 'multer';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import securityRoutes from './security-routes.js';
import { 
    validateProduct, 
    validateStore, 
    validateOrder, 
    validateFileUpload,
    securityLog,
    strictRateLimiter
} from './security-middleware.js';

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
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD) {
    console.error('❌ ERROR: Faltan variables de entorno requeridas');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================
// MIDDLEWARE DE SEGURIDAD (aplicado globalmente)
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Importar y usar rutas de seguridad
app.use(securityRoutes);

// ============================================
// CONFIGURACIÓN DE MULTER CON VALIDACIÓN MEJORADA
// ============================================
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { 
        fileSize: 5 * 1024 * 1024, // 5MB
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

// ============================================
// FUNCIONES AUXILIARES
// ============================================

async function uploadToSupabase(file, folder = 'Productos') {
    try {
        // Sanitizar nombre de archivo
        const fileExt = path.extname(file.originalname).toLowerCase();
        const name = path.basename(file.originalname, fileExt)
            .replace(/[^a-zA-Z0-9]/g, '_');
        const fileName = `${Date.now()}-${name}${fileExt}`;
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
        console.error('❌ Error subiendo imagen:', error);
        return null;
    }
}

async function deleteFromSupabase(imageUrl) {
    try {
        if (!imageUrl || !imageUrl.includes('/storage/v1/object/public/')) return false;
        const filePath = imageUrl.split('/Productos/')[1];
        if (!filePath) return false;

        const { error } = await supabase.storage
            .from('Productos')
            .remove([`Productos/${filePath}`]);

        if (error) throw error;
        return true;
    } catch (error) {
        console.error('❌ Error eliminando imagen:', error);
        return false;
    }
}

function generarCodigoUnico() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const code = Array.from({ length: 8 }, () => 
        chars.charAt(Math.floor(Math.random() * chars.length))
    ).join('');
    const timestamp = Date.now().toString(36).slice(-4).toUpperCase();
    return `${code}${timestamp}`;
}

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN CON REGISTRO
// ============================================
const AUTH = (req, res, next) => {
    const pass = req.headers['admin-password'] || req.query.password;
    const ip = req.ip || req.connection.remoteAddress;

    if (!pass) {
        securityLog(req, 'Intento de acceso sin credenciales', 'error');
        return res.status(401).json({ error: 'Credenciales requeridas' });
    }

    if (pass !== ADMIN_PASSWORD) {
        securityLog(req, `Intento de acceso con contraseña incorrecta desde ${ip}`, 'error');
        return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    securityLog(req, 'Acceso autorizado');
    next();
};

// ============================================
// RUTAS ESTÁTICAS
// ============================================
app.get('/', (req, res) => {
    securityLog(req, 'Carga de página principal');
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin.html', (req, res) => {
    securityLog(req, 'Carga de panel admin');
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// ============================================
// API PÚBLICA CON VALIDACIONES
// ============================================

app.get('/api/tiendas/:id', async (req, res) => {
    try {
        const id = req.params.id.replace(/[^a-z0-9\-_]/gi, '');
        const { data, error } = await supabase
            .from('stores')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Tienda no encontrada' });
        }

        // No devolver datos sensibles
        delete data.configuracion?.datos_bancarios;
        res.json(data);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/tiendas/:id/config', async (req, res) => {
    try {
        const id = req.params.id.replace(/[^a-z0-9\-_]/gi, '');
        const { data, error } = await supabase
            .from('stores')
            .select('configuracion')
            .eq('id', id)
            .single();

        if (error) throw error;
        res.json(data?.configuracion || {});
    } catch (error) {
        res.json({});
    }
});

app.get('/api/productos', async (req, res) => {
    try {
        const tienda = (req.query.tienda || 'electro')
            .replace(/[^a-z0-9\-_]/gi, '');
        
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('tienda', tienda)
            .eq('disponible', true)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.json([]);
    }
});

// ============================================
// API ADMIN CON VALIDACIONES Y CSRF
// ============================================

// GET /api/admin/tiendas
app.get('/api/admin/tiendas', AUTH, strictRateLimiter, async (req, res) => {
    try {
        const { data, error } = await supabase.from('stores').select('*');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        securityLog(req, `Error en tiendas: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno' });
    }
});

// POST /api/admin/tiendas - con validación
app.post('/api/admin/tiendas', AUTH, strictRateLimiter, validateStore, async (req, res) => {
    try {
        const { error } = await supabase.from('stores').insert({
            id: req.body.id.toLowerCase().trim(),
            nombre: req.body.nombre.trim(),
            icono: (req.body.icono || '🛒').slice(0, 10),
            descripcion: (req.body.descripcion || '').slice(0, 1000),
            configuracion: req.body.configuracion || {},
            categorias: (req.body.categorias || ['otros']).slice(0, 50),
            created_at: new Date(),
            updated_at: new Date()
        });

        if (error) throw error;
        securityLog(req, `Tienda ${req.body.id} creada`);
        res.json({ success: true });
    } catch (error) {
        securityLog(req, `Error creando tienda: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// POST /api/admin/productos - con validación y file upload
app.post('/api/admin/productos', 
    AUTH, 
    strictRateLimiter,
    upload.single('imagen'),
    validateFileUpload,
    validateProduct,
    async (req, res) => {
        console.log('========== CREANDO PRODUCTO (SEGURO) ==========');
        
        try {
            let imagen = req.body.imagen_url || 'https://via.placeholder.com/400';
            
            if (req.file) {
                const uploadedUrl = await uploadToSupabase(req.file, 'Productos');
                if (uploadedUrl) {
                    imagen = uploadedUrl;
                } else {
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Error al subir la imagen' 
                    });
                }
            }

            const productoData = {
                tienda: req.body.tienda.toLowerCase().trim(),
                nombre: req.body.nombre.trim().slice(0, 100),
                descripcion: (req.body.descripcion || '').slice(0, 5000),
                precio: parseFloat(req.body.precio),
                descuento: Math.min(parseInt(req.body.descuento) || 0, 100),
                imagen: imagen,
                disponible: req.body.disponible === 'true',
                tamanio: ['pequeno', 'grande'].includes(req.body.tamanio) ? req.body.tamanio : 'pequeno',
                categoria: (req.body.categoria || 'otros').slice(0, 50),
                created_at: new Date(),
                updated_at: new Date()
            };

            const { data, error } = await supabase
                .from('products')
                .insert(productoData)
                .select();

            if (error) throw error;

            securityLog(req, `Producto ${req.body.nombre} creado en ${req.body.tienda}`);
            console.log('✅ Producto creado exitosamente');
            res.json({ success: true, data: data });

        } catch (error) {
            console.error('❌ Error:', error);
            securityLog(req, `Error creando producto: ${error.message}`, 'error');
            res.status(500).json({ success: false, error: 'Error interno del servidor' });
        }
    }
);

// DELETE /api/admin/productos/:id
app.delete('/api/admin/productos/:id', AUTH, strictRateLimiter, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({ error: 'ID inválido' });
        }

        const { data: product } = await supabase
            .from('products')
            .select('imagen')
            .eq('id', id)
            .single();

        if (product?.imagen && !product.imagen.includes('via.placeholder.com')) {
            await deleteFromSupabase(product.imagen);
        }

        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', id);

        if (error) throw error;
        securityLog(req, `Producto ${id} eliminado`);
        res.json({ success: true });
    } catch (error) {
        securityLog(req, `Error eliminando producto: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno' });
    }
});

// GET /api/admin/pedidos
app.get('/api/admin/pedidos', AUTH, strictRateLimiter, async (req, res) => {
    try {
        const tienda = (req.query.tienda || '').replace(/[^a-z0-9\-_]/gi, '');
        
        let query = supabase
            .from('orders')
            .select('*')
            .order('created_at', { ascending: false });

        if (tienda) {
            query = query.eq('tienda', tienda);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        securityLog(req, `Error en pedidos: ${error.message}`, 'error');
        res.json([]);
    }
});

// POST /api/pedidos - con validación mejorada
app.post('/api/pedidos', strictRateLimiter, validateOrder, async (req, res) => {
    try {
        const tienda = (req.body.tienda || 'electro')
            .replace(/[^a-z0-9\-_]/gi, '');
        
        // Verificar que la tienda existe
        const { data: storeExists } = await supabase
            .from('stores')
            .select('id')
            .eq('id', tienda)
            .single();

        if (!storeExists) {
            return res.status(400).json({ 
                success: false, 
                error: 'Tienda no válida' 
            });
        }

        const codigoCliente = generarCodigoUnico();
        
        // Obtener contador
        const { data: counterData } = await supabase
            .from('order_counters')
            .select('counter')
            .eq('tienda', tienda)
            .single();

        const nextId = (counterData?.counter || 0) + 1;

        // Validar items - que existan en la tienda
        const productIds = req.body.items.map(i => parseInt(i.id));
        const { data: validProducts } = await supabase
            .from('products')
            .select('id, precio, disponible')
            .eq('tienda', tienda)
            .in('id', productIds);

        const validIds = new Set(validProducts?.map(p => p.id) || []);
        const allValid = req.body.items.every(i => validIds.has(parseInt(i.id)));

        if (!allValid) {
            return res.status(400).json({ 
                success: false, 
                error: 'Uno o más productos no son válidos para esta tienda' 
            });
        }

        const { error: insertError } = await supabase.from('orders').insert({
            id: nextId,
            codigo_cliente: codigoCliente,
            tienda: tienda,
            nombre: req.body.nombre.trim(),
            telefono: req.body.telefono.trim(),
            direccion: req.body.direccion.trim(),
            items: req.body.items.map(i => ({
                ...i,
                precio: parseFloat(i.precio)
            })),
            total: parseFloat(req.body.total),
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

        securityLog(req, `Pedido #${nextId} creado en ${tienda}`);
        res.json({ 
            success: true, 
            orderId: nextId, 
            codigoCliente: codigoCliente 
        });
    } catch (error) {
        console.error('Error:', error);
        securityLog(req, `Error en pedido: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('❌ Error global:', err);
    securityLog(req, `Error global: ${err.message}`, 'error');
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'El archivo excede el tamaño máximo' });
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
    console.log(`🚀 Tienda La Reina corriendo en puerto ${PORT}`);
    console.log(`🔐 Seguridad activa: ✅`);
    console.log(`🛡️ CSRF Protection: ✅`);
    console.log(`🚦 Rate Limiting: ✅`);
    console.log(`🛠️  Modo: ${process.env.NODE_ENV || 'development'}`);
});