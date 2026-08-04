import express from 'express';
import {
    helmetMiddleware,
    corsMiddleware,
    rateLimiter,
    strictRateLimiter,
    hppMiddleware,
    sanitizeInput,
    validateProduct,
    validateStore,
    validateOrder,
    validateFileUpload,
    generateCsrfToken,
    validateCsrfToken,
    sqlInjectionFilter,
    securityLog
} from './security-middleware.js';

const router = express.Router();

// Aplicar middlewares globales a todas las rutas
router.use(helmetMiddleware);
router.use(corsMiddleware);
router.use(hppMiddleware);
router.use(sqlInjectionFilter);
router.use(sanitizeInput);
router.use(rateLimiter);

// Rutas públicas (con rate limiting más estricto)
router.get('/api/status', (req, res) => {
    securityLog(req, 'Status check');
    res.json({ online: true, timestamp: new Date().toISOString() });
});

// Generar token CSRF
router.get('/api/csrf-token', rateLimiter, generateCsrfToken, (req, res) => {
    res.json({ token: req.csrfToken });
});

router.get('/api/tiendas/info', async (req, res) => {
    try {
        securityLog(req, 'Consulta de tiendas');
        // ... resto del código
    } catch (error) {
        securityLog(req, `Error en tiendas/info: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Rutas protegidas con validación de CSRF
const csrfProtected = [validateCsrfToken, rateLimiter];

router.post('/api/pedidos', ...csrfProtected, validateOrder, async (req, res) => {
    try {
        // ... código existente con validaciones adicionales
    } catch (error) {
        securityLog(req, `Error en pedidos: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

export default router;