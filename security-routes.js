import express from 'express';
import {
    helmetMiddleware,
    corsMiddleware,
    rateLimiter,
    strictRateLimiter,
    hppMiddleware,
    sanitizeInput,
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

// ============================================
// RUTAS PÚBLICAS
// ============================================

// Status
router.get('/api/status', (req, res) => {
    securityLog(req, 'Status check');
    res.json({ 
        online: true, 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Tiendas - Info pública
router.get('/api/tiendas/info', async (req, res) => {
    try {
        securityLog(req, 'Consulta de tiendas');
        // Esta ruta se maneja en server.js, solo la declaramos aquí
        // El código real está en server.js
        res.status(501).json({ error: 'Esta ruta debe implementarse en server.js' });
    } catch (error) {
        securityLog(req, `Error en tiendas/info: ${error.message}`, 'error');
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============================================
// RUTAS PROTEGIDAS CON CSRF
// ============================================
// Nota: Las rutas /api/admin/* están protegidas por requireAuth en server.js
// Las rutas públicas con CSRF se pueden agregar aquí si es necesario

export default router;