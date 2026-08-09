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

// Nota: Las rutas /api/tiendas/info y /api/productos se manejan en server.js
// Esta es solo una ruta de respaldo

// ============================================
// RUTAS PROTEGIDAS CON CSRF (opcional)
// ============================================

export default router;