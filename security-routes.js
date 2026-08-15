import express from 'express';
import {
    helmetMiddleware,
    corsMiddleware,
    rateLimiter,
    hppMiddleware,
    sanitizeInput,
    sqlInjectionFilter,
    securityLog
} from './security-middleware.js';

const router = express.Router();

// Aplicar middlewares de seguridad con exclusiones
router.use((req, res, next) => {
    if (req.path === '/api/admin/login') {
        return next();
    }
    helmetMiddleware(req, res, next);
});

router.use((req, res, next) => {
    if (req.path === '/api/admin/login') {
        return next();
    }
    corsMiddleware(req, res, next);
});

router.use((req, res, next) => {
    if (req.path === '/api/admin/login') {
        return next();
    }
    hppMiddleware(req, res, next);
});

router.use((req, res, next) => {
    if (req.path === '/api/admin/login') {
        return next();
    }
    sqlInjectionFilter(req, res, next);
});

router.use((req, res, next) => {
    if (req.path === '/api/admin/login') {
        return next();
    }
    sanitizeInput(req, res, next);
});

// Rate Limiter para todas las rutas
router.use(rateLimiter);

// ============================================
// RUTAS PÚBLICAS
// ============================================

router.get('/api/status', (req, res) => {
    securityLog(req, 'Status check');
    res.json({ 
        online: true, 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

export default router;