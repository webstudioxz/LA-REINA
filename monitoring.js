// monitoring.js
import { updateFeatureFlag, getFeatureFlags } from './feature-flags.js';

// Configuración
const ERROR_THRESHOLD = 5; // 5% de errores
const METRICS_WINDOW = 5 * 60 * 1000; // 5 minutos
const CHECK_INTERVAL = 60 * 1000; // 1 minuto

// Almacén de métricas
export const metrics = {
    totalRequests: 0,
    errorRequests: 0,
    versionCounts: { 'new-ui': 0, 'old-ui': 0 },
    errorsByFlag: {},
    startTime: Date.now()
};

// Registro de métricas
export function recordRequest(flagKey, isError) {
    metrics.totalRequests++;
    if (isError) metrics.errorRequests++;
    if (flagKey) {
        metrics.versionCounts[flagKey] = (metrics.versionCounts[flagKey] || 0) + 1;
        if (isError) {
            metrics.errorsByFlag[flagKey] = (metrics.errorsByFlag[flagKey] || 0) + 1;
        }
    }
}

// Reseteo de métricas
function resetMetrics() {
    metrics.totalRequests = 0;
    metrics.errorRequests = 0;
    metrics.versionCounts = { 'new-ui': 0, 'old-ui': 0 };
    metrics.errorsByFlag = {};
    metrics.startTime = Date.now();
}

// Verificación y rollback automático
export async function checkAndAutoRollback() {
    // Si no hay suficientes peticiones, no hacemos nada
    if (metrics.totalRequests < 10) {
        console.log('🔍 Monitor: No hay suficientes peticiones para evaluar.');
        return;
    }

    // Calcular el porcentaje de error global
    const errorRate = (metrics.errorRequests / metrics.totalRequests) * 100;
    console.log(`📊 Monitor: Error rate global: ${errorRate.toFixed(2)}%`);

    // Obtener flags actuales
    const flags = await getFeatureFlags(true);

    // Verificar por flag individual
    let needsRollback = false;
    const rollbackActions = [];

    for (const [flagKey, errorCount] of Object.entries(metrics.errorsByFlag)) {
        const totalForFlag = metrics.versionCounts[flagKey] || 0;
        if (totalForFlag === 0) continue;
        
        const errorRateForFlag = (errorCount / totalForFlag) * 100;
        console.log(`📊 Monitor: Error rate para "${flagKey}": ${errorRateForFlag.toFixed(2)}%`);
        
        // Si el flag está activo y su tasa de error supera el umbral
        if (flags[flagKey]?.enabled && errorRateForFlag > ERROR_THRESHOLD) {
            console.log(`🚨 Monitor: Error rate para "${flagKey}" (${errorRateForFlag.toFixed(2)}%) supera el umbral.`);
            needsRollback = true;
            rollbackActions.push({
                flagKey,
                reason: `Error rate ${errorRateForFlag.toFixed(2)}% > ${ERROR_THRESHOLD}%`
            });
        }
    }

    // Verificar error rate global si hay un flag con alto porcentaje de rollout
    if (!needsRollback && errorRate > ERROR_THRESHOLD) {
        // Verificar si algún flag tiene rollout > 50%
        for (const [flagKey, flag] of Object.entries(flags)) {
            if (flag.enabled && flag.rollout_percentage >= 50) {
                console.log(`🚨 Monitor: Error rate global (${errorRate.toFixed(2)}%) supera el umbral con flag "${flagKey}" al ${flag.rollout_percentage}%.`);
                needsRollback = true;
                rollbackActions.push({
                    flagKey,
                    reason: `Error rate global ${errorRate.toFixed(2)}% > ${ERROR_THRESHOLD}%`
                });
                break;
            }
        }
    }

    // Ejecutar rollback si es necesario
    if (needsRollback && rollbackActions.length > 0) {
        console.log('🔄 Monitor: Iniciando rollback automático...');
        
        for (const action of rollbackActions) {
            const result = await updateFeatureFlag(action.flagKey, {
                enabled: false,
                rollout_percentage: 0
            });
            
            if (result.success) {
                console.log(`✅ Rollback ejecutado para "${action.flagKey}" (${action.reason})`);
            } else {
                console.error(`❌ Error en rollback para "${action.flagKey}":`, result.error);
            }
        }
    } else if (needsRollback) {
        console.log('⚠️ Monitor: Rollback necesario pero no se encontraron flags para revertir.');
    } else {
        console.log('✅ Monitor: Todos los flags están saludables.');
    }

    // Resetear métricas después de cada ciclo
    resetMetrics();
}

// Iniciar el monitoreo periódico
export function startMonitoring() {
    console.log('🟢 Monitor de salud iniciado.');
    console.log(`📊 Umbral de error: ${ERROR_THRESHOLD}%`);
    console.log(`⏱️ Intervalo de verificación: ${CHECK_INTERVAL / 1000}s`);
    
    setInterval(checkAndAutoRollback, CHECK_INTERVAL);
}