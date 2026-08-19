// feature-flags.js
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
dotenv.config();

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Configuración por defecto de los flags
export const DEFAULT_FLAGS = {
    'new-ui': {
        name: 'Nueva Interfaz Moderna',
        description: 'Habilita la nueva versión del frontend con diseño actualizado, mejor SEO y accesibilidad.',
        enabled: false,
        rollout_percentage: 0,
        enabled_users: [],
        disabled_users: []
    }
};

// Cache de flags para reducir consultas a la BD
let flagsCache = null;
let lastCacheUpdate = 0;
const CACHE_TTL = 30000; // 30 segundos

export async function getFeatureFlags(forceRefresh = false) {
    const now = Date.now();
    if (flagsCache && !forceRefresh && (now - lastCacheUpdate) < CACHE_TTL) {
        return flagsCache;
    }

    try {
        const { data, error } = await supabase
            .from('feature_flags')
            .select('*');

        if (error) {
            console.error('Error loading feature flags from DB:', error);
            return DEFAULT_FLAGS;
        }

        // Fusionar flags de BD con defaults
        const mergedFlags = { ...DEFAULT_FLAGS };
        if (data) {
            data.forEach(dbFlag => {
                mergedFlags[dbFlag.flag_key] = {
                    name: dbFlag.name || dbFlag.flag_key,
                    description: dbFlag.description || '',
                    enabled: dbFlag.enabled || false,
                    rollout_percentage: dbFlag.rollout_percentage || 0,
                    enabled_users: dbFlag.enabled_users || [],
                    disabled_users: dbFlag.disabled_users || []
                };
            });
        }

        flagsCache = mergedFlags;
        lastCacheUpdate = now;
        return mergedFlags;
    } catch (error) {
        console.error('Error in getFeatureFlags:', error);
        return DEFAULT_FLAGS;
    }
}

export function isFeatureEnabled(flagKey, userId = null, flags = null) {
    const flag = flags ? flags[flagKey] : (flagsCache?.[flagKey] || DEFAULT_FLAGS[flagKey]);
    if (!flag) return false;

    // 1. Desactivado globalmente
    if (!flag.enabled) return false;

    // 2. Usuario en lista de deshabilitados (prioridad máxima)
    if (userId && flag.disabled_users && flag.disabled_users.includes(userId)) {
        return false;
    }

    // 3. Usuario en lista de habilitados (para testers)
    if (userId && flag.enabled_users && flag.enabled_users.includes(userId)) {
        return true;
    }

    // 4. Evaluar porcentaje de rollout
    if (flag.rollout_percentage && flag.rollout_percentage > 0) {
        if (userId) {
            // Hash determinístico basado en userId
            let hash = 0;
            for (let i = 0; i < userId.length; i++) {
                const char = userId.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            const percentage = Math.abs(hash) % 100;
            return percentage < flag.rollout_percentage;
        }
        // Si no hay userId, el rollout no aplica
        return false;
    }

    return false;
}

export async function updateFeatureFlag(flagKey, updates) {
    try {
        // Obtener el flag actual
        const currentFlags = await getFeatureFlags(true);
        const currentFlag = currentFlags[flagKey];
        
        if (!currentFlag) {
            return { success: false, error: 'Flag no encontrado' };
        }

        // Construir objeto de actualización
        const updateData = {
            flag_key: flagKey,
            name: updates.name || currentFlag.name,
            description: updates.description || currentFlag.description,
            enabled: updates.enabled !== undefined ? updates.enabled : currentFlag.enabled,
            rollout_percentage: updates.rollout_percentage !== undefined ? 
                Math.min(100, Math.max(0, parseInt(updates.rollout_percentage) || 0)) : 
                currentFlag.rollout_percentage,
            enabled_users: updates.enabled_users || currentFlag.enabled_users || [],
            disabled_users: updates.disabled_users || currentFlag.disabled_users || [],
            updated_at: new Date().toISOString()
        };

        const { error } = await supabase
            .from('feature_flags')
            .upsert(updateData, { onConflict: 'flag_key' });

        if (error) {
            console.error(`Error updating feature flag ${flagKey}:`, error);
            return { success: false, error: error.message };
        }

        // Invalidar cache
        flagsCache = null;
        lastCacheUpdate = 0;

        return { success: true };
    } catch (error) {
        console.error(`Error in updateFeatureFlag for ${flagKey}:`, error);
        return { success: false, error: error.message };
    }
}

export async function syncDefaultFeatureFlags() {
    try {
        for (const [flagKey, flagConfig] of Object.entries(DEFAULT_FLAGS)) {
            // Verificar si el flag ya existe
            const { data: existing } = await supabase
                .from('feature_flags')
                .select('flag_key')
                .eq('flag_key', flagKey)
                .single();

            if (!existing) {
                // Insertar flag por defecto
                const { error } = await supabase
                    .from('feature_flags')
                    .insert({
                        flag_key: flagKey,
                        name: flagConfig.name,
                        description: flagConfig.description,
                        enabled: flagConfig.enabled,
                        rollout_percentage: flagConfig.rollout_percentage,
                        enabled_users: flagConfig.enabled_users || [],
                        disabled_users: flagConfig.disabled_users || [],
                        created_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    });

                if (error) {
                    console.error(`Error syncing default flag ${flagKey}:`, error);
                } else {
                    console.log(`✅ Flag "${flagKey}" creado en la base de datos`);
                }
            }
        }
    } catch (error) {
        console.error('Error in syncDefaultFeatureFlags:', error);
    }
}