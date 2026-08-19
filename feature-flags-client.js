// feature-flags-client.js

// Almacena los flags en una variable global
let featureFlags = {};
let isLoading = false;
let loadPromise = null;

// Lee los flags desde el backend
export async function loadFeatureFlags(forceRefresh = false) {
    if (isLoading && loadPromise) {
        return loadPromise;
    }

    if (!forceRefresh && featureFlags && Object.keys(featureFlags).length > 0) {
        return featureFlags;
    }

    isLoading = true;
    loadPromise = (async () => {
        try {
            const response = await fetch('/api/feature-flags?_=' + Date.now());
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            featureFlags = data;
            console.log('🚩 Feature Flags cargados:', featureFlags);
            return featureFlags;
        } catch (error) {
            console.error('Error loading feature flags:', error);
            // Fallback: usar flags por defecto
            featureFlags = {
                'new-ui': { enabled: false, rollout_percentage: 0 }
            };
            return featureFlags;
        } finally {
            isLoading = false;
            loadPromise = null;
        }
    })();

    return loadPromise;
}

// Verificar si un flag está activo para el usuario actual
export function isFeatureEnabled(flagKey, userId = null) {
    const flag = featureFlags[flagKey];
    if (!flag) return false;

    // 1. Desactivado globalmente
    if (!flag.enabled) return false;

    // 2. Usuario en lista de deshabilitados
    if (userId && flag.disabled_users && flag.disabled_users.includes(userId)) {
        return false;
    }

    // 3. Usuario en lista de habilitados
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
        return false;
    }

    return false;
}

// Obtener el userId del usuario actual
export function getUserId() {
    let userId = localStorage.getItem('lareina_user_id');
    if (!userId) {
        userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
        localStorage.setItem('lareina_user_id', userId);
    }
    return userId;
}

// Función para determinar qué versión de la UI usar
export async function getUIVersion() {
    const flags = await loadFeatureFlags();
    const userId = getUserId();
    const useNewUI = isFeatureEnabled('new-ui', userId);
    
    return {
        useNewUI,
        userId,
        flags,
        flagKey: 'new-ui',
        enabled: useNewUI
    };
}

// Función para forzar una recarga de flags (útil para administradores)
export async function refreshFeatureFlags() {
    return loadFeatureFlags(true);
}