// ui-v2.js - Nueva interfaz moderna con mejor SEO, accesibilidad y rendimiento

// Esta función se ejecuta cuando el usuario debe ver la nueva UI
export function initUIV2(container) {
    console.log('🆕 Inicializando UI v2...');
    
    // Renderizar la nueva interfaz
    container.innerHTML = `
        <div style="padding: 20px; max-width: 1200px; margin: 0 auto;">
            <header style="display: flex; justify-content: space-between; align-items: center; padding: 16px 0; border-bottom: 2px solid #e2e8f0; margin-bottom: 24px;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <img src="https://i.ibb.co/LDG7Gf2d/fotor-ai-2025020222510.jpg" alt="Logo" style="width: 40px; height: 40px; border-radius: 12px;">
                    <h1 style="font-size: 1.4rem; font-weight: 700; background: linear-gradient(135deg, #4f46e5, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Tienda La Reina</h1>
                </div>
                <div style="display: flex; align-items: center; gap: 16px;">
                    <span style="background: #4f46e5; color: white; padding: 6px 14px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;">NUEVA VERSIÓN</span>
                    <button id="cartBtnV2" style="background: #f1f5f9; border: none; padding: 8px 16px; border-radius: 30px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;">
                        <i class="fas fa-shopping-cart"></i> Carrito
                        <span id="cartBadgeV2" style="background: #ef4444; color: white; border-radius: 50%; padding: 0 6px; font-size: 0.7rem; min-width: 20px; text-align: center;">0</span>
                    </button>
                </div>
            </header>

            <!-- Hero Section mejorado -->
            <div style="background: linear-gradient(135deg, rgba(79,70,229,0.9), rgba(139,92,246,0.8)), url('https://d.top4top.io/p_3525b1u9b0.jpg'); background-size: cover; background-position: center; border-radius: 16px; padding: 60px 40px; color: white; text-align: center; margin-bottom: 32px;">
                <h2 style="font-size: 2.2rem; font-weight: 800; margin-bottom: 8px;">Bienvenido a Tienda La Reina</h2>
                <p style="font-size: 1.1rem; opacity: 0.9; max-width: 500px; margin: 0 auto 20px;">Encuentra los mejores productos al mejor precio</p>
                <button onclick="document.getElementById('productosV2').scrollIntoView({behavior:'smooth'})" style="background: #f97316; color: white; border: none; padding: 12px 32px; border-radius: 30px; font-weight: 600; font-size: 1rem; cursor: pointer;">Ver Catálogo <i class="fas fa-arrow-right"></i></button>
            </div>

            <!-- Categorías -->
            <div id="categoriasV2" style="display: flex; gap: 8px; overflow-x: auto; padding: 4px 0 16px; margin-bottom: 24px;">
                <button class="cat-btn-v2" data-cat="todos" style="background: #4f46e5; color: white; border: none; padding: 8px 20px; border-radius: 20px; font-weight: 600; cursor: pointer; white-space: nowrap;">TODOS</button>
                <!-- Las categorías se cargan dinámicamente -->
            </div>

            <!-- Grid de Productos -->
            <div id="productosV2" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 16px;">
                <!-- Los productos se cargan dinámicamente -->
            </div>

            <!-- Footer mejorado -->
            <footer style="margin-top: 40px; padding: 24px 0; border-top: 2px solid #e2e8f0; text-align: center;">
                <p style="font-weight: 700; font-size: 1.1rem; background: linear-gradient(135deg, #4f46e5, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Tienda La Reina</p>
                <p style="color: #64748b; font-size: 0.8rem;">Calidad y Confianza</p>
                <p style="font-size: 0.65rem; color: #94a3b8;">&copy; 2026 Tienda La Reina</p>
            </footer>
        </div>
    `;

    // Cargar productos y categorías
    loadProductsV2();
    loadCategoriesV2();
}

// Cargar categorías
async function loadCategoriesV2() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const store = urlParams.get('tienda') || 'electro';
        const response = await fetch(`/api/categorias?tienda=${store}`);
        const categorias = await response.json();
        
        const container = document.getElementById('categoriasV2');
        if (container) {
            const existingButtons = container.querySelectorAll('.cat-btn-v2');
            existingButtons.forEach(btn => btn.remove());
            
            const allBtn = document.createElement('button');
            allBtn.className = 'cat-btn-v2';
            allBtn.dataset.cat = 'todos';
            allBtn.style.cssText = 'background: #4f46e5; color: white; border: none; padding: 8px 20px; border-radius: 20px; font-weight: 600; cursor: pointer; white-space: nowrap;';
            allBtn.textContent = 'TODOS';
            allBtn.onclick = () => filterProductsV2('todos');
            container.prepend(allBtn);
            
            categorias.forEach(cat => {
                const btn = document.createElement('button');
                btn.className = 'cat-btn-v2';
                btn.dataset.cat = cat;
                btn.style.cssText = 'background: #f1f5f9; color: #1e293b; border: none; padding: 8px 20px; border-radius: 20px; font-weight: 600; cursor: pointer; white-space: nowrap;';
                btn.textContent = cat.toUpperCase();
                btn.onclick = () => filterProductsV2(cat);
                container.appendChild(btn);
            });
        }
    } catch (error) {
        console.error('Error loading categories:', error);
    }
}

// Cargar productos
let allProductsV2 = [];
let currentCategoryV2 = 'todos';

async function loadProductsV2() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const store = urlParams.get('tienda') || 'electro';
        const response = await fetch(`/api/productos?tienda=${store}&_=${Date.now()}`);
        allProductsV2 = await response.json();
        renderProductsV2(allProductsV2);
    } catch (error) {
        console.error('Error loading products:', error);
    }
}

function renderProductsV2(products) {
    const container = document.getElementById('productosV2');
    if (!container) return;
    
    if (!products || products.length === 0) {
        container.innerHTML = `
            <div style="grid-column: 1/-1; text-align: center; padding: 60px 20px; background: #f8fafc; border-radius: 12px;">
                <i class="fas fa-box-open" style="font-size: 3rem; color: #cbd5e1; display: block; margin-bottom: 12px;"></i>
                <h3 style="font-size: 1.1rem; color: #64748b;">No hay productos disponibles</h3>
                <p style="color: #94a3b8; font-size: 0.85rem;">Vuelve más tarde o contacta al administrador.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = products.map(p => {
        const finalPrice = p.precio * (1 - (p.descuento || 0) / 100);
        const img = Array.isArray(p.imagen) ? p.imagen[0] : p.imagen || 'https://via.placeholder.com/300';
        const available = p.disponible === true || p.disponible === 'true';
        
        return `
            <div style="background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); border: 1px solid #f1f5f9; transition: all 0.3s; cursor: pointer;" 
                 onmouseover="this.style.transform='translateY(-4px)';this.style.boxShadow='0 8px 25px rgba(0,0,0,0.1)'" 
                 onmouseout="this.style.transform='';this.style.boxShadow='0 1px 3px rgba(0,0,0,0.08)'">
                <div style="position: relative; aspect-ratio: 1; overflow: hidden; background: #f8fafc;">
                    <img src="${img}" alt="${p.nombre}" style="width: 100%; height: 100%; object-fit: cover; transition: transform 0.6s;" 
                         onerror="this.src='https://via.placeholder.com/300'"
                         loading="lazy">
                    <span style="position: absolute; top: 8px; left: 8px; padding: 2px 12px; border-radius: 12px; font-size: 0.5rem; font-weight: 700; text-transform: uppercase; background: ${available ? 'rgba(16,185,129,0.92)' : 'rgba(239,68,68,0.92)'}; color: white;">
                        ${available ? 'DISPONIBLE' : 'AGOTADO'}
                    </span>
                </div>
                <div style="padding: 10px 12px 12px;">
                    <h3 style="font-size: 0.8rem; font-weight: 600; margin: 0 0 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; line-height: 1.3; min-height: 2.2em;">${p.nombre}</h3>
                    <div style="display: flex; align-items: center; gap: 4px; margin-bottom: 6px;">
                        ${p.descuento ? `<span style="text-decoration: line-through; color: #94a3b8; font-size: 0.6rem;">$${p.precio.toFixed(0)}</span>` : ''}
                        <span style="color: #4f46e5; font-weight: 700; font-size: 0.85rem;">$${finalPrice.toFixed(0)}</span>
                    </div>
                    <button onclick="event.stopPropagation(); addToCartV2(${p.id})" 
                            style="width: 100%; background: ${available ? '#4f46e5' : '#cbd5e1'}; color: white; border: none; padding: 6px; border-radius: 6px; font-weight: 600; font-size: 0.7rem; cursor: ${available ? 'pointer' : 'not-allowed'};">
                        <i class="fas fa-cart-plus"></i> ${available ? 'Añadir' : 'Agotado'}
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function filterProductsV2(category) {
    currentCategoryV2 = category;
    // Actualizar estilo de botones
    document.querySelectorAll('.cat-btn-v2').forEach(btn => {
        const isActive = btn.dataset.cat === category;
        btn.style.background = isActive ? '#4f46e5' : '#f1f5f9';
        btn.style.color = isActive ? 'white' : '#1e293b';
    });
    
    const filtered = category === 'todos' 
        ? allProductsV2 
        : allProductsV2.filter(p => (p.categoria || 'otros') === category);
    renderProductsV2(filtered);
}

// Función para añadir al carrito (versión v2)
let cartV2 = [];

function addToCartV2(productId) {
    const product = allProductsV2.find(p => p.id === productId);
    if (!product || !(product.disponible === true || product.disponible === 'true')) {
        showToastV2('❌ Producto no disponible', 'error');
        return;
    }
    
    const existing = cartV2.find(item => item.id === productId);
    if (existing) {
        existing.qty += 1;
    } else {
        cartV2.push({
            id: product.id,
            nombre: product.nombre,
            precio: product.precio * (1 - (product.descuento || 0) / 100),
            imagen: Array.isArray(product.imagen) ? product.imagen[0] : product.imagen || 'https://via.placeholder.com/60',
            qty: 1
        });
    }
    
    updateCartBadgeV2();
    showToastV2(`✨ ${product.nombre} agregado`);
}

function updateCartBadgeV2() {
    const badge = document.getElementById('cartBadgeV2');
    if (badge) {
        const total = cartV2.reduce((sum, item) => sum + item.qty, 0);
        badge.textContent = total;
        badge.style.display = total > 0 ? 'inline' : 'none';
    }
}

// Toast para la nueva UI
function showToastV2(message, type = 'success') {
    const existing = document.querySelector('.toast-v2');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = 'toast-v2';
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; 
        background: ${type === 'success' ? '#10b981' : '#ef4444'}; 
        color: white; padding: 12px 24px; 
        border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.2);
        font-weight: 600; z-index: 9999;
        animation: slideUp 0.4s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        toast.style.transition = 'all 0.4s ease';
        setTimeout(() => toast.remove(), 400);
    }, 2800);
}

// Exponer funciones globalmente para que puedan ser usadas desde el HTML
window.initUIV2 = initUIV2;
window.addToCartV2 = addToCartV2;
window.filterProductsV2 = filterProductsV2;

// Estilos adicionales para la nueva UI (se añaden al DOM)
const styleV2 = document.createElement('style');
styleV2.textContent = `
    @keyframes slideUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .cat-btn-v2 {
        transition: all 0.2s ease;
    }
    .cat-btn-v2:hover {
        transform: scale(1.04);
    }
`;
document.head.appendChild(styleV2);