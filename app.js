// ============================================
// TIENDA LA REINA - APP OPTIMIZADA v4.0
// ============================================

const appCache = {
    products: {},
    categorias: {},
    config: null,
    tiendas: null,
    
    set(key, data) {
        this[key] = data;
        try {
            localStorage.setItem(`cache_${key}`, JSON.stringify({
                data,
                timestamp: Date.now()
            }));
        } catch (e) {}
    },
    
    get(key) {
        try {
            const cached = localStorage.getItem(`cache_${key}`);
            if (cached) {
                const parsed = JSON.parse(cached);
                if (Date.now() - parsed.timestamp < 300000) {
                    return parsed.data;
                }
            }
        } catch (e) {}
        return null;
    }
};

const urlParams = new URLSearchParams(window.location.search);
let currentStore = urlParams.get('tienda') || '';
let products = [];
let categorias = [];
let cart = [];
let currentCategory = 'todos';
let exchangeRates = { CUP: 1, USD: 25, EUR: 27 };
let currentCurrency = 'CUP';
let carouselIntervals = {};
let serverOnline = false;
let storeConfig = null;
let storeInfo = null;
let offlineSlideshowInterval = null;
let primeraCarga = true;

const MALAS_PALABRAS = [
    'puta', 'puto', 'pendejo', 'pendeja', 'coño', 'cojones',
    'verga', 'carajo', 'mierda', 'cabron', 'cabrona',
    'hijodeputa', 'hijo de puta', 'malparido', 'malparida',
    'gonorrea', 'maricon', 'maricona', 'bollo', 'bollera',
    'trola', 'zorra', 'perra', 'perro', 'putamadre',
    'chinga', 'chingar', 'joder', 'jodido', 'jodida',
    'culo', 'culero', 'culera', 'chucha', 'chupame',
    'mamaguevo', 'mamagueva', 'come mierda', 'soplapollas',
    'cagada', 'cagado', 'gilipollas', 'gilipolla',
    'capullo', 'capulla', 'subnormal', 'retrasado',
    'retrasada', 'mongolo', 'mongola', 'imbecil',
    'imbécil', 'estupido', 'estúpido', 'estupida',
    'idiota', 'tarado', 'tarada', 'tonto', 'tonta'
];

function filtrarPalabrasOfensivas(texto) {
    if (!texto) return { limpio: '', ofensivo: false, palabras: [] };
    
    const palabras = texto.toLowerCase().split(/\s+/);
    const ofensivas = [];
    let textoLimpio = texto;
    
    palabras.forEach(palabra => {
        const limpia = palabra.replace(/[^a-zA-ZáéíóúñÑ]/g, '');
        if (limpia.length > 2) {
            MALAS_PALABRAS.forEach(mala => {
                if (limpia.includes(mala) || limpia === mala) {
                    if (!ofensivas.includes(mala)) {
                        ofensivas.push(mala);
                    }
                    const regex = new RegExp(mala, 'gi');
                    textoLimpio = textoLimpio.replace(regex, '****');
                }
            });
        }
    });
    
    return {
        limpio: textoLimpio,
        ofensivo: ofensivas.length > 0,
        palabras: ofensivas
    };
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const icon = toast.querySelector('i');
    const msg = document.getElementById('toastMsg');
    
    toast.style.borderLeftColor = type === 'success' ? 'var(--success-color)' : 'var(--danger-color)';
    icon.style.color = type === 'success' ? 'var(--success-color)' : 'var(--danger-color)';
    icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
    msg.innerText = message;
    
    toast.classList.add('show');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => toast.classList.remove('show'), 2800);
}

function convertPrice(priceCUP) {
    if (currentCurrency === 'CUP') return priceCUP;
    return priceCUP / exchangeRates[currentCurrency];
}

function formatPrice(priceCUP) {
    const v = convertPrice(priceCUP);
    if (currentCurrency === 'CUP') {
        return `$${v.toFixed(0)}`;
    }
    return `${currentCurrency} ${v.toFixed(2)}`;
}

async function loadConfig() {
    try { 
        const r = await fetch('/api/config?_=' + Date.now()); 
        const c = await r.json(); 
        exchangeRates.USD = 1 / c.tasas.USD; 
        exchangeRates.EUR = 1 / c.tasas.EUR;
        appCache.set('config', c);
    } catch (e) {
        console.error('Error loading config:', e);
        const cached = appCache.get('config');
        if (cached) {
            exchangeRates.USD = 1 / cached.tasas.USD;
            exchangeRates.EUR = 1 / cached.tasas.EUR;
        }
    }
}

window.checkServerAndReload = async function() {
    const statusEl = document.getElementById('footerStatus');
    const offlineScreen = document.getElementById('offlineScreen');
    
    try {
        const r = await fetch('/api/status?_=' + Date.now());
        if (r.ok) {
            serverOnline = true;
            offlineScreen.classList.remove('active');
            statusEl.innerHTML = '<i class="fas fa-circle" style="color:#10b981"></i> Tienda Abierta';
            statusEl.className = 'footer-status online';
            clearOfflineSlideshow();
            await refreshAllData();
            return true;
        }
    } catch (e) {
        console.log('Server offline, using cache');
    }
    
    serverOnline = false;
    offlineScreen.classList.add('active');
    statusEl.innerHTML = '<i class="fas fa-circle" style="color:#ef4444"></i> Fuera de Línea';
    statusEl.className = 'footer-status offline';
    loadCachedProductsForOffline();
    generateOfflineSlides();
    return false;
};

async function refreshAllData() {
    try {
        const prodRes = await fetch(`/api/productos?tienda=${currentStore}&_=${Date.now()}`);
        products = await prodRes.json();
        appCache.set(`products_${currentStore}`, products);
        
        const cats = [...new Set(products.map(p => p.categoria || 'otros'))];
        categorias = cats;
        renderCategorias();
        renderContent();
        
        return true;
    } catch (e) {
        console.error('Error refrescando datos:', e);
        loadCachedProductsForOffline();
        return false;
    }
}

function loadCachedProductsForOffline() {
    const cached = appCache.get(`products_${currentStore}`);
    if (cached) {
        try {
            products = cached;
            const cats = [...new Set(products.map(p => p.categoria || 'otros'))];
            categorias = cats;
            renderCategorias();
            renderContent();
            generateOfflineSlides();
        } catch (e) {
            console.error('Error parsing cached products:', e);
            showEmptyProductsMessage();
        }
    } else {
        showEmptyProductsMessage();
    }
}

function renderCategorias() {
    const nav = document.getElementById('categoryNav');
    let html = `<a class="cat-link active" data-cat="todos" onclick="filterByCategory('todos')">TODOS</a>`;
    categorias.forEach(c => {
        html += `<a class="cat-link" data-cat="${c}" onclick="filterByCategory('${c}')">${c.toUpperCase()}</a>`;
    });
    nav.innerHTML = html;
}

window.filterByCategory = function(cat) {
    currentCategory = cat;
    document.querySelectorAll('.cat-link').forEach(l => {
        l.classList.toggle('active', l.dataset.cat === cat);
    });
    document.querySelector('#categoryTitle span').innerText = cat === 'todos' ? 'Todos los Productos' : cat.toUpperCase();
    renderContent();
    
    const url = new URL(window.location);
    url.searchParams.set('categoria', cat);
    window.history.replaceState({}, '', url);
};

function renderContent() {
    const container = document.getElementById('dynamicContent');
    
    if (!products || products.length === 0) {
        showEmptyProductsMessage();
        return;
    }
    
    if (currentCategory === 'todos') {
        let html = '';
        categorias.forEach(cat => {
            const prodsCat = products.filter(p => (p.categoria || 'otros') === cat);
            if (prodsCat.length === 0) return;
            html += `
                <div class="category-section">
                    <div class="category-header">
                        <h3><i class="fas fa-tag"></i> ${cat.toUpperCase()}</h3>
                    </div>
                    ${renderCategoryCarousel(cat, prodsCat)}
                    ${renderProductGrid(prodsCat)}
                </div>
            `;
        });
        
        const otros = products.filter(p => !p.categoria || !categorias.includes(p.categoria));
        if (otros.length > 0) {
            html += `
                <div class="category-section">
                    <div class="category-header"><h3><i class="fas fa-box"></i> OTROS</h3></div>
                    ${renderProductGrid(otros)}
                </div>
            `;
        }
        
        container.innerHTML = html || '<p style="text-align:center;padding:40px;">No hay productos</p>';
        
        categorias.forEach(cat => {
            const prodsCat = products.filter(p => (p.categoria || 'otros') === cat);
            if (prodsCat.length > 0) initCategoryCarousel(cat, prodsCat);
        });
    } else {
        const filtrados = products.filter(p => (p.categoria || 'otros') === currentCategory);
        if (filtrados.length === 0) {
            container.innerHTML = '<p style="text-align:center;padding:40px;">No hay productos en esta categoría</p>';
            return;
        }
        let html = '';
        html += renderCategoryCarousel(currentCategory, filtrados);
        html += renderProductGrid(filtrados);
        container.innerHTML = html;
        if (filtrados.length > 0) initCategoryCarousel(currentCategory, filtrados);
    }
}

function renderCategoryCarousel(cat, productos) {
    const imagenes = productos.slice(0, 5).map(p => Array.isArray(p.imagen) ? p.imagen[0] : p.imagen).filter(img => img);
    if (imagenes.length === 0) return '';
    return `
        <div class="category-carousel-container" id="carousel-${cat}">
            <div class="category-carousel-slides" id="slides-${cat}">
                ${imagenes.map(src => `<div class="category-carousel-slide"><img src="${src}" loading="lazy" alt="${cat} - imagen promocional"></div>`).join('')}
            </div>
            <div class="category-carousel-dots" id="dots-${cat}"></div>
        </div>
    `;
}

function initCategoryCarousel(cat, productos) {
    const container = document.getElementById(`carousel-${cat}`);
    const slides = document.getElementById(`slides-${cat}`);
    const dots = document.getElementById(`dots-${cat}`);
    if (!container || !slides || !dots) return;
    
    const imagenes = productos.slice(0, 5).map(p => Array.isArray(p.imagen) ? p.imagen[0] : p.imagen).filter(img => img);
    dots.innerHTML = imagenes.map((_, i) => `<div class="category-dot ${i===0?'active':''}" onclick="goToSlide('${cat}',${i})" role="button" tabindex="0" aria-label="Slide ${i+1}"></div>`).join('');
    
    let currentSlide = 0;
    
    window.goToSlide = (catName, idx) => {
        if (catName !== cat) return;
        currentSlide = idx;
        slides.style.transform = `translateX(-${currentSlide * 100}%)`;
        document.querySelectorAll(`#dots-${cat} .category-dot`).forEach((d,i) => d.classList.toggle('active', i===currentSlide));
    };
    
    function nextSlide() {
        if (imagenes.length <= 1) return;
        currentSlide = (currentSlide + 1) % imagenes.length;
        slides.style.transform = `translateX(-${currentSlide * 100}%)`;
        document.querySelectorAll(`#dots-${cat} .category-dot`).forEach((d,i) => d.classList.toggle('active', i===currentSlide));
    }
    
    if (carouselIntervals[cat]) clearInterval(carouselIntervals[cat]);
    if (imagenes.length > 1) {
        carouselIntervals[cat] = setInterval(nextSlide, 5000);
    }
}

function renderProductGrid(productos) {
    if (!productos || productos.length === 0) return '';
    return `<div class="grid-productos">${productos.map(p => renderProductCard(p)).join('')}</div>`;
}

function renderProductCard(p) {
    const d = p.precio * (1 - (p.descuento || 0) / 100);
    const available = p.disponible === true || p.disponible === 'true';
    const img = Array.isArray(p.imagen) ? p.imagen[0] : p.imagen;
    const imgSrc = img || 'https://via.placeholder.com/300';
    
    return `
        <div class="producto-card" itemscope itemtype="https://schema.org/Product">
            <div class="card-img-wrapper" onclick="openProductModal(${p.id})" role="button" tabindex="0" aria-label="Ver detalles de ${p.nombre}">
                <img src="${imgSrc}" loading="lazy" alt="${p.nombre}" itemprop="image">
                <div class="availability-badge ${available ? 'badge-available' : 'badge-soldout'}">
                    ${available ? 'DISPONIBLE' : 'AGOTADO'}
                </div>
            </div>
            <div class="card-body">
                <h3 class="card-title" itemprop="name">${p.nombre}</h3>
                <div class="price-box">
                    ${p.descuento ? `<span class="old-price">${formatPrice(p.precio)}</span>` : ''}
                    <span class="new-price" itemprop="price">${formatPrice(d)}</span>
                </div>
                <div class="card-footer">
                    <div class="qty-control">
                        <button class="qty-btn" onclick="updateCardQty(this,-1)" ${!available ? 'disabled' : ''} aria-label="Disminuir cantidad">-</button>
                        <span class="qty-val" aria-label="Cantidad">1</span>
                        <button class="qty-btn" onclick="updateCardQty(this,1)" ${!available ? 'disabled' : ''} aria-label="Aumentar cantidad">+</button>
                    </div>
                    <button class="btn-add" onclick="addToCartFromCard(${p.id},this)" ${!available ? 'disabled' : ''} aria-label="Añadir ${p.nombre} al carrito">
                        <i class="fas fa-cart-plus"></i><span>Añadir</span>
                    </button>
                </div>
            </div>
        </div>
    `;
}

window.updateCardQty = (btn, delta) => {
    const val = btn.parentElement.querySelector('.qty-val');
    let v = parseInt(val.innerText) + delta;
    if (v >= 1) val.innerText = v;
};

window.openProductModal = (id) => {
    const p = products.find(x => x.id == id);
    if (!p) return;
    
    const available = p.disponible === true || p.disponible === 'true';
    const finalPrice = p.precio * (1 - (p.descuento || 0) / 100);
    const img = Array.isArray(p.imagen) ? p.imagen[0] : p.imagen || 'https://via.placeholder.com/500';
    
    document.getElementById('modalBody').innerHTML = `
        <div class="modal-product-image"><img src="${img}" alt="${p.nombre}" itemprop="image"></div>
        <div class="modal-product-info">
            <h2 class="modal-product-name" id="modalTitle">${p.nombre}</h2>
            <span class="modal-product-category">${p.categoria || 'General'}</span>
            <p class="modal-product-description">${p.descripcion || 'Producto de alta calidad.'}</p>
            <div class="modal-product-features">
                ${storeConfig?.envio?.disponible ? `
                <div class="feature-item"><i class="fas fa-truck" aria-hidden="true"></i><span>Envío <small>${storeConfig.envio.tiempo_estimado || '24-48h'}</small></span></div>
                ` : ''}
                ${storeConfig?.garantia?.disponible ? `
                <div class="feature-item"><i class="fas fa-shield-alt" aria-hidden="true"></i><span>Garantía <small>${storeConfig.garantia.duracion || '12 meses'}</small></span></div>
                ` : ''}
                <div class="feature-item"><i class="fas fa-credit-card" aria-hidden="true"></i><span>${storeConfig?.metodos_pago?.join(', ') || 'Efectivo, Transferencia'}</span></div>
            </div>
            <div class="modal-product-price">
                <div class="modal-price-label">Precio</div>
                <div><span class="modal-price-value">${formatPrice(finalPrice)}</span>${p.descuento ? `<span class="modal-old-price">${formatPrice(p.precio)}</span>` : ''}</div>
            </div>
            <div class="modal-product-actions">
                <div class="modal-qty-control">
                    <button class="modal-qty-btn" onclick="updateModalQty(-1)" ${!available ? 'disabled' : ''} aria-label="Disminuir cantidad">-</button>
                    <span class="modal-qty-val" id="modalQty">1</span>
                    <button class="modal-qty-btn" onclick="updateModalQty(1)" ${!available ? 'disabled' : ''} aria-label="Aumentar cantidad">+</button>
                </div>
                <button class="modal-btn-add" onclick="addToCartFromModal(${p.id})" ${!available ? 'disabled' : ''} aria-label="Añadir ${p.nombre} al carrito">
                    <i class="fas fa-cart-plus"></i> ${available ? 'Añadir' : 'Agotado'}
                </button>
            </div>
        </div>
    `;
    document.getElementById('productModal').classList.add('active');
    document.body.style.overflow = 'hidden';
};

window.closeProductModal = () => {
    document.getElementById('productModal').classList.remove('active');
    document.body.style.overflow = '';
};

window.updateModalQty = (delta) => {
    const val = document.getElementById('modalQty');
    let v = parseInt(val.innerText) + delta;
    if (v >= 1) val.innerText = v;
};

window.addToCartFromModal = (id) => {
    const qty = parseInt(document.getElementById('modalQty').innerText);
    addToCart(id, qty);
    closeProductModal();
};

window.addToCartFromCard = (id, btn) => {
    const card = btn.closest('.producto-card');
    const qty = parseInt(card.querySelector('.qty-val').innerText);
    addToCart(id, qty);
    card.querySelector('.qty-val').innerText = '1';
    btn.innerHTML = '<i class="fas fa-check"></i><span>✓</span>';
    btn.style.background = 'var(--success-color)';
    setTimeout(() => { 
        btn.innerHTML = '<i class="fas fa-cart-plus"></i><span>Añadir</span>'; 
        btn.style.background = ''; 
    }, 1000);
};

function addToCart(id, qty) {
    const p = products.find(x => x.id == id);
    if (!p || !(p.disponible === true || p.disponible === 'true')) {
        showToast('❌ Producto no disponible', 'error');
        return;
    }
    const price = p.precio * (1 - (p.descuento || 0) / 100);
    const exist = cart.find(i => i.id == id);
    if (exist) {
        exist.qty += qty;
    } else {
        cart.push({
            id: p.id,
            nombre: p.nombre,
            precio: price,
            imagen: Array.isArray(p.imagen) ? p.imagen[0] : p.imagen || 'https://via.placeholder.com/60',
            qty: qty
        });
    }
    updateCartUI();
    saveCart();
    showToast(`✨ ${p.nombre} agregado`);
}

function updateCartUI() {
    const cont = document.getElementById('cartItemsContainer');
    const totalSpan = document.getElementById('cartTotal');
    const subtotalSpan = document.getElementById('cartSubtotal');
    const countSpan = document.getElementById('cartCount');
    const cartBtn = document.getElementById('cartBtn');
    const floatBtn = document.getElementById('floatingCheckoutBtn');
    const checkoutTotal = document.getElementById('checkoutTotalAmount');
    
    let total = 0, count = 0;
    
    if (!cart.length) {
        cont.innerHTML = '<div class="cart-empty-state"><i class="fas fa-shopping-basket"></i><p>Tu carrito está vacío</p></div>';
        totalSpan.innerText = `0 ${currentCurrency}`;
        subtotalSpan.innerText = `0 ${currentCurrency}`;
        countSpan.innerText = '0';
        cartBtn.classList.remove('has-items');
        floatBtn.style.display = 'none';
        if (checkoutTotal) checkoutTotal.innerText = `0 ${currentCurrency}`;
        return;
    }
    
    cartBtn.classList.add('has-items');
    floatBtn.style.display = 'flex';
    
    cont.innerHTML = cart.map((i, idx) => {
        total += i.precio * i.qty;
        count += i.qty;
        return `<div class="cart-item">
            <img src="${i.imagen}" loading="lazy" alt="${i.nombre}">
            <div class="item-details">
                <div class="item-name">${i.nombre}</div>
                <div class="item-price">${formatPrice(i.precio * i.qty)}</div>
                <div class="item-actions">
                    <button class="cart-qty-btn" onclick="modifyCartQty(${idx},-1)" aria-label="Disminuir cantidad">−</button>
                    <span class="cart-qty-val">${i.qty}</span>
                    <button class="cart-qty-btn" onclick="modifyCartQty(${idx},1)" aria-label="Aumentar cantidad">+</button>
                    <i class="fas fa-trash-alt item-remove" onclick="removeFromCart(${idx})" role="button" tabindex="0" aria-label="Eliminar producto"></i>
                </div>
            </div>
        </div>`;
    }).join('');
    
    const formattedTotal = formatPrice(total);
    totalSpan.innerText = formattedTotal;
    subtotalSpan.innerText = formattedTotal;
    countSpan.innerText = count;
    if (checkoutTotal) checkoutTotal.innerText = formattedTotal;
}

window.modifyCartQty = (idx, d) => {
    if (cart[idx]) {
        cart[idx].qty += d;
        if (cart[idx].qty <= 0) cart.splice(idx, 1);
        updateCartUI();
        saveCart();
    }
};

window.removeFromCart = (idx) => {
    cart.splice(idx, 1);
    updateCartUI();
    saveCart();
    showToast('Producto eliminado');
};

function saveCart() {
    localStorage.setItem(`lareina_cart_${currentStore}`, JSON.stringify(cart));
}

function loadCart() {
    const saved = localStorage.getItem(`lareina_cart_${currentStore}`);
    if (saved) try { cart = JSON.parse(saved); updateCartUI(); } catch { cart = []; }
}

window.toggleBankInfo = () => {
    const metodo = document.querySelector('input[name="paymentMethod"]:checked')?.value;
    const bankBox = document.getElementById('bankInfoBox');
    const noCardWarning = document.getElementById('noCardWarning');
    const btnConfirmar = document.getElementById('btnConfirmarPedido');
    const codigoBox = document.getElementById('codigoClienteBox');
    
    if (codigoBox) codigoBox.style.display = 'none';
    
    if (metodo === 'Transferencia') {
        const numeroTarjeta = storeConfig?.datos_bancarios?.numero_tarjeta;
        const whatsapp = storeConfig?.datos_bancarios?.whatsapp_confirmacion;
        
        if (!numeroTarjeta || numeroTarjeta.trim() === '') {
            bankBox.classList.remove('visible');
            noCardWarning.style.display = 'block';
            if (btnConfirmar) {
                btnConfirmar.disabled = true;
                btnConfirmar.style.opacity = '0.5';
                btnConfirmar.style.cursor = 'not-allowed';
            }
        } else {
            noCardWarning.style.display = 'none';
            if (btnConfirmar) {
                btnConfirmar.disabled = false;
                btnConfirmar.style.opacity = '1';
                btnConfirmar.style.cursor = 'pointer';
            }
            
            document.getElementById('bankCardNumber').innerText = numeroTarjeta;
            
            if (whatsapp) {
                const total = cart.reduce((s, i) => s + i.precio * i.qty, 0);
                const mensaje = encodeURIComponent(
                    `Hola, adjunto comprobante de transferencia por ${formatPrice(total)} ` +
                    `del pedido en ${storeInfo?.nombre || currentStore}. ` +
                    `Nombre: [Escribe tu nombre aquí]`
                );
                document.getElementById('whatsappBankLink').href = 
                    `https://wa.me/${whatsapp.replace(/\D/g, '')}?text=${mensaje}`;
                document.getElementById('whatsappBankLink').style.display = 'block';
            } else {
                document.getElementById('whatsappBankLink').style.display = 'none';
            }
            
            bankBox.classList.add('visible');
        }
    } else {
        bankBox.classList.remove('visible');
        noCardWarning.style.display = 'none';
        if (btnConfirmar) {
            btnConfirmar.disabled = false;
            btnConfirmar.style.opacity = '1';
            btnConfirmar.style.cursor = 'pointer';
        }
    }
};

window.showCheckoutForm = () => {
    if (!cart.length) { 
        showToast('Agrega productos primero', 'error'); 
        return; 
    }
    
    document.getElementById('cartItemsView').style.display = 'none';
    document.getElementById('checkoutFormView').style.display = 'block';
    document.getElementById('floatingCheckoutBtn').style.display = 'none';
    
    const total = cart.reduce((s, i) => s + i.precio * i.qty, 0);
    document.getElementById('checkoutTotalAmount').innerText = formatPrice(total);
    
    document.querySelector('input[name="paymentMethod"][value="Efectivo"]').checked = true;
    const codigoBox = document.getElementById('codigoClienteBox');
    if (codigoBox) codigoBox.style.display = 'none';
    toggleBankInfo();
};

window.cancelarCheckout = () => {
    document.getElementById('cartItemsView').style.display = 'flex';
    document.getElementById('checkoutFormView').style.display = 'none';
    
    document.getElementById('cliName').value = '';
    document.getElementById('cliPhone').value = '';
    document.getElementById('cliAddress').value = '';
    
    document.getElementById('cliName').classList.remove('error');
    document.getElementById('cliPhone').classList.remove('error');
    document.getElementById('cliAddress').classList.remove('error');
    
    const codigoBox = document.getElementById('codigoClienteBox');
    if (codigoBox) codigoBox.style.display = 'none';
    
    if (cart.length) {
        document.getElementById('floatingCheckoutBtn').style.display = 'flex';
    }
};

window.enviarPedido = async () => {
    if (!validarFormularioPedido()) return;
    
    const n = document.getElementById('cliName').value.trim();
    const t = document.getElementById('cliPhone').value.trim();
    const d = document.getElementById('cliAddress').value.trim();
    const metodoPago = document.querySelector('input[name="paymentMethod"]:checked')?.value || 'Efectivo';
    
    const telefonoLimpio = t.replace(/[^0-9]/g, '');
    const telefonoFinal = telefonoLimpio.startsWith('53') && telefonoLimpio.length === 10 
        ? telefonoLimpio.substring(2) 
        : telefonoLimpio;
    
    if (!cart.length) { 
        showToast('⚠️ Carrito vacío', 'error'); 
        return; 
    }
    
    if (metodoPago === 'Transferencia') {
        const numeroTarjeta = storeConfig?.datos_bancarios?.numero_tarjeta;
        if (!numeroTarjeta || numeroTarjeta.trim() === '') {
            showToast('❌ Transferencia no disponible. Contacte al administrador.', 'error');
            return;
        }
    }
    
    const total = cart.reduce((s, i) => s + i.precio * i.qty, 0);
    
    const btn = document.getElementById('btnConfirmarPedido');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
    btn.disabled = true;
    
    try {
        const payload = {
            tienda: currentStore,
            nombre: n,
            telefono: telefonoFinal,
            direccion: d,
            items: cart.map(item => ({
                id: item.id,
                nombre: item.nombre,
                precio: item.precio,
                qty: item.qty,
                imagen: item.imagen || ''
            })),
            total: parseFloat(total.toFixed(2)),
            moneda: currentCurrency,
            metodoPago: metodoPago
        };
        
        const r = await fetch('/api/pedidos', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await r.json();
        
        if (data.success) {
            document.getElementById('codigoClienteDisplay').innerText = data.codigoCliente;
            document.getElementById('codigoClienteBox').style.display = 'block';
            document.getElementById('btnConfirmarPedido').style.display = 'none';
            showToast(`✅ ¡Pedido #${data.orderId} registrado! Su código: ${data.codigoCliente}`);
            cart = [];
            updateCartUI();
            saveCart();
            
            document.getElementById('cliName').value = '';
            document.getElementById('cliPhone').value = '';
            document.getElementById('cliAddress').value = '';
        } else {
            showToast('❌ ' + (data.error || 'Error al procesar el pedido'), 'error');
        }
    } catch (e) { 
        console.error('Error al enviar pedido:', e);
        showToast('❌ Error de conexión. Verifica tu internet.', 'error'); 
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
};

function validarFormularioPedido() {
    const nombre = document.getElementById('cliName').value.trim();
    const telefono = document.getElementById('cliPhone').value.trim();
    const direccion = document.getElementById('cliAddress').value.trim();
    
    if (!nombre) { showToast('⚠️ El nombre es obligatorio', 'error'); return false; }
    if (!/^[a-zA-ZáéíóúñÑ\s]+$/.test(nombre)) { 
        showToast('⚠️ El nombre solo puede contener letras', 'error'); 
        return false; 
    }
    if (nombre.length < 2 || nombre.length > 60) {
        showToast('⚠️ El nombre debe tener entre 2 y 60 caracteres', 'error');
        return false;
    }
    
    const nombreFiltrado = filtrarPalabrasOfensivas(nombre);
    if (nombreFiltrado.ofensivo) {
        showToast('⚠️ El nombre contiene palabras inapropiadas', 'error');
        return false;
    }
    
    if (!telefono) { showToast('⚠️ El teléfono es obligatorio', 'error'); return false; }
    const telefonoLimpio = telefono.replace(/[^0-9]/g, '');
    if (telefonoLimpio.length !== 8 && !(telefonoLimpio.length === 10 && telefonoLimpio.startsWith('53'))) {
        showToast('⚠️ Teléfono cubano: 5XXXXXXX (8 dígitos)', 'error');
        return false;
    }
    
    if (!direccion) { showToast('⚠️ La dirección es obligatoria', 'error'); return false; }
    if (direccion.length < 5 || direccion.length > 200) {
        showToast('⚠️ La dirección debe tener entre 5 y 200 caracteres', 'error');
        return false;
    }
    
    if (!cart || cart.length === 0) {
        showToast('⚠️ El carrito está vacío', 'error');
        return false;
    }
    
    return true;
}

function showEmptyProductsMessage() {
    const container = document.getElementById('dynamicContent');
    container.innerHTML = `
        <div class="empty-products">
            <i class="fas fa-box-open"></i>
            <h3>No hay productos disponibles</h3>
            <p>Actualmente no tenemos productos en esta categoría.<br>Vuelve más tarde o contacta con el administrador.</p>
        </div>
    `;
}

function generateOfflineSlides() {
    const slidesContainer = document.getElementById('promoSlides');
    const indicators = document.getElementById('promoIndicators');
    
    const productImages = [];
    if (categorias.length > 0) {
        categorias.forEach(cat => {
            const productInCat = products.find(p => (p.categoria || 'otros') === cat);
            if (productInCat) {
                productImages.push({
                    url: Array.isArray(productInCat.imagen) ? productInCat.imagen[0] : productInCat.imagen,
                    category: cat
                });
            }
        });
    }
    
    if (productImages.length === 0) {
        productImages.push({ url: 'https://images.unsplash.com/photo-1581091226033-d5c48150dbaa?w=1200', category: 'Productos' });
        productImages.push({ url: 'https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=1200', category: 'Ofertas' });
    }

    slidesContainer.innerHTML = productImages.map((img, i) => `
        <div class="promo-slide ${i === 0 ? 'active' : ''}" style="background-image: url('${img.url}')">
            <div class="promo-content">
                <span class="promo-badge">${img.category.toUpperCase()}</span>
                <h1>Tienda La Reina</h1>
                <p>Productos de alta calidad</p>
            </div>
        </div>
    `).join('');

    indicators.innerHTML = productImages.map((_, i) => `
        <div class="promo-dot ${i === 0 ? 'active' : ''}" data-slide="${i}"></div>
    `).join('');

    document.querySelectorAll('.promo-dot').forEach(dot => {
        dot.addEventListener('click', function() {
            const slideIndex = parseInt(this.dataset.slide);
            document.querySelectorAll('.promo-slide').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.promo-dot').forEach(d => d.classList.remove('active'));
            document.querySelectorAll('.promo-slide')[slideIndex].classList.add('active');
            this.classList.add('active');
        });
    });

    if (offlineSlideshowInterval) clearInterval(offlineSlideshowInterval);
    let currentSlide = 0;
    offlineSlideshowInterval = setInterval(() => {
        currentSlide = (currentSlide + 1) % productImages.length;
        document.querySelectorAll('.promo-slide').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.promo-dot').forEach(d => d.classList.remove('active'));
        document.querySelectorAll('.promo-slide')[currentSlide].classList.add('active');
        document.querySelectorAll('.promo-dot')[currentSlide].classList.add('active');
    }, 4000);
}

function clearOfflineSlideshow() {
    if (offlineSlideshowInterval) {
        clearInterval(offlineSlideshowInterval);
        offlineSlideshowInterval = null;
    }
}

window.scrollToProducts = () => {
    document.getElementById('productosSection').scrollIntoView({ behavior: 'smooth' });
};

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('menuToggle').onclick = () => {
        document.getElementById('sideMenu').classList.add('mostrar');
        document.getElementById('overlay').classList.add('mostrar');
    };
    
    document.getElementById('closeMenu').onclick = () => {
        document.getElementById('sideMenu').classList.remove('mostrar');
        document.getElementById('overlay').classList.remove('mostrar');
    };
    
    document.getElementById('overlay').onclick = () => {
        document.getElementById('sideMenu').classList.remove('mostrar');
        document.getElementById('overlay').classList.remove('mostrar');
    };
    
    document.getElementById('cartBtn').onclick = () => {
        document.getElementById('cartPanel').classList.add('active');
        document.getElementById('floatingCheckoutBtn').style.display = 'none';
        document.getElementById('cartItemsView').style.display = 'flex';
        document.getElementById('checkoutFormView').style.display = 'none';
    };
    
    document.getElementById('closeCart').onclick = () => {
        document.getElementById('cartPanel').classList.remove('active');
        if (cart.length) {
            document.getElementById('floatingCheckoutBtn').style.display = 'flex';
        }
    };

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.getElementById('sideMenu').classList.remove('mostrar');
            document.getElementById('overlay').classList.remove('mostrar');
            document.getElementById('cartPanel').classList.remove('active');
            closeProductModal();
        }
    });

    const currencyBtn = document.getElementById('currencyBtn');
    const currencyMenu = document.getElementById('currencyMenu');
    
    currencyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        currencyMenu.classList.toggle('active');
    });
    
    document.addEventListener('click', () => currencyMenu.classList.remove('active'));
    
    document.querySelectorAll('.currency-option').forEach(opt => {
        opt.addEventListener('click', () => {
            currentCurrency = opt.dataset.currency;
            document.getElementById('selectedCurrencyText').textContent = currentCurrency;
            document.querySelectorAll('.currency-option').forEach(o => o.classList.remove('active'));
            opt.classList.add('active');
            currencyMenu.classList.remove('active');
            renderContent();
            updateCartUI();
        });
    });
});

async function init() {
    console.log("🚀 Iniciando tienda optimizada...");
    
    await loadConfig();
    await loadTiendasMenu();
    
    if (!currentStore || currentStore === '') {
        document.getElementById('dynamicContent').innerHTML = `
            <div class="empty-products">
                <i class="fas fa-store-slash"></i>
                <h3>No hay tiendas disponibles</h3>
                <p>Actualmente no hay tiendas creadas. Contacta al administrador.</p>
            </div>
        `;
        document.getElementById('globalLoader').classList.add('hidden');
        return;
    }
    
    await updateUIForStore();
    
    const online = await window.checkServerAndReload();
    if (!online) {
        loadCachedProductsForOffline();
        generateOfflineSlides();
    }
    
    await loadTiendasMenu();
    loadCart();
    
    document.getElementById('globalLoader').classList.add('hidden');
    console.log(`✅ Tienda inicializada: ${currentStore}`);
    
    setInterval(() => window.checkServerAndReload(), 30000);
}

async function loadTiendasMenu() {
    try {
        const res = await fetch('/api/tiendas/info?_=' + Date.now());
        let tiendas = await res.json();
        const container = document.getElementById('tiendasList');
        
        if (!tiendas || tiendas.length === 0) {
            container.innerHTML = '<p class="text-center text-muted">No hay tiendas disponibles</p>';
            return;
        }
        
        if (primeraCarga && (!currentStore || currentStore === '')) {
            currentStore = tiendas[0].id;
            const url = new URL(window.location);
            url.searchParams.set('tienda', currentStore);
            window.history.pushState({}, '', url);
            primeraCarga = false;
        }
        
        const tiendaExiste = tiendas.some(t => t.id === currentStore);
        if (!tiendaExiste && tiendas.length > 0) {
            currentStore = tiendas[0].id;
            const url = new URL(window.location);
            url.searchParams.set('tienda', currentStore);
            window.history.pushState({}, '', url);
        }
        
        container.innerHTML = tiendas.map(t => `
            <a href="/?tienda=${t.id}" class="tienda-link ${t.id === currentStore ? 'active' : ''}">
                <i class="fas fa-store"></i> ${t.nombre || t.id}
            </a>
        `).join('');
    } catch (e) {
        console.error('Error loading tiendas menu:', e);
    }
}

async function updateUIForStore() {
    if (!currentStore) return;
    try {
        const res = await fetch(`/api/tiendas/${currentStore}?_=${Date.now()}`);
        storeInfo = await res.json();
        
        document.getElementById('headerStoreName').innerText = storeInfo.nombre || 'Tienda La Reina';
        document.getElementById('dynamicTitle').innerText = storeInfo.nombre || 'Tienda La Reina';
        document.getElementById('heroTitle').innerText = `Bienvenido a ${storeInfo.nombre || 'Tienda La Reina'}`;
        document.getElementById('heroDescription').innerText = storeInfo.descripcion || 'Encuentra los mejores productos.';
        
        await loadStoreConfig();
    } catch (e) {
        console.error('Error updating UI for store:', e);
    }
}

async function loadStoreConfig() {
    try {
        const res = await fetch(`/api/tiendas/${currentStore}/config?_=${Date.now()}`);
        storeConfig = await res.json();
    } catch (e) {
        console.error('Error loading store config:', e);
    }
}

document.addEventListener('DOMContentLoaded', init);

window.addEventListener('beforeunload', () => {
    clearOfflineSlideshow();
    Object.values(carouselIntervals).forEach(clearInterval);
});